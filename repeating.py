"""Phase 3: breaking repeating-key XOR (e.g. key ICE -> ICEICEICE...).

The attack:
  1. guess_keysizes   find likely key lengths with the Hamming distance
  2. transpose        split the ciphertext into one column per key byte
  3. recover_key      break each column as single-byte XOR (Phase 2)
  4. break_repeating_xor
                      try every candidate length and keep the best decryption
"""

import math

from core import xor_bytes
from scoring import chi_squared_score
from single_byte import best_key


# ------------------------------------------------------- finding the key length

def hamming_distance(a: bytes, b: bytes) -> int:
    """Number of differing bits between two equal-length byte strings.

    XOR sets a 1 bit exactly where two bytes differ, so we count the 1 bits.
    """
    if len(a) != len(b):
        raise ValueError("a and b must have the same length")
    distance = 0
    for x, y in zip(a, b):
        distance += (x ^ y).bit_count()
    return distance


def keysize_score(cipher: bytes, keysize: int) -> float:
    """Average normalised Hamming distance between consecutive blocks.

    If `keysize` is the real key length, two consecutive blocks were XORed
    with the same key bytes, so the key cancels out and we compare English
    with English, which differs in fewer bits than random bytes.
    Lower = more likely key length. Returns inf if there aren't 2 blocks.
    """
    num_blocks = len(cipher) // keysize
    if num_blocks < 2:
        return float("inf")

    blocks = [cipher[i * keysize:(i + 1) * keysize] for i in range(num_blocks)]
    distances = []
    for i in range(num_blocks - 1):
        d = hamming_distance(blocks[i], blocks[i + 1])
        distances.append(d / keysize)      # per byte, so lengths are comparable
    return sum(distances) / len(distances)


def guess_keysizes(cipher: bytes, min_k: int = 2, max_k: int = 40, top: int = 5) -> list[int]:
    """The `top` most likely key lengths, best first.

    Multiples of the real length score as well as the real length, so the
    top candidates are usually all multiples of it. Their greatest common
    divisor is then the real length: if it's greater than 1 and not already
    in the list, it's added at the front.
    """
    results = sorted((keysize_score(cipher, k), k) for k in range(min_k, max_k + 1))
    top_ks = [k for score, k in results[:top]]
    g = math.gcd(*top_ks)
    if g > 1 and g not in top_ks:
        top_ks.insert(0, g)
    return top_ks


# ------------------------------------------------------ recovering the key

def transpose(cipher: bytes, keysize: int) -> list[bytes]:
    """Split `cipher` into `keysize` columns.

    Column i holds every byte encrypted by key byte i (positions i, i+k, i+2k...),
    so each column is a single-byte XOR problem.
    """
    return [cipher[i::keysize] for i in range(keysize)]


def recover_key(cipher: bytes, keysize: int) -> bytes:
    """Recover the key, assuming it has length `keysize`: one key byte per column."""
    return bytes(best_key(column) for column in transpose(cipher, keysize))


def break_repeating_xor(cipher: bytes, tolerance: float = 0.10) -> tuple[bytes, bytes]:
    """Recover (key, plaintext) from a repeating-key XOR ciphertext.

    Every candidate length gives a key and a decryption, scored with
    chi-squared (lower = more English). Longer keys can overfit the text
    and score slightly better than the real key, so among candidates within
    `tolerance` of the best score, the shortest key wins.
    """
    candidates = []              # (score, key length, key, plaintext)
    for keysize in guess_keysizes(cipher):
        key = recover_key(cipher, keysize)
        plain = xor_bytes(cipher, key)
        candidates.append((chi_squared_score(plain), len(key), key, plain))

    if not candidates:
        return b"", b""

    best = min(c[0] for c in candidates)                             # lowest chi-squared
    close = [c for c in candidates if c[0] <= best * (1 + tolerance)]
    winner = min(close, key=lambda c: c[1])                          # shortest key among them
    return winner[2], winner[3]


if __name__ == "__main__":
    # Checkpoint: this must print 37.
    print(hamming_distance(b"this is a test", b"wokka wokka!!!"))