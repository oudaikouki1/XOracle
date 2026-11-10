import math
from core import xor_bytes
from single_byte import best_key
from scoring import chi_squared_score


def hamming_distance(a: bytes,b: bytes) -> int :
    """Number of differing bits between two equal-length byte strings."""
    if len(a) != len(b):
        raise ValueError("a and b must have the same length")
    distance = 0
    for x,y in zip(a,b):
        distance += (x ^ y).bit_count()

    return distance

def keysize_score(cipher: bytes,keysize: int) -> float:
    """Average normalized Hamming distance between blocks. Lower = more likely key length."""    
    num_blocks = len(cipher) // keysize

    if num_blocks < 2:
        return float("inf")

    blocks = [cipher[i * keysize:(i + 1) * keysize] for i in range(num_blocks)]
    distances = []
    for i in range(num_blocks - 1):
        d = hamming_distance(blocks[i], blocks[i + 1])
        distances.append(d / keysize)

    return sum(distances) / len(distances)

def guess_keysizes(cipher: bytes, min_k: int = 2, max_k: int = 40, top: int = 5) -> list[int]:
    results = sorted((keysize_score(cipher, k), k) for k in range(min_k, max_k+1))
    top_ks = [k for score, k in results[:top]]
    g = math.gcd(*top_ks)
    if g>1 and g not in top_ks:
        top_ks.insert(0,g)
    return top_ks

def transpose(cipher: bytes, keysize: int) -> list[bytes]:
    """Split cipher into keysize columns; column i holds every byte encrypted by key byte i."""
    columns = []
    for i in range(keysize):
        column = cipher[i::keysize]
        columns.append(column)
    return columns

def recover_key(cipher: bytes, keysize: int) -> bytes:
    """Recover the key, assuming it has length keysize."""
    columns = transpose(cipher, keysize)
    key_bytes = []
    for column in columns:
        key_bytes.append(best_key(column))
    return bytes(key_bytes)

def break_repeating_xor(cipher: bytes, tolerance: float = 0.10) -> tuple[bytes, bytes]:
    """Recover (key, plaintext) from a repeating-key XOR ciphertext.

    Longer keys can overfit the text and score slightly better than the real key,
    so among candidates scoring within `tolerance` of the best, pick the shortest key.
    """
    candidates = []
    for keysize in guess_keysizes(cipher):
        key = recover_key(cipher, keysize)
        plain = xor_bytes(cipher, key)
        score = chi_squared_score(plain)
        candidates.append((score, len(key), key, plain))

    if not candidates:
        return b"", b""

    best = min(c[0] for c in candidates)                            # lowest chi-squared
    close = [c for c in candidates if c[0] <= best * (1 + tolerance)]
    winner = min(close, key=lambda c: c[1])                         # shortest key among them
    return winner[2], winner[3]


if __name__ == "__main__":
    #checkpoint for hamming distance
    print(hamming_distance(b"this is a test", b"wokka wokka!!!"))