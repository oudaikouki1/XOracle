"""Phase 3 experiments: break repeating-key XOR and find where it stops working.

Running this file:
  1. demo:         encrypt samples/plain.txt with b"ICE" and recover key + text,
  2. stress test:  random keys of several lengths x texts of several lengths,
                   reporting how many key bytes were recovered wrongly.
"""

import random

from core import xor_bytes
from repeating import break_repeating_xor, guess_keysizes

PLAINTEXT_PATH = "./samples/plain.txt"
DEMO_KEY = b"ICE"

# Stress-test grid. Bytes per column = text length // key length:
# the less text each key byte gets, the harder it is to recover.
KEY_LENGTHS = [3, 7, 16, 29]
TEXT_LENGTHS_SHORT = [1000, 500, 200, 100]   # the full text length is added in main()
SEED = 42                                    # fixed seed: same random keys every run

# Returned by wrong_bytes when the recovered key has the wrong length.
# A real count of wrong bytes can never be negative, so -1 can't be mistaken for one.
WRONG_LENGTH = -1


def load_plaintext(path: str) -> bytes:
    """Read the test plaintext as raw bytes."""
    with open(path, "rb") as file:
        return file.read()


def wrong_bytes(found: bytes, real: bytes) -> int:
    """Number of key bytes recovered incorrectly, or WRONG_LENGTH if the
    recovered key doesn't even have the right length."""
    if len(found) != len(real):
        return WRONG_LENGTH
    return sum(1 for a, b in zip(found, real) if a != b)


def demo(data: bytes, key: bytes) -> None:
    """Encrypt `data` with `key`, then recover both from the ciphertext alone."""
    cipher = xor_bytes(data, key)
    print("Candidate key lengths:", guess_keysizes(cipher))

    found_key, found_text = break_repeating_xor(cipher)
    print("Recovered key:", found_key, "| correct:", found_key == key)
    print(found_text.decode("utf-8", errors="replace"))


def stress_test(data: bytes) -> None:
    """Try every key length against every text length and print one line each.

    Under each line, a diagnostic shows the candidate key lengths and whether
    the real length was among them, which separates the two kinds of failure:
    the real length never guessed, or a multiple of it chosen instead.
    """
    rng = random.Random(SEED)
    text_lengths = [len(data)] + TEXT_LENGTHS_SHORT

    for key_len in KEY_LENGTHS:
        key = rng.randbytes(key_len)              # same key for every text length
        for text_len in text_lengths:
            cipher = xor_bytes(data[:text_len], key)
            found_key, _ = break_repeating_xor(cipher)

            bad = wrong_bytes(found_key, key)
            result = "wrong length" if bad == WRONG_LENGTH else f"{bad} wrong"
            per_column = text_len // key_len
            print(f"key={key_len:2d}  text={text_len:4d}  bytes/col={per_column:4d}  {result}")

            candidates = guess_keysizes(cipher)
            print("   candidates:", candidates,
                  "| real in list:", key_len in candidates,
                  "| found len:", len(found_key))


def main() -> None:
    data = load_plaintext(PLAINTEXT_PATH)
    print(f"===== Demo: key {DEMO_KEY!r} on {len(data)} bytes =====")
    demo(data, DEMO_KEY)
    print("\n===== Stress test =====")
    stress_test(data)


if __name__ == "__main__":
    main()