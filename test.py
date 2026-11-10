"""Phase 2 experiment: compare the three scorers on single-byte XOR cracking.

Each test sentence is encrypted with the same single-byte key. For every
scorer, all 256 keys are tried and ranked, and the script prints:
  * where the correct key ranked, and its score,
  * the top 3 candidates with their decryptions,
  * the best wrong key and the separation ratio (how clearly the scorer
    tells the real key from its strongest impostor).
"""

from core import xor_bytes
from scoring import english_score, frequency_score, chi_squared_score
from single_byte import crack

# The key every test sentence is encrypted with.
KEY = 0x58

# Sentences chosen to be awkward: all capitals, and digits.
TESTS = [
    b"I LOVE WORKING OUT",
    b"I WANT TO BE THE BEST IN THE WORLD",
    b"I tried to stop smoking 125970 times",
]

# (name, scoring function, higher_is_better)
# v1 and v2 reward English-like text; v3 (chi-squared) measures distance
# from English, so for it a LOWER score is better.
SCORERS = [
    ("v1 english", english_score, True),
    ("v2 frequency", frequency_score, True),
    ("v3 chi-squared", chi_squared_score, False),
]


def separation(real: float, impostor: float, higher_is_better: bool) -> str:
    """How many times better the real key scores than the best wrong key.

    The scorers use different scales, so a ratio is the fair way to compare
    them. For lower-is-better scorers the ratio is flipped (impostor / real),
    so a bigger number always means a clearer win. Returns "n/a" when the
    ratio isn't meaningful (division by zero or an infinite score).
    """
    good, bad = (real, impostor) if higher_is_better else (impostor, real)
    if bad <= 0 or good == float("inf"):
        return "n/a"
    return f"{good / bad:.2f}x"


def report(text: bytes, scorer, higher_is_better: bool) -> None:
    """Encrypt `text` with KEY, crack it with `scorer`, and print the results."""
    cipher = xor_bytes(text, bytes([KEY]))
    results = crack(cipher, scorer, higher_is_better)   # (key, score, plaintext), best first

    rank = [r[0] for r in results].index(KEY) + 1
    real_score = next(r[1] for r in results if r[0] == KEY)
    best_wrong = next(r for r in results if r[0] != KEY)

    print(f"\n{text}")
    print(f"  correct key 0x{KEY:02x} ranked #{rank}, score {real_score:.2f}")
    print("  top 3:")
    for k, score, plain in results[:3]:
        mark = "  <-- correct" if k == KEY else ""
        print(f"    0x{k:02x}  {score:10.2f}  {plain!r}{mark}")
    print(
        f"  best impostor 0x{best_wrong[0]:02x} "
        f"({best_wrong[1]:.2f}), separation: "
        f"{separation(real_score, best_wrong[1], higher_is_better)}"
    )


def main() -> None:
    """Run every test sentence through every scorer."""
    for name, scorer, higher_is_better in SCORERS:
        direction = "higher" if higher_is_better else "lower"
        print(f"\n===== {name} ({direction} is better) =====")
        for text in TESTS:
            report(text, scorer, higher_is_better)


if __name__ == "__main__":
    main()