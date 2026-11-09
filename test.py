"""Compare the three scorers on single-byte XOR cracking."""

from core import xor_bytes
from scoring import english_score, frequency_score, chi_squared_score

KEY = 0x58

TESTS = [
    b"I LOVE WORKING OUT",
    b"I WANT TO BE THE BEST IN THE WORLD",
    b"I tried to stop smoking 125970 times",
]

# (name, function, higher_is_better)
SCORERS = [
    ("v1 english", english_score, True),
    ("v2 frequency", frequency_score, True),
    ("v3 chi-squared", chi_squared_score, False),
]


def crack(cipher: bytes, scorer, higher_is_better: bool) -> list:
    """Try all 256 keys; return (key, score, plaintext) sorted best first."""
    results = []
    for k in range(256):
        plain = xor_bytes(cipher, bytes([k]))
        results.append((k, scorer(plain), plain))
    results.sort(key=lambda r: r[1], reverse=higher_is_better)
    return results


def separation(real: float, impostor: float, higher_is_better: bool) -> str:
    """How many times better the real key scores than the best wrong key."""
    good, bad = (real, impostor) if higher_is_better else (impostor, real)
    if bad <= 0 or good == float("inf"):
        return "n/a"
    return f"{good / bad:.2f}x"


def main():
    for name, scorer, higher_is_better in SCORERS:
        print(f"\n===== {name} ({'higher' if higher_is_better else 'lower'} is better) =====")
        for text in TESTS:
            cipher = xor_bytes(text, bytes([KEY]))
            results = crack(cipher, scorer, higher_is_better)

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


if __name__ == "__main__":
    main()