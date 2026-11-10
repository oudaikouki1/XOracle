"""Phase 2: breaking single-byte XOR.

A single-byte key has only 256 possible values, so we simply try them all
and rank each decryption with a scorer that measures how English it looks.
Phases 3 and 5 reuse this to break each column of a longer key.
"""

from core import xor_bytes
from scoring import chi_squared_score


def crack(cipher: bytes, scorer, higher_is_better: bool) -> list[tuple[int, float, bytes]]:
    """Try all 256 single-byte keys and rank the decryptions.

    `scorer` takes a plaintext and returns a number. Set `higher_is_better`
    to match it: True for english_score and frequency_score, False for
    chi_squared_score (a distance from English, so lower is better).

    Returns (key, score, plaintext) tuples, best candidate first.
    """
    results = []
    for k in range(256):
        plain = xor_bytes(cipher, bytes([k]))
        results.append((k, scorer(plain), plain))
    results.sort(key=lambda r: r[1], reverse=higher_is_better)
    return results


def best_key(cipher: bytes, scorer=chi_squared_score, higher_is_better: bool = False) -> int:
    """Return the most likely single-byte key for `cipher`.

    Defaults to chi-squared, the strongest of the three scorers in Phase 2.
    """
    results = crack(cipher, scorer, higher_is_better)
    return results[0][0]        # key of the best-ranked candidate
