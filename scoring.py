"""Scorers that measure how much a byte string looks like English text.

Used to rank candidate decryptions (Phase 2) and the columns of a
repeating key (Phases 3 and 5). Three versions, each fixing the
weaknesses of the one before:

  v1  english_score      character classes          higher = more English
  v2  frequency_score    English letter frequencies higher = more English
  v3  chi_squared_score  whole-distribution check   LOWER  = more English
"""

import string

# ------------------------------------------------------------------- tables

# Share of each letter (and the space) in English text.
english_frequencies = {
    "a": 0.08167,
    "b": 0.01492,
    "c": 0.02202,
    "d": 0.04253,
    "e": 0.12702,
    "f": 0.02880,
    "g": 0.01935,
    "h": 0.06749,
    "i": 0.07507,
    "j": 0.00153,
    "k": 0.01292,
    "l": 0.04126,
    "m": 0.02563,
    "n": 0.06749,
    "o": 0.07507,
    "p": 0.01935,
    "q": 0.00153,
    "r": 0.06749,
    "s": 0.06749,
    "t": 0.09285,
    "u": 0.02880,
    "v": 0.01935,
    "w": 0.01492,
    "x": 0.00153,
    "y": 0.00153,
    "z": 0.00153,
    " ": 0.13000,
}

# Expected share of spaces, and of everything that isn't a letter or a space
# (digits, punctuation, symbols, non-ASCII bytes) in English text.
SPACE_SHARE = 0.15
OTHER_SHARE = 0.02


def _build_chi_table() -> dict[str, float]:
    """Expected share of each chi-squared category, summing to 1.

    The letters are rescaled to fill what's left after the space and
    "other" shares, so expected counts add up to the text's real length.
    """
    letters = {c: f for c, f in english_frequencies.items() if c in string.ascii_lowercase}
    letter_total = sum(letters.values())
    letter_share = 1 - SPACE_SHARE - OTHER_SHARE
    table = {c: f / letter_total * letter_share for c, f in letters.items()}
    table[" "] = SPACE_SHARE
    table["other"] = OTHER_SHARE
    return table


CHI_TABLE = _build_chi_table()

# Control bytes that do appear in normal text: tab, newline, carriage return.
ALLOWED_CONTROL = (0x09, 0x0A, 0x0D)


# ----------------------------------------------------------------- scorers

def english_score(data: bytes) -> float:
    """v1: reward letters and spaces, penalise everything else.

    lowercase or space +2, uppercase +1, common punctuation 0,
    anything else (digits, symbols, control bytes) -5.
    Higher = more English-like.
    """
    score = 0
    for ch in data:
        c = chr(ch)
        if c in string.ascii_lowercase or c == " ":
            score += 2
        elif c in string.ascii_uppercase:
            score += 1
        elif c in ".,'!?-":
            pass                # punctuation is neutral
        else:
            score -= 5          # digits, symbols, control bytes: probably garbage
    return score


def frequency_score(data: bytes) -> float:
    """v2: add each letter's English frequency.

    Common letters (e, t, a) add a lot, rare ones (z, q) almost nothing.
    Printable non-letters are neutral; non-printable bytes cost 0.5.
    Higher = more English-like.
    """
    score = 0.0
    for ch in data:
        c = chr(ch).lower()
        if c in english_frequencies:
            score += english_frequencies[c]
        elif c in string.printable:
            pass                # digits and punctuation are neutral
        else:
            score -= 0.5        # non-printable characters: probably garbage
    return score


def chi_squared_score(data: bytes) -> float:
    """v3: chi-squared distance between the text's character distribution
    and English. Lower = more English-like; 0 would be a perfect match.

    Categories: the 26 letters (case ignored), the space, and "other".
    Control bytes (except tab, newline, carriage return) never appear in
    text, so any of them gives inf. Non-ASCII bytes (e.g. UTF-8 accents)
    count as "other" rather than being rejected.
    """
    # 1. Observed: how many times each category appears.
    observed = {}
    for ch in data:
        if ch < 0x20 and ch not in ALLOWED_CONTROL:
            return float("inf")
        c = chr(ch).lower()
        key = c if (c in string.ascii_lowercase or c == " ") else "other"
        observed[key] = observed.get(key, 0) + 1

    total_chars = sum(observed.values())
    if total_chars == 0:
        return float("inf")     # empty input: nothing to judge

    # 2. Expected: how many times each category would appear in English
    #    text of this length; 3. add up (O - E)^2 / E over all categories.
    chi_squared = 0.0
    for category, share in CHI_TABLE.items():
        expected = share * total_chars
        if expected > 0:
            chi_squared += (observed.get(category, 0) - expected) ** 2 / expected
    return chi_squared