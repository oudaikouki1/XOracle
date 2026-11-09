import string

def english_score(data: bytes) -> float:
    score = 0
    for ch in data:
        c = chr(ch)
        if c in string.ascii_lowercase or c == " ":
            score += 2
        elif c in string.ascii_uppercase:
            score += 1
        elif c in ".,'!?-":
            score += 0
        else:
            score -= 5          # digits, symbols, control bytes: probably garbage
    return score

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

def frequency_score(data: bytes) -> float:
    score = 0
    for ch in data:
        c = chr(ch).lower()
        if c in english_frequencies:
            score += english_frequencies[c]
        elif c in string.printable:
            score += 0
        else:
            score -= 0.5  # non-printable characters: probably garbage
            
    return score

