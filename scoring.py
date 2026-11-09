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













   