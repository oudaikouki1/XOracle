"""Phase 5: breaking a reused one-time pad.

Two messages encrypted with the same pad:  C1 ^ C2 = P1 ^ P2  (the pad cancels out).
Many messages with the same pad: byte i of every message was XORed with the same
pad byte, so each column is a single-byte XOR problem (Phase 2).
"""

import math
from collections import defaultdict

from core import xor_bytes
from single_byte import best_key

ALPHABET = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ .,'!?-"
TEXT_BYTES = set(ALPHABET)


# ---------------------------------------------------------------- two messages

def xor_ciphertexts(c1: bytes, c2: bytes) -> bytes:
    """C1 ^ C2 over their common length. Equals P1 ^ P2 when the pad was reused."""
    n = min(len(c1), len(c2))
    return xor_bytes(c1[:n], c2[:n])


def looks_like_text(fragment: bytes) -> bool:
    """True if every byte is a letter, space or common punctuation."""
    return all(b in TEXT_BYTES for b in fragment)


def crib_drag(x: bytes, crib: bytes) -> list[tuple[int, bytes]]:
    """Slide `crib` across x = P1 ^ P2. At each position, return what the other
    message would contain there if the crib were at that position."""
    results = []
    for pos in range(len(x) - len(crib) + 1):
        window = x[pos:pos + len(crib)]
        results.append((pos, xor_bytes(window, crib)))
    return results


def crib_hits(x: bytes, crib: bytes) -> list[tuple[int, bytes]]:
    """Only the crib-drag positions whose result looks like text.
    Positions where x is all zeros are skipped: there the crib just comes back
    unchanged, which proves nothing."""
    hits = []
    for pos, other in crib_drag(x, crib):
        if x[pos:pos + len(crib)] == bytes(len(crib)):
            continue
        if looks_like_text(other):
            hits.append((pos, other))
    return hits


# ---------------------------------------------------------- the language model

def train_language_model(text: bytes, order: int = 3):
    """Character n-gram model learned from example English text.

    Returns logp(context, char): the log-probability that `char` follows the
    last (order - 1) characters in `context`. Falls back to shorter contexts
    when a context was never seen in the training text.
    """
    cleaned = bytes(b if b in TEXT_BYTES else 32 for b in text)
    cleaned = b" ".join(cleaned.split())            # collapse runs of spaces

    counts = defaultdict(lambda: defaultdict(int))
    for i in range(len(cleaned)):
        context = cleaned[max(0, i - order + 1):i]
        counts[context][cleaned[i]] += 1

    totals = {ctx: sum(d.values()) for ctx, d in counts.items()}
    vocab = len(ALPHABET)

    def logp(context: bytes, char: int) -> float:
        for k in range(len(context), -1, -1):        # longest known context first
            sub = context[len(context) - k:] if k else b""
            if sub in counts:
                d = counts[sub]
                prob = (d.get(char, 0) + 0.1) / (totals[sub] + 0.1 * vocab)
                return math.log(prob) - 0.5 * (len(context) - k)   # small backoff penalty
        return math.log(1 / vocab)

    return logp


def text_score(text: bytes, logp, order: int = 3) -> float:
    """Average log-probability per character: higher = more English-like."""
    if not text:
        return float("-inf")
    total = sum(logp(text[max(0, i - order + 1):i], text[i]) for i in range(len(text)))
    return total / len(text)


# ------------------------------------------------- automatic two-message attack

def auto_decode(x: bytes, logp, order: int = 3, beam: int = 1500,
                fixed: dict[int, int] | None = None) -> tuple[bytes, bytes]:
    """Guess both plaintexts from x = P1 ^ P2.

    For every position, a character `a` for message 1 fixes message 2's
    character as a ^ x[i]. Viterbi search keeps the `beam` best partial
    guesses, scored by how English BOTH messages look under the language model.
    `fixed` maps position -> known byte of message 1; those positions are not guessed.
    """
    fixed = fixed or {}
    states = {b"": 0.0}            # last (order-1) chars of message 1 -> score
    history = []                    # per position: state -> (previous state, chosen char)

    for i, xi in enumerate(x):
        candidates = {}
        choices = [fixed[i]] if i in fixed else ALPHABET
        for state, score in states.items():
            other_state = bytes(c ^ x[i - len(state) + j] for j, c in enumerate(state))
            for a in choices:
                b = a ^ xi
                if b not in TEXT_BYTES and i not in fixed:
                    continue
                total = score + logp(state, a) + logp(other_state, b)
                new_state = (state + bytes([a]))[-(order - 1):]
                if new_state not in candidates or total > candidates[new_state][0]:
                    candidates[new_state] = (total, state, a)

        if not candidates:          # no printable pair fits here: give up on this x
            return b"?" * len(x), b"?" * len(x)

        best = sorted(candidates.items(), key=lambda kv: -kv[1][0])[:beam]
        history.append({s: (prev, a) for s, (_, prev, a) in best})
        states = {s: total for s, (total, _, _) in best}

    state = max(states, key=states.get)
    chars = []
    for i in range(len(x) - 1, -1, -1):
        prev, a = history[i][state]
        chars.append(a)
        state = prev
    p1 = bytes(reversed(chars))
    p2 = bytes(a ^ b for a, b in zip(p1, x))
    return p1, p2


def best_placements(x: bytes, word: bytes, guess1: bytes, guess2: bytes, logp,
                    fixed: dict[int, int] | None = None,
                    top: int = 3) -> list[tuple[float, int, int, bytes, bytes]]:
    """Where does `word` fit best? Try it at every position in both messages.

    Putting `word` in one message forces the other message's letters there
    (x ^ word). Each option is scored by how English BOTH lines read around
    that spot, so the word goes into the message where it continues the text.
    Options that overwrite letters already locked in are allowed (so you can
    correct a mistake) but cost a penalty per overwritten letter.
    Returns (score, message number, position, what the other message shows,
    the exact bytes placed).
    """
    fixed = fixed or {}
    options = []
    # Try the word with spaces around it too: words in a sentence usually have
    # them, and every extra known character makes a wrong spot less likely to fit.
    for variant in {b" " + word + b" ", word + b" ", b" " + word, word}:
        bonus = 0.5 * (len(variant) - len(word))
        options += _placements_for(x, variant, guess1, guess2, logp, fixed, bonus)
    options.sort(key=lambda o: o[0], reverse=True)
    return options[:top]


def _placements_for(x: bytes, word: bytes, guess1: bytes, guess2: bytes, logp,
                    fixed: dict[int, int], bonus: float) -> list[tuple[float, int, int, bytes, bytes]]:
    """All valid spots for one exact byte string, with their scores."""
    options = []
    for pos, other_part in crib_drag(x, word):
        if x[pos:pos + len(word)] == bytes(len(word)) or not looks_like_text(other_part):
            continue
        end = pos + len(word)
        for msg in (1, 2):
            as_msg1 = word if msg == 1 else other_part
            # letters already locked in that this option would overwrite
            conflicts = sum(1 for j, c in enumerate(as_msg1) if fixed.get(pos + j, c) != c)
            own_line, other_line = (guess1, guess2) if msg == 1 else (guess2, guess1)
            own = own_line[max(0, pos - 4):pos] + word + own_line[end:end + 4]
            other = other_line[max(0, pos - 4):pos] + other_part + other_line[end:end + 4]
            score = text_score(own, logp) + text_score(other, logp) + bonus - 1.0 * conflicts
            options.append((score, msg, pos, other_part, word))
    return options


def guided_session(c1: bytes, c2: bytes, logp) -> tuple[bytes, bytes]:
    """Recover two messages by typing words you can read or guess.

    The tool finds where each word fits, locks it in, and re-guesses everything
    around it. Commands: a word to place it, `2`/`3` to use the 2nd/3rd option
    for the last word instead, `u` to undo, `q` to quit.
    """
    x = xor_ciphertexts(c1, c2)
    fixed: dict[int, int] = {}          # position -> known byte of message 1
    undo_stack: list[dict[int, int]] = []
    last_options: list[tuple[float, int, int, bytes, bytes]] = []

    def lock(msg: int, pos: int, word: bytes) -> None:
        undo_stack.append(dict(fixed))
        for j, ch in enumerate(word):
            # store everything as message-1 bytes
            fixed[pos + j] = ch if msg == 1 else ch ^ x[pos + j]

    guess1, guess2 = auto_decode(x, logp, fixed=fixed)
    while True:
        ruler = "".join(str(i // 10) if i % 10 == 0 else " " for i in range(len(x)))
        print()
        print("   ", ruler)
        print("1: ", guess1.decode(errors="replace"))
        print("2: ", guess2.decode(errors="replace"))
        locked = "".join("^" if i in fixed else " " for i in range(len(x)))
        print("   ", locked, " (^ = locked in)")

        cmd = input("Type a word you can read or guess (u = undo, q = quit): ")
        if cmd == "q":
            break
        if cmd == "u":
            if undo_stack:
                fixed = undo_stack.pop()
        elif cmd in ("2", "3") and last_options:
            idx = int(cmd) - 1
            if idx < len(last_options):
                fixed = undo_stack.pop() if undo_stack else {}
                _, msg, pos, _, placed = last_options[idx]
                lock(msg, pos, placed)
        elif cmd.strip():
            word = cmd.encode()
            last_options = best_placements(x, word, guess1, guess2, logp, fixed)
            if not last_options:
                print("   That word doesn't fit anywhere.")
                continue
            _, msg, pos, other, placed = last_options[0]
            lock(msg, pos, placed)
            print(f"   Placed {placed!r} in message {msg} at position {pos}; the other message shows {other!r}.")
            for n, (_, m, p, o, w) in enumerate(last_options[1:], start=2):
                print(f"   (type {n} to use {w!r} in message {m} at position {p} instead: {o!r})")
        else:
            continue
        guess1, guess2 = auto_decode(x, logp, fixed=fixed)

    return guess1, guess2


# --------------------------------------------------------------- many messages

def break_many_time_pad(ciphertexts: list[bytes]) -> tuple[bytes, list[bytes]]:
    """Recover the pad from several messages encrypted with the same pad.

    Column i holds byte i of every ciphertext, all XORed with pad[i], so each
    column is a single-byte XOR problem solved with the Phase 2 breaker.
    Only positions covered by every message are used.
    """
    n = min(len(c) for c in ciphertexts)
    columns = [bytes(c[i] for c in ciphertexts) for i in range(n)]
    pad = bytes(best_key(column) for column in columns)
    plaintexts = [xor_bytes(c[:n], pad) for c in ciphertexts]
    return pad, plaintexts


if __name__ == "__main__":
    import os
    import random

    P1 = b"Meet me at the old bridge at nine tonight."
    P2 = b"The package arrives on Tuesday by train."
    pad = random.Random(7).randbytes(max(len(P1), len(P2)))
    C1, C2 = xor_bytes(P1, pad), xor_bytes(P2, pad)

    # Training text: the bigger and more ordinary the English, the better.
    corpus_path = "samples/language.txt" if os.path.exists("samples/language.txt") else "samples/plain.txt"
    with open(corpus_path, "rb") as f:
        model = train_language_model(f.read())
    print(f"Language model trained on {corpus_path}")

    rec1, rec2 = guided_session(C1, C2, model)
    n = len(rec1)
    # x can't tell which message is which, so the two lines may come out swapped
    matches = pad[:n] in (xor_bytes(C1[:n], rec1), xor_bytes(C1[:n], rec2))
    print("Recovered pad matches:", matches)