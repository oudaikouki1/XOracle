"""Phase 5 experiments: two messages encrypted with the same one-time pad.

Running this file:
  1. encrypts two test sentences with ONE shared random pad (the mistake),
  2. checks that the pad cancels out:  C1 ^ C2 == P1 ^ P2,
  3. drags a crib across P1 ^ P2 and prints the readable hits,
  4. opens a manual session where you place guessed words to recover both messages.
"""

import random

from core import xor_bytes
from crib import crib_drag, looks_like_text

# Two test sentences of similar length. They share their first 12 characters,
# which shows up as 12 zero bytes in P1 ^ P2.
P1 = b"This is the first plaintext message."
P2 = b"This is the second plaintext message."

# Fixed seed so every run uses the same "random" pad.
PAD_SEED = 7

# Words to try in the crib-drag check.
CRIBS = [b"this"]


def make_ciphertexts(p1: bytes, p2: bytes, seed: int) -> tuple[bytes, bytes, bytes]:
    """Encrypt both messages with the same random pad.

    The pad is as long as the longer message, so it never repeats, exactly
    like a real one-time pad. Returns (pad, C1, C2).
    """
    pad = random.Random(seed).randbytes(max(len(p1), len(p2)))
    return pad, xor_bytes(p1, pad), xor_bytes(p2, pad)


def check_pad_cancels(pad: bytes, c1: bytes, c2: bytes, p1: bytes, p2: bytes) -> bytes:
    """Run the Phase 5 checkpoints and return X = C1 ^ C2.

    Prints True three times when everything works:
      - decrypting C1 with the pad gives P1
      - decrypting C2 with the pad gives P2
      - C1 ^ C2 equals P1 ^ P2, i.e. the pad cancels out
    """
    print("C1 decrypts to P1:", xor_bytes(c1, pad) == p1)
    print("C2 decrypts to P2:", xor_bytes(c2, pad) == p2)

    x = xor_bytes(c1, c2)
    print("C1 ^ C2 == P1 ^ P2:", x == xor_bytes(p1, p2))
    print("X =", x)   # the attacker's view: no pad, only the two plaintexts mixed
    return x


def show_crib_hits(x: bytes, cribs: list[bytes]) -> None:
    """Drag each crib across x and print the positions where the other
    message would read as text."""
    for crib in cribs:
        print("crib:", crib)
        for pos, other in crib_drag(x, crib):
            if looks_like_text(other):
                print("  ", pos, other)


def place(x: bytes, mine: bytearray, other: bytearray, crib: bytes, pos: int) -> None:
    """Assume `crib` is in `mine` at `pos`; fill both partial messages.

    `mine` gets the guessed word itself. `other` gets x ^ crib at the same
    spot, because (P1 ^ P2) ^ P1 = P2.
    """
    end = pos + len(crib)
    mine[pos:end] = crib
    other[pos:end] = xor_bytes(x[pos:end], crib)


def manual_session(x: bytes) -> None:
    """Recover both messages by hand, one guessed word at a time.

    Unknown bytes are shown as '?'. At each prompt, choose the message the
    word belongs to (1 or 2), its position, and the word. Type q to quit.
    """
    recovered1 = bytearray(b"?" * len(x))
    recovered2 = bytearray(b"?" * len(x))

    while True:
        print("1:", recovered1.decode(errors="replace"))
        print("2:", recovered2.decode(errors="replace"))

        which = input("Message (1/2, q to quit): ")
        if which == "q":
            break
        pos = int(input("Position: "))
        crib = input("Crib: ").encode()

        if which == "1":
            place(x, recovered1, recovered2, crib, pos)
        else:
            place(x, recovered2, recovered1, crib, pos)


def main() -> None:
    pad, c1, c2 = make_ciphertexts(P1, P2, PAD_SEED)
    x = check_pad_cancels(pad, c1, c2, P1, P2)
    show_crib_hits(x, CRIBS)
    manual_session(x)


if __name__ == "__main__":
    main()