import random
from core import xor_bytes
from crib import crib_drag, looks_like_text

P1 = b"This is the first plaintext message."     # an English sentence, 40-80 characters
P2 = b"This is the second plaintext message."     # another one, similar length

pad = random.Random(7).randbytes(max(len(P1), len(P2)))  # a random pad of the same length as the longer plaintext

C1 = xor_bytes(P1, pad)
C2 = xor_bytes(P2, pad)

#checkpoint
print(xor_bytes(C1, pad) == P1)   # True
print(xor_bytes(C2, pad) == P2)   # True

X = xor_bytes(C1, C2)
print(X == xor_bytes(P1, P2))     # True
print(X) # the key cancels out, leaving only the XOR of the two plaintexts

# checkpoint for crib_drag
for crib in [b"this"]:
    print("crib:", crib)
    for pos, other in crib_drag(X, crib):
        if looks_like_text(other):
            print("  ", pos, other)

recovered1 = bytearray(b"?" * len(X))
recovered2 = bytearray(b"?" * len(X))

def place(x: bytes, mine: bytearray, other: bytearray, crib: bytes, pos: int) -> None:
    """Assume `crib` is in `mine` at `pos`; fill both partial messages."""
    end = pos + len(crib)
    mine[pos:end] = crib
    other[pos:end] = xor_bytes(x[pos:end], crib)
while True:
    print("1:", recovered1.decode(errors="replace"))
    print("2:", recovered2.decode(errors="replace"))
    which = input("Message (1/2, q to quit): ")
    if which == "q":
        break
    pos = int(input("Position: "))
    crib = input("Crib: ").encode()
    if which == "1":
        place(X, recovered1, recovered2, crib, pos)
    else:
        place(X, recovered2, recovered1, crib, pos)