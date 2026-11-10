"""Phase 4: known-plaintext attack on XOR-encrypted files.

Most file formats start (and some end) with fixed bytes. If we know part of
the plaintext P, XOR gives the key directly:

    C = P ^ K   ->   K = C ^ P

Two attacks live here:
  * header only:   the file signature reveals the first key bytes; if the key
                   repeats inside the header, we know the whole key.
  * long keys:     known bytes at BOTH ends of the file (PNG: header + IEND)
                   reveal key bytes at many positions; we then find the one
                   key length that agrees with all of them.
"""

from core import xor_bytes

# --------------------------------------------------------------------- data

# First bytes of each file format ("magic numbers").
SIGNATURES = {
    "png": bytes.fromhex("89 50 4E 47 0D 0A 1A 0A"),
    "pdf": b"%PDF-",
    "zip": b"PK\x03\x04",
    "elf": b"\x7fELF",
    "gif": b"GIF89a",
}

# Known plaintext at several places in a file, as (offset, bytes).
# A negative offset counts from the end of the file. Only PNG is filled in.
KNOWN_PARTS = {
    "png": [
        # signature + IHDR chunk length (13) + "IHDR": 16 bytes at the start
        (0, bytes.fromhex("89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52")),
        # IEND chunk, which closes every PNG: 12 bytes at the end
        (-12, bytes.fromhex("00 00 00 00 49 45 4E 44 AE 42 60 82")),
    ],
}


# -------------------------------------------------------- header-only attack

def keystream_from_header(cipher: bytes, header: bytes) -> bytes:
    """Key bytes revealed by assuming `cipher` starts with `header`.

    K = C ^ P on the first len(header) bytes. Raises ValueError if the
    ciphertext is shorter than the header.
    """
    if len(cipher) < len(header):
        raise ValueError("ciphertext is shorter than the header")
    return xor_bytes(cipher[:len(header)], header)


def find_period(stream: bytes) -> int:
    """Smallest p such that stream[i] == stream[i + p] wherever both exist.

    E.g. b"XORacleX" -> 7, b"keyke" -> 3. Returns len(stream) if no
    repetition is visible (the key may be longer than the stream).
    """
    for p in range(1, len(stream)):
        if all(stream[i] == stream[i + p] for i in range(len(stream) - p)):
            return p
    return len(stream)


def recover_with_signature(cipher: bytes, filetype: str) -> tuple[bytes, bytes] | None:
    """Assume `cipher` is a `filetype` file; return (key, plaintext).

    Returns None when the keystream revealed by the signature doesn't repeat:
    either the guessed file type is wrong, or the key is longer than the
    signature (see recover_long_key for that case).
    """
    stream = keystream_from_header(cipher, SIGNATURES[filetype])
    p = find_period(stream)
    if p == len(stream):
        return None
    key = stream[:p]
    return key, xor_bytes(cipher, key)


def identify_filetype(cipher: bytes) -> str:
    """Guess the file type by trying every known signature.

    The right signature gives a keystream that repeats (the real key); a
    wrong one gives random-looking bytes that don't. Returns the first type
    that fits, or "unknown".
    """
    for filetype in SIGNATURES:
        if recover_with_signature(cipher, filetype) is not None:
            return filetype
    return "unknown"


# ------------------------------------------------------ keys longer than header

def known_keystream(cipher: bytes, parts: list[tuple[int, bytes]]) -> dict[int, int]:
    """Map file position -> key byte, for every position where plaintext is known.

    A negative offset counts from the end of the file. Positions outside the
    file are skipped.
    """
    keystream = {}
    for offset, known in parts:
        if offset < 0:
            offset = len(cipher) + offset      # e.g. 5000 + (-12) = 4988
        for i, byte in enumerate(known):
            pos = offset + i
            if 0 <= pos < len(cipher):
                keystream[pos] = cipher[pos] ^ byte
    return keystream


def key_for_length(known: dict[int, int], L: int) -> bytes | None:
    """Key of length L consistent with every known byte, or None.

    The byte at file position `pos` was encrypted with key byte pos % L.
    L is rejected if two known positions land on the same key byte with
    different values (contradiction), or if some key byte is never covered (gap).
    """
    slots = [None] * L

    for pos, k in known.items():
        i = pos % L
        if slots[i] is None:
            slots[i] = k
        elif slots[i] != k:
            return None          # contradiction: L is impossible

    if None in slots:
        return None              # gap: some key bytes never revealed
    return bytes(slots)


def recover_long_key(cipher: bytes, filetype: str, max_len: int = 64) -> bytes | None:
    """Recover a repeating key up to `max_len` bytes from known plaintext
    at several positions in the file.

    Tries every length from 1 upward and returns the first consistent key.
    The smallest wins because multiples of the real length are consistent too.
    Returns None if no length fits, or if no known parts exist for `filetype`
    (currently only "png" has them).
    """
    if filetype not in KNOWN_PARTS:
        return None
    known = known_keystream(cipher, KNOWN_PARTS[filetype])
    for L in range(1, max_len + 1):
        key = key_for_length(known, L)
        if key is not None:
            return key
    return None