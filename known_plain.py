from core import xor_bytes



SIGNATURES = {
    "png": bytes.fromhex("89 50 4E 47 0D 0A 1A 0A"),
    "pdf": b"%PDF-",
    "zip": b"PK\x03\x04", 
    "elf": b"\x7fELF",
    "gif": b"GIF89a"

}

KNOWN_PARTS = {
    "png": [
        (0, bytes.fromhex("89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52")),     # start: 16 bytes
        (-12, bytes.fromhex("00 00 00 00 49 45 4E 44 AE 42 60 82")),   # end: IEND chunk
    ],
}


def keystream_from_header(cipher: bytes, header: bytes) -> bytes:
    """Key bytes revealed by assuming 'cipher' starts with 'header'"""
    if len(cipher)<len(header):
        raise ValueError("ciphertext is shorter than the header")
    cipher_header = cipher[:len(header)] 
    keystream = xor_bytes(cipher_header,header)
    return keystream

def find_period(stream: bytes) -> int:
    """Smallest p such that stream[i] == stream[i + p] wherever both exist.
    Returns len(stream) if no repetition is visible."""
    for p in range(1, len(stream)):
        if all(stream[i] == stream[i + p] for i in range(len(stream) - p)):
            return p
    return len(stream)

def recover_with_signature(cipher: bytes, filetype: str) -> bytes:
    header = SIGNATURES[filetype]
    stream = keystream_from_header(cipher, header)
    p = find_period(stream)
    if p == len(stream):
        return None
    key = stream[:p]
    plain = xor_bytes(cipher, key)
    return key, plain

def identify_filetype(cipher: bytes) -> str:
    """Identify the file type of a ciphered file based on its signature."""
    for ftype, header in SIGNATURES.items():
       result = recover_with_signature(cipher, ftype)
       if result is not None:
           return ftype
    return "unknown"

def known_keystream(cipher: bytes, parts: list[tuple[int, bytes]]) -> dict[int, int]:
    """Map file position -> key byte, for every position where plaintext is known.
    A negative offset counts from the end of the file."""
    keystream = {}
    for offset, known in parts:
        if offset < 0:
            offset = len(cipher) + offset      # e.g. 5000 + (-12) = 4988
        for i, byte in enumerate(known):
            pos = offset + i
            if pos < 0 or pos >= len(cipher):
                continue
            keystream[pos] = cipher[pos] ^ byte
    return keystream

def key_for_length(known: dict[int, int], L: int) -> bytes | None:
    """Key of length L consistent with every known byte, or None if L is
    contradictory or leaves some key bytes unknown."""
    slots = [None] * L

    for pos, k in known.items():
        i = pos % L
        if slots[i] is None:
            slots[i] = k
        elif slots[i] != k:
            return None          # contradiction: L is impossible

    if None in slots:
        return None              # some key bytes never revealed
    return bytes(slots)

def recover_long_key(cipher: bytes, filetype: str, max_len: int = 64) -> bytes | None:
    """Recover a repeating key of any length up to max_len using known plaintext
    at several positions in the file. None if no length fits."""
    known = known_keystream(cipher, KNOWN_PARTS[filetype])
    for L in range(1, max_len + 1):
        key = key_for_length(known, L)
        if key is not None:
            return key
    return None