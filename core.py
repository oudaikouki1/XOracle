"""Phase 1: the XOR cipher every other module builds on.

    ciphertext = plaintext ^ key
    plaintext  = ciphertext ^ key      (XOR is its own inverse)
"""

from itertools import cycle


def xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR `data` with `key`, repeating the key to cover the data.

    XOR is its own inverse, so the same call encrypts and decrypts.
    Works for any key length: one byte, a short repeating key, or a key
    at least as long as the data (a one-time pad, which never repeats).
    Raises ValueError if the key is empty.
    """
    if key == b"":
        raise ValueError("The key must not be empty")
    return bytes(a ^ b for a, b in zip(data, cycle(key)))