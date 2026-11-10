from core import xor_bytes



SIGNATURES = {
    "png": bytes.fromhex("89 50 4E 47 0D 0A 1A 0A"),
    "pdf": b"%PDF-",
    "zip": b"PK\x03\x04", 
    "elf": b"\x7fELF",
    "gif": b"GIF89a"

}


def keystream_from_header(cipher: bytes, header: bytes) -> bytes:
    """Key bytes revealed by assuming 'cipher' starts with 'header'"""
    if len(cipher)<len(header):
        raise ValueError("ciphertext is shorter than the header")
    cipher_header = cipher[:len(header)] 
    keystream = xor_bytes(cipher_header,header)
    return keystream
            