"""Phase 4 experiments: known-plaintext attack on encrypted files.

Running this file:
  1. encrypts samples/img.png and samples/sample.pdf with known keys and saves them,
  2. checks the encryption round-trips and that the originals carry their signatures,
  3. runs the header-only attack (keystream, period, file-type identification),
  4. runs the long-key attack (start + IEND bytes) on random keys of growing length.
"""

import random

from core import xor_bytes
from known_plain import (
    KNOWN_PARTS,
    SIGNATURES,
    find_period,
    identify_filetype,
    keystream_from_header,
    known_keystream,
    recover_long_key,
    recover_with_signature,
)

PNG_PATH = "./samples/img.png"
PDF_PATH = "./samples/sample.pdf"
PNG_OUT = "./samples/encrypted.png.enc"
PDF_OUT = "./samples/encrypted.pdf.enc"

# 13 bytes: longer than the 8-byte PNG signature, so the header-only attack
# can't see it repeat, but the long-key attack (28 known bytes) can.
PNG_KEY = b"XORacleISGOOD"
# 3 bytes: shorter than "%PDF-", so the header alone reveals it.
PDF_KEY = b"key"

LONG_KEY_LENGTHS = [7, 12, 16, 20, 24, 28, 29, 35]
SEED = 42                     # fixed seed: same random keys every run


# ------------------------------------------------------------------ helpers

def read_bytes(path: str) -> bytes:
    with open(path, "rb") as file:
        return file.read()


def write_bytes(path: str, data: bytes) -> None:
    with open(path, "wb") as file:
        file.write(data)


# ------------------------------------------------------------------- steps

def encrypt_samples() -> tuple[bytes, bytes, bytes, bytes]:
    """Encrypt the sample PNG and PDF, save the results, and check that
    decrypting gives back the originals.

    Returns (png, encrypted_png, pdf, encrypted_pdf).
    """
    png = read_bytes(PNG_PATH)
    pdf = read_bytes(PDF_PATH)
    encrypted_png = xor_bytes(png, PNG_KEY)
    encrypted_pdf = xor_bytes(pdf, PDF_KEY)
    write_bytes(PNG_OUT, encrypted_png)
    write_bytes(PDF_OUT, encrypted_pdf)

    print("PNG round-trips:", xor_bytes(encrypted_png, PNG_KEY) == png)
    print("PDF round-trips:", xor_bytes(encrypted_pdf, PDF_KEY) == pdf)
    print("PNG has PNG signature:", png.startswith(SIGNATURES["png"]))
    print("PDF has PDF signature:", pdf.startswith(SIGNATURES["pdf"]))
    return png, encrypted_png, pdf, encrypted_pdf


def check_find_period() -> None:
    """find_period on known inputs: expect 7, 3, 8."""
    print(find_period(b"XORacleX"), find_period(b"keyke"), find_period(b"abcdefgh"))


def header_attack(encrypted_png: bytes, encrypted_pdf: bytes) -> None:
    """Header-only attack: K = C ^ P on the signature bytes.

    The right signature gives a keystream that repeats (the real key);
    wrong ones give random-looking bytes with no repetition.
    """
    print("PNG keystream:", keystream_from_header(encrypted_png, SIGNATURES["png"]))
    print("PDF keystream:", keystream_from_header(encrypted_pdf, SIGNATURES["pdf"]))

    result = recover_with_signature(encrypted_pdf, "pdf")
    print("PDF key from header:", result[0] if result else "not visible (key longer than header)")
    result = recover_with_signature(encrypted_png, "png")
    print("PNG key from header:", result[0] if result else "not visible (key longer than header)")

    print("Every signature tried on the encrypted PNG:")
    for filetype, header in SIGNATURES.items():
        stream = keystream_from_header(encrypted_png, header)
        print(f"   {filetype}: keystream {stream!r}, period {find_period(stream)}")

    print("Identified PNG as:", identify_filetype(encrypted_png))
    print("Identified PDF as:", identify_filetype(encrypted_pdf))


def check_known_keystream(encrypted_png: bytes) -> None:
    """Known plaintext at both ends of a PNG: expect 28 positions,
    from 0 to the last byte of the file."""
    known = known_keystream(encrypted_png, KNOWN_PARTS["png"])
    print("Known key bytes:", len(known), "| positions", min(known), "to", max(known),
          "| file length", len(encrypted_png))


def long_key_test(png: bytes) -> None:
    """Long-key attack on random keys of growing length.

    28 known bytes can cover at most 28 key positions, so recovery stops
    working somewhere around that length.
    """
    rng = random.Random(SEED)
    for length in LONG_KEY_LENGTHS:
        key = rng.randbytes(length)
        found = recover_long_key(xor_bytes(png, key), "png")
        print(f"key length {length:2d}: {'OK' if found == key else 'FAILED'}")


def main() -> None:
    print("===== Encrypting samples =====")
    png, encrypted_png, pdf, encrypted_pdf = encrypt_samples()
    print("\n===== find_period =====")
    check_find_period()
    print("\n===== Header-only attack =====")
    header_attack(encrypted_png, encrypted_pdf)
    print("\n===== Known bytes at both ends =====")
    check_known_keystream(encrypted_png)
    print("\n===== Long-key attack =====")
    long_key_test(png)


if __name__ == "__main__":
    main()