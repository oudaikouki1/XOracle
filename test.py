from core import xor_bytes
from scoring import english_score

tests = [
    b"I LOVE WORKING OUT",
    b"I WANT TO BE THE BEST IN THE WORLD",
    b"I tried to stop smoking 125970 times"
]
for text in tests:
    cipher = xor_bytes(text, b"\x58")
    print(f"cipher is {cipher.hex()}")
    ranked = sorted(range(256), key=lambda k: english_score(xor_bytes(cipher,bytes([k]))), reverse = True)
    print(f"{text} top three keys are {ranked[:3]} correct, {0x58}")


cipher1 = "117814170e1d780f170a1311161f78170d0c"
plain1 = xor_bytes(bytes.fromhex(cipher1) ,key = b"\x47")
print(f"test 0x47 key : {plain1},{english_score(plain1)}")
