from core import xor_bytes
from scoring import english_score, frequency_score 

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

print("english score test")
cipher1 = "117814170e1d780f170a1311161f78170d0c"
plain1 = xor_bytes(bytes.fromhex(cipher1) ,key = b"\x47")
print(f"test 0x47 key : {plain1},{english_score(plain1)}")

for text in tests:
    cipher = xor_bytes(text, b"\x58")
    print(f"cipher is {cipher.hex()}")
    ranked1 = sorted(range(256), key=lambda k: frequency_score(xor_bytes(cipher,bytes([k]))), reverse = True)
    print(f"{text} top three keys are {ranked1[:3]} correct, {0x58}")

print("frequency score test")
cipher3 =  "11782c2a313d3c782c37782b2c3728782b35373331363f78696a6d616f68782c31353d2b"
plain3 = xor_bytes(bytes.fromhex(cipher3) ,key = b"\x58")
print(f"test 0x58 key : {plain3},{frequency_score(plain3)}")
plain3 = xor_bytes(bytes.fromhex(cipher3) ,key = b"\x47")
print(f"test 0x47 key : {plain3},{frequency_score(plain3)}")

print("comparing scores")
cipher3 =  "11782c2a313d3c782c37782b2c3728782b35373331363f78696a6d616f68782c31353d2b"
plain3 = xor_bytes(bytes.fromhex(cipher3) ,key = b"\x58")
print(f"test 0x58 key (frequency) : {plain3},{frequency_score(plain3)}")
print(f"test 0x58 key (english): {plain3},{english_score(plain3)}")
plain3 = xor_bytes(bytes.fromhex(cipher3) ,key = b"\x47")
print(f"test 0x47 key (frequency) : {plain3},{frequency_score(plain3)}") #ratio x3.7
print(f"test 0x47 key (english): {plain3},{english_score(plain3)}") #ratio x1.45
