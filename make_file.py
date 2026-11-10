from core import xor_bytes
from known_plain import SIGNATURES, keystream_from_header,find_period, recover_long_key, recover_with_signature,identify_filetype,known_keystream,KNOWN_PARTS
import random







with open("./samples/img.png","rb") as file:
    data_png = file.read()

KEY1 = b"XORacleISGOOD"
encrypted_png = xor_bytes(data_png,KEY1)

with open("./samples/encrypted.png.enc", "wb") as file: 
    file.write(encrypted_png)
 
with open("./samples/sample.pdf", "rb") as file:
    data_pdf = file.read()

KEY2 = b"key"
encrypted_pdf = xor_bytes(data_pdf,KEY2) 

with open("./samples/encrypted.pdf.enc", "wb") as file: 
    file.write(encrypted_pdf)

#checkpoint step 1
decrypted_png = xor_bytes(encrypted_png,KEY1)
decrypted_pdf = xor_bytes(encrypted_pdf,KEY2)

print(f"comparison of real and decrypted png = {data_png == decrypted_png}")
print(f"comparison of real and decrypted pdf = {data_pdf == decrypted_pdf}")

#checkpoint step 2
print(f"Verification of PNG File : {data_png.startswith(SIGNATURES["png"])}")
print(f"Verification of PDF File : {data_pdf.startswith(SIGNATURES["pdf"])}")

#checkpoint step 3 
print(f"KEY : {keystream_from_header(encrypted_png,SIGNATURES["png"])}")
print(f"KEY : {keystream_from_header(encrypted_pdf,SIGNATURES["pdf"])}")

#checkpoint step 4
print(find_period(b"XORacleX"))  # 7
print(find_period(b"keyke"))     # 3
print(find_period(b"abcdefgh"))  # 8

#chekpoint step 5 
#key, plain = recover_with_signature(encrypted_png,"png")
#print(f"Recovered Key : {key}")

#experiment identify
for ftype, header in SIGNATURES.items():
    keystream = keystream_from_header(encrypted_png, header)
    print(f"File type: {ftype}, Keystream: {keystream}, Period: {find_period(keystream)}")


print(f"Identified file type for encrypted PNG: {identify_filetype(encrypted_png)}")

#CHECKPPIT FOR HEADER AND KNOWN PARTS
known = known_keystream(encrypted_png, KNOWN_PARTS["png"])
print(len(known))                      # 28
print(min(known), max(known))          # 0  and  len(png_cipher) - 1
print(known[0], ord("X"))              # 88 88

rng = random.Random(42)
for L in [7, 12, 16, 20, 24, 28, 29, 35]:
    key = rng.randbytes(L)
    cipher = xor_bytes(data_png, key)
    found = recover_long_key(cipher, "png")
    print(f"key length {L:2d}: {'OK' if found == key else 'FAILED'}")

print(L, found)