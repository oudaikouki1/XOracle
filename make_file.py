from core import xor_bytes
from known_plain import SIGNATURES, keystream_from_header








with open("./samples/img.png","rb") as file:
    data_png = file.read()

KEY1 = b"XORacle"
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