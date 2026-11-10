from core import xor_bytes
from repeating import keysize_score,guess_keysizes,transpose
from single_byte import best_key
from repeating import recover_key,break_repeating_xor
import random 

rng = random.Random(42) #fixed seed
key2 = rng.randbytes(5)
key = b"ICE"
key1 = b"Xor!"
plain = b"I tried to stop smoking 125970 times"
with open("./samples/plain.txt","rb") as file:
    data = file.read()

cipher = xor_bytes(data,key)

WRONG_LENGTH = -1
def wrong_bytes(found: bytes, real: bytes) -> int:
    """Number of key bytes recovered incorrectly."""
    if len(found) != len(real):
        return WRONG_LENGTH
    return sum(1 for a, b in zip(found, real) if a != b)

KEY_LENGTHS = [3, 7, 16, 29]
TEXT_LENGTHS = [len(data), 1000, 500, 200, 100]
rng = random.Random(42)

for key_len in KEY_LENGTHS:
    key = rng.randbytes(key_len)
    for text_len in TEXT_LENGTHS:
        sample = data[:text_len]
        cipher = xor_bytes(sample,key )
        found_key, found_text = break_repeating_xor(cipher)
        bad = wrong_bytes(found_key, key)
        per_column = text_len // key_len
        result = "wrong length" if bad == WRONG_LENGTH else f"{bad} wrong"
        print(f"key={key_len:2d}  text={text_len:4d}  bytes/col={per_column:4d}  {result}")
        candidates = guess_keysizes(cipher)
        print("   candidates:", candidates, "| real in list:", key_len in candidates, "| found len:", len(found_key))

#checkpoint


keysize = guess_keysizes(cipher)
print(f"Key size is {keysize[0]}")


print(recover_key(cipher,3))
found_key, found_text = break_repeating_xor(cipher)
print(found_key)
print(found_text.decode("utf-8"))