from itertools import cycle


def xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR data with key, repeating the key to cover the data.
    XOR is its own inverse: the same call encrypts and decrypts."""
    
    if key == b"":  
        raise ValueError("The key must be not empty") 
    
    return bytes(a ^ b for a, b in zip(data, cycle(key))) 