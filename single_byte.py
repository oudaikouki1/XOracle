from core import xor_bytes
from scoring import chi_squared_score

def crack(cipher: bytes, scorer, higher_is_better: bool) -> list:
    """Try all 256 keys; return (key, score, plaintext) sorted best first."""
    results = []
    for k in range(256):
        plain = xor_bytes(cipher, bytes([k]))
        results.append((k, scorer(plain), plain))
    results.sort(key=lambda r: r[1], reverse=higher_is_better)
    return results

def best_key(cipher: bytes, scorer=chi_squared_score, higher_is_better: bool = False): 
    """Return the most likely single-byte key for cipher"""
    results =crack(cipher,scorer,higher_is_better)
    return results[0][0]
