# XOracle

**Encrypt with XOR, then break it.**

XOracle is a Python toolkit I'm building to learn cryptanalysis by doing it. It implements XOR "encryption" and then attacks it from several angles, showing step by step why XOR on its own is not real encryption.

> 🚧 **Work in progress.** I'm building this one phase at a time; see the [roadmap](#roadmap).

---

## Why XOR?

XOR is the basic building block of real ciphers (stream ciphers, the one-time pad, the mixing steps inside AES). Used **on its own** with a short or reused key, though, it's trivially breakable, and it still shows up that way in practice:

- **Malware** hides config strings, C2 addresses and payloads with single-byte or repeating-key XOR.
- **IoT firmware and proprietary file formats** sometimes "protect" data with a fixed XOR key.
- **Reused one-time pads** have broken real systems (see the Venona project).

Malware analysts and reverse engineers break these schemes routinely. XOracle builds both sides: the obfuscator and the breaker.

---

## The core idea

```
ciphertext = plaintext ⊕ key
plaintext  = ciphertext ⊕ key      # XOR is its own inverse
```

If the key is shorter than the data, it repeats. That repetition, together with the predictable statistics of real data, is what the attacks exploit.

---

## Roadmap

- [x] **Phase 1: Core cipher.** `xor_bytes(data, key)` with single-byte, repeating and full-length keys.
- [ ] **Phase 2: Break single-byte XOR.** Brute-force all 256 keys and rank the candidates with an English-likeness score.
  - [x] v1: character-class scoring (letters, spaces, garbage penalty)
  - [x] v2: letter-frequency scoring
  - [ ] v3: chi-squared test
- [ ] **Phase 3: Break repeating-key XOR.** Guess the key length with Hamming distance, then split the problem into single-byte columns.
- [ ] **Phase 4: Known-plaintext attack on files.** Recover keys from file signatures (PNG, PDF, ZIP, ELF...).
- [ ] **Phase 5: Reused one-time pad.** Interactive crib dragging on `C1 ⊕ C2 = P1 ⊕ P2`.
- [ ] **CLI**: `xoracle encrypt | decrypt | crack | identify`
- [ ] **Stretch**: break XOR-obfuscated UDP traffic from my FPGA Ethernet project

---

## Project structure

```
XOracle/
├── core.py        # xor_bytes: the XOR primitive
├── scoring.py     # english_score: how English-like is a byte string?
├── test.py        # experiments and checks
└── README.md
```

The layout will grow as new phases are added (single_byte.py, repeating.py, known_plain.py, crib.py, cli.py, tests/).

---

## Quick start

Requires Python 3.10+. No external dependencies so far.

```bash
git clone https://github.com/<your-username>/XOracle.git
cd XOracle
python test.py
```

---

## Results so far

### Phase 2: breaking single-byte XOR

Test setup: three English sentences encrypted with key `0x58`. Every candidate key 0–255 is tried and each decryption is ranked with a scorer.

**v1 (character-class scorer):** lowercase/space +2, uppercase +1, common punctuation 0, anything else −5. It recovers `0x58` in first place for all test sentences, including all-caps text and text with digits.

**v2 (letter-frequency scorer):** each letter adds its frequency in English (e.g. `e` ≈ 0.127, `z` ≈ 0.0007), and garbage bytes are penalised.

Head-to-head on the hardest sentence, `I tried to stop smoking 125970 times`, comparing the real key with the best impostor (key `0x47`, which decrypts to `V?kmvz{?kp?lkpo?lrptvqx?.-*&(/?kvrzl`):

| Scorer | Real text | Runner-up | Separation (ratio) |
|---|---|---|---|
| v1: character classes | 29 | 20 | 1.45× |
| v2: letter frequency | 2.41 | 0.65 | **3.7×** |

The two scorers use different scales, so I compare the **ratio** between the real text and the runner-up rather than the raw difference.

**Why v2 wins:** v1 rewards `k`, `v`, `z` and `q` as much as `e` and `t`, so a string of random letters looks like English. v2 gives rare letters almost nothing, and the impostor is full of them.

**What I learned along the way**
- `sorted()` is ascending by default, so my first run printed the three *worst* keys. They were consecutive (3, 4, 5) because they tied at the minimum score and `sorted()` keeps ties in their original order.
- v1 told English from garbage mostly by the **spaces**: under the wrong key, spaces became `?`, which my scorer treated as neutral punctuation.
- Penalties only mean something relative to rewards. Switching the frequency table from percent to fractions left the old −5 penalty about 40× bigger than the best letter's reward.
- Text with digits is the hardest case: the real plaintext pays a penalty for its digits, while the wrong key turns them into neutral punctuation.

---

## Lessons learned

*(This section grows with each phase.)*

- A 256-key space is not security: brute force takes milliseconds.
- To recognise the right answer, you only need the plaintext to be *statistically different* from noise.
- A scorer that checks *which kind* of character appears is weak. One that checks *how often each letter appears* is much stronger, because English has a fingerprint (ETAOIN SHRDLU).
- Measure improvements. A before/after number (1.45× → 3.7×) beats "it seems better".

---

## References

- Laurens Van Houtven, *Crypto 101*: chapters on XOR and stream ciphers
- [Letter frequency, Wikipedia](https://en.wikipedia.org/wiki/Letter_frequency)
- [Cryptopals challenges, Set 1](https://cryptopals.com/sets/1)

---

## Ethics

Everything here is for learning. All attacks are tested only on data I generated and encrypted myself.

## License

MIT