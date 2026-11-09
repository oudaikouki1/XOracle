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
- [x] **Phase 2: Break single-byte XOR.** Brute-force all 256 keys and rank the candidates with an English-likeness score.
  - [x] v1: character-class scoring (letters, spaces, garbage penalty)
  - [x] v2: letter-frequency scoring
  - [x] v3: chi-squared test
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
├── scoring.py     # english_score, frequency_score, chi_squared_score
├── test.py        # cracks test sentences with every scorer and compares them
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

Three scorers, each one built to fix the weaknesses found in the one before:

- **v1, character classes:** lowercase/space +2, uppercase +1, common punctuation 0, anything else −5. Higher is better.
- **v2, letter frequency:** each letter adds its frequency in English (`e` ≈ 0.127, `z` ≈ 0.0007); non-printable bytes −0.5. Higher is better.
- **v3, chi-squared:** compares the whole character distribution (26 letters + space + "other") with English. Control or non-ASCII bytes are rejected outright. Lower is better.

#### Results (`python test.py`)

Separation = how many times better the correct key scores than **that scorer's own** best wrong key. The scorers use different scales, so the ratio is the fair comparison. For chi-squared it's computed as impostor / real.

| Sentence | v1 | v2 | v3 |
|---|---|---|---|
| `I LOVE WORKING OUT` | #1, 1.40× | #1, 1.53× | #1, **3.48×** |
| `I WANT TO BE THE BEST IN THE WORLD` | #1, 1.62× | #1, 1.92× | #1, **5.79×** |
| `I tried to stop smoking 125970 times` | #1, 1.45× | #1, 1.84× | #1, **3.83×** |

All three scorers find the key, but v3 does it with about 2–3× more margin than v1 and v2. That margin matters for Phase 3, where each column of ciphertext is short and a weak scorer starts picking wrong bytes.

#### How each version improved on the last

- **v1 → v2:** v1 rewards `k`, `v`, `z` and `q` as much as `e` and `t`, so a string of random letters looks like English. v2 gives rare letters almost nothing.
- **v2 → v3:** v2 *adds up* rewards, so a candidate can score well with a few lucky common letters. Chi-squared checks whether the *proportions* match English, so too many `e`s, too few spaces or too many symbols all cost points.

#### Getting chi-squared right took four fixes

My first v3 put the correct key at **#129–#142**. Each fix came from reading what was beating it:

1. **Pure garbage scored a perfect 0.** With no letters to count, every term was skipped. Fix: return `inf` when there's nothing to count.
2. **The case-flip key nearly won.** XOR with `0x78` turns `WANT` into `want` (invisible after `.lower()`) and spaces into `\x00` (ignored). Fix: reject control and non-ASCII bytes.
3. **Few letters plus lots of symbols won.** Only letters were counted, so `,E)*3 E2*7.,+"E*01` was judged on 4 letters. Fix: count every byte, with symbols in an `"other"` category.
4. **Expected counts didn't add up.** The table had no `"other"` entry and didn't sum to 1. Fix: rescale letters to 83%, space 15%, other 2%.

**Known limit:** on very short ciphertexts (e.g. `Hi`), no frequency-based scorer can decide: `No`, `On` and `Hi` are all plausible. Frequency analysis needs enough text.

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
- Measure improvements. A before/after number beats "it seems better".
- Compare fairly: measure each method against its *own* best competitor, not against one picked for another method.
- When a scorer fails, print what beat it. Every fix to chi-squared came from reading the winning impostor.

---

## References

- Laurens Van Houtven, *Crypto 101*: chapters on XOR and stream ciphers
- [Letter frequency, Wikipedia](https://en.wikipedia.org/wiki/Letter_frequency)
- [Cryptopals challenges, Set 1](https://cryptopals.com/sets/1)

---

## Ethics

Everything here is for learning. All attacks are tested only on data I generated and encrypted myself.

