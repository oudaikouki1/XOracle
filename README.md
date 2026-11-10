# XOracle

**Encrypt with XOR, then break it.**

XOracle is a Python toolkit I'm building to learn cryptanalysis by doing it. It implements XOR "encryption" and then attacks it from several angles, showing step by step why XOR on its own is not real encryption.

> ✅ **Completed.** All five attack phases are implemented, tested on my own data and documented below. Possible extensions are listed under [Future work](#future-work).

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
- [x] **Phase 3: Break repeating-key XOR.** Guess the key length with Hamming distance, then split the problem into single-byte columns.
- [x] **Phase 4: Known-plaintext attack on files.** Recover keys from file signatures (PNG, PDF, ZIP, ELF...).
  - [x] Header-only attack + automatic file-type identification
  - [x] Keys longer than the header, using known bytes at both ends of the file
- [x] **Phase 5: Reused one-time pad.** Interactive crib dragging on `C1 ⊕ C2 = P1 ⊕ P2`.
  - [x] Two messages: guided crib dragging
  - [x] Many messages: automatic column attack (reuses Phase 2)

### Future work

Ideas I may come back to; they're not part of the completed project:

- Majority vote across key copies, to fix overfitting on medium-length texts (Phase 3)
- Known end-of-file bytes for more formats than PNG (Phase 4)
- A `tests/` folder with automated checks
- Break XOR-obfuscated UDP traffic from my FPGA Ethernet project

---

## Project structure

```
XOracle/
├── core.py         # xor_bytes: the XOR primitive
├── scoring.py      # english_score, frequency_score, chi_squared_score
├── single_byte.py  # crack, best_key: Phase 2 single-byte breaker
├── repeating.py    # hamming_distance, keysize_score, guess_keysizes, transpose,
│                   # shortest_period, recover_key, break_repeating_xor
├── known_plain.py  # SIGNATURES, KNOWN_PARTS, keystream_from_header, find_period,
│                   # recover_with_signature, identify_filetype,
│                   # known_keystream, key_for_length, recover_long_key
├── crib.py         # xor_ciphertexts, crib_drag, crib_hits, guided session,
│                   # break_many_time_pad
├── make_file.py    # encrypts the sample PNG and PDF with known keys
├── make_sample.py  # encrypts plain.txt and runs the Phase 3 attack
├── test.py         # Phase 2 scorer comparison
├── test_crib.py    # Phase 5 experiments
├── samples/        # plain.txt, img.png, sample.pdf
└── README.md
```

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
- **v3, chi-squared:** compares the whole character distribution (26 letters + space + "other") with English. Control bytes are rejected outright; non-ASCII bytes count as "other" (see Phase 3). Lower is better.

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
2. **The case-flip key nearly won.** XOR with `0x78` turns `WANT` into `want` (invisible after `.lower()`) and spaces into `\x00` (ignored). Fix: reject control bytes.
3. **Few letters plus lots of symbols won.** Only letters were counted, so `,E)*3 E2*7.,+"E*01` was judged on 4 letters. Fix: count every byte, with symbols in an `"other"` category.
4. **Expected counts didn't add up.** The table had no `"other"` entry and didn't sum to 1. Fix: rescale letters to 83%, space 15%, other 2%.

**Known limit:** on very short ciphertexts (e.g. `Hi`), no frequency-based scorer can decide: `No`, `On` and `Hi` are all plausible. Frequency analysis needs enough text.

**What I learned along the way**
- `sorted()` is ascending by default, so my first run printed the three *worst* keys. They were consecutive (3, 4, 5) because they tied at the minimum score and `sorted()` keeps ties in their original order.
- v1 told English from garbage mostly by the **spaces**: under the wrong key, spaces became `?`, which my scorer treated as neutral punctuation.
- Penalties only mean something relative to rewards. Switching the frequency table from percent to fractions left the old −5 penalty about 40× bigger than the best letter's reward.
- Text with digits is the hardest case: the real plaintext pays a penalty for its digits, while the wrong key turns them into neutral punctuation.

### Phase 3: breaking repeating-key XOR

Given only a ciphertext encrypted with a repeating key (`ICE` → `ICEICEICE…`), recover the key and the plaintext.

#### The attack

```
ciphertext
  │
  ├─ 1. guess_keysizes    which key lengths are likely?        (Hamming distance)
  ├─ 2. transpose         one column per key byte
  ├─ 3. best_key          break each column as single-byte XOR  (Phase 2, chi-squared)
  ├─ 4. shortest_period   ICEICEICE → ICE
  └─ 5. pick the winner   decrypt with each candidate, score with chi-squared
                          → shortest key within 10% of the best score
```

**Step 1: finding the key length.** Cut the ciphertext into blocks of `k` bytes and measure the Hamming distance (differing bits) between consecutive blocks. If `k` is the real length, both blocks were encrypted with the same key bytes, so the key cancels out:

```
(P1 ⊕ K) ⊕ (P2 ⊕ K) = P1 ⊕ P2
```

That leaves two pieces of English, which differ in fewer bits than random bytes. The lowest normalized distance points to the key length **and its multiples**. Taking the GCD of the top candidates recovers the real length.

**Step 2: transposing.** Once the length is known, every k-th byte was encrypted with the same key byte:

```
ciphertext:  A B C D E F G H I J     key length 3
key:         I C E I C E I C E I
column 0:    A     D     G     J  →  single-byte XOR with 'I'
column 1:      B     E     H      →  single-byte XOR with 'C'
column 2:        C     F     I    →  single-byte XOR with 'E'
```

One hard problem becomes `k` easy ones, each solved with the Phase 2 breaker.

#### Results: stress test (`python test.py`)

Random keys (seed 42) of 4 lengths × 5 plaintext lengths, from a 3,245-byte English text. *Bytes/col* = text length ÷ key length, the amount of data each column gets.

| Key length | 3,245 bytes | 1,000 | 500 | 200 | 100 |
|---|---|---|---|---|---|
| 3 | ✅ | ✗ length (27) | ✗ length (24) | ✗ length (39) | ✗ length (27) |
| 7 | ✅ | ✗ length (28) | ✗ length (28) | ✗ length (35) | ~ 3 bytes wrong |
| 16 | ✅ | ✗ length (32) | ✗ length (32) | ~ 5 bytes wrong | ~ 11 bytes wrong |
| 29 | ✅ | ✅ | ~ 3 bytes wrong | ~ 13 bytes wrong | ~ 18 bytes wrong |

✅ key recovered exactly · ~ right length, some bytes wrong · ✗ wrong length (found length in brackets)

**Every key is recovered from the full text.** Below that, there are two kinds of failure:

1. **Too little data per column** (key 29 on short texts). With 3–17 bytes per column, chi-squared can't reliably pick the right byte. This is the same limit as `Hi` in Phase 2, and no tuning fixes it. Even so, the partly correct key gives partly readable text (`rIt WiLD… triTITs… the`), which an attacker could finish by hand.
2. **A multiple of the key length wins** (keys 3, 7 and 16 on medium texts). Every wrong length found was an exact multiple of the real one.

#### Debugging the "wrong length" failures

My first guess was that `guess_keysizes` missed the real length. A diagnostic showed the opposite: **the real length was in the candidate list every time.** Chi-squared was choosing a multiple instead.

The reason is **overfitting**. With key length 27 instead of 3, the text is split into 27 small columns instead of 3 large ones, and each column picks its own best byte. A slightly wrong byte can fit a small column's noise a little better, and with 27 independent choices, the long key tunes itself to this specific text. Its decryption ends up scoring slightly *better* than the real key's, even though it's wrong in places.

**Fix:** among candidates scoring within 10% of the best, take the **shortest** key. This is Occam's razor: a multiple overfits by a few percent, while a truly wrong length scores far worse.

| | Exact recoveries (of 20) | Wrong-length failures |
|---|---|---|
| Lowest score wins | 4 | 13 |
| Shortest key within 10% | **5** | **9** |

Multiples still win on medium texts, where the overfitting gain exceeds 10%. The next step is a **majority vote** across the copies of the key: a 27-byte result like `ICEIXEICE…` is mostly correct copies of `ICE`, so voting per position would recover it.

#### Bugs found along the way

- **One `ä` broke everything.** The first full run returned `b'\x00\x00\x00'`. The plaintext contained `Tannhäuser` and curly quotes, which are UTF-8 bytes above `0x7E`, and the scorer rejected any candidate containing one, **including the correct key**. All 256 keys tied at `inf`, so key 0 won. Fix: reject only control bytes (which never appear in text) and count high bytes as "other".
- **Similar key bytes hide the key length.** `ICE` = `0x49 0x43 0x45`: the bytes differ in only a few bits, so wrong lengths looked almost as good as the right one. Comparing only 4 blocks made it invisible. Using **every** block in the ciphertext fixed it.
- **Multiples tie with the real length.** For `Xor!`, lengths 4, 8, 12… 40 all scored about 2.7, with the order decided by noise. The GCD of the top candidates gives 4.

### Phase 4: known-plaintext attack on files

Phases 2 and 3 guess the key with **statistics**, which only works when the plaintext is English. Images, PDFs and archives aren't text, but they have something better: **bytes whose values are known in advance.**

#### The idea

Almost every file format starts with a fixed *signature* (magic number):

| Type | First bytes |
|---|---|
| PNG | `89 50 4E 47 0D 0A 1A 0A` |
| PDF | `%PDF-` |
| ZIP / DOCX / XLSX | `PK\x03\x04` |
| ELF | `\x7fELF` |
| GIF | `GIF89a` |

If you know part of the plaintext, XOR hands you the key directly:

```
C = P ⊕ K   →   K = C ⊕ P
```

No brute force, no scoring: one XOR. This is how analysts break XOR-obfuscated malware payloads: guess "this is probably a ZIP or an executable", and the header gives up the key.

#### Header-only attack

1. `keystream_from_header`: XOR the first ciphertext bytes with the signature.
2. `find_period`: find where that keystream starts repeating. That's the key length.
3. `recover_with_signature`: slice the key and decrypt the whole file.
4. `identify_filetype`: try every signature, and keep the one whose keystream repeats.

| File | Key | Keystream revealed | Period | Result |
|---|---|---|---|---|
| PNG | `XORacle` (7) | `XORacleX` | 7 | ✅ image opens |
| PDF | `key` (3) | `keyke` | 3 | ✅ PDF opens |

**How it tells the file type:** with the right signature, the keystream *is* the key, so it repeats. With a wrong one, it's random-looking bytes with no repetition:

| Guess on the PNG | Keystream | Period | Repeats? |
|---|---|---|---|
| **png** | `XORacleX` | **7** | ✅ |
| pdf | `\xf4OX`C` | 5 | no |
| zip | `\x81T\x1f"` | 4 | no |
| elf | `\xaeZP`` | 4 | no |
| gif | `\x96VZ\x1eW\x07` | 6 | no |

**Limit:** the header only reveals as many key bytes as it has. A key longer than the signature never shows a repeat, so the file is reported as `"unknown"`.

#### Breaking keys longer than the header

A PNG has fixed bytes at **both ends**:

| Where | Known bytes |
|---|---|
| Start (16 bytes) | signature + IHDR chunk length + `IHDR` |
| End (12 bytes) | the `IEND` chunk: `00 00 00 00 49 45 4E 44 AE 42 60 82` |

That's 28 known bytes. With key length `L`, the byte at position `pos` was encrypted by key byte `pos % L`. So for each candidate `L`:

- **Contradiction:** two known positions land on the same key byte but give different values, so `L` is impossible.
- **Gap:** some key byte is never covered, so `L` can't be completed.
- Otherwise, the key is fully determined.

The smallest `L` with no contradiction and no gap is the key length. Its multiples are also consistent, as in Phase 3, but here the check is **exact**, so no statistics or tolerance are needed.

#### Results: random keys on a real PNG

| Key length | 7 | 12 | 16 | 20 | 24 | 28 | 29 | 35 |
|---|---|---|---|---|---|---|---|---|
| Header only | ✅ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Header + IEND | ✅ | ✅ | ✅ | ✅ | ✅ | ✗ | ✗ | ✗ |

**From 7 bytes to 24 bytes** by using known plaintext from a second place in the file.

**Why it stops at about 28:** a key of length `L` has `L` slots, and 28 known bytes can fill at most 28 of them. At exactly 28, it would only work if the IEND bytes landed precisely on the slots the start didn't cover, which depends on `(file length − 12) mod 28`. In practice they overlap, and some slots stay empty. **The rule: a key is recoverable when the known plaintext covers every key position at least once.**

#### The one-time-pad connection

If the key is as long as the file, it has as many slots as the file has bytes, and 28 known bytes reveal 28 key bytes and **nothing else**. Without repetition, knowing part of the plaintext says nothing about the rest. That's exactly why a true one-time pad is unbreakable, unless the same pad is used twice (Phase 5).

#### Bugs found along the way

- **Half the known plaintext silently ignored.** Negative offsets (counted from the end) were treated as invalid positions and skipped, so only the start bytes were used. No error, just missing data. Fix: convert `-12` to `len(file) - 12` first.
- **"Everything fails" in the stress test** came from the test, not the attack: arguments to `xor_bytes` were swapped (the output was only `L` bytes long), and the image was encrypted twice. Lesson: when every case fails, check the shared code first.

### Phase 5: the reused one-time pad

A one-time pad (a random key as long as the message, used once) is provably unbreakable. Phase 4 showed why: with no repetition, knowing part of the plaintext reveals nothing else. This phase breaks the classic mistake of **using the same pad twice**.

#### The key cancels out

```
C1 = P1 ⊕ K
C2 = P2 ⊕ K
C1 ⊕ C2 = (P1 ⊕ K) ⊕ (P2 ⊕ K) = P1 ⊕ P2
```

From the two ciphertexts alone, an attacker gets the two plaintexts XORed together, and the pad is gone. That isn't readable yet, but it's no longer random. This is what happened in the **Venona project**, where reused Soviet pads were broken for decades.

#### What `P1 ⊕ P2` already leaks

Test messages: `This is the first plaintext message.` and `This is the second plaintext message.`

```
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x15\x0c\x11\x1c\x1aDP\x1c\r…
```

- **12 zero bytes:** `a ⊕ a = 0`, so both messages start with the same 12 characters. An attacker sees this without knowing a single letter.
- **Letters in the noise (`D`, `P`, `T`, `M`, `K`):** `' ' ⊕ 'a' = 'A'`. Where one message has a space and the other a letter, `P1 ⊕ P2` shows that letter with its case flipped.

#### Crib dragging

Guess a word that's probably in one message (a *crib*) and slide it along `P1 ⊕ P2`:

```
X ⊕ P1 = (P1 ⊕ P2) ⊕ P1 = P2
```

At the right position, the other message appears as readable text. At wrong positions you get garbage. Every correct guess reveals the other message **and the pad** at that position, and each newly revealed fragment suggests the next guess, back and forth like a zipper:

```
                                  1: ????????????????????????????????????
                                  2: ????????????????????????????????????
msg 1, pos  0, "This is the "  →  1: This is the ????????????????????????
                                  2: This is the ????????????????????????
msg 1, pos 12, "first"         →  1: This is the first???????????????????
                                  2: This is the secon???????????????????
msg 2, pos 12, "second "       →  1: This is the first p?????????????????
                                  2: This is the second ?????????????????
msg 1, pos 17, " plaintext "   →  1: This is the first plaintext ????????
                                  2: This is the second plaintext????????
msg 1, pos 27, " message."     →  1: This is the first plaintext message.
                                  2: This is the second plaintext message
```

Both messages were recovered, and `C1 ⊕ P1` reproduced the pad exactly.

**A wrong guess shows itself immediately.** Placing `laintext ` one position too early turned the other message into `<}dfsii,`. That's the built-in check of crib dragging.

**Limits:**
- In regions where both messages are identical, `P1 ⊕ P2` is all zeros, so every crib "fits". You learn that the messages are equal there, not what they say.
- Positions beyond the shorter message can't be recovered from two ciphertexts.

#### Many messages with one pad: fully automatic

If the same pad encrypts many messages, byte `i` of every message was XORed with the same pad byte. So each **column** is a single-byte XOR problem, and the Phase 2 breaker solves it with no guessing, the same idea as the columns in Phase 3.

| Messages sharing the pad | Pad bytes wrong | Message 1, decrypted |
|---|---|---|
| 4 | 18 / 38 | `lDet met r thE O @ b idgE at HiRO  ONa` |
| 8 | 8 / 38 | `mEet me ar thC olD bridge at niRe tSNi` |
| 15 | 5 / 38 | `mDet me at the old bridgy at niRe toNi` |

The more messages, the more bytes per column, and the better the result: the same "enough data per column" rule as Phase 3. Many remaining errors are only wrong capitalisation (`mDet`), because chi-squared ignores case.

---

## Lessons learned

*(This section grows with each phase.)*

- A 256-key space is not security: brute force takes milliseconds.
- To recognise the right answer, you only need the plaintext to be *statistically different* from noise.
- A scorer that checks *which kind* of character appears is weak. One that checks *how often each letter appears* is much stronger, because English has a fingerprint (ETAOIN SHRDLU).
- Measure improvements. A before/after number beats "it seems better".
- Compare fairly: measure each method against its *own* best competitor, not against one picked for another method.
- When a scorer fails, print what beat it. Every fix to chi-squared came from reading the winning impostor.
- Split a hard problem into ones you've already solved: repeating-key XOR is just `k` single-byte problems.
- Diagnose before fixing. I assumed the key-length guesser was failing; one print showed it was right every time and the real problem was elsewhere.
- More free parameters fit the data better, but not always more truthfully. A longer key overfits, as in machine learning, and the simplest good-enough answer is usually the right one.
- Real data is messy. Text copied from the web is UTF-8, not ASCII, and a scorer that's too strict rejects the right answer.
- Known plaintext beats statistics. A few predictable bytes recover a key instantly, where frequency analysis needs thousands of bytes of English.
- File formats are full of predictable bytes: signatures, chunk names, trailers. Every one is a crib for an attacker.
- Repetition is the weakness. Every attack so far exploits a key that repeats, and a key that never repeats (a true one-time pad) leaks nothing.
- "Unbreakable" depends on how a system is used. A one-time pad used twice is broken by the same XOR property that makes it work.
- The same few ideas keep coming back: XOR cancels itself, columns turn one hard problem into many easy ones, and English has statistics that noise doesn't.

---

## References

- Laurens Van Houtven, *Crypto 101*: chapters on XOR and stream ciphers
- [Letter frequency, Wikipedia](https://en.wikipedia.org/wiki/Letter_frequency)
- [Cryptopals challenges, Set 1](https://cryptopals.com/sets/1)
- [Venona project, Wikipedia](https://en.wikipedia.org/wiki/Venona_project)

---

## Ethics

Everything here is for learning. All attacks are tested only on data I generated and encrypted myself.

## License

MIT