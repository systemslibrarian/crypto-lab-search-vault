# Search Vault

**Searchable symmetric encryption · public-key keyword search**

Executable searchable encryption from two role models: a symmetric encrypted index whose access pattern enables inference attacks, and public-key searchable tags whose exposed trapdoor enables offline keyword guessing.

**Live demo:** https://systemslibrarian.github.io/crypto-lab-search-vault/

---

## What It Is

An encrypted inverted index, built and searched in your browser, plus the published attacks that turn its leakage back into your queries. A focused PEKS extension then separates public sender, recipient, and server roles with real BLS12-381 pairings.

The scheme is a single-keyword SSE construction in the Song–Wagner–Perrig (2000) / Curtmola–Garay–Kamara–Ostrovsky (SSE-1, 2006) style, with real primitives throughout:

| Value | Derivation | Primitive |
| --- | --- | --- |
| search token `t_w` | `HMAC(K_prf, "token" ‖ w)` | HMAC-SHA-256 (RFC 2104 / FIPS 198-1) |
| posting key `k_w` | `HMAC(K_enc, "posting" ‖ w)` | HMAC-SHA-256 |
| index address `addr_i` | `HMAC(t_w, "address" ‖ i)` | HMAC-SHA-256 |
| posting value | `AES-256-GCM(k_w, docId)`, AAD = `addr_i` | AES-256-GCM (NIST SP 800-38D) |
| document body | `AES-256-GCM(k_d, title ‖ body)` | AES-256-GCM |

The SSE primitives run through WebCrypto. Keys are generated per session with `crypto.getRandomValues`, held in memory, and never persisted or transmitted.

**The public-key extension.** Exhibit 7 implements an algebra-preserving Type-3 BLS12-381 adaptation of Boneh–Di Crescenzo–Ostrovsky–Persiano PEKS (EUROCRYPT 2004). With `e : G1 × G2 → GT`, the recipient chooses `x` and publishes `X = xP2`. A sender with only `X` and keyword `w` samples fresh nonzero `r`, stores `A = rP2` and `B = H2(e(H1(w), rX))`, and discards `r`. The recipient issues `T_w = xH1(w)`; the server tests whether `B = H2(e(T_w, A))`. `H1` is RFC 9380 hash-to-BLS12-381-G1 under a PEKS-specific domain, while `H2` is SHA-256 over a domain-separated, length-framed 576-byte noble Fp12 coefficient encoding.

Bilinearity proves executable correctness: `e(xH1(w), rP2) = e(H1(w), rX)`. It does **not** prove that the original symmetric-pairing BDH reduction transfers to this Type-3 adaptation. A precisely stated Type-3 hardness assumption and a separate formal reduction would be required; this lab supplies neither and makes no such security claim. The recipient, sender, server, and attacker are separate objects in one browser tab, not production network or process isolation.

**The security model.** The server is *honest but curious*: it follows the protocol and records everything it sees. It cannot invert a token (it holds no key) and cannot read a posting or a document (AES-GCM). What it does see, by design, is the **leakage profile**:

- **search pattern** — tokens are deterministic, so repeat queries are linkable;
- **volume** — how many documents a token matches;
- **access pattern** — exactly which documents matched, because it has to hand them over.

That third item is the subject of the demo. Exhibit 2 also contains a separate dishonest-server integrity exercise: it alters a copy of the real answer after the normal honest-but-curious server computes it, so learners can compare per-record authenticity with answer completeness and freshness without changing the base server model. Leakage-abuse attacks (Islam–Kuzu–Kantarcioglu, NDSS 2012; Cash–Grubbs–Perry–Ristenpart, CCS 2015) reconstruct queries from the pattern alone, given background statistics about a similar corpus. Both attacks are implemented here and run against the log the page has actually accumulated while you used it.

**Not production crypto — a teaching demo.** The SSE corpus is deliberately small (24 documents, 14 keywords) and the PEKS store has six synthetic tags, so both attack families finish while you watch. The index is static and every role is co-located in one page.

---

## Exhibits

1. **Build the encrypted index** — step through one keyword becoming an encrypted inverted index, one real PRF call at a time: keyword → token → posting key → address → sealed value → a row landing in the server's store. The hex shown is the vault's own bytes, not a re-enactment. Alongside it, the server's complete store: 55 rows with nothing to say which belong together.
2. **Search it — and watch what the server learns** — run a real query and see both ends at once. The client column shows the keyword and the decrypted results; the server column shows the 32 bytes it received, the address walk it performed (`addr_0`, `addr_1`, … until a miss), and the document identifiers it returned. A running log records every query. Searching a keyword that is not indexed shows the miss path. A second integrity exercise then switches among an honest answer, omission of one authentic posting, one fabricated posting, and replay of an older snapshot. The client retains a snapshot id, expected count, and SHA-256 digest of the complete ordered encrypted answer, making visible why AES-GCM authenticity of each returned record is not the same guarantee as completeness or freshness.
3. **What the pattern alone reveals** — three views built from the log and nothing else: a query-frequency histogram (search pattern), a result-set overlap graph (access pattern), and a document co-occurrence matrix. Plus the share of the database that has appeared in some result set.
4. **Break it: turn the access pattern back into queries** — the count attack pins any token whose result size is unique in the keyword universe; the IKK attack matches the observed token co-occurrence matrix against a known corpus's matrix by simulated annealing. A slider degrades the adversary's background knowledge so you can watch recovery fall off. The per-token table reports what the adversary said, how confident it was, and what the token actually was.
5. **Your turn: you are the server** — you get the tokens, their result sizes, their overlaps, and the same public statistics the attack gets. Assign keywords to tokens by hand, score yourself, then let the machine try the same puzzle.
6. **SSE, ORAM, FHE** — what each hides and what each costs. The SSE latency column is measured in your browser on this vault; the ORAM and FHE columns are labelled as cited, order-of-magnitude figures, because this page runs neither.
7. **Public-key search — and the trapdoor dictionary attack** — generate a recipient key, build randomized tags using only its public key, issue and repeat a recipient trapdoor, scan every tag with public `Test`, and separate search-pattern, volume, and access leakage from an active bounded dictionary attack. Both a recovered target and an honestly worded bounded miss are executable states.

Plus a **scope** panel stating what is real, what is scaled down, what this does not prove, and what is deliberately out of scope.

---

## When to Use It

**Use searchable symmetric encryption when:**

- you must search a large encrypted store and per-query cost has to scale with the number of *matches*, not the size of the database;
- the threat you care about is a passive host reading data at rest, or a breach of storage;
- you can tolerate the server learning which records match a query, and you have thought about what that means for your data.

**Do NOT use it when:**

- **the query itself is the secret you must protect against the storage provider.** This is the case the demo exists to make: given background knowledge about your corpus, the access pattern can be inverted. If your queries are sensitive (a journalist's sources, a patient's diagnosis codes), SSE alone is the wrong tool — you want ORAM, or PIR, or to not outsource the index.
- you need conjunctive or ranked search and assume the leakage is unchanged. It is not; richer queries leak more.
- your index changes constantly and you have not chosen a scheme with forward and backward privacy.
- you are tempted to reach for order-preserving or deterministic encryption to make SQL work. That leaks far more than this does.

The PEKS exhibit is a construction-and-attack lesson, not a production recommendation. Public-key tag creation can be useful when senders must not share the recipient’s search secret, but basic PEKS adds a full tag scan, exposes deterministic trapdoors, permits offline guessing for low-entropy words, and supplies no sender authentication or tag/body binding.

---

## Live Demo

https://systemslibrarian.github.io/crypto-lab-search-vault/

You can: step the index build for any of the 14 keywords; search real and non-existent keywords and watch the server's log fill; observe a realistically skewed round of queries; read the three SSE leakage views; run both SSE inference attacks at any level of adversary background-knowledge error; try to deanonymise the tokens yourself; time 50 real searches; then build real PEKS tags, repeat a trapdoor, and run successful, absent-target, and zero-guess bounded dictionary cases.

---

## What Can Go Wrong

- **Access-pattern leakage is not a footnote.** With exact background statistics, the attack in Exhibit 4 recovers all 14 queries in tens of milliseconds. The jitter slider is a synthetic sensitivity control; no value is calibrated to realistic attacker error.
- **Volume leakage is enough on its own.** Any keyword whose document count is unique in the vocabulary is identified by result size, with no co-occurrence analysis at all. Padding result sets is the standard countermeasure, and it costs storage and bandwidth.
- **Deterministic tokens link queries over time.** The server cannot read a token, but it recognises every repeat, so it can build a per-user query-frequency profile and line it up against public word-frequency data.
- **Background similarity is an assumption to evaluate.** The adversary needs statistics for a *similar* corpus, not yours — leaked archives, public filings, and comparable organisations all supply them.
- **A static index hides an ongoing hazard.** This demo builds the index once. Adding documents later leaks whether a new document matches an earlier query unless the scheme is explicitly forward-private.
- **Tampering fails closed, and that is deliberate.** Each posting is sealed with its own address as associated data, so a server that relocates, forges or flips a row causes the whole result to be rejected rather than silently mis-answered. Six tests cover this path.
- **Authentic records can still form an incomplete or stale answer.** Omitting one valid posting leaves every returned AES-GCM ciphertext authentic; replaying a previously valid answer can also preserve record authenticity. The integrity exercise detects those cases only because the client retained an independent checkpoint for the expected answer and current snapshot. That checkpoint is intentionally a teaching construction, not a claim of a general verifiable-SSE protocol.
- **An exposed PEKS trapdoor is a keyword oracle for a small dictionary.** Anyone with the public key and trapdoor can create a fresh tag for a candidate and invoke public `Test` locally. A secure channel can stop an outside capture, but not the search server that receives the trapdoor.
- **A bounded miss proves only a bounded miss.** If no tested candidate passes, the target may be absent or beyond the chosen bound. It does not establish trapdoor privacy or security.
- **Public writers are not authenticated.** Basic PEKS lets anyone with `X` make a tag, but does not prove a word appears in a separately encrypted body, bind tag to body, or authenticate the sender. `Test` also gives no completeness or freshness guarantee.
- **A trapdoor remains useful after its query.** A server can retain it and test existing and future tags. Equal-keyword tags are randomized before query, but repeated trapdoors, volume, and matching opaque identifiers remain visible after issuance.

---

## Real-World Usage

Searchable encryption is what gets deployed when fully homomorphic encryption is too slow, which is nearly always. Variants appear in encrypted-database products, encrypted-search appliances, and client-side-encrypted note and mail services that still offer a search box. The academic line runs Song–Wagner–Perrig (2000) → Curtmola et al.'s SSE-CKA security definitions (2006) → the OXT conjunctive scheme of Cash–Jarecki–Jutla–Krawczyk–Roşu–Steiner (2013) → the leakage-abuse attacks that reshaped the field's expectations (Islam–Kuzu–Kantarcioglu 2012, Cash–Grubbs–Perry–Ristenpart 2015) → forward- and backward-private dynamic schemes designed in their wake.

The lasting lesson is the one this demo is built around: for SSE, **the leakage profile is the security model.** A scheme is not "secure" or "insecure" in the abstract — it is secure *relative to a stated leakage function*, and whether that leakage is acceptable is a question about your data and your adversary, not about the cryptography.

For PEKS, public encryption changes who may create searchable data, not whether query artifacts need a threat model. Basic PEKS tags do not encrypt the body, authenticate the sender, hide the post-query access pattern, or protect a low-entropy exposed trapdoor from public guess verification.

### Primary sources and construction boundary

- Boneh, Di Crescenzo, Ostrovsky, and Persiano, [*Public Key Encryption with Keyword Search*](https://web.cs.ucla.edu/~rafail/PUBLIC/61.pdf), EUROCRYPT 2004 — original `KeyGen`, `PEKS`, `Trapdoor`, and `Test` construction and security game.
- [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380.html), especially §8.8 and Appendix J.9.1 — BLS12-381 hash-to-curve suite and the unit-test point.
- Byun et al., [*Off-Line Keyword Guessing Attacks on Recent Keyword Search Schemes over Encrypted Data*](https://doi.org/10.1007/11844662_6), 2006 — low-entropy keyword-space attack boundary.
- Rhee, Susilo, and Kim, [*Secure searchable public key encryption scheme against keyword guessing attacks*](https://www.jstage.jst.go.jp/article/elex/6/5/6_5_237/_pdf), 2009 — explicit public-PEKS-then-`Test` offline attack used here.
- Abdalla et al., [*Searchable Encryption Revisited: Consistency Properties, Relation to Anonymous IBE, and Extensions*](https://www.iacr.org/cryptodb/archive/2005/CRYPTO/927/927.pdf), CRYPTO 2005 — computational consistency and the anonymous-IBE relation.
- IRTF CFRG, [*Pairing-Friendly Curves* Internet-Draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/) — work-in-progress concrete estimate near 126 bits for BLS12-381. The lab deliberately makes no exact 128-bit claim.

The first paper uses a symmetric pairing. This implementation instead follows the algebra in Type-3 groups because BLS12-381 has no efficient G1↔G2 isomorphism. That engineering adaptation preserves the demonstrated correctness equation; it is not presented as inheriting the paper’s proof.

---

## How to Run Locally

```bash
npm install
npm run dev          # http://localhost:5173
npm test             # unit tests, including the spec KATs
npm run build        # typecheck + production build
npm run test:a11y    # axe-core WCAG 2.1 AA gate against the production build
npm run test:e2e     # the same Playwright run, including the functional claims suite
```

Both Playwright scripts build first and start `vite preview` on port **4237** automatically, so what is scanned and driven is what ships.

---

## Related Demos

- [crypto-lab-oram-vault](https://systemslibrarian.github.io/crypto-lab-oram-vault/) — Path ORAM: hiding the access pattern this demo leaks.
- [crypto-lab-psi-gate](https://systemslibrarian.github.io/crypto-lab-psi-gate/) — private set intersection: computing on two private sets without revealing the non-matching elements.
- [crypto-lab-fhe-arena](https://systemslibrarian.github.io/crypto-lab-fhe-arena/) — fully homomorphic encryption: the expensive end of the same trade-off.
- [crypto-lab-ibe-gate](https://systemslibrarian.github.io/crypto-lab-ibe-gate/) — the related Type-3 pairing identity in executable Boneh–Franklin IBE.
- [crypto-lab-pairing-gate](https://systemslibrarian.github.io/crypto-lab-pairing-gate/) — BLS12-381 pairing and RFC 9380 foundations.

---

## Build & Verify

**117 unit tests**, all passing, run by `npm test` and gating the deploy.

**12 published specification known-answer cases:**

| File | Vectors |
| --- | --- |
| `src/core/prf.test.ts` | 6 × HMAC-SHA-256 from RFC 4231 §4 (cases 1, 2, 3, 4, 6, 7) |
| `src/core/prf.test.ts` | 3 × SHA-256 from FIPS 180-4 (empty, `"abc"`, the 448-bit two-block message) |
| `src/core/aead.test.ts` | 2 × AES-256-GCM from the GCM specification's vector set (test cases 13 and 14), checked in both directions |
| `src/peks/core.test.ts` | 1 × RFC 9380 Appendix J.9.1 BLS12381G1 hash-to-curve point, checked in both affine coordinates |

Beyond the KATs, the suite covers: index construction (one posting per keyword–document pair, distinct pseudorandom addresses, no two identical ciphertexts); search correctness for every keyword in the corpus; the miss path for unindexed keywords and random tokens; six SSE fail-closed cases; what the server's ledger does and does not record; leakage computations and inference attacks; and the query-integrity checkpoint. PEKS tests pin an independently derived fixed `x=7, r=11` transcript; verify the two pairing routes and full H2 digest; require randomized equal-keyword tags; reject wrong keywords, foreign recipients, tampered digests, identity, malformed, non-canonical, and non-subgroup point encodings; prove the server record shape contains no keyword, scalar, randomness, body, or demo GT element; and exercise recovered, absent, truncated, zero-bound, normalized-duplicate, and wrong-recipient dictionaries.

**Functional browser gate:** `e2e/claims.spec.ts` drives the production build and asserts each SSE number against other rendered evidence rather than constants. `e2e/query-integrity.spec.ts` separately drives all four integrity cases plus unindexed-keyword refusal. `e2e/peks.spec.ts` proves the sender/server record counts agree, repeated-word tag bytes differ in that measured run, every server tag receives `Test`, matched rows equal the verdict and ledger, repeated trapdoors match in all 48 bytes, the attack headline equals its first passing row, bounded misses make no security claim, build failure keeps dependent controls disabled, an in-flight attack cannot restore evidence after its trapdoor is retired, and a rebuild retires all prior-key evidence. Uncaught page or console errors fail the run.

**Accessibility gate:** `@axe-core/playwright` scans the production build for WCAG 2.1 A/AA violations in the supported dark theme at desktop and 380px. The shared drive scans 34 learner states per viewport, including PEKS arrival, build, query, repeat, attack success, absent-target miss, and zero-guess miss. Arithmetic text and control contrast, non-text contrast ratchets, keyboard-reachable scrollers, focus visibility, reduced motion, unique landmarks, and horizontal reflow are separate enforced oracles. Zero new violations are required; a regression blocks deployment.

---

## Performance

Search is fast because SSE lets the server do an ordinary index lookup: the work is proportional to the number of matching documents, not the size of the database. Exhibit 6 measures it live — 50 full searches, each covering token derivation, address probing, AES-GCM posting decryption and document fetch — and reports the per-search figure for your browser. On a modern laptop it lands in the low single-digit milliseconds.

The attacks are comparably cheap: the count attack is a table lookup, and the IKK annealing (8 restarts × 12,000 iterations, plus a greedy polish) resolves 14 tokens in tens of milliseconds. Being cheap to attack is the point.

Basic PEKS has a different cost: this exhibit runs one pairing-based `Test` for every stored tag, so query work is proportional to the tag store rather than the number of matches. Each offline guess also constructs a real randomized tag and runs `Test`; the dictionary is deliberately small and the UI yields between guesses. No deployment-scale timing claim is made.

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*

## Auxiliary-corpus sensitivity

[Revisiting the attacker’s knowledge in inference attacks against SSE](https://arxiv.org/abs/2504.09879), 14 April 2025, ACNS 2025, studies auxiliary-data similarity and sample size. Exhibit 4 now separates exact-target statistics, arbitrary statistic jitter, and independently sampled modeled corpora (64 documents, 12 from the same auxiliary generator, or a declared payroll-heavy distribution shift). Counts and co-occurrences come jointly from each corpus; counts are rescaled to the public target size for the count attack. The fixed handwritten target is not asserted to be drawn from that generator. Matrix RMSE and three actual seeded recovery results are evaluation metrics, not attacker inputs or a replication of the paper. Annealing is heuristic: no monotonic recovery guarantee, realistic-error calibration, or general SSE safety threshold is claimed.
