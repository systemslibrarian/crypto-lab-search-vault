# Search Vault

**Searchable symmetric encryption · encrypted keyword search**

Searchable encryption where a server finds matching records in an encrypted database without learning the query or the data — but the access pattern it observes is itself an attack surface.

**Live demo:** https://systemslibrarian.github.io/crypto-lab-search-vault/

---

## What It Is

An encrypted inverted index, built and searched in your browser, plus the published attacks that turn its leakage back into your queries.

The scheme is a single-keyword SSE construction in the Song–Wagner–Perrig (2000) / Curtmola–Garay–Kamara–Ostrovsky (SSE-1, 2006) style, with real primitives throughout:

| Value | Derivation | Primitive |
| --- | --- | --- |
| search token `t_w` | `HMAC(K_prf, "token" ‖ w)` | HMAC-SHA-256 (RFC 2104 / FIPS 198-1) |
| posting key `k_w` | `HMAC(K_enc, "posting" ‖ w)` | HMAC-SHA-256 |
| index address `addr_i` | `HMAC(t_w, "address" ‖ i)` | HMAC-SHA-256 |
| posting value | `AES-256-GCM(k_w, docId)`, AAD = `addr_i` | AES-256-GCM (NIST SP 800-38D) |
| document body | `AES-256-GCM(k_d, title ‖ body)` | AES-256-GCM |

All of it runs through WebCrypto. Keys are generated per session with `crypto.getRandomValues`, held in memory, and never persisted or transmitted.

**The security model.** The server is *honest but curious*: it follows the protocol and records everything it sees. It cannot invert a token (it holds no key) and cannot read a posting or a document (AES-GCM). What it does see, by design, is the **leakage profile**:

- **search pattern** — tokens are deterministic, so repeat queries are linkable;
- **volume** — how many documents a token matches;
- **access pattern** — exactly which documents matched, because it has to hand them over.

That third item is the subject of the demo. Leakage-abuse attacks (Islam–Kuzu–Kantarcioglu, NDSS 2012; Cash–Grubbs–Perry–Ristenpart, CCS 2015) reconstruct queries from the pattern alone, given background statistics about a similar corpus. Both attacks are implemented here and run against the log the page has actually accumulated while you used it.

**Not production crypto — a teaching demo.** The corpus is deliberately small (24 documents, 14 keywords) so the attack finishes while you watch, the index is static, and the "client" and "server" are two objects in one page rather than two hosts.

---

## Exhibits

1. **Build the encrypted index** — step through one keyword becoming an encrypted inverted index, one real PRF call at a time: keyword → token → posting key → address → sealed value → a row landing in the server's store. The hex shown is the vault's own bytes, not a re-enactment. Alongside it, the server's complete store: 55 rows with nothing to say which belong together.
2. **Search it — and watch what the server learns** — run a real query and see both ends at once. The client column shows the keyword and the decrypted results; the server column shows the 32 bytes it received, the address walk it performed (`addr_0`, `addr_1`, … until a miss), and the document identifiers it returned. A running log records every query. Searching a keyword that is not indexed shows the miss path.
3. **What the pattern alone reveals** — three views built from the log and nothing else: a query-frequency histogram (search pattern), a result-set overlap graph (access pattern), and a document co-occurrence matrix. Plus the share of the database that has appeared in some result set.
4. **Break it: turn the access pattern back into queries** — the count attack pins any token whose result size is unique in the keyword universe; the IKK attack matches the observed token co-occurrence matrix against a known corpus's matrix by simulated annealing. A slider degrades the adversary's background knowledge so you can watch recovery fall off. The per-token table reports what the adversary said, how confident it was, and what the token actually was.
5. **Your turn: you are the server** — you get the tokens, their result sizes, their overlaps, and the same public statistics the attack gets. Assign keywords to tokens by hand, score yourself, then let the machine try the same puzzle.
6. **SSE, ORAM, FHE** — what each hides and what each costs. The SSE latency column is measured in your browser on this vault; the ORAM and FHE columns are labelled as cited, order-of-magnitude figures, because this page runs neither.

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

---

## Live Demo

https://systemslibrarian.github.io/crypto-lab-search-vault/

You can: step the index build for any of the 14 keywords; search real and non-existent keywords and watch the server's log fill; observe a realistically skewed round of queries; read the three leakage views; run both attacks at any level of adversary background-knowledge error; try to deanonymise the tokens yourself and be scored against the machine; and time 50 real searches in your own browser.

---

## What Can Go Wrong

- **Access-pattern leakage is not a footnote.** With exact background statistics, the attack in Exhibit 4 recovers all 14 queries in tens of milliseconds. Even with the adversary's statistics degraded well past realistic error, most tokens still fall.
- **Volume leakage is enough on its own.** Any keyword whose document count is unique in the vocabulary is identified by result size, with no co-occurrence analysis at all. Padding result sets is the standard countermeasure, and it costs storage and bandwidth.
- **Deterministic tokens link queries over time.** The server cannot read a token, but it recognises every repeat, so it can build a per-user query-frequency profile and line it up against public word-frequency data.
- **The background-knowledge assumption is weaker than it sounds.** The adversary needs statistics for a *similar* corpus, not yours — leaked archives, public filings, and comparable organisations all supply them.
- **A static index hides an ongoing hazard.** This demo builds the index once. Adding documents later leaks whether a new document matches an earlier query unless the scheme is explicitly forward-private.
- **Tampering fails closed, and that is deliberate.** Each posting is sealed with its own address as associated data, so a server that relocates, forges or flips a row causes the whole result to be rejected rather than silently mis-answered. Six tests cover this path.

---

## Real-World Usage

Searchable encryption is what gets deployed when fully homomorphic encryption is too slow, which is nearly always. Variants appear in encrypted-database products, encrypted-search appliances, and client-side-encrypted note and mail services that still offer a search box. The academic line runs Song–Wagner–Perrig (2000) → Curtmola et al.'s SSE-CKA security definitions (2006) → the OXT conjunctive scheme of Cash–Jarecki–Jutla–Krawczyk–Roşu–Steiner (2013) → the leakage-abuse attacks that reshaped the field's expectations (Islam–Kuzu–Kantarcioglu 2012, Cash–Grubbs–Perry–Ristenpart 2015) → forward- and backward-private dynamic schemes designed in their wake.

The lasting lesson is the one this demo is built around: for SSE, **the leakage profile is the security model.** A scheme is not "secure" or "insecure" in the abstract — it is secure *relative to a stated leakage function*, and whether that leakage is acceptable is a question about your data and your adversary, not about the cryptography.

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

---

## Build & Verify

**77 unit tests**, all passing, run by `npm test` and gating the deploy.

**11 specification known-answer vectors:**

| File | Vectors |
| --- | --- |
| `src/core/prf.test.ts` | 6 × HMAC-SHA-256 from RFC 4231 §4 (cases 1, 2, 3, 4, 6, 7) |
| `src/core/prf.test.ts` | 3 × SHA-256 from FIPS 180-4 (empty, `"abc"`, the 448-bit two-block message) |
| `src/core/aead.test.ts` | 2 × AES-256-GCM from the GCM specification's vector set (test cases 13 and 14), checked in both directions |

Beyond the KATs, the suite covers: index construction (one posting per keyword–document pair, distinct pseudorandom addresses, no two identical ciphertexts); search correctness for every keyword in the corpus; the miss path for unindexed keywords and random tokens; six fail-closed cases (flipped ciphertext, tampered IV, wrong key, truncated blob, relocated posting, forged posting); what the server's ledger does and does not record; the leakage computations — including a proof-shaped check that the observed co-occurrence matrix is *identical* to the plaintext one, and a colour-refinement check that no two keywords in the corpus are information-theoretically interchangeable; and the attacks — full recovery with exact background knowledge, graceful degradation under noise, determinism under a fixed seed, and refusal on malformed input.

**Functional browser gate:** `e2e/claims.spec.ts` drives the production build and asserts the numbers each exhibit puts on screen — against each other, not against constants. The 14 per-keyword row counts must sum to the store's own total; the search verdict's document set must be the set the client decrypted, the set the server says it sent, and the set in the ledger row; the exposure percentage must be the touched/total the summary itself reports, and the histogram's per-token query counts must partition the query total; the attack's headline must be the tally of its own per-token table, with the count-attack figure matching the rows it labelled; the challenge score must equal the rows it marked recovered; and the measured latency must be the measured total over the measured run count. Every failure path is asserted to reach its state *and* name its cause — the miss path, the empty query, the attack with nothing to attack, the board with nothing to work with. Uncaught page exceptions fail the run.

**Accessibility gate:** `@axe-core/playwright` scans the production build for WCAG 2.1 A/AA violations in **both themes**, across four scans — every exhibit driven to its post-interaction state, and the empty/miss states that are the other branch of each conditional render. Zero violations required; a regression blocks the deploy.

---

## Performance

Search is fast because SSE lets the server do an ordinary index lookup: the work is proportional to the number of matching documents, not the size of the database. Exhibit 6 measures it live — 50 full searches, each covering token derivation, address probing, AES-GCM posting decryption and document fetch — and reports the per-search figure for your browser. On a modern laptop it lands in the low single-digit milliseconds.

The attacks are comparably cheap: the count attack is a table lookup, and the IKK annealing (8 restarts × 12,000 iterations, plus a greedy polish) resolves 14 tokens in tens of milliseconds. Being cheap to attack is the point.

---

*One of 170+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
