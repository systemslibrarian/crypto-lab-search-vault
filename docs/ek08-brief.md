# E-K-08 implementation brief — gram-based fuzzy search

Date: 2026-10-26

## Source and construction

The lesson implements a bounded adaptation of Jin Li, Qian Wang, Cong Wang,
Ning Cao, Kui Ren, and Wenjing Lou, *Enabling Efficient Fuzzy Keyword Search
over Encrypted Data in Cloud Computing*, IACR ePrint 2009/593 (the INFOCOM
2010 paper), using the ePrint revision dated 2009-12-04.

The parts used are:

- §3.4 for Levenshtein edit distance and the fuzzy-search result definition;
- §4.2, Algorithm 2 for the gram set made from every relative-order-preserving
  subsequence obtained by deleting at most `d` characters;
- §5.1 for the keyed-trapdoor listing route and client-side filtering;
- §6, especially Theorem 2, for completeness and the explicit warning that
  the gram route can return false positives; and
- §6's `Trace` definition for the server-visible equality matrix: two fuzzy
  queries are linked when any trapdoor in their bundles matches.

The paper's implementation uses SHA-1-sized trapdoors and presents several
server data structures. This lesson uses HMAC-SHA-256 trapdoors and an exact
map lookup, then binds independently randomized AES-256-GCM payloads to their
trapdoor as associated data. That is an engineering adaptation of the paper's
gram-set listing idea, not a claim to reproduce its trie, proof, performance,
or complete deployment model.

## Bounded model

- The fixed vocabulary is Search Vault's 14-keyword, 24-document corpus.
- Inputs are lowercase ASCII letters after case/outer-whitespace normalization.
- Thresholds are exactly 0, 1, and 2. Each table row is an alternative index;
  their storage totals are not added together.
- For threshold `d`, both the stored keyword and query use all deletion grams
  from 0 through `d`, as in Algorithm 2.
- The server receives only deterministic 32-byte trapdoors and encrypted
  payload rows. The client decrypts candidate keywords, computes the real
  Levenshtein distance, and discards gram collisions outside the threshold.
- Candidate false-positive and false-negative rates classify unique decrypted
  keyword candidates against an independently computed plaintext Levenshtein
  oracle. Final-document false-positive and false-negative rates separately
  compare the post-filter access request with all 24 corpus documents. Neither
  layer is an estimate for another corpus.

## Leakage exercise

The server retains three prior fuzzy-query bundles whose labels became known
out of band: `audit`, `lawsuit`, and `breach`. Its inference function receives
only those labels, the prior exact/fuzzy tokens, and the new exact/fuzzy tokens;
it receives no key, query text, keyword list, plaintext result, or edit distance.
It compares exact-token equality with fuzzy-bundle intersection. With the
default query `asudit` and threshold 1, exact SSE links none of the three known
queries while the fuzzy bundle overlaps the known `audit` bundle.

Those anchor bundles are sent through the same isolated exact and fuzzy server
query boundaries during lesson initialization and retained as opaque bytes.
Only the later control associates the declared outside-context labels with
those observations; neither server query receives a label or plaintext gram.

This establishes one concrete extra inference under the declared known-query
anchor assumption. It does not establish plaintext recovery in general, and it
does not say that all encrypted fuzzy-search schemes expose the same pattern.

## Required controls

- `asudit`, threshold 1: `audit` is the one true candidate and final keyword.
- `asudit`, threshold 2: `audit` remains true; `lawsuit` is a gram collision
  whose edit distance is 3 and must be filtered.
- threshold 0: the typo has no result and no anchor overlap.
- every true neighbor in the bounded corpus must occur among server candidates;
  the client-filtered result must equal the plaintext oracle.
- invalid input is rejected before either comparison server receives a query.
- changed input or threshold retires prior learner-visible evidence.
- tampered or relocated encrypted rows fail closed under AES-GCM.

## Explicit non-claims

This is not the paper's symbol trie, not LSH, not ranked or semantic search,
not transposition distance, not PEKS, not multi-user search, not a dynamic
index, and not a production security or performance claim. HMAC hides gram
contents from an observer without the key; it does not hide deterministic
bundle equality, bundle size, matching-row volume, or the final access request.
