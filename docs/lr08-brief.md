# L-R-08 implementation brief — multi-user search and collusion

Date: 2026-10-26

## Sources reviewed

The lesson is grounded in two primary sources by Cédric Van Rompay, Refik
Molva, and Melek Önen:

- *A Leakage-Abuse Attack Against Multi-User Searchable Encryption*,
  Proceedings on Privacy Enhancing Technologies 2017(3), pp. 168–178,
  DOI 10.1515/popets-2017-0034. The implementation uses §§3.1–3.2 and Figure 2
  for the reader/writer authorization graph, iterative-testing transcript,
  keyword-access-pattern equivalence classes, and known-query propagation; it
  uses §§4.1–4.2 for the distinction between ordinary access-pattern leakage
  and `L_KWAP`. The reviewed final PDF was created 2017-06-27 and has SHA-256
  `d3bec78d1a663e51f3cab866aeb9f3ad37ea23c5e59346036055edca5a5acefa`.
- *Secure and Scalable Multi-User Searchable Encryption*, SCC 2018,
  DOI 10.1145/3201595.3201597, also IACR ePrint 2018/090. The implementation
  uses §§2–3 for roles, correctness, leakage and response unlinkability; §§4.1,
  4.2 and 4.3 for pairings, zero-sum garbled Bloom filters and the
  additively-homomorphic selector shape; §5 for key generation, delegation,
  blinded query transformation, data-host processing and reader opening; and
  §6.3 for packing several selected Bloom-filter shares into one response. The
  reviewed author-hosted final PDF was created 2018-05-18 and has SHA-256
  `8f96a3a90089d57c25bbfcd305aed8f653bbda0a1e3eb3cca03893e9f4dc972b`.

The 2018 paper's complete construction and proofs are the authority for the
role split. The code below is a bounded adaptation, not a claim to reproduce
the paper's full optimized protocol or to inherit its proof.

## Why Search Vault owns the lesson

Search Vault already owns executable exact-search leakage, role-separated
public-key search, BLS12-381 pairings, browser claim tests and a clean-baseline
mutation gate. Rekey Relay remains a useful conceptual bridge for delegated
key transformation, but proxy re-encryption alone neither defines searchable
indexes nor prevents the keyword-access-pattern attack. Implementing this item
in Search Vault avoids presenting PRE as a MUSE construction.

## Executed single-server model

There are distinct writer and reader principals. Each writer chooses a nonzero
scalar `gamma_w` and stores one independently keyed encrypted index. Each
reader chooses nonzero `rho_r`, publishes `P2^(1/rho_r)`, and keeps `rho_r`.
For a writer-authorized reader:

```text
I_w(x)     = e(H(x), P2^gamma_w)
Delta_r,w  = (P2^(1/rho_r))^gamma_w
T_r(q)     = H(q)^rho_r
Test token = e(T_r(q), Delta_r,w) = I_w(q)
```

`H` is RFC 9380 hash-to-BLS12-381-G1 under an L-R-08-only domain. The server
tests every encrypted keyword in every requested authorized index and records
the exact matching opaque row. This is the iterative-testing structure from
the 2017 paper; it is not random ciphertext corruption and not an attack on
the pairing primitive.

The fixed teaching graph includes one colluding reader who is authorized for
writer A but not writer B, and one target reader authorized for both. A known
`audit` query by the colluder labels A's matching row. The target's later query
connects that row to B's matching row, so the server labels both the target
query and data outside the colluder's own authorization. The attack receives
only server transcript nodes, equality edges, and the colluder's declared
query label; its interface has no reader secret, writer secret, hidden query,
or plaintext index.

## Executed split-trust adaptation

The defensive route follows the 2018 paper's Query Multiplexer (`QM`) and Data
Host (`DH`) split:

1. A reader samples fresh nonzero `xi`, sends `H(q)^(xi*rho_r)` to QM, and
   sends `xi` to DH.
2. QM applies each authorization with a real pairing, obtaining
   `e(H(q),P2)^(xi*gamma_w)`, then maps that value to three ZGBF positions.
3. DH raises each writer's stored GT token to `xi` and builds that query's
   zero-sum garbled Bloom filter from the resulting values.
4. QM asks for all three shares with one packed Paillier selector vector. DH
   evaluates the encrypted linear selection, adds a fresh encryption of zero,
   encrypts the writer id under the reader's AES-256-GCM key, and shuffles all
   responses.
5. QM decrypts only packed Bloom shares, keeps zero-XOR responses, and forwards
   opaque encrypted writer ids. Only the reader opens those ids.

The ZGBF uses 128-bit XOR shares and three domain-separated SHA-256 positions.
The browser route uses a freshly generated 1024-bit Paillier modulus so the
exercise remains responsive. That modulus is intentionally non-production;
no computational-security level is claimed. Paillier supplies real
additively-homomorphic arithmetic, but this adapter does not reproduce
Lipmaa/Stern's complete OT proof, recursive OT, in-line ZGBF, malicious-party
security, or the SCC paper's optimized parameter selection. It implements the
specified honest-but-curious dataflow and exposes every retained assumption.

## Views and collusion boundaries

- The single server sees writer identity, matching row identity and query
  linkage. A colluding reader's one known label propagates through the equality
  graph to another reader and an unauthorized writer index.
- QM sees public authorizations, blinded reader trapdoors, its own selector
  ciphertexts, sanitized shuffled responses and result length. Fresh `xi`
  changes the same keyword's transformed bytes on every query.
- DH sees index ownership, encrypted index values, `xi`, selector ciphertexts
  and one uniformly shaped response per authorized writer. It does not hold
  the Paillier decryption key and does not learn which positions were selected
  or which responses were positive.
- The reader sees the final writer ids. The omniscient teaching oracle that
  checks those ids against plaintext is separate from every attacker view.
- Collusion of a user with either QM or DH is the intended comparison.
  Collusion between QM and DH is explicitly outside the construction: their
  combined views recover the selected positions and index association, so the
  lab must show this failure boundary rather than hide it.

The lesson does not claim that equal result lengths are unlinkable; QM is
allowed to learn result length in the 2018 leakage profile. It distinguishes
that leakage from the matching-row equality edges required by the
keyword-access-pattern attack.

## Required operations and controls

- one writer upload and one reader search succeed only under the declared
  role and authorization;
- a reader upload, writer query, and query naming any unauthorized index are
  rejected before an encrypted-search transcript is recorded;
- the single-server attack labels the target query and writer B's `audit` row
  from the colluding reader's one known `audit` query;
- changing the target query breaks that equality path rather than reading the
  hidden target keyword;
- the split-trust route returns an independently verified result set while QM
  and DH views omit the forbidden match labels;
- repeated split-trust searches for the same keyword use different blinded
  trapdoor and selector bytes;
- sanitization and shuffling are explicit trace parameters; a unit control
  disables both and confirms deterministic response order without pretending
  that this bounded observation is the paper's response-unlinkability proof;
- combining QM and DH views reconstructs the association, explicitly testing
  the non-collusion assumption;
- malformed group encodings, zero scalars, malformed selectors, authorization
  substitution, out-of-range Paillier ciphertext encodings and encrypted-id
  tampering fail closed; valid Paillier malleability remains outside the
  honest-but-curious model and is not mislabeled as detected;
- a clean-baseline mutation gate removes or corrupts owning constraints and
  each named test fails before exact source restoration.

## Explicit non-claims

This is a three-writer, three-reader, static exact-keyword lesson. It is not a
production MUSE deployment, dynamic SSE, ORAM, ranked search, conjunctive
search, malicious-server proof, network/process isolation, revocation system,
full SCC 2018 implementation, or proof that 1024-bit Paillier is secure. The
paper's honest-but-curious and QM/DH non-collusion assumptions remain visible.
Algebraic correctness and passing controls do not transfer the paper's full
simulation proof to this Type-3/browser/Paillier adaptation.
