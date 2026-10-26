/** Honest scoping: what is real, what is not, what this does not prove. */
import { el, panel } from './dom';
import { CORPUS, KEYWORDS } from '../sse/corpus';

export function renderScope(): HTMLElement {
  const { section, body } = panel(
    'SCOPE',
    'What is real here, and what this does not prove',
    'The standard this demo is built to requires saying both plainly.',
  );

  body.append(
    el('h3', { text: 'Real' }),
    el(
      'ul',
      { class: 'nongoals' },
      el('li', {}, 'HMAC-SHA-256 (RFC 2104 / FIPS 198-1) via WebCrypto for every token, address and derived key — verified against the RFC 4231 vectors in the test suite.'),
      el('li', {}, 'AES-256-GCM (NIST SP 800-38D) via WebCrypto for every posting and document body, with the address bound in as associated data — verified against the GCM specification vectors.'),
      el('li', {}, `The encrypted inverted index itself: ${KEYWORDS.length} keywords over ${CORPUS.length} documents, built and searched exactly as described.`),
      el('li', {}, 'The server’s query log — written by the code path that answers the query, so it records what a real server would genuinely observe.'),
      el('li', {}, 'The query-integrity exercise builds client-retained checkpoints from the encrypted snapshot that was actually produced: snapshot id, expected answer count and a SHA-256 digest over the complete ordered encrypted answer. Its dishonest-server cases alter only copied replies; the normal SearchServer remains honest-but-curious.'),
      el('li', {}, 'The count attack and the IKK simulated-annealing attack, run against that log with no access to keys or plaintext.'),
      el('li', {}, 'The bounded two-term OXT lesson uses independent keys, HMAC-SHA-512-to-scalar derivation, canonical RFC 9496 ristretto255 operations, a globally shuffled flat TSet, exact XSet membership, and real AES-GCM identifier ciphertexts. Its naïve comparison runs two actual searches through an isolated copy of the existing SSE implementation.'),
      el('li', {}, 'The PEKS extension runs the Type-3 BLS12-381 pairing equation with RFC 9380 hash-to-curve, randomized public-key tags, recipient trapdoors, full server Test scans, and a bounded offline keyword-guessing attack.'),
      el('li', {}, 'The fuzzy extension runs the existing exact SSE route beside Li et al.’s Algorithm 2 deletion-gram listing shape. HMAC-SHA-256 produces every opaque gram trapdoor, AES-256-GCM binds every encrypted keyword/document-list payload to its trapdoor, and a separately implemented Levenshtein oracle filters candidates and scores the bounded result.'),
      el('li', {}, 'The multi-user extension instantiates Van Rompay–Molva–Önen’s delegation equation over BLS12-381 and executes the iterative-testing keyword-access-pattern graph, 128-bit zero-sum garbled Bloom-filter shares, packed Paillier selection arithmetic, AES-256-GCM writer-id envelopes, response sanitization and shuffling. Its plaintext oracle is kept separate from both server views.'),
      el('li', {}, 'Keys are generated per session with crypto.getRandomValues and held in memory only. Nothing is persisted; nothing leaves the browser.'),
    ),

    el('h3', { text: 'Scaled down' }),
    el(
      'ul',
      { class: 'nongoals' },
      el('li', {}, `The corpus is ${CORPUS.length} short documents and ${KEYWORDS.length} keywords so the attack finishes while you watch. Real leakage-abuse studies run over tens of thousands of documents and thousands of keywords.`),
      el('li', {}, 'The client and the server are two objects in one page. There is no network, so nothing here measures network-level leakage — and a real deployment leaks timing and message sizes too.'),
      el('li', {}, 'Exact-statistics mode is a favorable attacker control derived from the target. Its slider adds synthetic jitter, not realistic error. Other modes use independently sampled modeled corpora; they are educational sensitivity experiments.'),
      el('li', {}, 'The completeness checkpoint deliberately keeps per-query client metadata for one static snapshot. That is enough to expose the difference between authentic records and a complete, fresh answer, but it is not a scalable or general verifiable-search protocol.'),
      el('li', {}, 'The OXT implementation is a static two-term teaching adapter over 24 documents and 14 keywords. Its flat addressed TSet is not the optimized TSet from the paper, and the exact XSet replaces the paper’s probabilistic-filter choice.'),
      el('li', {}, 'The OXT client, search server, and narrator are objects in one browser tab. It models one trusted owner and an honest-but-curious server, not process isolation, multiple owners, collusion, dynamic updates, or constant-time JavaScript. Its final access evidence records requested document identifiers; a separate encrypted body store is not executed.'),
      el('li', {}, 'The Path ORAM comparison derives transfer counts; it does not run ORAM. It assumes one document per block, Z=4, a separate non-colluding semi-honest storage server, a client position map and stash, and a fixed three-fetch result envelope.'),
      el('li', {}, 'The PEKS recipient, public sender, server, and attacker are separate objects co-located in one browser tab. Their inputs are separated in code, but no production network or process isolation is modeled.'),
      el('li', {}, 'The fuzzy route is three alternative static indexes over 14 ASCII keywords at thresholds 0, 1, and 2. Its displayed storage counts include 32-byte trapdoors and the AES-GCM payload blobs held by this adapter, not JavaScript object overhead, document bodies, a trie, or deployment-scale timing.'),
      el('li', {}, 'The MUSE route has three writers, three readers and two keywords per writer. Its browser-generated 1024-bit Paillier modulus is deliberately below a production parameter, and its 64-slot ZGBF is an observable teaching instance whose measured false positives are reported rather than hidden.'),
    ),

    el('h3', { text: 'What this does NOT prove' }),
    el(
      'ul',
      { class: 'nongoals' },
      el('li', {}, 'It does not prove SSE is broken. It shows that this leakage profile — access pattern, volume and search pattern, with no padding and a static index — is invertible given background knowledge.'),
      el('li', {}, 'It does not prove the attack works at deployment scale on any particular system. Published results vary widely with corpus, vocabulary and how much the adversary really knows.'),
      el('li', {}, 'It proves nothing about the security of AES-GCM or HMAC-SHA-256. Neither was attacked; both held throughout.'),
      el('li', {}, 'A recovery of 100% at zero background-knowledge error is a property of an exact-statistics adversary, not a claim about the real world.'),
      el('li', {}, 'The checkpoint exercise does not prove this SSE construction is verifiable in production. It assumes the client already retained a trusted current snapshot reference and the exact expected encrypted answer commitment.'),
      el('li', {}, 'OXT algebraic correctness and honest-server exact membership do not prove the full OXT security theorem for this adapter, result soundness/correctness, completeness or freshness against an active server, or that zero repeated candidate points means two x-terms differ. An active server can omit a valid match or return an authentic s-list row that failed the x-term test, and the static adapter has no version proof. RFC 9496 specifies ristretto255; DDH hardness is a separate explicit assumption.'),
      el('li', {}, 'The Path ORAM arithmetic does not hide the OXT search server’s stag, s-list size, membership-test pattern, equality/intersection evidence, volume, or timing. It models block transfers, not network round trips, and omits recursive position maps, stash overflow, and active integrity.'),
      el('li', {}, 'PEKS pairing correctness does not prove the Type-3 adaptation inherits the original symmetric-pairing BDH reduction. No formal reduction, chosen-ciphertext security, trapdoor privacy, sender authentication, or distribution hiding is claimed.'),
      el('li', {}, 'Failure of a bounded PEKS dictionary does not prove a trapdoor is safe. It means only that no candidate tested within that declared bound passed public Test.'),
      el('li', {}, 'A gram candidate is not automatically an edit-distance neighbor. The client must decrypt and filter it; the candidate false-positive and false-negative rates shown here are exact only for the displayed word, threshold, and 14-keyword vocabulary. Zero final error in this bounded run is not a universal EFSE guarantee.'),
      el('li', {}, 'The known-anchor control establishes only that deterministic fuzzy bundles reveal more neighborhood structure than one exact token under its declared outside-label assumption. It does not recover arbitrary plaintext, transfer Li et al.’s proof to this adapter, reproduce later inference attacks, or show that every fuzzy-search construction leaks the same relation.'),
      el('li', {}, 'MUSE pairing correctness and the observed separation of QM and DH views do not transfer the SCC 2018 simulation proof to this Type-3/browser/Paillier adaptation. Result length still leaks to QM; authorization is public; malicious parties, revocation, dynamic indexes and network/process isolation are not established.'),
      el('li', {}, 'The split-trust route is not safe if QM and DH collude. The combined-view table deliberately reconstructs response positivity by writer to make that assumption executable. A user colluding with one service role is not the same adversary as both service roles colluding together.'),
    ),

    el('h3', { text: 'Deliberately out of scope' }),
    el(
      'ul',
      { class: 'nongoals' },
      el('li', {}, el('strong', { text: 'Dynamic SSE with forward and backward privacy. ' }), 'This index is static — built once, never updated. Adding documents later leaks whether a new document matches an old query unless the scheme is designed to prevent it, which is what forward privacy means.'),
      el('li', {}, el('strong', { text: 'Boolean queries beyond two-term conjunctions. ' }), 'The OXT lesson accepts exactly two known, distinct terms joined by AND. OR, NOT, parentheses, ranked results, three-or-more terms, and dynamic updates are not implemented. The original OXT work supports a broader class than this bounded adapter.'),
      el('li', {}, el('strong', { text: 'CryptDB-style encrypted SQL. ' }), 'No query rewriting, no order-preserving or deterministic column encryption — a different design with a different, larger leakage surface.'),
      el('li', {}, el('strong', { text: 'Volume-hiding SSE. ' }), 'Nothing here pads result sets to a common size, so result size leaks exactly. Padding is the standard countermeasure to the count attack, and it costs storage and bandwidth.'),
      el('li', {}, el('strong', { text: 'Advanced PEKS variants. ' }), 'No designated-tester, authenticated-sender, conjunctive, fuzzy, dynamic, or multi-user PEKS construction is implemented.'),
      el('li', {}, el('strong', { text: 'Other approximate-search models. ' }), 'No adjacent-transposition shortcut, Unicode grapheme distance, semantic similarity, ranking, wildcard trie, Bloom-filter fuzzy index, locality-sensitive hash, ORAM wrapper, dynamic fuzzy index, or malicious-server result proof is implemented.'),
      el('li', {}, el('strong', { text: 'Full optimized MUSE. ' }), 'The multi-user lesson omits recursive OT, in-line ZGBF, deployment parameter selection, malicious-party proofs, writer/reader revocation, updates, conjunctive search and the complete SCC 2018 protocol proof. Rekey Relay remains a separate PRE lab; PRE by itself is not a MUSE construction.'),
    ),

    el(
      'details',
      {},
      el('summary', { text: 'Where this would grow next (extension seams)' }),
      el(
        'ul',
        { class: 'nongoals' },
        el('li', {}, 'Address derivation is already keyed by a per-keyword token and a counter — a forward-private scheme adds a per-update state to that derivation, which is the marked seam in the client.'),
        el('li', {}, 'The server’s ledger is a list of observations; a volume-hiding variant changes what goes into it rather than how it is read, so the leakage views survive unchanged.'),
        el('li', {}, 'The attack takes a co-occurrence matrix and a candidate list. A different leakage-abuse attack (for instance the CGPR attack on partially known documents) drops into the same interface.'),
      ),
    ),

    el('p', { class: 'honesty' }, 'Not production crypto — a teaching demo.'),
  );

  return section;
}
