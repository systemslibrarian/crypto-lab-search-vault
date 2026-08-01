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
      el('li', {}, 'The count attack and the IKK simulated-annealing attack, run against that log with no access to keys or plaintext.'),
      el('li', {}, 'Keys are generated per session with crypto.getRandomValues and held in memory only. Nothing is persisted; nothing leaves the browser.'),
    ),

    el('h3', { text: 'Scaled down' }),
    el(
      'ul',
      { class: 'nongoals' },
      el('li', {}, `The corpus is ${CORPUS.length} short documents and ${KEYWORDS.length} keywords so the attack finishes while you watch. Real leakage-abuse studies run over tens of thousands of documents and thousands of keywords.`),
      el('li', {}, 'The client and the server are two objects in one page. There is no network, so nothing here measures network-level leakage — and a real deployment leaks timing and message sizes too.'),
      el('li', {}, 'The adversary’s “background knowledge” is derived from this same corpus. Setting the error slider above zero is the honest setting; zero is the strongest possible assumption.'),
    ),

    el('h3', { text: 'What this does NOT prove' }),
    el(
      'ul',
      { class: 'nongoals' },
      el('li', {}, 'It does not prove SSE is broken. It shows that this leakage profile — access pattern, volume and search pattern, with no padding and a static index — is invertible given background knowledge.'),
      el('li', {}, 'It does not prove the attack works at deployment scale on any particular system. Published results vary widely with corpus, vocabulary and how much the adversary really knows.'),
      el('li', {}, 'It proves nothing about the security of AES-GCM or HMAC-SHA-256. Neither was attacked; both held throughout.'),
      el('li', {}, 'A recovery of 100% at zero background-knowledge error is a property of an exact-statistics adversary, not a claim about the real world.'),
    ),

    el('h3', { text: 'Deliberately out of scope' }),
    el(
      'ul',
      { class: 'nongoals' },
      el('li', {}, el('strong', { text: 'Dynamic SSE with forward and backward privacy. ' }), 'This index is static — built once, never updated. Adding documents later leaks whether a new document matches an old query unless the scheme is designed to prevent it, which is what forward privacy means.'),
      el('li', {}, el('strong', { text: 'Multi-keyword boolean queries. ' }), 'Single-keyword lookup only. Conjunctive search (OXT, Cash–Jarecki–Jutla–Krawczyk–Roşu–Steiner 2013) has its own richer leakage profile.'),
      el('li', {}, el('strong', { text: 'CryptDB-style encrypted SQL. ' }), 'No query rewriting, no order-preserving or deterministic column encryption — a different design with a different, larger leakage surface.'),
      el('li', {}, el('strong', { text: 'Volume-hiding SSE. ' }), 'Nothing here pads result sets to a common size, so result size leaks exactly. Padding is the standard countermeasure to the count attack, and it costs storage and bandwidth.'),
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
