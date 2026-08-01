import { el } from './dom';

/** The plain-language on-ramp: zero math, before any hex appears on the page. */
export function renderIntro(): HTMLElement {
  const glossary: Array<[string, string]> = [
    [
      'Searchable symmetric encryption (SSE)',
      'A way to store encrypted files on a server you do not trust and still ask it "which files mention this word?" — without telling it the word.',
    ],
    [
      'Keyword token',
      'A 32-byte value the client computes from the keyword and its secret key. It looks like random noise. The server can use it to find matching files and can do nothing else with it.',
    ],
    [
      'Inverted index',
      'The lookup table a search engine keeps: for each word, the list of documents containing it. Here every entry is encrypted and every label is scrambled.',
    ],
    [
      'Access pattern',
      'Which documents came back for a query. The server sees this because it has to hand those documents over — even though it never learns the keyword.',
    ],
    [
      'Leakage',
      'Information a scheme reveals by design, on top of what it is meant to hide. SSE deliberately trades some leakage for speed.',
    ],
    [
      'Leakage-abuse attack',
      'Turning that leakage back into the secret. Given enough observed queries and some public statistics, an attacker can work out which keyword each token was.',
    ],
  ];

  return el(
    'section',
    { class: 'panel intro-panel', 'aria-labelledby': 'h-what-is-this' },
    el('span', { class: 'panel-num', text: 'START HERE' }),
    el('h2', { id: 'h-what-is-this', text: 'What is searchable encryption, and why does it matter?' }),
    el(
      'p',
      {},
      'Suppose you keep your company files on a server you do not control. Encrypting them is easy. ' +
        'Searching them is the hard part: normally the server has to read your files to find the ones mentioning "layoff", ' +
        'and reading them is exactly what you were trying to prevent.',
    ),
    el(
      'p',
      {},
      'Searchable encryption is the compromise that actually ships. You hand the server a scrambled lookup table, and when you ' +
        'want to search you send a 32-byte token instead of a word. The server finds the matching files and hands them back — ' +
        'never learning the word you searched for, and never being able to read a file.',
    ),
    el(
      'p',
      {},
      'That sounds airtight. It is not, and the gap is the whole point of this demo: the server does see ',
      el('strong', { text: 'which documents matched' }),
      '. Do that a few dozen times and the pattern of overlapping result sets is a fingerprint. Published attacks turn that ' +
        'fingerprint back into your queries — sometimes into your data. You will run one of those attacks yourself, further down.',
    ),
    el(
      'p',
      { class: 'honesty' },
      'Not production crypto — a teaching demo. Every value you see is real: HMAC-SHA-256 and AES-256-GCM through the ' +
        'browser’s WebCrypto, keys generated per session and never stored. What is scaled down is the corpus (24 documents, ' +
        '14 keywords), so the attack finishes while you watch.',
    ),
    el(
      'details',
      {},
      el('summary', { text: 'Glossary — the six words you need for the rest of the page' }),
      el(
        'dl',
        {},
        ...glossary.flatMap(([term, def]) => [
          el('dt', { text: term, style: 'font-weight:600;margin-top:.5rem' }),
          el('dd', { text: def, style: 'margin:.15rem 0 0 1rem' }),
        ]),
      ),
    ),
  );
}
