/** Shared shapes for the searchable-encryption vault. */

export interface Document {
  id: string;
  title: string;
  body: string;
  keywords: string[];
}

/** The three independent keys the client holds. They never leave the browser
 *  and are never persisted — a reload generates a fresh vault. */
export interface VaultKeys {
  /** derives search tokens t_w = F(kPrf, w) — the only value the server sees */
  kPrf: Uint8Array;
  /** derives per-keyword posting keys k_w = F(kEnc, w) */
  kEnc: Uint8Array;
  /** derives per-document body keys k_d = F(kDoc, id) */
  kDoc: Uint8Array;
}

/** One row of the encrypted inverted index, exactly as the server holds it:
 *  a pseudorandom label and an authenticated ciphertext. Nothing else. */
export interface IndexRow {
  address: string;
  value: Uint8Array;
}

/** What the client can show a learner while building one posting — the whole
 *  point of the build exhibit is that every one of these is a real value. */
export interface BuildStep {
  keyword: string;
  counter: number;
  docId: string;
  tokenHex: string;
  /** the per-keyword posting key — real bytes, and the one value never sent */
  postingKeyHex: string;
  addressHex: string;
  valueHex: string;
}

export interface EncryptedVault {
  index: IndexRow[];
  documents: Array<{ id: string; blob: Uint8Array }>;
}

/** One line of the server's leakage ledger: what an honest-but-curious server
 *  genuinely observes per query, and nothing it does not. */
export interface QueryObservation {
  seq: number;
  tokenHex: string;
  /** result size — "volume leakage" */
  resultSize: number;
  /** which document identifiers were returned — "access pattern leakage" */
  resultIds: string[];
}
