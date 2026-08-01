/**
 * The client half of an inverted-index SSE scheme in the Song–Wagner–Perrig /
 * Curtmola–Garay–Kamara–Ostrovsky (SSE-1) style. Everything secret lives here;
 * the server (server.ts) only ever holds pseudorandom labels and AES-GCM blobs.
 *
 * For keyword w and its i-th matching document:
 *
 *   t_w    = HMAC(kPrf, "token"   ‖ w)          32 bytes — the search token
 *   k_w    = HMAC(kEnc, "posting" ‖ w)          32 bytes — the posting key
 *   addr_i = HMAC(t_w,  "address" ‖ i)          the index label
 *   val_i  = AES-256-GCM(k_w, docId, aad=addr_i)
 *
 * The server can recompute addr_i for i = 0,1,2,… once it is handed t_w — and
 * for no other keyword. Binding addr_i in as associated data means a posting
 * relocated to a different label fails to open: fail-closed, not silently wrong.
 */
import { seal, open } from '../core/aead';
import { fromUtf8, toHex, u32be, utf8, randomBytes } from '../core/bytes';
import { DOMAIN, prf } from '../core/prf';
import { CORPUS, documentsFor } from './corpus';
import type { BuildStep, Document, EncryptedVault, IndexRow, VaultKeys } from './types';

/** Fresh 256-bit keys, in memory only. Nothing here is ever written to
 *  localStorage, cookies, or the network — reload and the vault is gone. */
export function generateKeys(): VaultKeys {
  return { kPrf: randomBytes(32), kEnc: randomBytes(32), kDoc: randomBytes(32) };
}

export async function searchToken(keys: VaultKeys, keyword: string): Promise<Uint8Array> {
  return prf(keys.kPrf, DOMAIN.TOKEN, utf8(normalize(keyword)));
}

export async function postingKey(keys: VaultKeys, keyword: string): Promise<Uint8Array> {
  return prf(keys.kEnc, DOMAIN.POSTING_KEY, utf8(normalize(keyword)));
}

export async function documentKey(keys: VaultKeys, docId: string): Promise<Uint8Array> {
  return prf(keys.kDoc, DOMAIN.DOC_KEY, utf8(docId));
}

/** addr_i under a token. Keyed by the *token*, so holding t_w is exactly the
 *  capability to enumerate that keyword's postings and nothing more. */
export async function addressFor(token: Uint8Array, counter: number): Promise<Uint8Array> {
  return prf(token, DOMAIN.ADDRESS, u32be(counter));
}

/** Build the whole encrypted index and the encrypted document bodies. */
export async function buildVault(
  keys: VaultKeys,
  corpus: Document[] = CORPUS,
): Promise<{ vault: EncryptedVault; steps: BuildStep[] }> {
  const keywords = [...new Set(corpus.flatMap((d) => d.keywords))].sort();
  const rows: IndexRow[] = [];
  const steps: BuildStep[] = [];

  for (const w of keywords) {
    const token = await searchToken(keys, w);
    const kw = await postingKey(keys, w);
    const ids = documentsFor(w, corpus);
    for (let i = 0; i < ids.length; i++) {
      const address = await addressFor(token, i);
      const addressHex = toHex(address);
      const value = await seal(kw, utf8(ids[i]!), address);
      rows.push({ address: addressHex, value });
      steps.push({
        keyword: w,
        counter: i,
        docId: ids[i]!,
        tokenHex: toHex(token),
        postingKeyHex: toHex(kw),
        addressHex,
        valueHex: toHex(value),
      });
    }
  }

  const documents = await Promise.all(
    corpus.map(async (d) => ({
      id: d.id,
      blob: await seal(await documentKey(keys, d.id), utf8(`${d.title}\n${d.body}`)),
    })),
  );

  // Hand the rows over in a keyword-independent order. Insertion order would
  // otherwise cluster each keyword's postings together — free structure the
  // server did not have to work for.
  return { vault: { index: shuffle(rows), documents }, steps };
}

/**
 * Turn the postings the server returned back into document identifiers.
 * Fail-closed: any blob that does not authenticate under k_w at its own
 * address aborts the whole result rather than yielding a partial answer.
 */
export async function openPostings(
  keys: VaultKeys,
  keyword: string,
  postings: Array<{ address: Uint8Array; value: Uint8Array }>,
): Promise<string[]> {
  const kw = await postingKey(keys, keyword);
  const ids: string[] = [];
  for (const p of postings) {
    ids.push(fromUtf8(await open(kw, p.value, p.address)));
  }
  return ids;
}

export async function openDocument(
  keys: VaultKeys,
  docId: string,
  blob: Uint8Array,
): Promise<{ title: string; body: string }> {
  const text = fromUtf8(await open(await documentKey(keys, docId), blob));
  const nl = text.indexOf('\n');
  return nl < 0 ? { title: text, body: '' } : { title: text.slice(0, nl), body: text.slice(nl + 1) };
}

/** Keywords are matched exactly after this normalisation — the index holds one
 *  entry per normalised form, so "Salary " and "salary" are the same token. */
export function normalize(keyword: string): string {
  return keyword.trim().toLowerCase();
}

function shuffle<T>(items: T[]): T[] {
  const out = items.slice();
  for (let i = out.length - 1; i > 0; i--) {
    const j = crypto.getRandomValues(new Uint32Array(1))[0]! % (i + 1);
    [out[i], out[j]] = [out[j]!, out[i]!];
  }
  return out;
}
