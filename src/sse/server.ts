/**
 * The honest-but-curious server. It stores the encrypted index and the
 * encrypted document bodies, answers search tokens, and — the point of this
 * demo — keeps a ledger of exactly what it observes while doing so.
 *
 * The ledger is deliberately not a simulation of leakage: it is populated from
 * the same code path that answers the query. If the server can write it down,
 * the server genuinely learned it.
 */
import { addressFor } from './client';
import { toHex } from '../core/bytes';
import type { EncryptedVault, IndexRow, QueryObservation } from './types';

export class SearchServer {
  private readonly store = new Map<string, Uint8Array>();
  private readonly documents = new Map<string, Uint8Array>();
  private readonly ledger: QueryObservation[] = [];
  private seq = 0;

  constructor(vault: EncryptedVault) {
    for (const row of vault.index) this.store.set(row.address, row.value);
    for (const d of vault.documents) this.documents.set(d.id, d.blob);
  }

  /** Everything the server holds — random-looking labels and sealed blobs. */
  rows(): IndexRow[] {
    return [...this.store.entries()].map(([address, value]) => ({ address, value }));
  }

  get indexSize(): number {
    return this.store.size;
  }

  get documentCount(): number {
    return this.documents.size;
  }

  /**
   * Answer a search token: walk addr_0, addr_1, … until a label is missing.
   * The server never learns the keyword — only how many postings exist and,
   * once the client fetches them, which documents matched.
   */
  async search(token: Uint8Array): Promise<Array<{ address: Uint8Array; value: Uint8Array }>> {
    const found: Array<{ address: Uint8Array; value: Uint8Array }> = [];
    for (let i = 0; ; i++) {
      const address = await addressFor(token, i);
      const value = this.store.get(toHex(address));
      if (!value) break;
      found.push({ address, value });
    }
    return found;
  }

  /**
   * The client comes back for the matching documents. This fetch is where the
   * access pattern becomes visible, so this is where the ledger is written.
   */
  fetchDocuments(token: Uint8Array, docIds: string[]): Array<{ id: string; blob: Uint8Array }> {
    const out: Array<{ id: string; blob: Uint8Array }> = [];
    for (const id of docIds) {
      const blob = this.documents.get(id);
      if (blob) out.push({ id, blob });
    }
    this.ledger.push({
      seq: this.seq++,
      tokenHex: toHex(token),
      resultSize: out.length,
      resultIds: out.map((d) => d.id),
    });
    return out;
  }

  observations(): QueryObservation[] {
    return this.ledger.slice();
  }

  clearLedger(): void {
    this.ledger.length = 0;
    this.seq = 0;
  }
}
