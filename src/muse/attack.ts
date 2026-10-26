/** Figure-2-style keyword-access-pattern propagation over a server transcript. */
import { normalizeMuseKeyword, type SingleServerObservation } from './core';

export interface KnownQueryLabel {
  readonly queryId: string;
  readonly keyword: string;
}

export interface RecoveredTranscriptNode {
  readonly nodeId: string;
  readonly kind: 'query' | 'encrypted-row';
  readonly keyword: string;
  readonly sourceQueryId: string;
}

export interface KeywordAccessAttackResult {
  readonly equalityEdges: readonly {
    readonly queryNodeId: string;
    readonly rowNodeId: string;
  }[];
  readonly equivalenceClasses: readonly (readonly string[])[];
  readonly recovered: readonly RecoveredTranscriptNode[];
}

export function runKeywordAccessPatternAttack(
  observations: readonly SingleServerObservation[],
  knownLabels: readonly KnownQueryLabel[],
): KeywordAccessAttackResult {
  const queryIds = new Set<string>();
  const nodes = new Set<string>();
  const union = new UnionFind();
  const equalityEdges: { queryNodeId: string; rowNodeId: string }[] = [];

  for (const observation of observations) {
    if (queryIds.has(observation.queryId)) throw new Error('server transcript repeats a query id');
    queryIds.add(observation.queryId);
    const queryNodeId = queryNode(observation.queryId);
    nodes.add(queryNodeId);
    union.add(queryNodeId);
    for (const match of observation.matches) {
      const rowNodeId = rowNode(match.rowId);
      nodes.add(rowNodeId);
      union.add(rowNodeId);
      union.join(queryNodeId, rowNodeId);
      equalityEdges.push({ queryNodeId, rowNodeId });
    }
  }

  const labelsByRoot = new Map<string, { keyword: string; sourceQueryId: string }>();
  for (const known of knownLabels) {
    if (!queryIds.has(known.queryId)) throw new Error(`known label names missing query ${known.queryId}`);
    const keyword = normalizeMuseKeyword(known.keyword);
    const root = union.root(queryNode(known.queryId));
    const prior = labelsByRoot.get(root);
    if (prior && prior.keyword !== keyword) {
      throw new Error('contradictory known labels occupy one equality class');
    }
    labelsByRoot.set(root, { keyword, sourceQueryId: known.queryId });
  }

  const recovered: RecoveredTranscriptNode[] = [];
  for (const nodeId of [...nodes].sort()) {
    const known = labelsByRoot.get(union.root(nodeId));
    if (!known) continue;
    recovered.push({
      nodeId,
      kind: nodeId.startsWith('query/') ? 'query' : 'encrypted-row',
      keyword: known.keyword,
      sourceQueryId: known.sourceQueryId,
    });
  }

  const classes = new Map<string, string[]>();
  for (const nodeId of nodes) {
    const root = union.root(nodeId);
    const members = classes.get(root) ?? [];
    members.push(nodeId);
    classes.set(root, members);
  }

  return {
    equalityEdges,
    equivalenceClasses: [...classes.values()]
      .map((members) => members.sort())
      .sort((left, right) => left[0]!.localeCompare(right[0]!)),
    recovered,
  };
}

export function queryNode(queryId: string): string {
  return `query/${queryId}`;
}

export function rowNode(rowId: string): string {
  return `row/${rowId}`;
}

class UnionFind {
  readonly #parent = new Map<string, string>();

  add(value: string): void {
    if (!this.#parent.has(value)) this.#parent.set(value, value);
  }

  root(value: string): string {
    const parent = this.#parent.get(value);
    if (!parent) throw new Error(`unknown equality node: ${value}`);
    if (parent === value) return value;
    const root = this.root(parent);
    this.#parent.set(value, root);
    return root;
  }

  join(left: string, right: string): void {
    const leftRoot = this.root(left);
    const rightRoot = this.root(right);
    if (leftRoot !== rightRoot) this.#parent.set(rightRoot, leftRoot);
  }
}
