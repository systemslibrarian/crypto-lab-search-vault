#!/usr/bin/env node
/** Clean-baseline, exact-restoration mutation gate for Exhibit 9. */
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { stripVTControlCharacters } from 'node:util';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const VITEST = path.join(ROOT, 'node_modules', 'vitest', 'vitest.mjs');
const CHILD_ENV = { ...process.env, CI: '1', FORCE_COLOR: '0', NO_COLOR: '1' };

const MUTATIONS = [
  {
    name: 'include the declared deletion threshold',
    file: 'src/fuzzy/core.ts',
    anchor: 'for (let removed = 0; removed <= threshold; removed++) {',
    replacement: 'for (let removed = 0; removed < threshold; removed++) {',
    spec: 'src/fuzzy/core.test.ts',
    test: 'reproduces the paper’s CASTLE threshold-1 gram example',
  },
  {
    name: 'charge zero for equal Levenshtein characters',
    file: 'src/fuzzy/core.ts',
    anchor: '(left[row - 1] === right[column - 1] ? 0 : 1);',
    replacement: '(left[row - 1] === right[column - 1] ? 1 : 1);',
    spec: 'src/fuzzy/core.test.ts',
    test: 'uses insertion, deletion, and substitution with no transposition shortcut',
  },
  {
    name: 'count server-visible fuzzy-token intersections',
    file: 'src/fuzzy/core.ts',
    anchor: 'for (const token of target) if (candidate.has(token)) intersection += 1;',
    replacement: 'for (const token of target) if (false && candidate.has(token)) intersection += 1;',
    spec: 'src/fuzzy/core.test.ts',
    test: 'infers one uniquely overlapping known anchor when exact tokens are unrelated',
  },
  {
    name: 'refuse to invent a label when maximum overlap is tied',
    file: 'src/fuzzy/core.ts',
    anchor: 'inferredAnchor: largest > 0 && leaders.length === 1 ? leaders[0]!.label : null,',
    replacement: 'inferredAnchor: largest > 0 && leaders.length >= 1 ? leaders[0]!.label : null,',
    spec: 'src/fuzzy/core.test.ts',
    test: 'reports ties and zero-overlap cases rather than inventing a label',
  },
  {
    name: 'build each index for its selected threshold',
    file: 'src/fuzzy/client.ts',
    anchor: 'deletionGramSet(keyword, threshold).map(async (gram): Promise<FuzzyIndexRow> => {',
    replacement: 'deletionGramSet(keyword, 0).map(async (gram): Promise<FuzzyIndexRow> => {',
    spec: 'src/fuzzy/server.test.ts',
    test: 'derives the bounded corpus association counts from actual rows',
  },
  {
    name: 'bind candidate payloads to their trapdoor as AES-GCM AAD',
    file: 'src/fuzzy/client.ts',
    anchor: 'value: await seal(keys.kPayload, plaintext, trapdoor),',
    replacement: 'value: await seal(keys.kPayload, plaintext, new Uint8Array()),',
    spec: 'src/fuzzy/server.test.ts',
    test: 'sends only opaque trapdoors and finds the one-edit audit candidate',
  },
  {
    name: 'accept candidates at the inclusive edit-distance boundary',
    file: 'src/fuzzy/client.ts',
    anchor: 'accepted: distance <= threshold,',
    replacement: 'accepted: distance < threshold,',
    spec: 'src/fuzzy/lesson.test.ts',
    test: 'recovers a one-edit neighbor that exact SSE misses',
  },
  {
    name: 'record every matched trapdoor in the server response',
    file: 'src/fuzzy/server.ts',
    anchor: 'matchedTrapdoorHexes.push(token);',
    replacement: 'void token;',
    spec: 'src/fuzzy/server.test.ts',
    test: 'sends only opaque trapdoors and finds the one-edit audit candidate',
  },
  {
    name: 'retain the validated opaque query bundle for leakage analysis',
    file: 'src/fuzzy/server.ts',
    anchor: 'this.#queryBundles.push([...query.trapdoorHexes]);',
    replacement: 'this.#queryBundles.push([]);',
    spec: 'src/fuzzy/server.test.ts',
    test: 'records only validated opaque query bundles and returns defensive copies',
  },
  {
    name: 'count query lookups rather than returned rows',
    file: 'src/fuzzy/server.ts',
    anchor: 'lookups: query.trapdoorHexes.length,',
    replacement: 'lookups: rows.length,',
    spec: 'src/fuzzy/server.test.ts',
    test: 'sends only opaque trapdoors and finds the one-edit audit candidate',
  },
  {
    name: 'include returned trapdoor bytes in response cost',
    file: 'src/fuzzy/server.ts',
    anchor: 'responseBytes: rows.reduce((bytes, row) => bytes + 32 + row.value.length, 0),',
    replacement: 'responseBytes: rows.reduce((bytes, row) => bytes + row.value.length, 0),',
    spec: 'src/fuzzy/server.test.ts',
    test: 'sends only opaque trapdoors and finds the one-edit audit candidate',
  },
  {
    name: 'count every stored association without an off-by-one omission',
    file: 'src/fuzzy/server.ts',
    anchor: 'associations: this.#rows.length,',
    replacement: 'associations: this.#rows.length - 1,',
    spec: 'src/fuzzy/server.test.ts',
    test: 'reports stored associations rather than distinct trapdoor buckets',
  },
  {
    name: 'classify candidate false positives against the plaintext oracle',
    file: 'src/fuzzy/lesson.ts',
    anchor: '.filter((keyword) => !groundTruth.has(keyword)).length;',
    replacement: '.filter(() => false).length;',
    spec: 'src/fuzzy/lesson.test.ts',
    test: 'reports a gram collision separately from the filtered final answer',
  },
  {
    name: 'filter rejected candidates before requesting documents',
    file: 'src/fuzzy/lesson.ts',
    anchor: 'candidates\n          .filter((candidate) => candidate.accepted)\n          .flatMap((candidate) => candidate.documentIds),',
    replacement: 'candidates\n          .filter(() => true)\n          .flatMap((candidate) => candidate.documentIds),',
    spec: 'src/fuzzy/lesson.test.ts',
    test: 'reports a gram collision separately from the filtered final answer',
  },
  {
    name: 'use nonmatching corpus documents as the final false-positive denominator',
    file: 'src/fuzzy/lesson.ts',
    anchor: 'denominator: this.#corpus.length - expectedDocuments.size,',
    replacement: 'denominator: this.#corpus.length,',
    spec: 'src/fuzzy/lesson.test.ts',
    test: 'reports a gram collision separately from the filtered final answer',
  },
  {
    name: 'send the filtered document identifiers through the server boundary',
    file: 'src/fuzzy/lesson.ts',
    anchor: 'const serverObservedDocumentIds = server.recordDocumentRequest(finalDocumentIds);',
    replacement: 'const serverObservedDocumentIds = server.recordDocumentRequest([]);',
    spec: 'src/fuzzy/lesson.test.ts',
    test: 'recovers a one-edit neighbor that exact SSE misses',
  },
];

const literal = (value) => value.replaceAll(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`);
const originals = new Map(
  [...new Set(MUTATIONS.map((mutation) => mutation.file))].map((file) => {
    const bytes = readFileSync(path.join(ROOT, file));
    return [file, { bytes, hash: sha256(bytes) }];
  }),
);

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function replaceExactly(source, mutation) {
  const first = source.indexOf(mutation.anchor);
  if (first < 0) throw new Error(`mutation anchor missing: ${mutation.name}`);
  if (source.indexOf(mutation.anchor, first + mutation.anchor.length) >= 0) {
    throw new Error(`mutation anchor is not unique: ${mutation.name}`);
  }
  return source.slice(0, first) + mutation.replacement + source.slice(first + mutation.anchor.length);
}

function run(specs, testName) {
  const args = [VITEST, 'run', ...specs];
  if (testName) args.push('-t', literal(testName), '--reporter=verbose');
  const child = spawnSync(process.execPath, args, {
    cwd: ROOT,
    env: CHILD_ENV,
    encoding: 'utf8',
    maxBuffer: 20 * 1024 * 1024,
    timeout: 300_000,
  });
  return {
    status: child.status,
    output: stripVTControlCharacters(`${child.stdout ?? ''}${child.stderr ?? ''}`),
  };
}

function restore(file) {
  const original = originals.get(file);
  if (!original) throw new Error(`missing saved source: ${file}`);
  writeFileSync(path.join(ROOT, file), original.bytes);
  const restored = readFileSync(path.join(ROOT, file));
  if (sha256(restored) !== original.hash) throw new Error(`exact restoration failed: ${file}`);
}

function assertNamedTestRan(result, mutation) {
  if (!result.output.includes(mutation.test)) {
    throw new Error(`owning test did not run for ${mutation.name}`);
  }
  if (/No test files found|No tests found|Failed Suites|Unhandled Error|Transform failed/i.test(result.output)) {
    throw new Error(`mutation did not produce an ordinary assertion failure: ${mutation.name}`);
  }
  if (!/Tests\s+1 failed/.test(result.output)) {
    throw new Error(`owning assertion did not fail exactly once: ${mutation.name}`);
  }
}

let caught = 0;
try {
  const baseline = run(['src/fuzzy']);
  if (baseline.status !== 0) {
    process.stderr.write(baseline.output);
    throw new Error('baseline: unmutated copy FAILED; mutation results are meaningless');
  }
  console.log('baseline: unmutated copy PASSES');

  for (const mutation of MUTATIONS) {
    const original = originals.get(mutation.file);
    if (!original) throw new Error(`missing original: ${mutation.file}`);
    const source = original.bytes.toString('utf8');
    writeFileSync(path.join(ROOT, mutation.file), replaceExactly(source, mutation), 'utf8');
    const result = run([mutation.spec], mutation.test);
    restore(mutation.file);
    if (result.status === 0) {
      process.stderr.write(result.output);
      throw new Error(`mutation survived: ${mutation.name}`);
    }
    assertNamedTestRan(result, mutation);
    caught += 1;
    console.log(`caught: ${mutation.name}`);
  }

  const restoredBaseline = run(['src/fuzzy']);
  if (restoredBaseline.status !== 0) {
    process.stderr.write(restoredBaseline.output);
    throw new Error('restored source FAILED its clean baseline');
  }
} finally {
  for (const file of originals.keys()) restore(file);
}

console.log(`all ${caught} mutation(s) caught`);
