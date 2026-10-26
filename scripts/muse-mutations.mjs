#!/usr/bin/env node
/** Clean-baseline, exact-restoration mutation gate for Exhibit 10. */
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
    name: 'publish the reciprocal reader exponent',
    file: 'src/muse/core.ts',
    anchor: 'const inverse = modInverse(rho, ORDER);',
    replacement: 'const inverse = rho;',
    spec: 'src/muse/core.test.ts',
    test: 'executes the paper’s delegation equation against the stored GT value',
  },
  {
    name: 'include fresh xi in the split-trust reader trapdoor',
    file: 'src/muse/core.ts',
    anchor: 'bytes: hashMuseKeyword(keyword).multiply((xi * this.#rho) % ORDER).toBytes(true),',
    replacement: 'bytes: hashMuseKeyword(keyword).multiply(this.#rho).toBytes(true),',
    spec: 'src/muse/split.test.ts',
    test: 'returns the independently expected writers while separating QM and DH views',
  },
  {
    name: 'reject an unauthorized mixed request without a partial transcript',
    file: 'src/muse/core.ts',
    anchor: 'if (!authorization) throw new Error(`reader ${trapdoor.readerId} is not authorized for ${writerId}`);',
    replacement: `if (!authorization) {
        this.#observations.push({ queryId: 'partial', readerId: trapdoor.readerId, requestedWriterIds: [writerId], trapdoorHex: '', testedRows: 0, matches: [] });
        throw new Error(\`reader \${trapdoor.readerId} is not authorized for \${writerId}\`);
      }`,
    spec: 'src/muse/core.test.ts',
    test: 'searches only authorized writer indexes and rejects a mixed request atomically',
  },
  {
    name: 'accept exactly equal pairing values as search matches',
    file: 'src/muse/core.ts',
    anchor: "if (bls.fields.Fp12.eql(transformed, decodeGt(row.gtBytes, 'encrypted index token'))) {",
    replacement: "if (false && bls.fields.Fp12.eql(transformed, decodeGt(row.gtBytes, 'encrypted index token'))) {",
    spec: 'src/muse/core.test.ts',
    test: 'searches only authorized writer indexes and rejects a mixed request atomically',
  },
  {
    name: 'join query and matching-row nodes in the KWAP equality graph',
    file: 'src/muse/attack.ts',
    anchor: 'union.join(queryNodeId, rowNodeId);',
    replacement: 'void rowNodeId;',
    spec: 'src/muse/core.test.ts',
    test: 'propagates one colluding label to another reader and unauthorized writer index',
  },
  {
    name: 'refuse contradictory labels in one equality class',
    file: 'src/muse/attack.ts',
    anchor: 'if (prior && prior.keyword !== keyword) {',
    replacement: 'if (false && prior && prior.keyword !== keyword) {',
    spec: 'src/muse/core.test.ts',
    test: 'refuses contradictory labels and labels for absent transcript nodes',
  },
  {
    name: 'map one element to distinct ZGBF positions',
    file: 'src/muse/zgbf.ts',
    anchor: `if (!positions.includes(position)) {
          positions.push(position);
          break;
        }`,
    replacement: `positions.push(0);
        break;`,
    spec: 'src/muse/zgbf.test.ts',
    test: 'maps each element deterministically to distinct in-range positions',
  },
  {
    name: 'abort a ZGBF insertion when every mapped cell is occupied',
    file: 'src/muse/zgbf.ts',
    anchor: `if (pivot === undefined) {
      throw new ZgbfBuildError('every mapped position was already occupied');
    }`,
    replacement: `if (pivot === undefined) {
      continue;
    }`,
    spec: 'src/muse/zgbf.test.ts',
    test: 'implements the paper’s explicit abort when every mapped cell is occupied',
  },
  {
    name: 'recognize an all-zero XOR as a ZGBF membership match',
    file: 'src/muse/zgbf.ts',
    anchor: 'return aggregate === 0;',
    replacement: 'return aggregate !== 0;',
    spec: 'src/muse/zgbf.test.ts',
    test: 'makes every inserted element sum to zero while a fixed non-member does not',
  },
  {
    name: 'pack selected shares in their declared order',
    file: 'src/muse/math.ts',
    anchor: 'coefficients.set(position, 1n << BigInt(order * shareBits));',
    replacement: 'coefficients.set(position, 1n << BigInt((selectedPositions.length - 1 - order) * shareBits));',
    spec: 'src/muse/math.test.ts',
    test: 'retrieves three selected 128-bit cells in their declared order',
  },
  {
    name: 'sanitize a packed response with an independent encryption of zero',
    file: 'src/muse/math.ts',
    anchor: 'return sanitize\n    ? (response * paillierEncrypt(key, 0n)) % key.nSquared\n    : response;',
    replacement: 'return false && sanitize\n    ? (response * paillierEncrypt(key, 0n)) % key.nSquared\n    : response;',
    spec: 'src/muse/math.test.ts',
    test: 'sanitizes the same homomorphic response with a fresh encryption of zero',
  },
  {
    name: 'randomize identical packed-selector plaintext vectors independently',
    file: 'src/muse/math.ts',
    anchor: 'paillierEncrypt(key, coefficients.get(position) ?? 0n),',
    replacement: 'paillierEncrypt(key, coefficients.get(position) ?? 0n, 1n),',
    spec: 'src/muse/math.test.ts',
    test: 'randomizes identical packed-selector plaintext vectors independently',
  },
  {
    name: 'reject duplicate packed-selector positions',
    file: 'src/muse/math.ts',
    anchor: 'new Set(selectedPositions).size !== selectedPositions.length',
    replacement: 'false',
    spec: 'src/muse/math.test.ts',
    test: 'rejects duplicate/out-of-range positions, oversized packing, and malformed ciphertexts',
  },
  {
    name: 'join QM positivity to DH routing only in the explicit combined view',
    file: 'src/muse/split.ts',
    anchor: 'positive: positive.has(route.responseId),',
    replacement: 'positive: !positive.has(route.responseId),',
    spec: 'src/muse/split.test.ts',
    test: 'returns the independently expected writers while separating QM and DH views',
  },
  {
    name: 'bind encrypted result ids to reader and response context',
    file: 'src/muse/split.ts',
    anchor: 'return frame(utf8(RESULT_AAD_DOMAIN), utf8(readerId), utf8(responseId));',
    replacement: 'return new Uint8Array();',
    spec: 'src/muse/split.test.ts',
    test: 'binds each encrypted writer id to its reader and response context',
  },
  {
    name: 'derive selector evidence from the actual randomized ciphertexts',
    file: 'src/muse/split.ts',
    anchor: `frame(
      utf8(SELECTOR_DIGEST_DOMAIN),
      ...selector.ciphertexts.map((ciphertext) =>
        ciphertextBytes(paillier.publicKey, ciphertext),
      ),
    ),`,
    replacement: 'frame(utf8(SELECTOR_DIGEST_DOMAIN)),',
    spec: 'src/muse/split.test.ts',
    test: 'fresh xi and Paillier randomness change repeated preparations',
  },
  {
    name: 'keep writer upload capability disjoint from reader capability',
    file: 'src/muse/lesson.ts',
    anchor: 'if (!this.#writers.has(actorId)) throw new Error(`${actorId} does not hold the writer role`);',
    replacement: 'if (!this.#readers.has(actorId)) throw new Error(`${actorId} does not hold the writer role`);',
    spec: 'src/muse/lesson.test.ts',
    test: 'keeps writer and reader operations as disjoint runtime capabilities',
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
  const baseline = run(['src/muse']);
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

  const restoredBaseline = run(['src/muse']);
  if (restoredBaseline.status !== 0) {
    process.stderr.write(restoredBaseline.output);
    throw new Error('restored source FAILED its clean baseline');
  }
} finally {
  for (const file of originals.keys()) restore(file);
}

console.log(`all ${caught} mutation(s) caught`);
