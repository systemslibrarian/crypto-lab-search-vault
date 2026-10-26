import { describe, expect, it } from 'vitest';
import { MuseAccessController, MuseLesson } from './lesson';

describe('L-R-08 end-to-end lesson', () => {
  it('executes role refusals, the KWAP attack, and the split-trust comparison', async () => {
    const lesson = await MuseLesson.create();
    const run = await lesson.run();

    expect(run.rejected.map((entry) => entry.operation)).toEqual([
      'upload writer index',
      'issue reader query',
      'search writer-b',
    ]);
    expect(run.rejected.every((entry) => entry.transcriptCountAfter === entry.transcriptCountBefore)).toBe(true);
    expect(run.singleServer.knownQuery.matchedWriterIds).toEqual(['writer-a']);
    expect([...run.singleServer.targetQuery.matchedWriterIds].sort()).toEqual(['writer-a', 'writer-b']);
    expect(run.singleServer.recoveredTarget).toBe(true);
    expect(run.singleServer.crossedAuthorizationBoundary).toBe(true);
    expect(run.singleServer.changedTargetStayedUnknown).toBe(true);

    expect(run.splitTrust.oracleWriterIds).toEqual(['writer-a', 'writer-b']);
    expect(run.splitTrust.falseNegativeWriterIds).toEqual([]);
    expect([...run.splitTrust.first.reader.writerIds].sort()).toEqual(
      [...run.splitTrust.oracleWriterIds, ...run.splitTrust.falsePositiveWriterIds].sort(),
    );
    expect(run.splitTrust.freshTrapdoor).toBe(true);
    expect(run.splitTrust.freshSelectorCiphertexts).toBe(true);
    expect(
      run.splitTrust.combinedViews
        .filter((row) => row.positive)
        .map((row) => row.writerId)
        .sort(),
    ).toEqual([...run.splitTrust.first.reader.writerIds].sort());
  });

  it('keeps writer and reader operations as disjoint runtime capabilities', () => {
    const roles = new MuseAccessController(['reader-a'], ['writer-a']);
    expect(() => roles.assertCanQuery('reader-a')).not.toThrow();
    expect(() => roles.assertCanUpload('writer-a')).not.toThrow();
    expect(() => roles.assertCanUpload('reader-a')).toThrow(/writer role/);
    expect(() => roles.assertCanQuery('writer-a')).toThrow(/reader role/);
    expect(() => new MuseAccessController(['same-id'], ['same-id'])).toThrow(/both roles/);
  });
});
