import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { describe, expect, it } from 'vitest';
import { Workspace } from '../src/index.js';
import { CorpusReport, CorpusRunner, escapeCorpus } from '../src/corpus-runner.js';

/**
 * A workspace nested deep enough that the sweep's three levels stay inside our
 * own temp directory.
 *
 * NOT incidental. Placing a workspace directly in the system temp dir puts the
 * user profile three levels up, and the sweep then hits its file ceiling long
 * before it reaches anything this test planted — reporting a clean run because
 * it gave up, not because nothing escaped. That is the failure `sweepComplete`
 * now surfaces, and it is a real deployment caveat, not a test artefact.
 */
async function workspace(): Promise<{ ws: Workspace }> {
  const top = await mkdtemp(join(tmpdir(), 'prism-workspace-ts-corpus-'));
  const base = join(top, 'one', 'two');
  await mkdir(base, { recursive: true });
  const ws = new Workspace(base, 'agent-1');
  await ws.write('seed.txt', 'seed');

  return { ws };
}

describe('CorpusRunner', () => {
  it('fires the whole shipped corpus at a real workspace and passes', async () => {
    // This is the claim the package exists to make checkable by someone who
    // does not trust it. Until now the corpus only ever ran against the bare
    // PathGuard — never against a Workspace on a real disk, which is where a
    // wrongly assembled root would show up.
    const report = await new CorpusRunner().against((await workspace()).ws);

    expect(report.results).toHaveLength(134);
    expect(report.failures()).toEqual([]);
    expect(report.strays).toEqual([]);
    expect(report.passed()).toBe(true);
  }, 30_000);

  it('reports the corpus version it ran', async () => {
    const report = await new CorpusRunner().against((await workspace()).ws);

    expect(report.corpusVersion).toBe(escapeCorpus.version);
    expect(report.summary()).toContain('134 attempts');
  }, 30_000);

  it('FINDS a planted stray, so the sweep is a check and not a habit', async () => {
    // A sweep that has never found anything proves nothing. Planting a known
    // marker outside the workspace is the only way to show it can find one —
    // which is exactly why `against()` takes a marker override.
    const { ws } = await workspace();
    const marker = 'prism-workspace-escape-marker-planted-for-this-test';
    await writeFile(join(ws.root, '..', 'planted.txt'), marker);

    const report = await new CorpusRunner().against(ws, marker);

    expect(report.strays.length).toBeGreaterThan(0);
    expect(report.strays.some((path) => path.endsWith('planted.txt'))).toBe(true);
    expect(report.passed()).toBe(false);
    expect(report.summary()).toContain('ESCAPED THE WORKSPACE');
  }, 30_000);

  it('fails the report when an attempt is refused with the WRONG code', async () => {
    // Which refusal fires is what a consumer alerts on: "an agent tried to
    // leave its workspace" and "the name has a trailing dot" are different
    // pages in the middle of the night, so a wrong code is a failure.
    const { ws } = await workspace();
    const report = await new CorpusRunner().against(ws);
    const wrongCoded = {
      ...report.results[0]!,
      outcome: 'wrong-code' as const,
      detail: 'refused as [path_is_empty], expected [path_traverses_outside_workspace]',
    };
    const mutated = new CorpusReport([wrongCoded], [], true);

    expect(mutated.passed()).toBe(false);
    expect(mutated.failures()).toHaveLength(1);
  }, 30_000);

  it('does NOT pass when the sweep gave up early', () => {
    // A security check that stopped at its ceiling has not verified anything
    // about the part it never reached. The reference reports that truncated
    // sweep as a clean one; both ports refuse to.
    const report = new CorpusReport([], [], true, false);

    expect(report.passed()).toBe(false);
    expect(report.summary()).toContain('SWEEP INCOMPLETE');
  });
});
