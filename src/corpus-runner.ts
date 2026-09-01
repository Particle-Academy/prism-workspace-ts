import { Buffer } from 'node:buffer';
import { randomBytes } from 'node:crypto';
import { readFileSync, readdirSync, readFileSync as readBytesSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { PathRefused, type RefusalCode, type Workspace } from './index.js';

/**
 * Fires the whole escape corpus at a REAL workspace and reports what happened.
 *
 *     const report = await new CorpusRunner().against(workspace);
 *     if (!report.passed()) throw new Error(report.summary());
 *
 * This is the class that makes the package's central claim checkable by someone
 * who does not trust it. Our CI proves the boundary holds on OUR disk; yours
 * might use a different root, a network share, a case-insensitive volume — and
 * a security property is only true of the configuration it was measured on. So
 * the corpus ships, and you can measure yours.
 *
 * It is safe to run against a live workspace: every attempt is expected to be
 * refused, so a passing run writes nothing at all. The marker is per-run and
 * random, so a stray found afterwards is unambiguously from THIS run.
 *
 * ## Two checks, not one
 *
 * Every attempt must be refused with the code the corpus names — and then the
 * directories AROUND the workspace are swept for the marker. The second catches
 * what the first cannot: a guard that refuses everything correctly, paired with
 * a workspace root assembled wrongly, passes every unit test in this package
 * and still writes into the wrong place.
 */

/** How many levels above the workspace to sweep. */
const SWEEP_LEVELS = 3;

/** A ceiling, so sweeping a large disk cannot become the slowest thing in a suite. */
const SWEEP_FILE_LIMIT = 20000;

export type CorpusOutcome =
  /** Refused, with the code the corpus names. The only passing outcome. */
  | 'refused'
  /**
   * Refused, but as something else. A FAILURE, not a warning — which refusal
   * fires is what a consumer alerts on, and "an agent tried to leave its
   * workspace" and "the name has a trailing dot" are different pages in the
   * middle of the night.
   */
  | 'wrong-code'
  /** Accepted. The boundary did not hold. */
  | 'accepted'
  /** Something else went wrong, which is not a pass either. */
  | 'errored';

export interface EscapeAttempt {
  id: string;
  path_base64: string;
  hazard: string;
  refusal: RefusalCode;
  note?: string;
}

export interface CorpusResult {
  attempt: EscapeAttempt;
  outcome: CorpusOutcome;
  refusal: RefusalCode | null;
  detail: string;
}

const corpusDocument = JSON.parse(
  readFileSync(new URL('./security/escape-corpus.json', import.meta.url), 'utf8'),
) as { corpus_version: string; cases: EscapeAttempt[] };

/** The shipped corpus: 134 adversarial paths across twelve hazard classes. */
export const escapeCorpus = {
  version: corpusDocument.corpus_version,
  all: (): readonly EscapeAttempt[] => corpusDocument.cases,
};

export class CorpusReport {
  constructor(
    readonly results: readonly CorpusResult[],
    /** Files found OUTSIDE the workspace carrying this run's marker. Empty is the only acceptable answer. */
    readonly strays: readonly string[],
    /** Whether the surrounding directories could be swept at all. */
    readonly swept: boolean,
    /**
     * Whether the sweep reached the END of the surrounding tree.
     *
     * FALSE means it hit the file ceiling and stopped early, so `strays` is
     * "nothing found in the part I looked at" rather than "nothing escaped".
     * The reference does not carry this flag and reports the truncated sweep as
     * a clean one — a security check that silently half-runs and then says it
     * passed. Recorded in the port gaps register as a divergence the reference
     * should adopt.
     */
    readonly sweepComplete: boolean = true,
    readonly corpusVersion: string = escapeCorpus.version,
  ) {}

  /**
   * Both halves have to hold: every attempt refused with the code the corpus
   * names, no stray found, and THE SWEEP ACTUALLY FINISHED. A truncated sweep
   * is not a pass, because the half of the check that would catch a wrongly
   * assembled root never ran to completion.
   */
  passed(): boolean {
    return this.failures().length === 0 && this.strays.length === 0 && this.sweepComplete;
  }

  failures(): CorpusResult[] {
    return this.results.filter((result) => result.outcome !== 'refused');
  }

  summary(): string {
    const failures = this.failures();
    const lines = [
      `prism-workspace escape corpus v${this.corpusVersion}: ${this.results.length} attempts, ` +
        `${this.results.length - failures.length} refused correctly, ${failures.length} failed.`,
      this.swept
        ? `Swept the surrounding directories: ${this.strays.length} stray file(s).`
        : 'Surrounding directories NOT swept — containment was checked by refusal only.',
    ];

    if (!this.sweepComplete) {
      lines.push(
        `  SWEEP INCOMPLETE: stopped at the ${SWEEP_FILE_LIMIT}-file ceiling, so "no strays" ` +
          'means "none in the part that was searched". Place the workspace somewhere with a ' +
          'smaller surrounding tree, or treat the containment half as unverified.',
      );
    }

    for (const failure of failures) {
      lines.push(`  ${failure.attempt.id} (${failure.attempt.hazard}): ${failure.detail}`);
    }

    for (const stray of this.strays) {
      lines.push(`  ESCAPED THE WORKSPACE: ${stray}`);
    }

    return lines.join('\n');
  }
}

export class CorpusRunner {
  /**
   * @param marker Override the per-run marker. For testing the RUNNER itself —
   *   planting a known marker outside the workspace is the only way to prove
   *   the sweep can find one, and a sweep that has never found anything is not
   *   a check, it is a habit.
   */
  async against(workspace: Workspace, marker?: string): Promise<CorpusReport> {
    const token = marker ?? `prism-workspace-escape-marker-${randomBytes(16).toString('hex')}`;
    const results: CorpusResult[] = [];

    for (const attempt of escapeCorpus.all()) {
      results.push(await this.attempt(workspace, attempt, token));
    }

    const { strays, complete } = this.sweep(workspace.root, token);

    return new CorpusReport(results, strays, true, complete);
  }

  private async attempt(
    workspace: Workspace,
    attempt: EscapeAttempt,
    marker: string,
  ): Promise<CorpusResult> {
    try {
      // The RAW BYTES, not a decoded string. Several corpus cases are invalid
      // UTF-8 on purpose, and decoding them first would substitute U+FFFD and
      // quietly test a different path than the one the case names.
      await workspace.write(Uint8Array.from(Buffer.from(attempt.path_base64, 'base64')), marker);
    } catch (error) {
      if (error instanceof PathRefused) {
        return error.code === attempt.refusal
          ? { attempt, outcome: 'refused', refusal: error.code, detail: 'refused as expected' }
          : {
              attempt,
              outcome: 'wrong-code',
              refusal: error.code,
              detail: `refused as [${error.code}], expected [${attempt.refusal}]`,
            };
      }

      // Not a pass. Something failed for a reason the boundary did not choose,
      // which means the boundary was not what stopped it — and on a differently
      // configured disk it might not stop it at all.
      return {
        attempt,
        outcome: 'errored',
        refusal: null,
        detail: `threw ${error instanceof Error ? error.name : typeof error}: ${String(error)}`,
      };
    }

    return {
      attempt,
      outcome: 'accepted',
      refusal: null,
      detail: `was ACCEPTED; expected refusal [${attempt.refusal}]`,
    };
  }

  private sweep(root: string, marker: string): { strays: string[]; complete: boolean } {
    let top = root;

    for (let level = 0; level < SWEEP_LEVELS; level += 1) {
      const parent = dirname(top);
      if (parent === top) break;
      top = parent;
    }

    const strays: string[] = [];
    const length = Buffer.byteLength(marker);
    let seen = 0;
    let truncated = false;

    const walk = (directory: string): void => {
      if (seen > SWEEP_FILE_LIMIT) { truncated = true; return; }

      let entries;
      try {
        entries = readdirSync(directory, { withFileTypes: true });
      } catch {
        // A directory we cannot read is not evidence of an escape, and a sweep
        // that threw would turn an unreadable sibling into a failed security
        // check.
        return;
      }

      for (const entry of entries) {
        if (seen++ > SWEEP_FILE_LIMIT) { truncated = true; return; }
        const path = join(directory, entry.name);

        if (entry.isDirectory()) {
          if (!entry.isSymbolicLink()) walk(path);
          continue;
        }

        if (!entry.isFile()) continue;

        try {
          // The marker is the WHOLE content of anything an attempt wrote, so
          // anything the wrong size cannot be one. That check is what keeps
          // this from reading an entire storage directory.
          if (statSync(path).size !== length) continue;
          if (readBytesSync(path, 'utf8') === marker) strays.push(path);
        } catch {
          continue;
        }
      }
    };

    walk(top);

    return { strays, complete: !truncated };
  }
}
