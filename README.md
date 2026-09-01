# Prism Workspace for TypeScript

TypeScript implementation of Prism's guarded agent workspace. It provides a
Promise-based local workspace, stable owner addressing, optional authorization,
streamed directory listings, stable failure codes, lexical path guarding, and
realpath-based symlink containment.

Zero runtime dependencies. Node 20+.

This package is private while coordinated parity work is in progress.

## Verify it on YOUR disk

The package ships the same byte-preserving 134-case adversarial corpus as PHP —
and, since it ships, you can fire it at your own configuration:

```ts
import { Workspace } from '@particle-academy/prism-workspace';
import { CorpusRunner } from '@particle-academy/prism-workspace/corpus';

const report = await new CorpusRunner().against(new Workspace(base, owner));

if (!report.passed()) throw new Error(report.summary());
```

Our CI proves the boundary holds on *our* disk. Yours might use a different
root, a network share, or a case-insensitive volume, and **a security property
is only true of the configuration it was measured on.**

It is safe to run against a live workspace: every attempt is expected to be
refused, so a passing run writes nothing at all.

**Two checks, not one.** Every attempt must be refused with the code the corpus
names, *and* the directories around the workspace are then swept for a per-run
marker. The second catches what the first cannot — a guard that refuses
everything correctly, paired with a root assembled wrongly, passes every unit
test in this package and still writes into the wrong place.

**A truncated sweep is not a pass.** The sweep stops at a file ceiling so it
cannot become the slowest thing in your suite; when it does, `report.passed()`
is `false` and `sweepComplete` says why. "No strays found" and "no strays
exist" are different claims, and only one of them is a security result. The PHP
reference does not yet make this distinction.

## Paths can be bytes

`Workspace` methods take `string | Uint8Array`. Bytes are not a convenience:
several corpus cases are invalid UTF-8 on purpose, and such a path cannot be
expressed as a JavaScript string at all — it becomes U+FFFD on the way in. A
string-only API could never carry the attack the guard exists to refuse.

## Reading and writing

`read()` decodes UTF-8; `readBytes()` does not. `readStream()` and
`writeStream()` move content too large to hold in memory. **Every one of them
goes through the same guard before a handle is opened** — a streaming accessor
that skipped it would be a hole straight through the boundary, and it would
look like an optimisation.
