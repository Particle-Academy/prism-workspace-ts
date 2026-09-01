// The escape corpus is DATA, so tsc does not emit it — but `corpus-runner.js`
// resolves it relative to its own location, which after a build is `dist/`.
// Without this the published package would ship a runner that throws on import
// while every test passed, because the tests run from `src/`.
import { copyFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const asset = 'security/escape-corpus.json';

mkdirSync(resolve(root, 'dist/security'), { recursive: true });
copyFileSync(resolve(root, 'src', asset), resolve(root, 'dist', asset));
