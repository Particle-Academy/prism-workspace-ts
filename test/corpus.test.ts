import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { PathGuard, PathRefused, type RefusalCode } from '../src/index.js';

interface CorpusCase { id: string; path_base64: string; refusal: RefusalCode }
const corpus = JSON.parse(readFileSync(new URL('../src/security/escape-corpus.json', import.meta.url), 'utf8')) as {
  cases: CorpusCase[];
};

describe('shipped escape corpus', () => {
  it('contains the complete PHP v1 corpus', () => expect(corpus.cases).toHaveLength(134));
  it.each(corpus.cases)('$id refuses with $refusal', ({ path_base64: encoded, refusal }) => {
    try { new PathGuard().guard(Buffer.from(encoded, 'base64')); expect.fail('expected refusal'); }
    catch (error) { expect(error).toBeInstanceOf(PathRefused); expect((error as PathRefused).code).toBe(refusal); }
  });
});
