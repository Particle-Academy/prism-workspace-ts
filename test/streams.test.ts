import { mkdtemp, mkdir, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Readable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { PathRefused, Workspace, WorkspaceFailed } from '../src/index.js';

async function workspace(): Promise<Workspace> {
  return new Workspace(await mkdtemp(join(tmpdir(), 'prism-workspace-ts-stream-')), 'agent-1');
}

async function collect(stream: AsyncIterable<Uint8Array | string>): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk));

  return Buffer.concat(chunks);
}

describe('binary and streaming access', () => {
  it('reads raw bytes without decoding them as UTF-8', async () => {
    // `read()` decodes as UTF-8, which substitutes U+FFFD for anything that is
    // not text — and a workspace holds images and archives as readily as it
    // holds source. `prism-workspace-py` had `read_bytes` and this port did not.
    const ws = await workspace();
    const bytes = Uint8Array.from([0xff, 0xfe, 0x00, 0x01]);
    await ws.write('logo.png', bytes);

    expect(await ws.readBytes('logo.png')).toEqual(bytes);
  });

  it('streams a file back in chunks', async () => {
    const ws = await workspace();
    await ws.write('big.txt', 'hello streaming world');

    expect((await collect(await ws.readStream('big.txt'))).toString()).toBe('hello streaming world');
  });

  it('writes from a stream without buffering the payload', async () => {
    const ws = await workspace();
    await ws.writeStream('out.txt', Readable.from(['one ', 'two ', 'three']));

    expect(await ws.read('out.txt')).toBe('one two three');
  });

  it('writes from a plain async generator too', async () => {
    const ws = await workspace();
    async function* source(): AsyncGenerator<Uint8Array> {
      yield Uint8Array.from([104, 105]);
    }

    await ws.writeStream('gen.txt', source());

    expect(await ws.read('gen.txt')).toBe('hi');
  });

  it('GUARDS the path before opening a read handle', async () => {
    // The whole point of the package. A streaming accessor that skipped the
    // guard would be a hole straight through the boundary, and it would look
    // like an optimisation.
    const ws = await workspace();

    await expect(ws.readStream('../escape.txt')).rejects.toThrow(PathRefused);
    await expect(ws.readStream('/etc/passwd')).rejects.toThrow(PathRefused);
  });

  it('GUARDS the path before opening a write handle', async () => {
    const ws = await workspace();

    await expect(ws.writeStream('../escape.txt', Readable.from(['x']))).rejects.toThrow(PathRefused);
  });

  it('refuses to stream through a symlink that leaves the workspace', async () => {
    const base = await mkdtemp(join(tmpdir(), 'prism-workspace-ts-link-'));
    const ws = new Workspace(base, 'agent-1');
    await ws.write('seed.txt', 'seed');
    await mkdir(join(ws.root, 'nested'), { recursive: true });
    await symlink(tmpdir(), join(ws.root, 'nested', 'out'), 'dir');

    await expect(ws.readStream('nested/out/anything.txt')).rejects.toThrow(PathRefused);
  });

  it('reports a missing file by code rather than a raw filesystem error', async () => {
    const ws = await workspace();

    await expect(ws.readStream('nope.txt')).rejects.toThrow(WorkspaceFailed);
    await expect(ws.readBytes('nope.txt')).rejects.toThrow(WorkspaceFailed);
  });

  it('asks the authorizer before streaming, with the same abilities as the plain calls', async () => {
    const asked: string[] = [];
    const ws = new Workspace(await mkdtemp(join(tmpdir(), 'prism-workspace-ts-auth-')), 'agent-1', {
      authorize: (ability) => {
        asked.push(ability);
      },
    });

    await ws.writeStream('a.txt', Readable.from(['x']));
    await collect(await ws.readStream('a.txt'));
    await ws.readBytes('a.txt');

    expect(asked).toEqual(['write', 'read', 'read']);
  });
});
