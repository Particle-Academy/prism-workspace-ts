import { mkdtemp, mkdir, readFile, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { describe, expect, it } from 'vitest';
import { PathRefused, Workspace, workspaceAddress } from '../src/index.js';

describe('Workspace', () => {
  it('uses the stable slug plus digest address', () => {
    expect(workspaceAddress('session:ABC:one')).toBe('session-abc-one-ad223950606ee044');
  });

  it('reads, writes, lists, copies, moves, and deletes inside its address', async () => {
    const base = await mkdtemp(join(tmpdir(), 'prism-workspace-ts-'));
    const workspace = new Workspace(base, 'agent-1');
    await workspace.write('reports/q1.md', 'one');
    await workspace.append('reports/q1.md', ' two');
    expect(await workspace.read('reports/q1.md')).toBe('one two');
    expect(await workspace.size('reports/q1.md')).toBe(7);
    await workspace.copy('reports/q1.md', 'reports/copy.md');
    await workspace.move('reports/copy.md', 'final.md');
    const entries = [];
    for await (const entry of workspace.list()) entries.push(entry.path);
    expect(entries).toEqual(expect.arrayContaining(['reports', 'reports/q1.md', 'final.md']));
    await workspace.delete('final.md');
    expect(await workspace.exists('final.md')).toBe(false);
  });

  it('refuses real reads and writes through a link outside the workspace', async (context) => {
    const base = await mkdtemp(join(tmpdir(), 'prism-workspace-ts-'));
    const outside = await mkdtemp(join(tmpdir(), 'prism-workspace-outside-'));
    const workspace = new Workspace(base, 'linked');
    await workspace.write('seed.txt', 'x');
    await mkdir(outside, { recursive: true });
    await workspace.write('inside.md', 'inside');
    try { await symlink(outside, join(workspace.root, 'reports'), 'dir'); }
    catch { context.skip(); return; }
    await expect(workspace.read('reports/secret.txt')).rejects.toMatchObject<PathRefused>({
      code: 'path_escapes_workspace_via_link',
    });
    await expect(workspace.write('reports/planted.txt', 'planted')).rejects.toMatchObject<PathRefused>({
      code: 'path_escapes_workspace_via_link',
    });
    await expect(readFile(join(outside, 'planted.txt'), 'utf8')).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('allows a link that stays inside the workspace', async (context) => {
    const base = await mkdtemp(join(tmpdir(), 'prism-workspace-ts-'));
    const workspace = new Workspace(base, 'linked-inside');
    await workspace.write('real/notes.md', 'inside');
    try { await symlink(join(workspace.root, 'real'), join(workspace.root, 'shortcut'), 'dir'); }
    catch { context.skip(); return; }
    expect(await workspace.read('shortcut/notes.md')).toBe('inside');
  });
});
