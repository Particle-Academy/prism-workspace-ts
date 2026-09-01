import { createHash } from 'node:crypto';
import {
  appendFile, copyFile, mkdir, open, opendir, readFile, rename, rm, stat, writeFile,
} from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { existsSync, realpathSync } from 'node:fs';
import type { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { dirname, isAbsolute, join, parse, relative, resolve, sep } from 'node:path';

export const refusalCodes = [
  'path_traverses_outside_workspace', 'path_is_absolute',
  'path_is_unc_or_device_namespace', 'path_contains_null_byte',
  'path_contains_control_character', 'path_contains_invisible_character',
  'path_contains_separator_homoglyph', 'path_is_not_valid_utf8',
  'path_contains_encoded_separator', 'path_contains_alternate_data_stream',
  'path_is_reserved_device_name', 'path_has_edge_dot_or_space',
  'path_uses_short_name_alias', 'path_uses_home_expansion', 'path_is_empty',
  'path_too_long', 'path_segment_too_long', 'path_escapes_workspace_via_link',
] as const;

export type RefusalCode = (typeof refusalCodes)[number];

export class PathRefused extends Error {
  constructor(readonly code: RefusalCode, readonly path: string) {
    super(`Workspace path refused (${code}).`);
    this.name = 'PathRefused';
  }
}

const devices = new Set([
  'CON', 'PRN', 'AUX', 'NUL', 'CLOCK$', 'CONIN$', 'CONOUT$',
  ...Array.from({ length: 10 }, (_, i) => `COM${i}`),
  ...Array.from({ length: 10 }, (_, i) => `LPT${i}`),
  'COM¹', 'COM²', 'COM³', 'LPT¹', 'LPT²', 'LPT³',
]);
const invisible = /[\u00ad\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/u;
const homoglyph = /[\u2044\u2215\u29f5\u29f8\ufe68\uff0f\uff3c]/u;
const encoded = /%(?:00|25|2e|2f|5c|[89a-f][0-9a-f])|%u[0-9a-f]{4}/iu;
const shortAlias = /^[^./]{1,6}~[0-9]{1,4}(?:\.[^./]{1,3})?$/u;
const home = /^~[\p{L}\p{N}_.-]*$/u;

const refuse = (code: RefusalCode, path: string): never => { throw new PathRefused(code, path); };

/** Pure lexical guard. Symlink containment belongs to the filesystem adapter. */
export class PathGuard {
  constructor(readonly maxPathBytes = 1024, readonly maxSegmentBytes = 255) {}

  guard(input: string | Uint8Array): string {
    const raw = typeof input === 'string' ? null : input;
    const printable = typeof input === 'string' ? input : `0x${Buffer.from(input).toString('hex')}`;
    const bytes = raw?.byteLength ?? Buffer.byteLength(input as string, 'utf8');
    if (bytes === 0) refuse('path_is_empty', printable);
    if (bytes > this.maxPathBytes) refuse('path_too_long', printable);
    if (raw?.includes(0) || (typeof input === 'string' && input.includes('\0')))
      refuse('path_contains_null_byte', printable);
    const path = raw ? decodeUtf8(raw, printable) : input as string;
    // JavaScript strings are Unicode; reject unpaired UTF-16 surrogates because
    // encoding them would silently substitute U+FFFD rather than preserve bytes.
    if (/([\ud800-\udbff](?![\udc00-\udfff])|(^|[^\ud800-\udbff])[\udc00-\udfff])/u.test(path))
      refuse('path_is_not_valid_utf8', path);
    if (invisible.test(path)) refuse('path_contains_invisible_character', path);
    if (homoglyph.test(path)) refuse('path_contains_separator_homoglyph', path);
    if (/[\x01-\x1f\x7f]/u.test(path)) refuse('path_contains_control_character', path);
    if (encoded.test(path)) refuse('path_contains_encoded_separator', path);
    if (path.startsWith('\\\\') || path.startsWith('//')) refuse('path_is_unc_or_device_namespace', path);
    if (/^[A-Za-z]:/u.test(path)) refuse('path_is_absolute', path);

    const folded = path.replaceAll('\\', '/');
    if (folded.startsWith('/')) refuse('path_is_absolute', path);
    const kept: string[] = [];
    for (const segment of folded.split('/')) {
      if (segment === '' || segment === '.') continue;
      this.guardSegment(path, segment, kept.length === 0);
      kept.push(segment);
    }
    if (kept.length === 0) refuse('path_is_empty', path);
    return kept.join('/');
  }

  private guardSegment(path: string, segment: string, leading: boolean): void {
    if (segment.startsWith('..')) refuse('path_traverses_outside_workspace', path);
    if (segment.includes(':')) refuse('path_contains_alternate_data_stream', path);
    if (segment.endsWith('.') || segment.endsWith(' ') || segment.startsWith(' '))
      refuse('path_has_edge_dot_or_space', path);
    if (leading && home.test(segment)) refuse('path_uses_home_expansion', path);
    if (shortAlias.test(segment)) refuse('path_uses_short_name_alias', path);
    if (devices.has(segment.split('.', 1)[0]!.toUpperCase())) refuse('path_is_reserved_device_name', path);
    if (Buffer.byteLength(segment, 'utf8') > this.maxSegmentBytes) refuse('path_segment_too_long', path);
  }
}

function decodeUtf8(input: Uint8Array, printable: string): string {
  // Preserve a leading BOM as input. TextDecoder strips it by default,
  // which would launder the corpus's dec-0010 deception case.
  try { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(input); }
  catch { return refuse('path_is_not_valid_utf8', printable); }
}

export type FaultCode =
  | 'workspace_file_missing'
  | 'workspace_write_failed'
  | 'workspace_delete_failed'
  | 'workspace_owner_not_addressable';

export class WorkspaceFailed extends Error {
  constructor(readonly code: FaultCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'WorkspaceFailed';
  }
}

export interface WorkspaceOwner { workspaceKey(): string }
export interface KeyedOwner { key(): string }
export type WorkspaceIdentity = string | WorkspaceOwner | KeyedOwner;

export function workspaceAddress(owner: WorkspaceIdentity, guard = new PathGuard()): string {
  let key: string;
  if (typeof owner === 'string') key = owner;
  else if ('workspaceKey' in owner) key = owner.workspaceKey();
  else key = owner.key();
  if (key === '') throw new WorkspaceFailed('workspace_owner_not_addressable', 'Workspace owner key cannot be empty.');
  const slug = key.replace(/[^A-Za-z0-9]+/gu, '-').toLowerCase().replace(/^-|-$/gu, '')
    .slice(0, 48).replace(/-$/u, '') || 'w';
  const digest = createHash('sha256').update(key).digest('hex').slice(0, 16);
  return guard.guard(`${slug}-${digest}`);
}

/** Filesystem half of containment. The relative path must already be guarded. */
export class LocalBoundary {
  readonly root: string;

  constructor(root: string, readonly windowsMaxPath: number | null = 259) {
    if (!isAbsolute(root)) throw new TypeError('LocalBoundary root must be absolute.');
    this.root = resolve(root);
  }

  admit(relativePath: string): void {
    const target = join(this.root, ...relativePath.split('/'));
    if (process.platform === 'win32' && this.windowsMaxPath !== null && target.length > this.windowsMaxPath)
      refuse('path_too_long', relativePath);
    if (!existsSync(this.root)) return;
    const root = realpathSync.native(this.root);
    let candidate = target;
    for (let depth = 0; depth < 64; depth += 1) {
      if (existsSync(candidate)) {
        const resolved = realpathSync.native(candidate);
        if (!this.within(root, resolved)) refuse('path_escapes_workspace_via_link', relativePath);
        return;
      }
      const parent = dirname(candidate);
      if (parent === candidate || relative(this.root, parent).startsWith(`..${sep}`)) return;
      candidate = parent;
    }
  }

  private within(root: string, candidate: string): boolean {
    const normalize = (value: string) => process.platform === 'win32' ? value.toLowerCase() : value;
    const fromRoot = relative(normalize(root), normalize(candidate));
    return fromRoot === '' || (!fromRoot.startsWith('..') && !isAbsolute(fromRoot));
  }
}

/**
 * A path, as a string or as RAW BYTES.
 *
 * Bytes because a path is a byte string in the reference, and because the
 * corpus's byte-injection cases cannot be expressed as JavaScript strings at
 * all -- an invalid UTF-8 sequence becomes U+FFFD on the way in, so a
 * string-only API could never carry the attack the guard exists to refuse.
 * Everything downstream of `admit()` sees the guarded string.
 */
export type WorkspacePath = string | Uint8Array;

export type WorkspaceAbility = 'read' | 'write' | 'delete' | 'list';
export type Authorizer = (ability: WorkspaceAbility, workspace: Workspace, path?: string) => void | Promise<void>;

export interface WorkspaceEntry {
  path: string;
  isDirectory: boolean;
  size: number | null;
  lastModified: number | null;
}

export interface WorkspaceOptions {
  guard?: PathGuard;
  authorize?: Authorizer;
  windowsMaxPath?: number | null;
}

export class Workspace {
  readonly root: string;
  readonly address: string;
  private readonly guard: PathGuard;
  private readonly boundary: LocalBoundary;
  private readonly authorize?: Authorizer;

  constructor(baseDirectory: string, owner: WorkspaceIdentity, options: WorkspaceOptions = {}) {
    this.guard = options.guard ?? new PathGuard();
    this.address = workspaceAddress(owner, this.guard);
    this.root = resolve(baseDirectory, this.address);
    this.boundary = new LocalBoundary(this.root, options.windowsMaxPath);
    this.authorize = options.authorize;
  }

  path(path: WorkspacePath): string { return this.guard.guard(path); }

  async exists(path: WorkspacePath): Promise<boolean> {
    const admitted = await this.admit(path, 'read');
    try { await stat(this.absolute(admitted)); return true; } catch (error) {
      if (isMissing(error)) return false;
      throw error;
    }
  }

  async read(path: WorkspacePath): Promise<string> {
    const admitted = await this.admit(path, 'read');
    try { return await readFile(this.absolute(admitted), 'utf8'); }
    catch (error) { if (isMissing(error)) throw missing(path, error); throw error; }
  }

  /**
   * The bytes, undecoded.
   *
   * `read()` decodes as UTF-8, which silently corrupts anything that is not
   * text — and an agent workspace holds images and archives as readily as it
   * holds source. `prism-workspace-py` had this and this port did not, which is
   * the drift the parity work exists to catch.
   */
  async readBytes(path: WorkspacePath): Promise<Uint8Array> {
    const admitted = await this.admit(path, 'read');
    try { return Uint8Array.from(await readFile(this.absolute(admitted))); }
    catch (error) { if (isMissing(error)) throw missing(path, error); throw error; }
  }

  /**
   * A readable stream over the file, for content too large to hold in memory.
   *
   * Goes through `admit()` like every other read, BEFORE the handle is opened.
   * A streaming accessor that skipped the guard would be a hole straight
   * through the boundary this package exists to be, and it would look like an
   * optimisation.
   */
  async readStream(path: WorkspacePath): Promise<Readable> {
    const admitted = await this.admit(path, 'read');
    let handle: FileHandle;

    try { handle = await open(this.absolute(admitted), 'r'); }
    catch (error) { if (isMissing(error)) throw missing(path, error); throw error; }

    // `autoClose` is the default for a handle-backed stream, but it is stated
    // rather than assumed: a leaked descriptor per read is invisible until a
    // long-running agent exhausts the table.
    return handle.createReadStream({ autoClose: true });
  }

  /**
   * Write from a stream, without buffering the whole payload.
   *
   * Accepts anything iterable in chunks, so a caller can pipe a download or a
   * generator straight in. Parent directories are created first, matching
   * `write()`.
   */
  async writeStream(
    path: WorkspacePath,
    source: Readable | AsyncIterable<Uint8Array | string> | Iterable<Uint8Array | string>,
  ): Promise<this> {
    const admitted = await this.admit(path, 'write');
    const target = this.absolute(admitted);

    try {
      await mkdir(dirname(target), { recursive: true });
      const handle = await open(target, 'w');

      try { await pipeline(source as AsyncIterable<Uint8Array>, handle.createWriteStream()); }
      finally { await handle.close().catch(() => undefined); }

      return this;
    } catch (error) {
      throw failed('workspace_write_failed', `Could not write [${path}] to this workspace.`, error);
    }
  }

  async write(path: WorkspacePath, contents: string | Uint8Array): Promise<this> {
    const admitted = await this.admit(path, 'write');
    const target = this.absolute(admitted);
    try { await mkdir(dirname(target), { recursive: true }); await writeFile(target, contents); return this; }
    catch (error) { throw failed('workspace_write_failed', `Could not write [${path}] to this workspace.`, error); }
  }

  async append(path: WorkspacePath, contents: string | Uint8Array): Promise<this> {
    const admitted = await this.admit(path, 'write');
    const target = this.absolute(admitted);
    try { await mkdir(dirname(target), { recursive: true }); await appendFile(target, contents); return this; }
    catch (error) { throw failed('workspace_write_failed', `Could not append [${path}] to this workspace.`, error); }
  }

  async copy(from: WorkspacePath, to: WorkspacePath): Promise<this> {
    const source = await this.admit(from, 'read');
    const destination = await this.admit(to, 'write');
    try { await mkdir(dirname(this.absolute(destination)), { recursive: true }); await copyFile(this.absolute(source), this.absolute(destination)); return this; }
    catch (error) { throw failed('workspace_write_failed', `Could not copy [${from}] to [${to}].`, error); }
  }

  async move(from: WorkspacePath, to: WorkspacePath): Promise<this> {
    const source = await this.admit(from, 'write');
    const destination = await this.admit(to, 'write');
    try { await mkdir(dirname(this.absolute(destination)), { recursive: true }); await rename(this.absolute(source), this.absolute(destination)); return this; }
    catch (error) { throw failed('workspace_write_failed', `Could not move [${from}] to [${to}].`, error); }
  }

  async delete(path: WorkspacePath): Promise<this> {
    const admitted = await this.admit(path, 'delete');
    try { await rm(this.absolute(admitted), { force: true }); return this; }
    catch (error) { throw failed('workspace_delete_failed', `Could not delete [${path}] from this workspace.`, error); }
  }

  async makeDirectory(path: WorkspacePath): Promise<this> {
    const admitted = await this.admit(path, 'write');
    try { await mkdir(this.absolute(admitted), { recursive: true }); return this; }
    catch (error) { throw failed('workspace_write_failed', `Could not create [${path}].`, error); }
  }

  async deleteDirectory(path: WorkspacePath): Promise<this> {
    const admitted = await this.admit(path, 'delete');
    try { await rm(this.absolute(admitted), { recursive: true, force: true }); return this; }
    catch (error) { throw failed('workspace_delete_failed', `Could not delete [${path}].`, error); }
  }

  async size(path: WorkspacePath): Promise<number> {
    const admitted = await this.admit(path, 'read');
    try { return (await stat(this.absolute(admitted))).size; }
    catch (error) { if (isMissing(error)) throw missing(path, error); throw error; }
  }

  async lastModified(path: WorkspacePath): Promise<number> {
    const admitted = await this.admit(path, 'read');
    try { return Math.floor((await stat(this.absolute(admitted))).mtimeMs / 1000); }
    catch (error) { if (isMissing(error)) throw missing(path, error); throw error; }
  }

  async *list(directory = '', recursive = true): AsyncGenerator<WorkspaceEntry> {
    const location = directory === '' ? '' : await this.admit(directory, 'list');
    if (directory === '') await this.authorize?.('list', this);
    const start = location === '' ? this.root : this.absolute(location);
    if (!existsSync(start)) return;
    yield* this.walk(start, location, recursive);
  }

  async clear(): Promise<this> {
    await this.authorize?.('delete', this);
    if (!existsSync(this.root)) return this;
    for await (const entry of await opendir(this.root))
      await rm(join(this.root, entry.name), { recursive: true, force: true });
    return this;
  }

  private async *walk(directory: string, prefix: string, recursive: boolean): AsyncGenerator<WorkspaceEntry> {
    for await (const entry of await opendir(directory)) {
      const entryPath = prefix ? `${prefix}/${entry.name}` : entry.name;
      yield { path: entryPath, isDirectory: entry.isDirectory(), size: null, lastModified: null };
      if (recursive && entry.isDirectory()) yield* this.walk(join(directory, entry.name), entryPath, true);
    }
  }

  private async admit(path: WorkspacePath, ability: WorkspaceAbility): Promise<string> {
    const guarded = this.guard.guard(path);
    await this.authorize?.(ability, this, guarded);
    this.boundary.admit(guarded);
    return guarded;
  }

  private absolute(path: string): string { return join(this.root, ...path.split('/')); }
}

function isMissing(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT';
}
function missing(path: WorkspacePath, cause: unknown): WorkspaceFailed {
  return new WorkspaceFailed('workspace_file_missing', `There is no [${path}] in this workspace.`, { cause });
}
function failed(code: FaultCode, message: string, cause: unknown): WorkspaceFailed {
  return new WorkspaceFailed(code, message, { cause });
}
