import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import { mkdtempSync, rmSync } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as zlib from 'node:zlib';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  ArchiveLimitError,
  gunzipBounded,
  readBoundedArchive,
  readZipMember,
} from '../src/core-open/utils/archive-limits.js';
import { FileCache } from '../src/core-open/utils/fs.js';
import { loadPackageVersionManifest as loadCoreManifest } from '../src/core-open/package-version-manifest.js';
import { discover } from '../src/engine/discover.js';
import { untar } from '../src/install/module-core.js';
import { PackageManifestError, loadPackageVersionManifest } from '../src/reporting/package-version-manifest.js';
import { scanCommand } from '../src/reporting/commands/scan.js';
import { CliError, ExitCode } from '../src/util/exit.js';

const SENTINEL = 'archive-body-sentinel-9f3a2c';
const GIB = 1024 * 1024 * 1024;

function u16(n: number): Buffer {
  const buf = Buffer.alloc(2);
  buf.writeUInt16LE(n);
  return buf;
}

function u32(n: number): Buffer {
  const buf = Buffer.alloc(4);
  buf.writeUInt32LE(n >>> 0);
  return buf;
}

interface ZipEntry {
  name: string;
  data: Buffer;
  method?: number;
  /** Central-directory uncompressed size. Defaults to `data.length`. */
  declaredSize?: number;
}

/** Tiny ZIP. `comment` is stored only in the end-of-central-directory record. */
function craftZip(entries: ZipEntry[], comment = ''): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name);
    const method = entry.method ?? 0;
    const declared = entry.declaredSize ?? entry.data.length;
    const local = Buffer.concat([
      u32(0x04034b50),
      u16(20),
      u16(0),
      u16(method),
      u16(0),
      u16(0),
      u32(0),
      u32(entry.data.length),
      u32(declared),
      u16(name.length),
      u16(0),
      name,
      entry.data,
    ]);
    const central = Buffer.concat([
      u32(0x02014b50),
      u16(20),
      u16(20),
      u16(0),
      u16(method),
      u16(0),
      u16(0),
      u32(0),
      u32(entry.data.length),
      u32(declared),
      u16(name.length),
      u16(0),
      u16(0),
      u16(0),
      u16(0),
      u32(0),
      u32(offset),
      name,
    ]);
    locals.push(local);
    centrals.push(central);
    offset += local.length;
  }
  const cd = Buffer.concat(centrals);
  const commentBuf = Buffer.from(comment);
  const eocd = Buffer.concat([
    u32(0x06054b50),
    u16(0),
    u16(0),
    u16(entries.length),
    u16(entries.length),
    u32(cd.length),
    u32(offset),
    u16(commentBuf.length),
    commentBuf,
  ]);
  return Buffer.concat([...locals, cd, eocd]);
}

function tarHeader(name: string): Buffer {
  const block = Buffer.alloc(512);
  block.write(name);
  block.write('00000000000', 124);
  block[156] = '0'.charCodeAt(0);
  return block;
}

function bytesMessage(archivePath: string, actual: number, limitLabel: string): string {
  return (
    `Refusing to read archive ${archivePath}: ${actual} bytes exceeds the ${limitLabel} limit. ` +
    'Exclude this path or pass a smaller archive, then run the command again. ' +
    'Set VG_MAX_ARCHIVE_BYTES to raise the limit (0 disables it).'
  );
}

function outputMessage(archivePath: string, limitLabel: string): string {
  return (
    `Refusing to read archive ${archivePath}: uncompressed output exceeds the ${limitLabel} limit. ` +
    'Exclude this path or pass a smaller archive, then run the command again. ' +
    'Set VG_MAX_ARCHIVE_BYTES to raise the limit (0 disables it).'
  );
}

function entriesMessage(archivePath: string, actual: number, limit: number): string {
  return (
    `Refusing to read archive ${archivePath}: it declares ${actual} entries, over the ${limit}-entry limit. ` +
    'Exclude this path or pass a smaller archive, then run the command again. ' +
    'Set VG_MAX_ARCHIVE_ENTRIES to raise the limit (0 disables it).'
  );
}

function assertNoSentinel(message: string): void {
  expect(message).not.toContain(SENTINEL);
}

describe('archive limits', () => {
  const dirs: string[] = [];

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
    for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
    dirs.length = 0;
  });

  function tempDir(): string {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'vg-archive-'));
    dirs.push(dir);
    return dir;
  }

  it('refuses a ZIP that declares an uncompressed size over the cap', () => {
    const zipPath = path.join(tempDir(), 'bomb.zip');
    const bytes = craftZip(
      [{ name: 'package-versions.json', data: Buffer.from(SENTINEL), declaredSize: GIB }],
      SENTINEL,
    );
    const message = bytesMessage(zipPath, GIB, '256 MiB');
    const first = () => readZipMember(bytes, zipPath, ['package-versions.json']);
    expect(first).toThrow(ArchiveLimitError);
    expect(first).toThrow(message);
    expect(first).toThrow(message);
    try {
      first();
    } catch (err) {
      expect(err).toMatchObject({ kind: 'bytes', limit: 256 * 1024 * 1024, archivePath: zipPath });
      assertNoSentinel((err as Error).message);
    }
  });

  it('refuses a ZIP with too many entries before a size failure', () => {
    const zipPath = path.join(tempDir(), 'many.zip');
    const bytes = craftZip([
      { name: 'a.txt', data: Buffer.alloc(0), declaredSize: GIB },
      { name: 'b.txt', data: Buffer.alloc(0), declaredSize: GIB },
      { name: 'c.txt', data: Buffer.alloc(0), declaredSize: GIB },
    ]);
    const message = entriesMessage(zipPath, 3, 2);
    expect(() => readZipMember(bytes, zipPath, ['a.txt'], { maxEntries: 2 })).toThrow(message);
  });

  it('refuses a deflate member whose output exceeds the cap', () => {
    const zipPath = path.join(tempDir(), 'inflate.zip');
    const payload = Buffer.alloc(200, 7);
    const compressed = zlib.deflateRawSync(payload);
    const bytes = craftZip([
      { name: 'package-versions.json', data: compressed, method: 8, declaredSize: 10 },
    ]);
    const message = outputMessage(zipPath, '50-byte');
    expect(() => readZipMember(bytes, zipPath, ['package-versions.json'], { maxUncompressedBytes: 50 })).toThrow(
      message,
    );
  });

  it('reads one named member and ignores central-directory order', () => {
    const zipPath = path.join(tempDir(), 'ok.zip');
    const bytes = craftZip([
      { name: 'manifest.json', data: Buffer.from('{"npm":{"later":true}}') },
      { name: 'package-versions.json', data: Buffer.from('{"npm":{"react":{"latest":"19.0.0"}}}') },
    ]);
    const body = readZipMember(bytes, zipPath, ['package-versions.json', 'manifest.json']);
    expect(body.toString('utf8')).toBe('{"npm":{"react":{"latest":"19.0.0"}}}');
  });

  it('refuses an on-disk archive over the cap before reading it', async () => {
    const file = path.join(tempDir(), 'wide.zip');
    const handle = await fsp.open(file, 'w');
    await handle.truncate(GIB);
    await handle.close();
    const message = bytesMessage(file, GIB, '1 KiB');
    await expect(readBoundedArchive(file, { maxUncompressedBytes: 1024 })).rejects.toThrow(message);
  });

  it('surfaces the same limit error from a package-version ZIP', async () => {
    const dir = tempDir();
    const zipPath = path.join(dir, 'package-versions.zip');
    fs.writeFileSync(
      zipPath,
      craftZip([{ name: 'package-versions.json', data: Buffer.from(`{"npm":{},"note":"${SENTINEL}"}`), declaredSize: GIB }]),
    );
    const message = bytesMessage(zipPath, GIB, '256 MiB');

    const reporting = await loadPackageVersionManifest(zipPath).catch((err: unknown) => err);
    expect(reporting).toBeInstanceOf(PackageManifestError);
    expect(reporting).toMatchObject({ failure: 'unusable', message });
    assertNoSentinel((reporting as Error).message);

    const core = await loadCoreManifest(zipPath).catch((err: unknown) => err);
    expect(core).toBeInstanceOf(ArchiveLimitError);
    expect((core as Error).message).toBe(message);
  });

  it('still loads a stored ZIP package-version manifest', async () => {
    const dir = tempDir();
    const zipPath = path.join(dir, 'package-versions.zip');
    execFileSync('python3', [
      '-c',
      'import sys, zipfile; zipfile.ZipFile(sys.argv[1], "w").writestr(sys.argv[2], sys.argv[3])',
      zipPath,
      'package-versions.json',
      JSON.stringify({ npm: { react: { latest: '19.0.0' } } }),
    ]);
    const manifest = await loadPackageVersionManifest(zipPath);
    expect(manifest.npm?.react?.latest).toBe('19.0.0');
    const core = await loadCoreManifest(zipPath);
    expect(core.npm?.react?.latest).toBe('19.0.0');
  });

  it('stops vg scan before the walk when the manifest ZIP is over the cap', async () => {
    const dir = tempDir();
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 't', version: '1.0.0' }));
    fs.writeFileSync(path.join(dir, 'app.ts'), 'export const n = 1;\n');
    const zipPath = path.join(dir, 'package-versions.zip');
    fs.writeFileSync(
      zipPath,
      craftZip([{ name: 'package-versions.json', data: Buffer.from(SENTINEL), declaredSize: GIB }], SENTINEL),
    );
    vi.stubEnv('VIBGRATE_DSN', '');
    vi.stubEnv('VIBGRATE_NO_KERNEL', '1');
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation(((code?: number) => {
      throw new Error(`process.exit(${code}) called`);
    }) as never);
    const error = await scanCommand
      .parseAsync(['node', 'scan', dir, '--offline', '--no-daemon', '--no-graph', '--quiet', '--package-manifest', zipPath])
      .then(
        () => {
          throw new Error('expected the over-limit manifest to fail the scan');
        },
        (err: unknown) => err,
      );
    expect(error).toBeInstanceOf(CliError);
    expect(error).toMatchObject({ code: ExitCode.ERROR, message: bytesMessage(zipPath, GIB, '256 MiB') });
    assertNoSentinel((error as Error).message);
    expect(exitSpy).not.toHaveBeenCalled();
    expect(fs.existsSync(path.join(dir, '.vibgrate'))).toBe(false);
  });

  it('does not include an archive while vg build discovers files', () => {
    const dir = tempDir();
    const zipPath = path.join(dir, 'bomb.zip');
    fs.writeFileSync(zipPath, craftZip([{ name: 'package-versions.json', data: Buffer.from(SENTINEL), declaredSize: GIB }]));
    fs.writeFileSync(path.join(dir, 'app.ts'), 'export const n = 1;\n');
    const found = discover({ root: dir, maxEntries: 100 });
    expect(found.map((file) => file.rel)).toEqual(['app.ts']);
  });

  it('does not include an archive while a scan walk lists files', async () => {
    const dir = tempDir();
    const zipPath = path.join(dir, 'bomb.zip');
    await fsp.writeFile(zipPath, craftZip([{ name: 'x.txt', data: Buffer.from(SENTINEL), declaredSize: GIB }]));
    await fsp.writeFile(path.join(dir, 'app.ts'), 'export const n = 1;\n');
    const entries = await new FileCache().walkDir(dir);
    const files = entries.filter((entry) => entry.isFile).map((entry) => entry.name).sort();
    expect(files).toEqual(['app.ts']);
  });

  it('refuses a gzip bomb at the inflate cap', () => {
    const gz = zlib.gzipSync(Buffer.alloc(80, 3));
    expect(gz.length).toBeLessThan(40);
    const message = outputMessage('module.tgz', '40-byte');
    expect(() => gunzipBounded(gz, 'module.tgz', { maxUncompressedBytes: 40 })).toThrow(message);
    const small = gunzipBounded(gz, 'module.tgz', { maxUncompressedBytes: 80 });
    expect(small.length).toBe(80);
  });

  it('refuses a tarball with too many entries', () => {
    vi.stubEnv('VG_MAX_ARCHIVE_ENTRIES', '2');
    const tar = Buffer.concat([
      tarHeader('a.txt'),
      tarHeader('b.txt'),
      tarHeader('c.txt'),
      Buffer.alloc(1024),
    ]);
    expect(() => untar(tar, 'sample.tar')).toThrow(entriesMessage('sample.tar', 3, 2));
  });
});
