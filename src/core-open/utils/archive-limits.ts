// VENDORED from @vibgrate/core-open (packages/vibgrate-core-open) by
// scripts/vendor-core-open.mjs. Do not edit here — change the source package
// and re-run the vendor script. Apache-2.0.
/**
 * Size and entry caps for the places that inflate an archive.
 *
 * `vg build` and `vg scan` do not open archive files while they walk a tree.
 * The scan walk skips archive extensions, and file discovery only opens source
 * files. This module is the inflation guard for a ZIP package-version manifest
 * and for a gzip-compressed module tarball. Nothing here unpacks past the cap:
 * a declared size or entry count over the limit is refused before inflate, and
 * inflate itself is bounded.
 *
 * The same bytes and the same caps always produce the same error. Entry count
 * is checked before uncompressed size, so an archive that breaks both limits
 * reports the entry limit. `0` disables that one cap.
 */
import * as fs from 'node:fs/promises';
import * as zlib from 'node:zlib';

/** Default entry cap. A package-version ZIP and a module tarball are far smaller. */
export const DEFAULT_MAX_ARCHIVE_ENTRIES = 10_000;

/** Default uncompressed-byte cap (256 MiB). */
export const DEFAULT_MAX_ARCHIVE_UNCOMPRESSED_BYTES = 256 * 1024 * 1024;

export const ARCHIVE_ENTRIES_ENV = 'VG_MAX_ARCHIVE_ENTRIES';
export const ARCHIVE_BYTES_ENV = 'VG_MAX_ARCHIVE_BYTES';

const ZIP64_ENTRIES = 0xffff;
const ZIP64_SIZE = 0xffffffff;
const EOCD_SIG = 0x06054b50;
const CD_SIG = 0x02014b50;
const LOCAL_SIG = 0x04034b50;

export interface ArchiveLimits {
  /** `0` disables the entry cap. */
  maxEntries: number;
  /** `0` disables the uncompressed-byte cap. */
  maxUncompressedBytes: number;
}

export type ArchiveLimitKind = 'entries' | 'bytes';

/** A walk or a read stopped because an archive is over a cap. The message is the UX. */
export class ArchiveLimitError extends Error {
  readonly isArchiveLimitError = true;
  readonly archivePath: string;
  readonly limit: number;
  readonly kind: ArchiveLimitKind;

  constructor(message: string, archivePath: string, limit: number, kind: ArchiveLimitKind) {
    super(message);
    this.name = 'ArchiveLimitError';
    this.archivePath = archivePath;
    this.limit = limit;
    this.kind = kind;
  }
}

/** The bytes are not a usable ZIP member. Callers map this to their own not-usable error. */
export class ArchiveReadError extends Error {
  readonly isArchiveReadError = true;

  constructor(message: string) {
    super(message);
    this.name = 'ArchiveReadError';
  }
}

interface ZipMember {
  name: string;
  method: number;
  flags: number;
  compressedSize: number;
  uncompressedSize: number;
  localHeaderOffset: number;
}

function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === '') return fallback;
  const n = Number(raw);
  return Number.isInteger(n) && n >= 0 ? n : fallback;
}

function cleanLimit(value: number | undefined, envName: string, fallback: number): number {
  if (value !== undefined) return Number.isInteger(value) && value >= 0 ? value : fallback;
  return envInt(envName, fallback);
}

/** Explicit overrides win, then the environment, then the defaults. */
export function resolveArchiveLimits(override: Partial<ArchiveLimits> = {}): ArchiveLimits {
  return {
    maxEntries: cleanLimit(override.maxEntries, ARCHIVE_ENTRIES_ENV, DEFAULT_MAX_ARCHIVE_ENTRIES),
    maxUncompressedBytes: cleanLimit(
      override.maxUncompressedBytes,
      ARCHIVE_BYTES_ENV,
      DEFAULT_MAX_ARCHIVE_UNCOMPRESSED_BYTES,
    ),
  };
}

/** Stable, locale-independent label for a byte cap ("256 MiB", "64-byte"). */
export function formatByteLimit(n: number): string {
  const mib = 1024 * 1024;
  if (n >= mib && n % mib === 0) return `${n / mib} MiB`;
  if (n >= 1024 && n % 1024 === 0) return `${n / 1024} KiB`;
  return `${n}-byte`;
}

export function archiveBytesMessage(archivePath: string, actual: number, limit: number): string {
  return (
    `Refusing to read archive ${archivePath}: ${actual} bytes exceeds the ${formatByteLimit(limit)} limit. ` +
    'Exclude this path or pass a smaller archive, then run the command again. ' +
    `Set ${ARCHIVE_BYTES_ENV} to raise the limit (0 disables it).`
  );
}

export function archiveOutputMessage(archivePath: string, limit: number): string {
  return (
    `Refusing to read archive ${archivePath}: uncompressed output exceeds the ${formatByteLimit(limit)} limit. ` +
    'Exclude this path or pass a smaller archive, then run the command again. ' +
    `Set ${ARCHIVE_BYTES_ENV} to raise the limit (0 disables it).`
  );
}

export function archiveEntriesMessage(archivePath: string, actual: number, limit: number): string {
  return (
    `Refusing to read archive ${archivePath}: it declares ${actual} entries, over the ${limit}-entry limit. ` +
    'Exclude this path or pass a smaller archive, then run the command again. ' +
    `Set ${ARCHIVE_ENTRIES_ENV} to raise the limit (0 disables it).`
  );
}

function bytesError(archivePath: string, actual: number, limit: number): ArchiveLimitError {
  return new ArchiveLimitError(archiveBytesMessage(archivePath, actual, limit), archivePath, limit, 'bytes');
}

function outputError(archivePath: string, limit: number): ArchiveLimitError {
  return new ArchiveLimitError(archiveOutputMessage(archivePath, limit), archivePath, limit, 'bytes');
}

function entriesError(archivePath: string, actual: number, limit: number): ArchiveLimitError {
  return new ArchiveLimitError(archiveEntriesMessage(archivePath, actual, limit), archivePath, limit, 'entries');
}

function assertByteLimit(archivePath: string, actual: number, limits: ArchiveLimits): void {
  if (limits.maxUncompressedBytes <= 0) return;
  if (actual > limits.maxUncompressedBytes) throw bytesError(archivePath, actual, limits.maxUncompressedBytes);
}

function isBufferTooLarge(err: unknown): boolean {
  return Boolean(err) && typeof err === 'object' && (err as { code?: unknown }).code === 'ERR_BUFFER_TOO_LARGE';
}

/**
 * Read an archive file only when its on-disk size is within the byte cap.
 * A larger file is refused before it is read.
 */
export async function readBoundedArchive(
  archivePath: string,
  override?: Partial<ArchiveLimits>,
): Promise<Buffer> {
  const limits = resolveArchiveLimits(override);
  const info = await fs.stat(archivePath);
  assertByteLimit(archivePath, info.size, limits);
  const buf = await fs.readFile(archivePath);
  assertByteLimit(archivePath, buf.length, limits);
  return buf;
}

function need(buf: Buffer, start: number, len: number): void {
  if (
    !Number.isSafeInteger(start) ||
    !Number.isSafeInteger(len) ||
    start < 0 ||
    len < 0 ||
    start > buf.length - len
  ) {
    throw new ArchiveReadError('truncated archive');
  }
}

function findEocd(buf: Buffer): number {
  if (buf.length < 22) throw new ArchiveReadError('truncated archive');
  const maxComment = Math.min(buf.length - 22, 65535);
  for (let comment = 0; comment <= maxComment; comment++) {
    const pos = buf.length - 22 - comment;
    if (buf.readUInt32LE(pos) !== EOCD_SIG) continue;
    if (buf.readUInt16LE(pos + 20) !== comment) continue;
    return pos;
  }
  throw new ArchiveReadError('not a zip archive');
}

function zipName(raw: Buffer): string {
  const end = raw.indexOf(0);
  const text = (end === -1 ? raw : raw.subarray(0, end)).toString('utf8');
  return text.replace(/\\/g, '/').replace(/^\.\//, '');
}

function listZipMembers(buf: Buffer, archivePath: string, limits: ArchiveLimits): ZipMember[] {
  const eocd = findEocd(buf);
  const totalEntries = buf.readUInt16LE(eocd + 10);
  const cdSize = buf.readUInt32LE(eocd + 12);
  const cdOffset = buf.readUInt32LE(eocd + 16);

  if (totalEntries === ZIP64_ENTRIES || cdSize === ZIP64_SIZE || cdOffset === ZIP64_SIZE) {
    if (limits.maxEntries > 0 && (totalEntries === ZIP64_ENTRIES || totalEntries > limits.maxEntries)) {
      const declared = totalEntries === ZIP64_ENTRIES ? ZIP64_ENTRIES : totalEntries;
      throw entriesError(archivePath, declared, limits.maxEntries);
    }
    if (limits.maxUncompressedBytes > 0) {
      throw bytesError(archivePath, ZIP64_SIZE, limits.maxUncompressedBytes);
    }
    throw new ArchiveReadError('zip64 archive');
  }

  if (limits.maxEntries > 0 && totalEntries > limits.maxEntries) {
    throw entriesError(archivePath, totalEntries, limits.maxEntries);
  }

  need(buf, cdOffset, 0);
  const cdEnd = cdOffset + cdSize;
  if (cdEnd > buf.length) throw new ArchiveReadError('truncated archive');

  const members: ZipMember[] = [];
  let offset = cdOffset;
  let seen = 0;
  let uncompressedTotal = 0;
  while (seen < totalEntries) {
    need(buf, offset, 46);
    if (buf.readUInt32LE(offset) !== CD_SIG) throw new ArchiveReadError('truncated archive');
    const flags = buf.readUInt16LE(offset + 8);
    const method = buf.readUInt16LE(offset + 10);
    const compressedSize = buf.readUInt32LE(offset + 20);
    const uncompressedSize = buf.readUInt32LE(offset + 24);
    const nameLen = buf.readUInt16LE(offset + 28);
    const extraLen = buf.readUInt16LE(offset + 30);
    const commentLen = buf.readUInt16LE(offset + 32);
    const localHeaderOffset = buf.readUInt32LE(offset + 42);
    need(buf, offset + 46, nameLen + extraLen + commentLen);
    const name = zipName(buf.subarray(offset + 46, offset + 46 + nameLen));
    offset += 46 + nameLen + extraLen + commentLen;

    seen += 1;
    if (limits.maxEntries > 0 && seen > limits.maxEntries) {
      throw entriesError(archivePath, seen, limits.maxEntries);
    }
    if (uncompressedSize === ZIP64_SIZE || compressedSize === ZIP64_SIZE) {
      if (limits.maxUncompressedBytes > 0) {
        throw bytesError(archivePath, ZIP64_SIZE, limits.maxUncompressedBytes);
      }
      throw new ArchiveReadError('zip64 archive');
    }
    if (limits.maxUncompressedBytes > 0 && uncompressedSize > limits.maxUncompressedBytes) {
      throw bytesError(archivePath, uncompressedSize, limits.maxUncompressedBytes);
    }
    uncompressedTotal += uncompressedSize;
    if (limits.maxUncompressedBytes > 0 && uncompressedTotal > limits.maxUncompressedBytes) {
      throw bytesError(archivePath, uncompressedTotal, limits.maxUncompressedBytes);
    }
    if (flags & 1) throw new ArchiveReadError('encrypted archive');
    if (name.endsWith('/')) continue;
    members.push({ name, method, flags, compressedSize, uncompressedSize, localHeaderOffset });
  }
  return members;
}

function inflateMember(buf: Buffer, archivePath: string, member: ZipMember, limits: ArchiveLimits): Buffer {
  need(buf, member.localHeaderOffset, 30);
  if (buf.readUInt32LE(member.localHeaderOffset) !== LOCAL_SIG) throw new ArchiveReadError('truncated archive');
  const nameLen = buf.readUInt16LE(member.localHeaderOffset + 26);
  const extraLen = buf.readUInt16LE(member.localHeaderOffset + 28);
  const dataStart = member.localHeaderOffset + 30 + nameLen + extraLen;
  need(buf, dataStart, member.compressedSize);
  const data = buf.subarray(dataStart, dataStart + member.compressedSize);
  const cap = limits.maxUncompressedBytes;

  if (member.method === 0) {
    assertByteLimit(archivePath, data.length, limits);
    return Buffer.from(data);
  }
  if (member.method !== 8) throw new ArchiveReadError('unsupported compression');
  if (cap <= 0) return zlib.inflateRawSync(data);
  try {
    const out = zlib.inflateRawSync(data, { maxOutputLength: cap + 1 });
    if (out.length > cap) throw bytesError(archivePath, out.length, cap);
    return out;
  } catch (err) {
    if (err instanceof ArchiveLimitError) throw err;
    if (isBufferTooLarge(err)) throw outputError(archivePath, cap);
    throw new ArchiveReadError('truncated archive');
  }
}

/**
 * Inflate the first named member, in the order given (not central-directory
 * order). Refuses the archive before inflate when the central directory
 * declares too many entries or too many uncompressed bytes.
 */
export function readZipMember(
  buf: Buffer,
  archivePath: string,
  names: readonly string[],
  override?: Partial<ArchiveLimits>,
): Buffer {
  const limits = resolveArchiveLimits(override);
  const members = listZipMembers(buf, archivePath, limits);
  for (const name of names) {
    const member = members.find((item) => item.name === name);
    if (member) return inflateMember(buf, archivePath, member, limits);
  }
  throw new ArchiveReadError('archive member not found');
}

/**
 * Gunzip with the uncompressed cap pinned on zlib, so a gzip bomb is refused
 * before the full output exists. The compressed buffer itself must also fit
 * in the cap.
 */
export function gunzipBounded(gz: Buffer, archivePath: string, override?: Partial<ArchiveLimits>): Buffer {
  const limits = resolveArchiveLimits(override);
  assertByteLimit(archivePath, gz.length, limits);
  if (limits.maxUncompressedBytes <= 0) return zlib.gunzipSync(gz);
  const cap = limits.maxUncompressedBytes;
  try {
    const out = zlib.gunzipSync(gz, { maxOutputLength: cap + 1 });
    if (out.length > cap) throw bytesError(archivePath, out.length, cap);
    return out;
  } catch (err) {
    if (err instanceof ArchiveLimitError) throw err;
    if (isBufferTooLarge(err)) throw outputError(archivePath, cap);
    throw err;
  }
}
