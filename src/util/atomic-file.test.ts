import { afterEach, describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { CliError } from './exit.js';
import {
  isPidAlive,
  setAtomicWriteFaultForTests,
  sweepStrayAtomicTemps,
  writeAtomicSync,
} from './atomic-file.js';
import { writeJsonFile } from '../core-open/utils/fs.js';
import { writeTextFile } from '../reporting/utils/fs.js';

const dirs: string[] = [];

function tempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-atomic-'));
  dirs.push(dir);
  return dir;
}

afterEach(() => {
  setAtomicWriteFaultForTests(null);
  while (dirs.length) fs.rmSync(dirs.pop()!, { recursive: true, force: true });
});

function deadPid(): number {
  for (let pid = 2_000_000_000; pid < 2_000_000_050; pid++) {
    if (!isPidAlive(pid)) return pid;
  }
  throw new Error('expected a pid that is not running');
}

function byName(a: string, b: string): number {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

describe('sweepStrayAtomicTemps', () => {
  it('removes dead temps in sorted name order and keeps live writers', () => {
    const dir = tempDir();
    const dead = [
      '.scan_result.json.7.vg-tmp',
      '.baseline.json.9.vg-tmp',
      'scan_result.json.4.tmp',
      'scan_result.json.4.2.tmp',
      'scan_result.json.tmp.3',
    ];
    const live = ['.graph.json.42.vg-tmp', 'scan_result.json.42.tmp'];
    for (const name of [...dead].reverse()) fs.writeFileSync(path.join(dir, name), '{');
    for (const name of live) fs.writeFileSync(path.join(dir, name), '{');
    fs.writeFileSync(path.join(dir, 'notes.7.tmp'), 'user file');

    const removed = sweepStrayAtomicTemps(dir, {
      basename: 'scan_result.json',
      alive: (pid) => pid === 42,
    });

    expect(removed).toEqual([...dead].sort(byName));
    for (const name of live) expect(fs.existsSync(path.join(dir, name))).toBe(true);
    expect(fs.readFileSync(path.join(dir, 'notes.7.tmp'), 'utf8')).toBe('user file');
  });
});

describe('atomic artifact writes', () => {
  it('writes the same bytes on a normal run and leaves no temp', () => {
    const dir = tempDir();
    const file = path.join(dir, '.vibgrate', 'baseline.json');
    const body = '{"score":12,"items":["a","b"]}\n';
    writeAtomicSync(file, body);
    writeAtomicSync(file, body);
    expect(fs.readFileSync(file, 'utf8')).toBe(body);
    expect(fs.readdirSync(path.dirname(file)).filter((name) => name.includes('vg-tmp') || name.endsWith('.tmp'))).toEqual([]);
  });

  it('clears stray temps from a dead run before replacing the file', async () => {
    const dir = tempDir();
    const file = path.join(dir, 'sbom.json');
    const prior = '{"bomFormat":"CycloneDX","specVersion":"1.6"}\n';
    writeAtomicSync(file, prior);
    const dead = deadPid();
    const stray = [
      `.sbom.json.${dead}.vg-tmp`,
      `sbom.json.${dead}.tmp`,
      `sbom.json.${dead}.1.tmp`,
    ];
    for (const name of stray) fs.writeFileSync(path.join(dir, name), '{"trunc');
    const live = `.other.${process.pid}.vg-tmp`;
    fs.writeFileSync(path.join(dir, live), 'in-flight');

    const next = JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.6', serial: 'stable' }, null, 2);
    await writeTextFile(file, next);

    expect(fs.readFileSync(file, 'utf8')).toBe(next);
    expect(JSON.parse(fs.readFileSync(file, 'utf8')).serial).toBe('stable');
    for (const name of stray) expect(fs.existsSync(path.join(dir, name))).toBe(false);
    expect(fs.readFileSync(path.join(dir, live), 'utf8')).toBe('in-flight');
  });

  it('an interrupted scan write leaves the previous artifact parseable', async () => {
    const dir = tempDir();
    const file = path.join(dir, '.vibgrate', 'scan_result.json');
    const prior = { schemaVersion: '1.0', drift: { score: 40 }, findings: [{ id: 'a' }] };
    await writeJsonFile(file, prior);
    const priorBytes = fs.readFileSync(file);

    setAtomicWriteFaultForTests((tmp, data) => {
      const text = typeof data === 'string' ? data : Buffer.from(data as Uint8Array).toString('utf8');
      fs.writeFileSync(tmp, text.slice(0, 8));
      throw Object.assign(new Error('aborted mid-write'), { code: 'EIO' });
    });

    let caught: unknown;
    try {
      await writeJsonFile(file, { schemaVersion: '1.0', drift: { score: 1 }, findings: [] });
    } catch (err) {
      caught = err;
    }

    expect(caught).toBeInstanceOf(CliError);
    const message = (caught as CliError).message;
    expect(message).toContain(file);
    expect(message).toContain('(write failed)');
    expect(message).toContain('check the path and permissions, or choose another location');
    expect(message).not.toContain('.vg-tmp');
    expect(message).not.toContain('EIO');
    expect(message).not.toContain('aborted mid-write');
    expect(message).not.toMatch(/\n\s*at /);

    expect(fs.readFileSync(file).equals(priorBytes)).toBe(true);
    expect(JSON.parse(fs.readFileSync(file, 'utf8'))).toEqual(prior);
    expect(fs.readdirSync(path.dirname(file)).filter((name) => name.endsWith('.vg-tmp'))).toEqual([]);
  });
});
