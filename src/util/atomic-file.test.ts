import { describe, it, expect, afterEach } from 'vitest';
import { spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { writeJsonFile, readJsonFile } from '../reporting/utils/fs.js';
import {
  ATOMIC_TEMP_PREFIX,
  AtomicWriteError,
  cleanupStrayAtomicTemps,
  writeAtomic,
  writeAtomicSync,
} from './atomic-file.js';

const dirs: string[] = [];

function temp(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-atomic-'));
  dirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

function temps(dir: string): string[] {
  return fs.readdirSync(dir).filter((name) => name.startsWith(ATOMIC_TEMP_PREFIX)).sort();
}

describe('atomic artifact writes', () => {
  it('writes the same bytes on every successful run', () => {
    const dir = temp();
    const file = path.join(dir, 'graph.json');
    const body = `${JSON.stringify({ schemaVersion: '1.0', nodes: [{ id: 'a' }, { id: 'b' }] }, null, 2)}\n`;
    writeAtomicSync(file, body);
    const first = fs.readFileSync(file);
    expect(first.equals(Buffer.from(body))).toBe(true);
    writeAtomicSync(file, body);
    expect(fs.readFileSync(file).equals(first)).toBe(true);
    expect(temps(dir)).toEqual([]);
  });

  it('keeps an existing file mode when no mode is requested', () => {
    const dir = temp();
    const file = path.join(dir, 'baseline.json');
    fs.writeFileSync(file, '{"ok":true}\n', { mode: 0o640 });
    const mode = fs.statSync(file).mode & 0o777;
    writeAtomicSync(file, '{"ok":false}\n');
    expect(fs.statSync(file).mode & 0o777).toBe(mode);
    expect(fs.readFileSync(file, 'utf8')).toBe('{"ok":false}\n');
  });

  it('names the file, the reason, and the next step without echoing contents', () => {
    const leaked = 'do-not-echo-this-payload';
    const err = new AtomicWriteError(
      '/tmp/repo/.vibgrate/baseline.json',
      Object.assign(new Error(leaked), { code: 'ENOSPC' }),
    );
    expect(err).toBeInstanceOf(Error);
    expect(err.filePath).toBe('/tmp/repo/.vibgrate/baseline.json');
    expect(err.code).toBe('ENOSPC');
    expect(err.message).toContain('/tmp/repo/.vibgrate/baseline.json');
    expect(err.message).toContain('disk full');
    expect(err.message).toContain('previous file was left unchanged');
    expect(err.message).toContain('re-run the command');
    expect(err.message).not.toContain(leaked);
    expect(err.message).not.toMatch(/\bENOSPC\b/);

    const dir = temp();
    const blocker = path.join(dir, 'not-a-dir');
    fs.writeFileSync(blocker, leaked);
    const target = path.join(blocker, 'scan_result.json');
    let caught: unknown;
    try {
      writeAtomicSync(target, '{"findings":[]}\n');
    } catch (cause) {
      caught = cause;
    }
    expect(caught).toBeInstanceOf(AtomicWriteError);
    const cli = caught as AtomicWriteError;
    expect(cli.message).toContain(target);
    expect(cli.message).toContain('a parent path is not a directory');
    expect(cli.message).toContain('re-run the command');
    expect(cli.message).not.toContain(leaked);
    expect(fs.existsSync(target)).toBe(false);
  });

  it('aborts before rename and leaves the previous artifact parseable', () => {
    const dir = temp();
    const file = path.join(dir, '.vibgrate', 'baseline.json');
    const previous = '{"schemaVersion":"1.0","drift":{"score":12}}\n';
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, previous);
    const unrelated = path.join(dir, '.vibgrate', 'notes.tmp');
    fs.writeFileSync(unrelated, 'keep-me');

    let caught: unknown;
    try {
      writeAtomicSync(file, '{"schemaVersion":"1.0","drift":{"score":99},"partial":true}\n', {
        beforeRename() {
          throw new Error('aborted before rename');
        },
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(Error);
    expect((caught as Error).message).toBe('aborted before rename');
    expect(fs.readFileSync(file, 'utf8')).toBe(previous);
    expect(JSON.parse(fs.readFileSync(file, 'utf8'))).toEqual({ schemaVersion: '1.0', drift: { score: 12 } });
    expect(temps(path.dirname(file))).toEqual([]);
    expect(fs.readFileSync(unrelated, 'utf8')).toBe('keep-me');
  });

  it('cleans only its own temps, in sorted order, on the next write', () => {
    const dir = temp();
    const file = path.join(dir, 'scan_result.json');
    fs.writeFileSync(file, '{"ok":1}\n');
    fs.writeFileSync(path.join(dir, 'notes.tmp'), 'editor');
    fs.writeFileSync(path.join(dir, 'scan_result.json.bak'), 'backup');
    fs.writeFileSync(path.join(dir, 'other.json.4242.tmp'), 'other-legacy');
    fs.mkdirSync(path.join(dir, `${ATOMIC_TEMP_PREFIX}9.9.dir`));
    fs.writeFileSync(path.join(dir, `${ATOMIC_TEMP_PREFIX}2.1.scan_result.json`), '{"torn":true');
    fs.writeFileSync(path.join(dir, `${ATOMIC_TEMP_PREFIX}1.1.scan_result.json`), '');
    fs.writeFileSync(path.join(dir, 'scan_result.json.5150.tmp'), '{"half"');
    fs.writeFileSync(path.join(dir, 'scan_result.json.7.3.tmp'), 'legacy-seq');
    const link = path.join(dir, `${ATOMIC_TEMP_PREFIX}3.1.link`);
    fs.symlinkSync(file, link);

    const removed = cleanupStrayAtomicTemps(dir, 'scan_result.json').map((p) => path.basename(p));
    expect(removed).toEqual([
      `${ATOMIC_TEMP_PREFIX}1.1.scan_result.json`,
      `${ATOMIC_TEMP_PREFIX}2.1.scan_result.json`,
      'scan_result.json.5150.tmp',
      'scan_result.json.7.3.tmp',
    ]);
    expect(fs.readFileSync(file, 'utf8')).toBe('{"ok":1}\n');
    expect(JSON.parse(fs.readFileSync(file, 'utf8'))).toEqual({ ok: 1 });
    expect(fs.readFileSync(path.join(dir, 'notes.tmp'), 'utf8')).toBe('editor');
    expect(fs.readFileSync(path.join(dir, 'scan_result.json.bak'), 'utf8')).toBe('backup');
    expect(fs.readFileSync(path.join(dir, 'other.json.4242.tmp'), 'utf8')).toBe('other-legacy');
    expect(fs.statSync(path.join(dir, `${ATOMIC_TEMP_PREFIX}9.9.dir`)).isDirectory()).toBe(true);
    expect(fs.lstatSync(link).isSymbolicLink()).toBe(true);

    writeAtomicSync(file, '{"ok":2}\n');
    expect(fs.readFileSync(file, 'utf8')).toBe('{"ok":2}\n');
    // A directory or symlink that happens to share the temp prefix is not a
    // file we created, so the next write leaves it in place.
    expect(temps(dir)).toEqual([
      `${ATOMIC_TEMP_PREFIX}3.1.link`,
      `${ATOMIC_TEMP_PREFIX}9.9.dir`,
    ]);
    expect(fs.readFileSync(path.join(dir, 'notes.tmp'), 'utf8')).toBe('editor');
  });

  it('writeJsonFile output matches a direct serialize and survives a failed replace', async () => {
    const dir = temp();
    const file = path.join(dir, '.vibgrate', 'baseline.json');
    const data = { schemaVersion: '1.0', findings: [{ id: 'a' }], drift: { score: 4 } };
    await writeJsonFile(file, data);
    const body = `${JSON.stringify(data, null, 2)}\n`;
    expect(fs.readFileSync(file).equals(Buffer.from(body))).toBe(true);
    expect(await readJsonFile(file)).toEqual(data);

    const replaced = { schemaVersion: '1.0', findings: [], drift: { score: 9 } };
    await writeJsonFile(file, replaced);
    expect(fs.readFileSync(file, 'utf8')).toBe(`${JSON.stringify(replaced, null, 2)}\n`);
    expect(temps(path.dirname(file))).toEqual([]);

    const dest = path.join(dir, 'out.json');
    await writeAtomic(dest, body);
    expect(fs.readFileSync(dest).equals(Buffer.from(body))).toBe(true);
  });

  it('kills a write before rename and the next run drops the temp', async () => {
    const dir = temp();
    const artifactDir = path.join(dir, '.vibgrate');
    fs.mkdirSync(artifactDir);
    const dest = path.join(artifactDir, 'baseline.json');
    const previous = '{"schemaVersion":"1.0","drift":{"score":3},"findings":[]}\n';
    fs.writeFileSync(dest, previous);
    const unrelated = path.join(artifactDir, 'README.txt');
    fs.writeFileSync(unrelated, 'leave this');
    const ready = path.join(dir, 'ready');
    const helper = fileURLToPath(new URL('./atomic-file.ts', import.meta.url));
    const nextBody = '{"schemaVersion":"1.0","drift":{"score":80},"partial":true}\n';

    const child = spawn(
      process.execPath,
      [
        '--import',
        'tsx',
        '--input-type=module',
        '--eval',
        [
          `import { writeAtomicSync } from ${JSON.stringify(helper)};`,
          `import * as fs from 'node:fs';`,
          `writeAtomicSync(process.env.VG_ATOMIC_DEST, process.env.VG_ATOMIC_BODY, {`,
          `  beforeRename() {`,
          `    fs.writeFileSync(process.env.VG_ATOMIC_READY, 'ready');`,
          `    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 30000);`,
          `  },`,
          `});`,
        ].join('\n'),
      ],
      {
        cwd: path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..'),
        env: {
          ...process.env,
          VG_ATOMIC_DEST: dest,
          VG_ATOMIC_BODY: nextBody,
          VG_ATOMIC_READY: ready,
        },
      },
    );

    const started = Date.now();
    while (!fs.existsSync(ready)) {
      if (Date.now() - started > 15_000) {
        child.kill('SIGKILL');
        throw new Error(`writer did not reach rename: ${child.stderr?.read()?.toString?.() ?? ''}`);
      }
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    child.kill('SIGKILL');
    const signal = await new Promise<NodeJS.Signals | null>((resolve) => {
      child.on('exit', (_code, sig) => resolve(sig));
    });
    expect(signal).toBe('SIGKILL');

    expect(fs.readFileSync(dest, 'utf8')).toBe(previous);
    expect(JSON.parse(fs.readFileSync(dest, 'utf8'))).toEqual({
      schemaVersion: '1.0',
      drift: { score: 3 },
      findings: [],
    });
    expect(temps(artifactDir).length).toBeGreaterThan(0);
    const torn = fs.readFileSync(path.join(artifactDir, temps(artifactDir)[0]!), 'utf8');
    expect(torn).toBe(nextBody);
    expect(fs.readFileSync(unrelated, 'utf8')).toBe('leave this');

    writeAtomicSync(dest, previous);
    expect(fs.readFileSync(dest, 'utf8')).toBe(previous);
    expect(JSON.parse(fs.readFileSync(dest, 'utf8')).drift.score).toBe(3);
    expect(temps(artifactDir)).toEqual([]);
    expect(fs.readFileSync(unrelated, 'utf8')).toBe('leave this');
  });
});
