import { afterEach, describe, expect, it, vi } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { main } from '../../cli.js';
import { ExitCode } from '../../util/exit.js';
import { REPORT_FORMATS, reportCommand } from './report.js';

const roots: string[] = [];

function artifactFile(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-report-format-'));
  roots.push(root);
  const dir = path.join(root, '.vibgrate');
  fs.mkdirSync(dir, { recursive: true });
  const artifact = {
    schemaVersion: '1.0',
    timestamp: '2026-01-01T00:00:00.000Z',
    vibgrateVersion: '0.0.0',
    rootPath: root,
    projects: [],
    findings: [],
    drift: {
      score: 0,
      riskLevel: 'low',
      components: {
        runtimeScore: 0,
        frameworkScore: null,
        dependencyScore: 0,
        eolScore: null,
      },
    },
  };
  const file = path.join(dir, 'scan_result.json');
  fs.writeFileSync(file, JSON.stringify(artifact, null, 2));
  return file;
}

afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

async function runCli(args: string[]): Promise<{ code: number; stderr: string; stdout: string }> {
  vi.stubEnv('NO_COLOR', '1');
  vi.stubEnv('VIBGRATE_NO_KERNEL', '1');
  const stderr: string[] = [];
  const stdout: string[] = [];
  const write = (bucket: string[]) => (chunk: unknown, encodingOrCb?: unknown, cb?: unknown) => {
    bucket.push(String(chunk));
    const callback = typeof encodingOrCb === 'function' ? encodingOrCb : cb;
    if (typeof callback === 'function') callback();
    return true;
  };
  const errSpy = vi.spyOn(process.stderr, 'write').mockImplementation(write(stderr) as never);
  const outSpy = vi.spyOn(process.stdout, 'write').mockImplementation(write(stdout) as never);
  // Vitest captures console.log before it reaches stdout.write.
  const logSpy = vi.spyOn(console, 'log').mockImplementation((...parts: unknown[]) => {
    stdout.push(parts.map(String).join(' ') + '\n');
  });
  const exitSpy = vi.spyOn(process, 'exit').mockImplementation(((code?: number) => {
    throw new Error(`EXIT:${code ?? 0}`);
  }) as never);

  try {
    await main(['node', 'vg', ...args]);
    return { code: 0, stderr: stderr.join(''), stdout: stdout.join('') };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const match = /^EXIT:(\d+)$/.exec(message);
    if (!match) throw err;
    return { code: Number(match[1]), stderr: stderr.join(''), stdout: stdout.join('') };
  } finally {
    errSpy.mockRestore();
    outSpy.mockRestore();
    logSpy.mockRestore();
    exitSpy.mockRestore();
  }
}

describe('vg report --format', () => {
  it('names html in help and in the accepted list', () => {
    const option = reportCommand.options.find((item) => item.long === '--format');
    expect(option?.description).toBe('Output format (md|text|json|html)');
    expect(REPORT_FORMATS).toEqual(['md', 'text', 'json', 'html']);
  });

  it('renders html from the local artifact and leaves text, json, and md alone', async () => {
    const file = artifactFile();
    const html = await runCli(['report', '--in', file, '--format', 'html']);
    expect(html.code).toBe(0);
    expect(html.stdout).toContain('<!doctype html>');
    expect(html.stdout).toContain('id="summary"');
    expect(html.stdout).toContain('id="drift-score">0');
    expect(html.stderr).toBe('');

    const text = await runCli(['report', '--in', file]);
    expect(text.code).toBe(0);
    expect(text.stdout).toContain('Vibgrate Drift Report');
    expect(text.stdout).not.toContain('<!doctype');

    const md = await runCli(['report', '--in', file, '--format', 'md']);
    expect(md.code).toBe(0);
    expect(md.stdout).toContain('# Vibgrate Drift Report');
    expect(md.stdout).not.toContain('<!doctype');

    const json = await runCli(['report', '--in', file, '--format', 'json']);
    expect(json.code).toBe(0);
    expect(json.stdout).toBe(`${fs.readFileSync(file, 'utf8')}\n`);
  });

  it('rejects an unknown format, names it, lists the valid ones, and prints nothing', async () => {
    const missing = path.join(os.tmpdir(), 'vg-report-missing', 'scan_result.json');
    const result = await runCli(['report', '--in', missing, '--format', 'sarif']);

    expect(result.code).toBe(ExitCode.USAGE_ERROR);
    expect(result.code).not.toBe(0);
    expect(result.stdout).toBe('');
    expect(result.stderr).toBe('error: unknown --format "sarif" (expected md, text, json, html)\n');
    expect(result.stderr).not.toContain('Artifact not found');
  });

  it('matches the format exactly, so case or trailing space is a usage error', async () => {
    const missing = path.join(os.tmpdir(), 'vg-report-missing', 'scan_result.json');
    for (const format of ['HTML', 'Md', 'html ']) {
      const result = await runCli(['report', '--in', missing, '--format', format]);
      expect(result.code).toBe(ExitCode.USAGE_ERROR);
      expect(result.stdout).toBe('');
      expect(result.stderr).toBe(
        `error: unknown --format ${JSON.stringify(format)} (expected md, text, json, html)\n`,
      );
    }
  });

  it('keeps text as the default and still prints a report', async () => {
    const file = artifactFile();
    const result = await runCli(['report', '--in', file]);

    expect(result.code).toBe(0);
    expect(result.stdout).toContain('Vibgrate Drift Report');
    expect(result.stdout).toContain('DriftScore');
    expect(result.stderr).toBe('');
  });
});
