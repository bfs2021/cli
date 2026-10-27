// One scan, three reports: the exit code, the stderr gate line, and the
// `--junit` failure/skipped cases. A drift-budget breach fails (exit 2).
// Warn-mode and shadow breaches, an unmeasured score, and `--drift-worsening`
// without `--baseline` are skipped and do not fail. A `--baseline` that was
// passed but produced no numeric delta still fails.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { DRIFT_WORSENING_BASELINE_UNUSABLE, DRIFT_WORSENING_NO_BASELINE } from '../drift-budget-gate.js';
import { scanCommand } from './scan.js';

interface GateRow {
  name: string;
  /** Node engine. Omitted when the score must stay unmeasured. */
  engines?: string;
  config?: string;
  args: string[];
  exit: 0 | 2;
  summary: string;
  /** Present when the row must not print a failing gate line. */
  notFailing?: boolean;
  caseName?: string;
  caseStatus?: 'failure' | 'skipped';
  score: 'measured' | 'absent';
}

function packageJson(engines?: string): string {
  const manifest: { name: string; version: string; engines?: { node: string } } = {
    name: 'gate-fixture',
    version: '1.0.0',
  };
  if (engines) manifest.engines = { node: engines };
  return JSON.stringify(manifest);
}

const rows: GateRow[] = [
  {
    name: 'no gates',
    engines: '24',
    args: [],
    exit: 0,
    summary: 'JUnit XML written',
    notFailing: true,
    score: 'measured',
  },
  {
    name: '--fail-on error with an error finding',
    engines: '16',
    args: ['--fail-on', 'error'],
    exit: 2,
    summary: 'error finding(s) detected',
    score: 'measured',
  },
  {
    name: '--fail-on warn with only a warning',
    engines: '22',
    args: ['--fail-on', 'warn'],
    exit: 2,
    summary: 'findings detected at warn level or above',
    score: 'measured',
  },
  {
    name: '--drift-budget breach',
    engines: '16',
    args: ['--drift-budget', '40'],
    exit: 2,
    summary: 'exceeds budget 40',
    caseName: 'drift-budget',
    caseStatus: 'failure',
    score: 'measured',
  },
  {
    name: 'warn-mode budget breach',
    engines: '22',
    config: 'driftBudget:\n  mode: warn\n  maxScore: 0\n',
    args: [],
    exit: 0,
    summary: 'drift budget (warn):',
    notFailing: true,
    caseName: 'drift-budget maxScore',
    caseStatus: 'skipped',
    score: 'measured',
  },
  {
    name: 'shadow budget breach',
    engines: '22',
    config: 'driftBudget:\n  mode: shadow\n  maxScore: 0\n',
    args: [],
    exit: 0,
    summary: 'drift budget (shadow):',
    notFailing: true,
    caseName: 'drift-budget maxScore',
    caseStatus: 'skipped',
    score: 'measured',
  },
  {
    name: 'unmeasured score with --drift-budget',
    args: ['--drift-budget', '0'],
    exit: 0,
    summary: 'DriftScore is absent; --drift-budget 0 was not compared.',
    notFailing: true,
    caseName: 'drift-budget',
    caseStatus: 'skipped',
    score: 'absent',
  },
  {
    name: '--drift-worsening without --baseline',
    engines: '22',
    args: ['--drift-worsening', '5'],
    exit: 0,
    summary: DRIFT_WORSENING_NO_BASELINE,
    notFailing: true,
    caseName: 'drift-worsening',
    caseStatus: 'skipped',
    score: 'measured',
  },
  {
    name: '--drift-worsening with a missing --baseline file',
    engines: '22',
    args: ['--drift-worsening', '5', '--baseline', 'missing-baseline.json'],
    exit: 2,
    summary: DRIFT_WORSENING_BASELINE_UNUSABLE,
    caseName: 'drift-worsening',
    caseStatus: 'failure',
    score: 'measured',
  },
  {
    name: 'enforced worsening limit without --baseline',
    engines: '22',
    config: 'driftBudget:\n  mode: enforce\n  maxScore: 100\n  maxWorseningPercent: 0\n',
    args: [],
    exit: 0,
    summary: 'Run with --baseline to compare.',
    notFailing: true,
    caseName: 'drift-budget maxWorseningPercent',
    caseStatus: 'skipped',
    score: 'measured',
  },
];

function caseBlock(xml: string, name: string): string | null {
  const needle = `name="${name}"`;
  const at = xml.indexOf(needle);
  if (at < 0) return null;
  const open = xml.lastIndexOf('<testcase', at);
  const end = xml.indexOf('</testcase>', at);
  const self = xml.indexOf('/>', at);
  if (self !== -1 && (end === -1 || self < end) && !xml.slice(at, self).includes('<')) {
    return xml.slice(open, self + 2);
  }
  if (end === -1) return null;
  return xml.slice(open, end + '</testcase>'.length);
}

function failureCount(xml: string): number {
  return xml.match(/<failure[\s>]/g)?.length ?? 0;
}

describe('vg scan exit, stderr, and JUnit gates agree', () => {
  const dirs: string[] = [];

  afterEach(() => {
    vi.unstubAllEnvs();
    for (const dir of dirs) fs.rmSync(dir, { recursive: true, force: true });
    dirs.length = 0;
  });

  async function run(row: GateRow): Promise<void> {
    const dir = fs.mkdtempSync(path.join(tmpdir(), 'vg-gate-'));
    dirs.push(dir);
    fs.writeFileSync(path.join(dir, 'package.json'), packageJson(row.engines));
    if (row.config) {
      fs.mkdirSync(path.join(dir, '.vibgrate'));
      fs.writeFileSync(path.join(dir, '.vibgrate', 'config.yml'), row.config);
    }
    vi.stubEnv('VIBGRATE_DSN', '');
    vi.stubEnv('VIBGRATE_NO_KERNEL', '1');

    let stderr = '';
    const errorSpy = vi.spyOn(console, 'error').mockImplementation((...parts: unknown[]) => {
      stderr += parts.map((part) => String(part)).join(' ');
      stderr += '\n';
    });
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation(((code?: number) => {
      throw new Error(`process.exit(${code ?? 0}) called`);
    }) as typeof process.exit);

    const junitPath = path.join(dir, 'junit.xml');
    const outPath = path.join(dir, 'scan.json');
    let exit = 0;
    try {
      await scanCommand.parseAsync(
        ['node', 'scan', dir, '--offline', '--no-daemon', '--no-graph', '--format', 'json', '--out', outPath, '--junit', junitPath, ...row.args],
      );
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const match = /^process\.exit\((\d+)\) called$/.exec(message);
      if (!match) throw err;
      exit = Number(match[1]);
    } finally {
      errorSpy.mockRestore();
      logSpy.mockRestore();
      stdoutSpy.mockRestore();
      stderrSpy.mockRestore();
      exitSpy.mockRestore();
    }

    const label = row.name;
    expect(exit, label).toBe(row.exit);
    expect(stderr, label).toContain(row.summary);
    if (row.notFailing) expect(stderr, label).not.toContain('Failing');

    const xml = fs.readFileSync(junitPath, 'utf8');
    expect(xml, label).not.toContain('timestamp');
    expect(xml, label).not.toContain(dir);
    const failures = failureCount(xml);
    expect(exit !== 0, `${label}: exit ${exit} vs ${failures} JUnit failure(s)`).toBe(failures > 0);
    if (row.exit === 0) expect(failures, label).toBe(0);
    else expect(failures, label).toBeGreaterThan(0);

    if (row.caseName && row.caseStatus) {
      const block = caseBlock(xml, row.caseName);
      expect(block, `${label}: missing JUnit case ${row.caseName}`).not.toBeNull();
      if (row.caseStatus === 'failure') expect(block, label).toContain('<failure');
      else expect(block, label).toContain('<skipped');
      if (row.caseStatus === 'skipped') expect(block, label).not.toContain('<failure');
    }

    const artifact = JSON.parse(fs.readFileSync(outPath, 'utf8')) as { drift?: { score?: number | null } };
    const score = artifact.drift?.score;
    if (row.score === 'absent') expect(score, label).toBeNull();
    else {
      expect(typeof score, label).toBe('number');
      if (row.name === '--drift-budget breach') expect(score, label).toBeGreaterThan(40);
      if (row.name === '--fail-on warn with only a warning') {
        const findings = (artifact as { findings?: { level: string }[] }).findings ?? [];
        expect(findings.some((finding) => finding.level === 'warning'), label).toBe(true);
        expect(findings.some((finding) => finding.level === 'error'), label).toBe(false);
      }
    }
  }

  it.each(rows)('$name', async (row) => {
    await run(row);
  }, 60_000);
});
