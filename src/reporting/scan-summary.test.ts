import { describe, it, expect, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { buildScanSummary, prepareScanDriftBudget, writeScanSummary } from './scan-summary.js';
import { LOCAL_SCAN_RISK_NOTE, runCoreScan } from '../core-open/index.js';
import type { ScanArtifact } from '../core-open/types.js';
import { scanCommand } from './commands/scan.js';

function artifact(score: number | null, delta?: number): ScanArtifact {
  return {
    schemaVersion: '1.0',
    timestamp: '2026-10-06T00:00:00.000Z',
    vibgrateVersion: 'test',
    rootPath: '/test',
    projects: [],
    drift: {
      score,
      riskLevel: 'moderate',
      components: { runtimeScore: 10, frameworkScore: 62, dependencyScore: 30, eolScore: 0 },
    },
    findings: [],
    ...(delta !== undefined ? { delta } : {}),
  };
}

describe('buildScanSummary', () => {
  it('carries the score, risk level and components', () => {
    expect(buildScanSummary(artifact(47))).toEqual({
      schemaVersion: 1,
      driftScore: 47,
      riskLevel: 'moderate',
      components: { runtimeScore: 10, frameworkScore: 62, dependencyScore: 30, eolScore: 0 },
      delta: null,
      baselineScore: null,
      driftBudget: null,
    });
  });

  it('derives the baseline score from the delta (positive delta = worse)', () => {
    const s = buildScanSummary(artifact(47, 5));
    expect(s.delta).toBe(5);
    expect(s.baselineScore).toBe(42);
  });

  it('keeps a measured 0 as 0', () => {
    const s = buildScanSummary(artifact(0, 0));
    expect(s.driftScore).toBe(0);
    expect(s.delta).toBe(0);
    expect(s.baselineScore).toBe(0);
  });

  it('keeps an unmeasured score as null, never 0', () => {
    const s = buildScanSummary(artifact(null));
    expect(s.driftScore).toBeNull();
    expect(s.baselineScore).toBeNull();
  });
});

describe('writeScanSummary', () => {
  let dir: string;
  afterEach(() => {
    vi.restoreAllMocks();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('writes JSON, creating the parent directory', async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-summary-'));
    const file = path.join(dir, 'out', 'summary.json');
    await writeScanSummary(file, artifact(47));
    expect(JSON.parse(fs.readFileSync(file, 'utf8')).driftScore).toBe(47);
  });

  it('reports an unmeasured real scan as null', async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-summary-'));
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 't', version: '1.0.0', dependencies: {} }));
    vi.stubEnv('VIBGRATE_DSN', '');
    vi.spyOn(console, 'log').mockImplementation(() => {});
    const real = await runCoreScan(dir, {
      format: 'text', concurrency: 4, offline: true, noLocalArtifacts: true, vibgrateVersion: 'test', quiet: true,
    });
    const file = path.join(dir, 'summary.json');
    await writeScanSummary(file, real);
    const written = JSON.parse(fs.readFileSync(file, 'utf8'));
    expect(written.driftScore).toBe(real.drift.score);
    expect(written.driftScore).not.toBe(0);
    expect(written.driftBudget).toBeNull();
  });
});

describe('prepareScanDriftBudget', () => {
  const file = '.vibgrate/config.yml';

  it('is null when no budget is configured and neither flag was passed', () => {
    const prepared = prepareScanDriftBudget({ score: 90, delta: undefined, configRaw: undefined, configFile: file });
    expect(prepared.summary).toBeNull();
    expect(prepared.configGate?.verdict).toBeNull();
    expect(prepared.configScoreAbsent).toBe(false);
    expect(buildScanSummary(artifact(90), prepared.summary).driftBudget).toBeNull();
  });

  it('reports an all-pass config budget', () => {
    const prepared = prepareScanDriftBudget({
      score: 10,
      delta: undefined,
      configRaw: { mode: 'enforce', maxScore: 40 },
      configFile: file,
    });
    expect(prepared.summary).toEqual({
      source: 'config',
      mode: 'enforce',
      withinBudget: true,
      blocking: false,
      rules: [{ id: 'maxScore', status: 'pass', message: 'DriftScore 10 of 40, headroom 30.' }],
    });
    expect(prepared.configGate?.exitCode).toBe(0);
  });

  it('reports a warn-mode breach without blocking', () => {
    const prepared = prepareScanDriftBudget({
      score: 44,
      delta: undefined,
      configRaw: { maxScore: 40 },
      configFile: file,
    });
    expect(prepared.summary).toMatchObject({
      source: 'config',
      mode: 'warn',
      withinBudget: false,
      blocking: false,
    });
    expect(prepared.summary?.rules).toEqual([{
      id: 'maxScore',
      status: 'breach',
      message: 'DriftScore 44 is above the budget of 40. Lower it by 4 points to pass.',
    }]);
    expect(prepared.configGate?.exitCode).toBe(0);
  });

  it('reports an enforce-mode breach as blocking', () => {
    const prepared = prepareScanDriftBudget({
      score: 44,
      delta: undefined,
      configRaw: { mode: 'enforce', maxScore: 40 },
      configFile: file,
    });
    expect(prepared.summary).toMatchObject({
      source: 'config',
      mode: 'enforce',
      withinBudget: false,
      blocking: true,
    });
    expect(prepared.summary?.rules[0]?.status).toBe('breach');
    expect(prepared.configGate?.exitCode).toBe(2);
  });

  it('reports RiskScore limits as not_evaluated on a local scan', () => {
    const prepared = prepareScanDriftBudget({
      score: 90,
      delta: undefined,
      configRaw: { mode: 'enforce', maxRiskScore: 40, maxRiskWorseningPercent: 0 },
      configFile: file,
    });
    expect(prepared.summary?.blocking).toBe(false);
    expect(prepared.summary?.withinBudget).toBe(true);
    expect(prepared.summary?.rules.map((rule) => rule.status)).toEqual(['not_evaluated', 'not_evaluated']);
    expect(prepared.summary?.rules.map((rule) => rule.id)).toEqual(['maxRiskScore', 'maxRiskWorseningPercent']);
    expect(prepared.summary?.rules[0]?.message).toBe(LOCAL_SCAN_RISK_NOTE);
    expect(prepared.summary?.rules[0]?.status).not.toBe('pass');
  });

  it('keeps evaluator order, including a not_evaluated worsening limit', () => {
    const prepared = prepareScanDriftBudget({
      score: 20,
      delta: undefined,
      configRaw: {
        mode: 'enforce',
        maxScore: 40,
        maxWorseningPercent: 5,
        agents: { maxWorseningPercent: 0 },
        maxRiskScore: 50,
        maxRiskWorseningPercent: 0,
      },
      configFile: file,
    });
    expect(prepared.summary?.rules.map((rule) => rule.id)).toEqual([
      'maxScore',
      'maxWorseningPercent',
      'agents.maxWorseningPercent',
      'maxRiskScore',
      'maxRiskWorseningPercent',
    ]);
    expect(prepared.summary?.rules.map((rule) => rule.status)).toEqual([
      'pass',
      'not_evaluated',
      'not_evaluated',
      'not_evaluated',
      'not_evaluated',
    ]);
    expect(prepared.summary?.blocking).toBe(false);
  });

  it('does not treat an unmeasured score as 0 when a budget is configured', () => {
    const prepared = prepareScanDriftBudget({
      score: null,
      delta: undefined,
      configRaw: { mode: 'enforce', maxScore: 0 },
      configFile: file,
    });
    expect(prepared.configScoreAbsent).toBe(true);
    expect(prepared.configGate).toBeNull();
    expect(prepared.summary).toEqual({
      source: 'config',
      mode: 'enforce',
      withinBudget: true,
      blocking: false,
      rules: [{
        id: 'maxScore',
        status: 'not_evaluated',
        message: 'DriftScore is absent; the project drift budget was not compared.',
      }],
    });
    const summary = buildScanSummary(artifact(null), prepared.summary);
    expect(summary.driftScore).toBeNull();
    expect(summary.schemaVersion).toBe(1);
    expect(JSON.stringify(summary)).not.toContain('"driftScore":0');
  });

  it('reports --drift-budget as an enforce-mode flag verdict', () => {
    const breach = prepareScanDriftBudget({
      score: 44,
      delta: undefined,
      driftBudget: 40,
      configRaw: { mode: 'warn', maxScore: 100 },
      configFile: file,
    });
    expect(breach.summary).toEqual({
      source: '--drift-budget',
      mode: 'enforce',
      withinBudget: false,
      blocking: true,
      rules: [{
        id: 'maxScore',
        status: 'breach',
        message: 'Failing fitness function: DriftScore 44/100 exceeds budget 40.',
      }],
    });
    expect(breach.configGate).toBeNull();
    expect(breach.flagBudget).toEqual({
      exitCode: 2,
      message: 'Failing fitness function: DriftScore 44/100 exceeds budget 40.',
    });

    const pass = prepareScanDriftBudget({ score: 0, delta: undefined, driftBudget: 0 });
    expect(pass.summary?.rules).toEqual([{
      id: 'maxScore',
      status: 'pass',
      message: 'DriftScore 0 is within the budget of 0.',
    }]);
    expect(pass.summary?.blocking).toBe(false);

    const absent = prepareScanDriftBudget({ score: null, delta: undefined, driftBudget: 0 });
    expect(absent.summary?.rules).toEqual([{
      id: 'maxScore',
      status: 'not_evaluated',
      message: 'DriftScore is absent; --drift-budget 0 was not compared.',
    }]);
    expect(absent.summary?.blocking).toBe(false);
    expect(absent.flagBudget?.exitCode).toBe(0);
  });

  it('reports --drift-worsening, including a missing baseline', () => {
    const missing = prepareScanDriftBudget({ score: 50, delta: undefined, driftWorseningPercent: 5 });
    expect(missing.summary).toMatchObject({
      source: '--drift-worsening',
      mode: 'enforce',
      withinBudget: false,
      blocking: true,
    });
    expect(missing.summary?.rules[0]).toEqual({
      id: 'maxWorseningPercent',
      status: 'breach',
      message: 'Failing fitness function: --drift-worsening requires --baseline to compare against previous drift.',
    });

    const held = prepareScanDriftBudget({ score: 42, delta: 0, driftWorseningPercent: 5 });
    expect(held.summary?.rules[0]).toEqual({
      id: 'maxWorseningPercent',
      status: 'pass',
      message: 'Drift did not worsen (DriftScore 42 → 42).',
    });
    expect(held.summary?.blocking).toBe(false);

    const absent = prepareScanDriftBudget({ score: null, delta: undefined, driftWorseningPercent: 5 });
    expect(absent.summary?.rules[0]?.status).toBe('not_evaluated');
    expect(absent.summary?.blocking).toBe(false);
    expect(absent.flagWorsening?.exitCode).toBe(0);
  });

  it('reports both flags in flag order and ignores config', () => {
    const prepared = prepareScanDriftBudget({
      score: 50,
      delta: 10,
      driftBudget: 40,
      driftWorseningPercent: 5,
      configRaw: { mode: 'shadow', maxScore: 100 },
      configFile: '/tmp/not-used/.vibgrate/config.yml',
    });
    expect(prepared.summary?.source).toBe('--drift-budget --drift-worsening');
    expect(prepared.summary?.mode).toBe('enforce');
    expect(prepared.summary?.rules.map((rule) => rule.id)).toEqual(['maxScore', 'maxWorseningPercent']);
    expect(prepared.summary?.rules.map((rule) => rule.status)).toEqual(['breach', 'breach']);
    expect(prepared.summary?.blocking).toBe(true);
    expect(JSON.stringify(prepared.summary)).not.toContain('/tmp/not-used');
  });

  it('is deterministic and carries no clock or absolute path', () => {
    const input = {
      score: 44,
      delta: undefined as number | undefined,
      configRaw: { mode: 'warn' as const, maxScore: 40 },
      configFile: '/var/abs/.vibgrate/config.yml',
    };
    const a = prepareScanDriftBudget(input).summary;
    const b = prepareScanDriftBudget(input).summary;
    expect(a).toEqual(b);
    const json = JSON.stringify(buildScanSummary(artifact(44, 5), a));
    expect(json).toBe(JSON.stringify(buildScanSummary(artifact(44, 5), b)));
    expect(json).not.toMatch(/\d{4}-\d{2}-\d{2}T/);
    expect(json).not.toContain('/var/abs');
    expect(json).toContain('"schemaVersion":1');
  });
});

describe('vg scan --summary-out drift budget', () => {
  let dir: string;
  let logSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let exitSpy: ReturnType<typeof vi.spyOn>;

  afterEach(() => {
    logSpy?.mockRestore();
    errorSpy?.mockRestore();
    exitSpy?.mockRestore();
    vi.unstubAllEnvs();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  function project(): string {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-summary-budget-'));
    fs.writeFileSync(
      path.join(dir, 'package.json'),
      JSON.stringify({ name: 't', version: '1.0.0', engines: { node: '10' }, dependencies: {} }),
    );
    vi.stubEnv('VIBGRATE_DSN', '');
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    exitSpy = vi.spyOn(process, 'exit').mockImplementation(((code?: number) => {
      throw new Error(`process.exit(${code}) called`);
    }) as never);
    return dir;
  }

  async function run(extra: string[]): Promise<void> {
    await scanCommand.parseAsync(
      [dir, '--offline', '--no-graph', '--no-daemon', '--no-local-artifacts', '--quiet', '--format', 'text', ...extra],
      { from: 'user' },
    );
  }

  function readSummary(): Record<string, unknown> {
    return JSON.parse(fs.readFileSync(path.join(dir, 'summary.json'), 'utf8')) as Record<string, unknown>;
  }

  it('writes null when no budget is configured', async () => {
    project();
    await run(['--summary-out', path.join(dir, 'summary.json')]);
    expect(exitSpy).not.toHaveBeenCalled();
    const written = readSummary();
    expect(written.schemaVersion).toBe(1);
    expect(written.driftBudget).toBeNull();
    expect(typeof written.driftScore).toBe('number');
  });

  it('writes a blocking verdict before an enforced breach exits 2', async () => {
    project();
    fs.mkdirSync(path.join(dir, '.vibgrate'));
    fs.writeFileSync(
      path.join(dir, '.vibgrate', 'config.yml'),
      'driftBudget:\n  mode: enforce\n  maxScore: 40\n',
    );
    const summaryPath = path.join(dir, 'summary.json');
    await expect(run(['--summary-out', summaryPath])).rejects.toThrow('process.exit(2) called');
    expect(fs.existsSync(summaryPath)).toBe(true);
    const written = readSummary();
    expect(written.driftScore).not.toBe(0);
    expect(typeof written.driftScore).toBe('number');
    expect((written.driftScore as number) > 40).toBe(true);
    expect(written.driftBudget).toMatchObject({
      source: 'config',
      mode: 'enforce',
      withinBudget: false,
      blocking: true,
    });
    const rules = (written.driftBudget as { rules: { id: string; status: string }[] }).rules;
    expect(rules[0]).toMatchObject({ id: 'maxScore', status: 'breach' });
    expect(JSON.stringify(written)).not.toContain(dir);
  });

  it('writes the flag verdict and still exits 2, ignoring a warn-mode config', async () => {
    project();
    fs.mkdirSync(path.join(dir, '.vibgrate'));
    fs.writeFileSync(
      path.join(dir, '.vibgrate', 'config.yml'),
      'driftBudget:\n  mode: warn\n  maxScore: 100\n',
    );
    await expect(run(['--summary-out', path.join(dir, 'summary.json'), '--drift-budget', '40'])).rejects.toThrow('process.exit(2) called');
    const written = readSummary();
    expect(written.driftBudget).toMatchObject({
      source: '--drift-budget',
      mode: 'enforce',
      blocking: true,
      withinBudget: false,
    });
  });

  it('keeps a warn-mode breach in the file and exits 0', async () => {
    project();
    fs.mkdirSync(path.join(dir, '.vibgrate'));
    fs.writeFileSync(
      path.join(dir, '.vibgrate', 'config.yml'),
      'driftBudget:\n  mode: warn\n  maxScore: 40\n',
    );
    await run(['--summary-out', path.join(dir, 'summary.json')]);
    expect(exitSpy).not.toHaveBeenCalled();
    const written = readSummary();
    expect(written.driftBudget).toMatchObject({
      source: 'config',
      mode: 'warn',
      withinBudget: false,
      blocking: false,
    });
  });
});
