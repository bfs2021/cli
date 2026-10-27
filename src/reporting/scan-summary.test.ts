import { describe, it, expect, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { buildScanSummary, summarizeDriftBudget, writeScanSummary } from './scan-summary.js';
import { runCoreScan } from '../core-open/index.js';
import type { ScanArtifact } from '../core-open/types.js';

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
    expect(s.driftBudget).toBeNull();
  });

  it('leaves the existing fields in place when a budget verdict is attached', () => {
    const plain = buildScanSummary(artifact(47, 5));
    const withBudget = buildScanSummary(artifact(47, 5), { configRaw: { mode: 'enforce', maxScore: 40 } });
    expect(withBudget.driftScore).toBe(plain.driftScore);
    expect(withBudget.riskLevel).toBe(plain.riskLevel);
    expect(withBudget.components).toEqual(plain.components);
    expect(withBudget.delta).toBe(plain.delta);
    expect(withBudget.baselineScore).toBe(plain.baselineScore);
    expect(withBudget.driftBudget?.blocking).toBe(true);
  });
});

describe('summarizeDriftBudget', () => {
  it('is null when no budget is set', () => {
    expect(summarizeDriftBudget(47, undefined, {})).toBeNull();
    expect(summarizeDriftBudget(47, undefined)).toBeNull();
    expect(summarizeDriftBudget(null, undefined, { configRaw: null })).toBeNull();
  });

  it('reports a configured budget that is within the limit', () => {
    expect(summarizeDriftBudget(30, undefined, { configRaw: { mode: 'enforce', maxScore: 40 } })).toEqual({
      source: 'config',
      mode: 'enforce',
      withinBudget: true,
      blocking: false,
      rules: [{ id: 'maxScore', status: 'pass', message: 'DriftScore 30 of 40, headroom 10.' }],
    });
  });

  it('reports an enforced breach as blocking', () => {
    const verdict = summarizeDriftBudget(44, undefined, { configRaw: { mode: 'enforce', maxScore: 40 } });
    expect(verdict).toMatchObject({
      source: 'config',
      mode: 'enforce',
      withinBudget: false,
      blocking: true,
    });
    expect(verdict?.rules[0]).toMatchObject({ id: 'maxScore', status: 'breach' });
    expect(verdict?.rules[0]?.message).toContain('DriftScore 44 is above the budget of 40');
  });

  it('reports a warn-mode breach without blocking', () => {
    expect(summarizeDriftBudget(44, undefined, { configRaw: { maxScore: 40 } })).toMatchObject({
      source: 'config',
      mode: 'warn',
      withinBudget: false,
      blocking: false,
    });
  });

  it('does not treat an unmeasured score as 0 against a configured budget', () => {
    const verdict = summarizeDriftBudget(null, undefined, { configRaw: { mode: 'enforce', maxScore: 0 } });
    expect(verdict).toEqual({
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
    expect(verdict?.rules[0]?.status).not.toBe('pass');
  });

  it('does not fail a configured worsening limit when there is no baseline', () => {
    expect(summarizeDriftBudget(60, undefined, {
      configRaw: { mode: 'enforce', maxWorseningPercent: 0 },
    })).toMatchObject({
      source: 'config',
      withinBudget: true,
      blocking: false,
      rules: [{ id: 'maxWorseningPercent', status: 'not_evaluated' }],
    });
  });

  it('keeps a measured 0 as a real score against a configured budget', () => {
    expect(summarizeDriftBudget(0, undefined, { configRaw: { mode: 'enforce', maxScore: 0 } })).toMatchObject({
      withinBudget: true,
      blocking: false,
      rules: [{ id: 'maxScore', status: 'pass' }],
    });
  });

  it('is null when the project budget does not parse', () => {
    expect(summarizeDriftBudget(90, undefined, { configRaw: { mode: 'enforce', maxscore: 40 } })).toBeNull();
  });

  it('reports a flag budget as flag-sourced and blocking on a breach', () => {
    expect(summarizeDriftBudget(44, undefined, { flagBudget: 40, configRaw: { mode: 'warn', maxScore: 100 } })).toEqual({
      source: 'flags',
      mode: 'enforce',
      withinBudget: false,
      blocking: true,
      rules: [{
        id: 'maxScore',
        status: 'breach',
        message: 'Failing fitness function: DriftScore 44/100 exceeds --drift-budget 40.',
      }],
    });
  });

  it('reports a flag budget that the measured score meets, including 0', () => {
    expect(summarizeDriftBudget(40, undefined, { flagBudget: 40 })).toMatchObject({
      source: 'flags',
      withinBudget: true,
      blocking: false,
      rules: [{ id: 'maxScore', status: 'pass', message: 'DriftScore 40 is within --drift-budget 40.' }],
    });
    expect(summarizeDriftBudget(0, undefined, { flagBudget: 0 })).toMatchObject({
      withinBudget: true,
      rules: [{ status: 'pass' }],
    });
  });

  it('does not compare a flag budget when the score is absent', () => {
    expect(summarizeDriftBudget(null, undefined, { flagBudget: 0, flagWorseningPercent: 5 })).toEqual({
      source: 'flags',
      mode: 'enforce',
      withinBudget: true,
      blocking: false,
      rules: [
        {
          id: 'maxScore',
          status: 'not_evaluated',
          message: 'DriftScore is absent; --drift-budget 0 was not compared.',
        },
        {
          id: 'maxWorseningPercent',
          status: 'not_evaluated',
          message: 'DriftScore is absent; --drift-worsening was not compared.',
        },
      ],
    });
  });

  it('does not compare --drift-worsening when no --baseline was passed', () => {
    expect(summarizeDriftBudget(60, undefined, { flagWorseningPercent: 5 })).toEqual({
      source: 'flags',
      mode: 'enforce',
      withinBudget: true,
      blocking: false,
      rules: [{
        id: 'maxWorseningPercent',
        status: 'not_evaluated',
        message: '--drift-worsening was not compared. Pass --baseline to compare against previous drift.',
      }],
    });
  });

  it('blocks on --drift-worsening when --baseline was passed but produced no delta', () => {
    expect(summarizeDriftBudget(60, undefined, { flagWorseningPercent: 5, baseline: '.vibgrate/baseline.json' })).toEqual({
      source: 'flags',
      mode: 'enforce',
      withinBudget: false,
      blocking: true,
      rules: [{
        id: 'maxWorseningPercent',
        status: 'breach',
        message: 'Failing fitness function: --drift-worsening requires --baseline to compare against previous drift.',
      }],
    });
  });

  it('judges --drift-worsening against the baseline delta, not against zero', () => {
    const over = summarizeDriftBudget(47, 5, { flagWorseningPercent: 5 });
    expect(over).toMatchObject({
      source: 'flags',
      withinBudget: false,
      blocking: true,
      rules: [{ id: 'maxWorseningPercent', status: 'breach' }],
    });
    expect(over?.rules[0]?.message).toContain('--drift-worsening 5%');
    expect(summarizeDriftBudget(47, 0, { flagWorseningPercent: 5 })).toMatchObject({
      withinBudget: true,
      blocking: false,
      rules: [{ status: 'pass', message: 'Drift did not worsen against --drift-worsening 5%.' }],
    });
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
    const written = JSON.parse(fs.readFileSync(file, 'utf8'));
    expect(written.driftScore).toBe(47);
    expect(written.driftBudget).toBeNull();
  });

  it('writes a configured verdict and a flag verdict', async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-summary-'));
    const configured = path.join(dir, 'configured.json');
    const flagged = path.join(dir, 'flagged.json');
    await writeScanSummary(configured, artifact(44), { configRaw: { mode: 'enforce', maxScore: 40 } });
    await writeScanSummary(flagged, artifact(null), { flagBudget: 40 });
    expect(JSON.parse(fs.readFileSync(configured, 'utf8')).driftBudget).toMatchObject({
      source: 'config',
      blocking: true,
    });
    const absent = JSON.parse(fs.readFileSync(flagged, 'utf8'));
    expect(absent.driftScore).toBeNull();
    expect(absent.driftBudget).toMatchObject({
      source: 'flags',
      blocking: false,
      rules: [{ status: 'not_evaluated' }],
    });
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
    expect(written.driftBudget).toBeNull();
  });
});
