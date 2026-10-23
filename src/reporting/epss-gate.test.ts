import { describe, expect, it } from 'vitest';
import { CliError, ExitCode } from '../util/exit.js';
import {
  advisoriesForEpssGate,
  epssAdvisoryRow,
  evaluateEpssGate,
  parseEpssThreshold,
  type EpssAdvisoryRef,
} from './epss-gate.js';

function advisory(id: string, epss?: number, extra: Partial<EpssAdvisoryRef> = {}): EpssAdvisoryRef {
  return {
    ecosystem: extra.ecosystem ?? 'npm',
    package: extra.package ?? 'left-pad',
    version: extra.version ?? '1.3.0',
    id,
    ...(epss !== undefined ? { epss } : {}),
  };
}

describe('parseEpssThreshold', () => {
  it('accepts a probability from 0 to 1, including the endpoints', () => {
    expect(parseEpssThreshold(undefined)).toBeUndefined();
    expect(parseEpssThreshold('0')).toBe(0);
    expect(parseEpssThreshold('1')).toBe(1);
    expect(parseEpssThreshold('0.1')).toBe(0.1);
  });

  it('rejects a value outside 0 to 1 before a scan', () => {
    for (const value of ['-0.01', '1.01', '2', 'no', '']) {
      expect(() => parseEpssThreshold(value)).toThrow(CliError);
      expect(() => parseEpssThreshold(value)).toThrow('--fail-on-epss must be a number from 0 to 1.');
      try {
        parseEpssThreshold(value);
      } catch (err) {
        expect(err).toMatchObject({ code: ExitCode.ERROR });
      }
    }
  });
});

describe('evaluateEpssGate', () => {
  it('fails when any scored advisory is at or above the threshold', () => {
    const result = evaluateEpssGate({
      source: 'manifest',
      from: 'flag',
      threshold: 0.5,
      advisories: [advisory('GHSA-below', 0.49), advisory('GHSA-equal', 0.5), advisory('GHSA-above', 0.9)],
    });
    expect(result.exitCode).toBe(2);
    expect(result.skipped).toBe(false);
    expect(result.message).toBe('Failing: 2 advisories at or above EPSS 0.5.');
    expect(result.breached.map((row) => row.id)).toEqual(['GHSA-above', 'GHSA-equal']);
  });

  it('passes when every compared score is below the threshold', () => {
    const result = evaluateEpssGate({
      source: 'osv',
      from: 'flag',
      threshold: 0.5,
      advisories: [advisory('GHSA-low', 0), advisory('GHSA-mid', 0.499)],
    });
    expect(result).toMatchObject({ exitCode: 0, message: null, skipped: false, breached: [] });
  });

  it('does not treat a missing score as 0, including at threshold 0', () => {
    const missing = evaluateEpssGate({
      source: 'manifest',
      from: 'flag',
      threshold: 0,
      advisories: [advisory('GHSA-absent'), advisory('GHSA-also')],
    });
    expect(missing.exitCode).toBe(0);
    expect(missing.skipped).toBe(true);
    expect(missing.message).toBe('EPSS is absent; --fail-on-epss 0 was not compared.');

    const zero = evaluateEpssGate({
      source: 'manifest',
      from: 'flag',
      threshold: 0,
      advisories: [advisory('GHSA-zero', 0), advisory('GHSA-absent')],
    });
    expect(zero.exitCode).toBe(2);
    expect(zero.breached.map((row) => row.id)).toEqual(['GHSA-zero']);
    expect(zero.message).toBe('Failing: 1 advisory at or above EPSS 0.');
  });

  it('passes a vulnerability pass that found no advisories, and skips one that did not run', () => {
    expect(evaluateEpssGate({
      source: 'osv',
      from: 'config',
      threshold: 0,
      advisories: [],
    })).toMatchObject({ exitCode: 0, message: null, skipped: false });

    expect(evaluateEpssGate({
      source: 'manifest',
      from: 'flag',
      threshold: 0.2,
      advisories: [],
    }).exitCode).toBe(0);

    const notRun = evaluateEpssGate({ source: null, from: 'flag', threshold: 0.2, advisories: [] });
    expect(notRun).toMatchObject({
      exitCode: 0,
      skipped: true,
      message: 'EPSS is absent; --fail-on-epss 0.2 was not compared.',
    });

    const unreachable = evaluateEpssGate({ source: 'unreachable', from: 'config', threshold: 0.2, advisories: [] });
    expect(unreachable.message).toBe('EPSS is absent; failOnEpss 0.2 in the project config was not compared.');
    expect(unreachable.exitCode).toBe(0);
  });

  it('lists breached advisories in a stable order', () => {
    const input = {
      source: 'manifest' as const,
      from: 'flag' as const,
      threshold: 0.1,
      advisories: [
        advisory('GHSA-b', 0.4, { package: 'ms', ecosystem: 'npm' }),
        advisory('GHSA-a', 0.8, { package: 'left-pad', ecosystem: 'pypi' }),
        advisory('GHSA-c', 0.2, { package: 'left-pad', ecosystem: 'npm' }),
      ],
    };
    const once = evaluateEpssGate(input);
    const twice = evaluateEpssGate({ ...input, advisories: [...input.advisories].reverse() });
    expect(once.breached.map(epssAdvisoryRow)).toEqual(twice.breached.map(epssAdvisoryRow));
    expect(once.breached.map((row) => `${row.ecosystem}:${row.id}`)).toEqual([
      'npm:GHSA-c',
      'npm:GHSA-b',
      'pypi:GHSA-a',
    ]);
  });

  it('omits a missing score when reading the scan artifact', () => {
    const read = advisoriesForEpssGate({
      source: 'manifest',
      totalAdvisories: 2,
      severityCounts: { low: 0, moderate: 0, high: 2, critical: 0, unknown: 0 },
      packages: [
        {
          ecosystem: 'npm',
          package: 'left-pad',
          version: '1.3.0',
          advisories: [
            {
              id: 'GHSA-absent',
              aliases: [],
              summary: null,
              severity: 'high',
              cvss: null,
              cvssVector: null,
              fixedVersions: [],
              published: null,
              withdrawn: null,
              references: [],
            },
            {
              id: 'GHSA-zero',
              aliases: [],
              summary: null,
              severity: 'high',
              cvss: null,
              cvssVector: null,
              fixedVersions: [],
              published: null,
              withdrawn: null,
              references: [],
              epss: 0,
            },
          ],
        },
      ],
    });
    expect(read.advisories[0]).not.toHaveProperty('epss');
    expect(read.advisories[1]?.epss).toBe(0);
    expect(advisoriesForEpssGate(undefined)).toEqual({ source: null, advisories: [] });
  });
});
