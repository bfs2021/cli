import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runCoreScan, type ScanOptions } from '../../core-open/index.js';
import { applyPlan } from '../planning/apply.js';
import type { PlannedUpgrade, VulnDelta } from '../planning/types.js';
import { attemptsForApply, resolvedAdvisoryIds } from '../planning/advisory-resolution.js';

/**
 * A blocked `vg fix` upgrade must not clear the advisory on the next scan.
 * The package manager often rewrites the manifest before a failing install;
 * if that rewrite stuck, the scan would read the fixed version and drop the
 * advisory even though the install never landed.
 */

let dir: string;

afterEach(() => {
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

function emptyDelta(): VulnDelta {
  return { total: 0, bySeverity: { critical: 0, high: 0, moderate: 0, low: 0, unknown: 0 } };
}

function upgrade(over: Partial<PlannedUpgrade> = {}): PlannedUpgrade {
  return {
    package: 'lodash',
    ecosystem: 'npm',
    from: '4.17.20',
    to: '4.17.21',
    kind: 'patch',
    blastRadius: 'low',
    fixes: { ...emptyDelta(), total: 1, bySeverity: { ...emptyDelta().bySeverity, high: 1 } },
    reason: 'remediates GHSA-lodash',
    advisories: [{ id: 'GHSA-lodash', fixedVersion: '4.17.21' }],
    ...over,
  };
}

function seed(vuln: { fixed?: string }): string {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-fix-advisory-'));
  fs.writeFileSync(
    path.join(dir, 'package.json'),
    JSON.stringify({ name: 'fixture', version: '1.0.0', dependencies: { lodash: '4.17.20' } }, null, 2),
  );
  fs.writeFileSync(
    path.join(dir, 'package-lock.json'),
    JSON.stringify({
      lockfileVersion: 3,
      packages: { 'node_modules/lodash': { version: '4.17.20' } },
    }),
  );
  fs.writeFileSync(
    path.join(dir, 'versions.json'),
    JSON.stringify({
      npm: {
        lodash: {
          latest: '4.17.21',
          versions: ['4.17.20', '4.17.21'],
          vulns: [
            {
              id: 'GHSA-lodash',
              severity: 'high',
              ranges: [vuln.fixed ? { introduced: '0', fixed: vuln.fixed } : { introduced: '0' }],
            },
          ],
        },
      },
    }),
  );
  return dir;
}

async function openAdvisoryIds(root: string): Promise<string[]> {
  const opts: ScanOptions = {
    vibgrateVersion: 'test',
    format: 'json',
    out: path.join(root, 'scratch-scan.json'),
    quiet: true,
    concurrency: 2,
    offline: true,
    vulns: true,
    packageManifest: path.join(root, 'versions.json'),
  };
  const artifact = await runCoreScan(root, opts);
  const packages = artifact.extended?.vulnerabilities?.packages ?? [];
  return packages.flatMap((pkg) => pkg.advisories.map((advisory) => advisory.id)).sort();
}

/** Rewrite the manifest and lockfile the way a package manager does before it fails. */
function mutateToFixed(): void {
  fs.writeFileSync(
    path.join(dir, 'package.json'),
    JSON.stringify({ name: 'fixture', version: '1.0.0', dependencies: { lodash: '4.17.21' } }, null, 2),
  );
  fs.writeFileSync(
    path.join(dir, 'package-lock.json'),
    JSON.stringify({
      lockfileVersion: 3,
      packages: { 'node_modules/lodash': { version: '4.17.21' } },
    }),
  );
}

describe('vg fix never marks a blocked upgrade resolved', () => {
  it('keeps the advisory open when a failed install rewrote the manifest and lockfile', async () => {
    const root = seed({ fixed: '4.17.21' });
    expect(await openAdvisoryIds(root)).toEqual(['GHSA-lodash']);

    const planned = upgrade();
    const results = applyPlan(root, [planned], {
      run: () => {
        mutateToFixed();
        return { ok: false, detail: 'exit 1' };
      },
    });

    expect(results[0].status).toBe('failed');
    expect(resolvedAdvisoryIds(attemptsForApply([planned], results))).toEqual([]);
    expect(await openAdvisoryIds(root)).toEqual(['GHSA-lodash']);
    expect(JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).dependencies.lodash).toBe('4.17.20');
  });

  it.each([
    ['policy', 'blocked by policy'],
    ['peer', 'peer conflict: ERESOLVE unable to resolve dependency tree'],
  ] as const)('keeps the advisory open when the install is blocked by %s', async (_label, detail) => {
    const root = seed({ fixed: '4.17.21' });
    const planned = upgrade();
    const results = applyPlan(root, [planned], {
      run: () => {
        mutateToFixed();
        return { ok: false, detail };
      },
    });
    expect(resolvedAdvisoryIds(attemptsForApply([planned], results))).toEqual([]);
    expect(await openAdvisoryIds(root)).toEqual(['GHSA-lodash']);
  });

  it('keeps the advisory open when no fixed version is published, even after a successful bump', async () => {
    const root = seed({});
    expect(await openAdvisoryIds(root)).toEqual(['GHSA-lodash']);
    const planned = upgrade({
      advisories: [{ id: 'GHSA-lodash', fixedVersion: null }],
      to: '4.17.21',
    });
    const results = applyPlan(root, [planned], {
      run: () => {
        mutateToFixed();
        return { ok: true };
      },
    });
    expect(results[0].status).toBe('applied');
    expect(resolvedAdvisoryIds(attemptsForApply([planned], results))).toEqual([]);
    expect(await openAdvisoryIds(root)).toEqual(['GHSA-lodash']);
  });

  it('clears the advisory only when the install lands on the fixed version', async () => {
    const root = seed({ fixed: '4.17.21' });
    const planned = upgrade();
    const results = applyPlan(root, [planned], {
      run: () => {
        mutateToFixed();
        return { ok: true };
      },
    });
    expect(resolvedAdvisoryIds(attemptsForApply([planned], results))).toEqual(['GHSA-lodash']);
    expect(await openAdvisoryIds(root)).toEqual([]);
  });
});
