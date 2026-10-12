import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runCoreScan } from '../src/core-open/index.js';
import { findingsForDisplay, orderScanFindings } from '../src/core-open/findings-order.js';
import type { Finding } from '../src/core-open/types.js';

describe('scan findings order', () => {
  it('sorts JSON findings by path, rule, advisory id, and package URL', () => {
    const rows: Finding[] = [
      {
        ruleId: 'vibgrate/vulnerability',
        level: 'error',
        message: 'critical later advisory',
        location: 'left-pad',
        details: {
          advisoryId: 'GHSA-zzz',
          ecosystem: 'npm',
          package: 'left-pad',
          installedVersion: '1.3.0',
          aliases: ['OSV-9', 'CVE-2020-1'],
        },
      },
      {
        ruleId: 'vibgrate/vulnerability',
        level: 'note',
        message: 'low earlier advisory',
        location: 'left-pad',
        details: {
          advisoryId: 'GHSA-aaa',
          ecosystem: 'npm',
          package: 'left-pad',
          installedVersion: '1.3.0',
          aliases: ['OSV-1', 'CVE-2020-2'],
        },
      },
      {
        ruleId: 'vibgrate/runtime-eol',
        level: 'error',
        message: 'runtime',
        location: 'apps/z',
      },
      {
        ruleId: 'vibgrate/runtime-eol',
        level: 'error',
        message: 'runtime',
        location: 'apps/a',
      },
    ];

    const ordered = orderScanFindings([...rows].reverse());
    expect(ordered.map((finding) => `${finding.location}:${finding.details?.advisoryId ?? finding.ruleId}`)).toEqual([
      'apps/a:vibgrate/runtime-eol',
      'apps/z:vibgrate/runtime-eol',
      'left-pad:GHSA-aaa',
      'left-pad:GHSA-zzz',
    ]);
    expect(ordered[2]?.details?.aliases).toEqual(['CVE-2020-2', 'OSV-1']);
    expect(ordered[3]?.details?.aliases).toEqual(['CVE-2020-1', 'OSV-9']);
    expect(orderScanFindings(ordered)).toEqual(ordered);

    const displayed = findingsForDisplay(ordered);
    expect(displayed.map((finding) => finding.level)).toEqual(['error', 'error', 'error', 'note']);
    expect(displayed.map((finding) => finding.details?.advisoryId ?? finding.location)).toEqual([
      'apps/a',
      'apps/z',
      'GHSA-zzz',
      'GHSA-aaa',
    ]);
  });
});

describe('vg scan JSON findings order', () => {
  let root: string;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-findings-order-'));
    fs.mkdirSync(path.join(root, 'apps', 'z-app'), { recursive: true });
    fs.mkdirSync(path.join(root, 'apps', 'a-app'), { recursive: true });
    fs.writeFileSync(
      path.join(root, 'package.json'),
      JSON.stringify({
        name: 'findings-order-root',
        version: '1.0.0',
        dependencies: { 'left-pad': '1.3.0', ms: '2.1.3' },
      }),
    );
    fs.writeFileSync(
      path.join(root, 'apps', 'z-app', 'package.json'),
      JSON.stringify({ name: 'z-app', version: '1.0.0', dependencies: { 'left-pad': '1.3.0' } }),
    );
    fs.writeFileSync(
      path.join(root, 'apps', 'a-app', 'package.json'),
      JSON.stringify({ name: 'a-app', version: '1.0.0', dependencies: { ms: '2.1.3' } }),
    );
    fs.writeFileSync(
      path.join(root, 'package-lock.json'),
      JSON.stringify({
        name: 'findings-order-root',
        lockfileVersion: 3,
        packages: {
          '': { name: 'findings-order-root', version: '1.0.0', dependencies: { 'left-pad': '1.3.0', ms: '2.1.3' } },
          'node_modules/left-pad': { version: '1.3.0' },
          'node_modules/ms': { version: '2.1.3' },
        },
      }),
    );
    // Severity order is the reverse of advisory-id order. Alias lists are unsorted.
    fs.writeFileSync(
      path.join(root, 'package-versions.json'),
      JSON.stringify({
        npm: {
          ms: {
            latest: '2.1.3',
            versions: ['2.1.3'],
            vulns: [
              {
                id: 'GHSA-ms-low',
                severity: 'low',
                aliases: ['OSV-ms', 'CVE-2020-3'],
                ranges: [{ introduced: '0', fixed: '3.0.0' }],
              },
            ],
          },
          'left-pad': {
            latest: '1.3.0',
            versions: ['1.3.0'],
            vulns: [
              {
                id: 'GHSA-zzz',
                severity: 'critical',
                aliases: ['OSV-9', 'CVE-2020-1'],
                ranges: [{ introduced: '0', fixed: '1.3.1' }],
              },
              {
                id: 'GHSA-aaa',
                severity: 'low',
                aliases: ['OSV-1', 'CVE-2020-2'],
                ranges: [{ introduced: '0', fixed: '1.3.1' }],
              },
            ],
          },
        },
      }),
    );
    vi.stubGlobal('fetch', vi.fn(async () => {
      throw new Error('unexpected network access during offline scan');
    }));
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    fs.rmSync(root, { recursive: true, force: true });
  });

  function jsonFindings(logs: readonly string[]): Finding[][] {
    const parsed: Finding[][] = [];
    for (const line of logs) {
      if (!line.startsWith('{')) continue;
      const doc = JSON.parse(line) as { findings?: Finding[] };
      if (Array.isArray(doc.findings)) parsed.push(doc.findings);
    }
    return parsed;
  }

  it('emits the same findings order from two identical JSON scans', async () => {
    const logs: string[] = [];
    const spy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      logs.push(args.map(String).join(' '));
    });
    const opts = {
      format: 'json' as const,
      concurrency: 2,
      offline: true,
      vulns: true,
      quiet: true,
      noLocalArtifacts: true,
      packageManifest: path.join(root, 'package-versions.json'),
      vibgrateVersion: 'test',
    };
    try {
      const first = await runCoreScan(root, opts);
      const second = await runCoreScan(root, opts);
      const emitted = jsonFindings(logs);
      expect(emitted).toHaveLength(2);
      expect(emitted[1]).toEqual(emitted[0]);
      expect(emitted[0]).toEqual(first.findings);
      expect(second.findings).toEqual(first.findings);
      expect(first.findings).toEqual(orderScanFindings(first.findings));

      const vulns = first.findings.filter((finding) => finding.ruleId === 'vibgrate/vulnerability');
      expect(vulns.map((finding) => finding.details?.advisoryId)).toEqual([
        'GHSA-aaa',
        'GHSA-zzz',
        'GHSA-ms-low',
      ]);
      expect(vulns[0]?.details?.aliases).toEqual(['CVE-2020-2', 'OSV-1']);
      expect(vulns[1]?.details?.aliases).toEqual(['CVE-2020-1', 'OSV-9']);
      expect(vulns[2]?.details?.aliases).toEqual(['CVE-2020-3', 'OSV-ms']);

      const displayed = findingsForDisplay(first.findings).filter((finding) => finding.ruleId === 'vibgrate/vulnerability');
      expect(displayed.map((finding) => finding.details?.advisoryId)).toEqual([
        'GHSA-zzz',
        'GHSA-aaa',
        'GHSA-ms-low',
      ]);
    } finally {
      spy.mockRestore();
    }
  });
});
