import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runCoreScan } from '../src/core-open/index.js';
import { groupAdvisoryAliases } from '../src/core-open/scanners/vulnerability-scanner.js';
import type { Finding, VulnerabilityAdvisory } from '../src/core-open/types.js';

function adv(
  id: string,
  aliases: string[],
  severity: VulnerabilityAdvisory['severity'],
): VulnerabilityAdvisory {
  return {
    id,
    aliases,
    summary: null,
    severity,
    cvss: severity === 'critical' ? 9.1 : severity === 'high' ? 7.5 : null,
    cvssVector: null,
    fixedVersions: severity === 'moderate' ? [] : ['4.17.21'],
    published: null,
    withdrawn: null,
    references: [],
  };
}

describe('advisory alias groups', () => {
  it('collapses A↔B↔C into one group and keeps that group when the records arrive reversed', () => {
    const chain = [
      adv('GHSA-bbb', ['GHSA-aaa'], 'high'),
      adv('OSV-1', ['GHSA-bbb'], 'low'),
      adv('GHSA-aaa', ['CVE-2024-9', 'OSV-1'], 'critical'),
    ];
    const forward = groupAdvisoryAliases(chain);
    const reverse = groupAdvisoryAliases([...chain].reverse());
    expect(reverse).toEqual(forward);
    expect(forward).toEqual([
      expect.objectContaining({
        id: 'CVE-2024-9',
        aliases: ['GHSA-aaa', 'GHSA-bbb', 'OSV-1'],
        severity: 'critical',
        cvss: 9.1,
        fixedVersions: ['4.17.21'],
      }),
    ]);
  });
});

describe('vg scan --vulns JSON alias groups', () => {
  let root: string;

  const linked = [
    {
      id: 'GHSA-bbb',
      aliases: ['GHSA-aaa'],
      severity: 'high',
      cvss: 7.5,
      ranges: [{ introduced: '0', fixed: '4.17.21' }],
    },
    {
      id: 'OSV-1',
      aliases: ['GHSA-bbb'],
      severity: 'low',
      ranges: [{ introduced: '0', fixed: '4.17.21' }],
    },
    {
      id: 'GHSA-aaa',
      aliases: ['CVE-2024-9', 'OSV-1'],
      severity: 'critical',
      cvss: 9.1,
      ranges: [{ introduced: '0', fixed: '4.17.21' }],
    },
    {
      id: 'GHSA-lone',
      aliases: ['OSV-9', 'CVE-2020-1'],
      severity: 'moderate',
      ranges: [{ introduced: '0' }],
    },
  ];

  function writeTree(dir: string, vulns: typeof linked): void {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'package.json'),
      JSON.stringify({
        name: 'alias-groups',
        version: '1.0.0',
        dependencies: { lodash: '4.17.20', 'left-pad': '1.3.0' },
      }),
    );
    fs.writeFileSync(
      path.join(dir, 'package-lock.json'),
      JSON.stringify({
        name: 'alias-groups',
        lockfileVersion: 3,
        packages: {
          '': { name: 'alias-groups', version: '1.0.0', dependencies: { lodash: '4.17.20', 'left-pad': '1.3.0' } },
          'node_modules/lodash': { version: '4.17.20' },
          'node_modules/left-pad': { version: '1.3.0' },
        },
      }),
    );
    fs.writeFileSync(
      path.join(dir, 'package-versions.json'),
      JSON.stringify({
        npm: {
          lodash: { latest: '4.17.21', versions: ['4.17.20', '4.17.21'], vulns },
          'left-pad': {
            latest: '1.3.0',
            versions: ['1.3.0'],
            vulns: [
              {
                id: 'GHSA-pad',
                aliases: ['CVE-2019-1'],
                severity: 'low',
                ranges: [{ introduced: '0' }],
              },
            ],
          },
        },
      }),
    );
  }

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-alias-groups-'));
    writeTree(root, linked);
    vi.stubGlobal('fetch', vi.fn(async () => {
      throw new Error('unexpected network access during offline scan');
    }));
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    fs.rmSync(root, { recursive: true, force: true });
  });

  function jsonDocuments(logs: readonly string[]): Array<Record<string, unknown>> {
    const docs: Array<Record<string, unknown>> = [];
    for (const line of logs) {
      if (!line.startsWith('{')) continue;
      docs.push(JSON.parse(line) as Record<string, unknown>);
    }
    return docs;
  }

  function stable(doc: Record<string, unknown>): string {
    const copy = { ...doc };
    delete copy.timestamp;
    delete copy.durationMs;
    return JSON.stringify(copy);
  }

  const opts = (dir: string, format: 'json' | 'sarif') => ({
    format,
    concurrency: 2,
    offline: true,
    vulns: true,
    quiet: true,
    noLocalArtifacts: true,
    packageManifest: path.join(dir, 'package-versions.json'),
    vibgrateVersion: 'test',
  });

  it('emits one stable JSON group for a transitive alias chain from a package manifest', async () => {
    const logs: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      logs.push(args.map(String).join(' '));
    });
    const first = await runCoreScan(root, opts(root, 'json'));
    const second = await runCoreScan(root, opts(root, 'json'));
    const docs = jsonDocuments(logs);
    expect(docs).toHaveLength(2);
    expect(stable(docs[1]!)).toBe(stable(docs[0]!));
    expect(stable(second as unknown as Record<string, unknown>)).toBe(
      stable(first as unknown as Record<string, unknown>),
    );

    const vulns = first.findings.filter((finding) => finding.ruleId === 'vibgrate/vulnerability');
    expect(vulns.map((finding) => `${finding.location}:${finding.details?.advisoryId}`)).toEqual([
      'left-pad:GHSA-pad',
      'lodash:CVE-2024-9',
      'lodash:GHSA-lone',
    ]);
    expect(vulns[0]?.details?.aliases).toEqual(['CVE-2019-1']);
    expect(vulns[1]?.details).toMatchObject({
      advisoryId: 'CVE-2024-9',
      aliases: ['GHSA-aaa', 'GHSA-bbb', 'OSV-1'],
      severity: 'critical',
      cvss: 9.1,
      fixedVersions: ['4.17.21'],
    });
    expect(vulns[1]?.message).toBe('lodash@4.17.20: CVE-2024-9 (critical 9.1) — fix available (4.17.21)');
    expect(vulns[2]?.details?.aliases).toEqual(['CVE-2020-1', 'OSV-9']);
    expect(vulns[2]?.message).toBe('lodash@4.17.20: GHSA-lone (CVE-2020-1) (moderate)');

    const recorded = first.extended?.vulnerabilities;
    expect(recorded?.source).toBe('manifest');
    expect(recorded?.totalAdvisories).toBe(3);
    expect(recorded?.packages.find((pkg) => pkg.package === 'lodash')?.advisories.map((advisory) => advisory.id)).toEqual([
      'CVE-2024-9',
      'GHSA-lone',
    ]);
  });

  it('writes the same JSON group when the manifest lists the chain in reverse', async () => {
    const other = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-alias-groups-rev-'));
    writeTree(other, [...linked].reverse());
    vi.spyOn(console, 'log').mockImplementation(() => {});
    try {
      const forward = await runCoreScan(root, opts(root, 'json'));
      const reverse = await runCoreScan(other, opts(other, 'json'));
      const pick = (findings: Finding[]) =>
        findings
          .filter((finding) => finding.ruleId === 'vibgrate/vulnerability')
          .map((finding) => ({
            location: finding.location,
            message: finding.message,
            advisoryId: finding.details?.advisoryId,
            aliases: finding.details?.aliases,
            severity: finding.details?.severity,
            cvss: finding.details?.cvss,
            fixedVersions: finding.details?.fixedVersions,
          }));
      expect(pick(reverse.findings)).toEqual(pick(forward.findings));
      expect(reverse.extended?.vulnerabilities?.packages).toEqual(forward.extended?.vulnerabilities?.packages);
    } finally {
      fs.rmSync(other, { recursive: true, force: true });
    }
  });

  it('keeps one SARIF result per advisory id', async () => {
    const logs: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      logs.push(args.map(String).join(' '));
    });
    await runCoreScan(root, opts(root, 'sarif'));
    const sarif = jsonDocuments(logs).find((doc) => Array.isArray(doc.runs));
    expect(sarif).toBeTruthy();
    const results = (sarif!.runs as Array<{ results: Array<{ ruleId: string; properties?: { advisoryId?: string } }> }>)[0]!
      .results;
    const ids = results.filter((result) => result.ruleId === 'vibgrate/vulnerability').map((result) => result.properties?.advisoryId);
    expect(ids).toEqual(['GHSA-pad', 'GHSA-aaa', 'GHSA-bbb', 'GHSA-lone', 'OSV-1']);
  });
});
