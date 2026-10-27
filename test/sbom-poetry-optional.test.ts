/**
 * Poetry `[tool.poetry.dependencies]` inline `optional = true` is an optional
 * manifest row. A quoted spec in the same table stays required. The `python`
 * key is the runtime, not a package.
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { PyPICache } from '../src/core-open/scanners/pypi-cache.js';
import { scanPythonProjects } from '../src/core-open/scanners/python-scanner.js';
import { Semaphore } from '../src/core-open/utils/semaphore.js';
import { collectLockfileGraph, toCycloneDx, toSpdx } from '../src/reporting/commands/sbom.js';
import type { ProjectScan, ScanArtifact } from '../src/reporting/types.js';

const LOCKFILE = `[[package]]
name = "psycopg"
version = "3.1.18"
category = "main"

[[package]]
name = "requests"
version = "2.31.0"
category = "main"

[metadata]
lock-version = "2.0"
python-versions = "^3.11"
content-hash = "abc"
`;

function manifest(order: 'required-first' | 'optional-first'): string {
  const required = 'requests = "2.31.0"';
  const optional = order === 'required-first'
    ? 'psycopg = { version = "^3.1", optional = true }'
    : 'psycopg = { optional = true, version = "^3.1" }';
  const deps = order === 'required-first' ? `${required}\n${optional}` : `${optional}\n${required}`;
  return `[tool.poetry]
name = "app"
version = "0.1.0"

[tool.poetry.dependencies]
python = { version = "^3.11", optional = true }
${deps}
`;
}

function artifact(projects: ProjectScan[]): ScanArtifact {
  return {
    schemaVersion: '1.0',
    timestamp: '2026-02-19T00:00:00.000Z',
    vibgrateVersion: '0.0.1',
    rootPath: 'poetry-optional',
    drift: {
      score: 0,
      riskLevel: 'low',
      components: { runtimeScore: 0, frameworkScore: 0, dependencyScore: 0, eolScore: 0 },
    },
    findings: [],
    projects,
  };
}

async function scan(root: string): Promise<ProjectScan[]> {
  return scanPythonProjects(root, new PyPICache(new Semaphore(1), undefined, true));
}

describe('sbom export: Poetry optional dependencies', () => {
  let root: string;

  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  async function exportOrder(order: 'required-first' | 'optional-first') {
    fs.writeFileSync(path.join(root, 'pyproject.toml'), manifest(order));
    const projects = await scan(root);
    const scanArtifact = artifact(projects);
    const graph = collectLockfileGraph(scanArtifact, root);
    return {
      projects,
      cdx: toCycloneDx(scanArtifact, graph),
      spdx: toSpdx(scanArtifact, graph),
    };
  }

  it('marks the optional package and leaves the required package unmarked, independent of pyproject.toml order', async () => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-poetry-optional-'));
    fs.writeFileSync(path.join(root, 'poetry.lock'), LOCKFILE);

    const first = await exportOrder('required-first');
    const second = await exportOrder('optional-first');
    expect(JSON.stringify(second.cdx)).toBe(JSON.stringify(first.cdx));
    expect(JSON.stringify(second.spdx)).toBe(JSON.stringify(first.spdx));

    const project = first.projects[0]!;
    expect(project.runtime).toBe('^3.11');
    expect(project.dependencies.map((dep) => [dep.package, dep.section])).toEqual([
      ['psycopg', 'optionalDependencies'],
      ['requests', 'dependencies'],
    ]);

    const cdx = first.cdx as {
      components: Array<{ name: string; scope?: string; properties: Array<{ name: string; value: string }> }>;
      dependencies?: unknown;
    };
    const byName = new Map(cdx.components.map((component) => [component.name, component]));
    const vibScope = (name: string): string | undefined =>
      byName.get(name)?.properties.find((property) => property.name === 'vibgrate:scope')?.value;

    expect(byName.get('psycopg')?.scope).toBe('optional');
    expect(byName.get('requests')?.scope).toBeUndefined();
    expect(byName.has('python')).toBe(false);
    expect(vibScope('psycopg')).toBe('direct');
    expect(vibScope('requests')).toBe('direct');
    expect(cdx.dependencies).toBeUndefined();

    const spdx = first.spdx as {
      packages: Array<{ name: string }>;
      relationships: Array<{ spdxElementId: string; relatedSpdxElementId: string; relationshipType: string }>;
    };
    const id = (name: string): string => `SPDXRef-Package-${spdx.packages.findIndex((pkg) => pkg.name === name) + 1}`;
    expect(spdx.relationships).toEqual([
      {
        spdxElementId: id('psycopg'),
        relatedSpdxElementId: 'SPDXRef-DOCUMENT',
        relationshipType: 'OPTIONAL_DEPENDENCY_OF',
      },
    ]);
    expect(spdx.relationships.some((rel) => rel.relationshipType === 'DEV_DEPENDENCY_OF')).toBe(false);
    expect(spdx.relationships.some((rel) => rel.spdxElementId === id('requests'))).toBe(false);
    expect(spdx.packages.map((pkg) => pkg.name)).toEqual(['psycopg', 'requests']);
  });
});
