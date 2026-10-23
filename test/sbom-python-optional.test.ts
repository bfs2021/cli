/**
 * PEP 621 `[project.optional-dependencies]` is an optional manifest row.
 * `[dependency-groups]` and Poetry dependency groups stay off that mark.
 * A name that is also in `[project] dependencies` stays optional, and the
 * exported document does not depend on which table is written first.
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
name = "httpx"
version = "0.27.2"

[[package]]
name = "psycopg"
version = "3.1.18"

[[package]]
name = "pytest"
version = "8.3.2"
`;

function manifest(order: 'prod-first' | 'extra-first'): string {
  const noise = `[dependency-groups]
dev = ["pytest>=8"]

[tool.poetry.group.dev.dependencies]
pytest = "^8.0.0"
`;
  if (order === 'prod-first') {
    return `[project]
name = "app"
dependencies = ["httpx>=0.27", "psycopg>=3.1"]

[project.optional-dependencies]
postgres = ["psycopg>=3.1"]
db = ["psycopg>=3.1"]

${noise}`;
  }
  return `${noise}
[project.optional-dependencies]
db = ["psycopg>=3.1"]
postgres = ["psycopg>=3.1"]

[project]
name = "app"
dependencies = ["psycopg>=3.1", "httpx>=0.27"]
`;
}

function artifact(projects: ProjectScan[]): ScanArtifact {
  return {
    schemaVersion: '1.0',
    timestamp: '2026-02-19T00:00:00.000Z',
    vibgrateVersion: '0.0.1',
    rootPath: 'pyproject-optional',
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

describe('sbom export: PEP 621 optional extras', () => {
  let root: string;

  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  async function exportOrder(order: 'prod-first' | 'extra-first') {
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

  it('marks the extra and leaves the production requirement unmarked, independent of table order', async () => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-pyproject-optional-'));
    fs.writeFileSync(path.join(root, 'poetry.lock'), LOCKFILE);

    const first = await exportOrder('prod-first');
    const second = await exportOrder('extra-first');
    expect(JSON.stringify(second.cdx)).toBe(JSON.stringify(first.cdx));
    expect(JSON.stringify(second.spdx)).toBe(JSON.stringify(first.spdx));

    const byPackage = new Map(first.projects[0]!.dependencies.map((dep) => [dep.package, dep]));
    expect(byPackage.get('psycopg')?.section).toBe('optionalDependencies');
    expect(byPackage.get('psycopg')?.currentSpec).toBe('>=3.1');
    expect(byPackage.get('httpx')?.section).toBe('dependencies');
    expect(byPackage.get('httpx')?.currentSpec).toBe('>=0.27');
    expect(byPackage.has('pytest')).toBe(false);

    const cdx = first.cdx as {
      components: Array<{ name: string; scope?: string; properties: Array<{ name: string; value: string }> }>;
      dependencies?: unknown;
    };
    const byName = new Map(cdx.components.map((component) => [component.name, component]));
    const vibScope = (name: string): string | undefined =>
      byName.get(name)?.properties.find((property) => property.name === 'vibgrate:scope')?.value;

    expect(byName.get('psycopg')?.scope).toBe('optional');
    expect(byName.get('httpx')?.scope).toBeUndefined();
    expect(byName.get('pytest')?.scope).toBeUndefined();
    expect(vibScope('psycopg')).toBe('direct');
    expect(vibScope('httpx')).toBe('direct');
    expect(vibScope('pytest')).toBe('transitive');
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
    expect(spdx.packages.map((pkg) => pkg.name)).toEqual(['httpx', 'psycopg', 'pytest']);
  });
});
