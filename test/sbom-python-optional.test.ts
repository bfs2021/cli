/**
 * PEP 621 `[project.optional-dependencies]` is an optional manifest row.
 * `[dependency-groups]` and Poetry dependency groups stay off that mark.
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { PyPICache } from '../src/core-open/scanners/pypi-cache.js';
import { scanPythonProjects } from '../src/core-open/scanners/python-scanner.js';
import { Semaphore } from '../src/core-open/utils/semaphore.js';
import { compareCodeUnits } from '../src/core-open/utils/code-unit.js';
import { collectLockfileGraph, toCycloneDx, toSpdx } from '../src/reporting/commands/sbom.js';
import type { ProjectScan, ScanArtifact } from '../src/reporting/types.js';

const LOCKFILE = `[[package]]
name = "asyncpg"
version = "0.29.0"

[[package]]
name = "certifi"
version = "2024.8.30"

[[package]]
name = "httpx"
version = "0.27.2"

[[package]]
name = "psycopg"
version = "3.1.18"

[[package]]
name = "pymysql"
version = "2.2.0"

[[package]]
name = "pytest"
version = "8.3.3"

[[package]]
name = "redis"
version = "5.0.1"
`;

function manifest(order: 'postgres-first' | 'db-first'): string {
  const postgres = `postgres = [
  "psycopg>=3.1; python_version >= '3.11'",
  "asyncpg>=0.29",
]`;
  const db = `db = [
  "Psycopg>=9",
  "psycopg[binary]>=3.2",
  "redis>=4",
]`;
  const mysql = 'mysql = ["pymysql>=2.0"]';
  const extras = order === 'postgres-first' ? `${postgres}\n${mysql}\n${db}` : `${mysql}\n${db}\n${postgres}`;
  const project = `[project]
name = "demo"
dependencies = [
  "httpx>=0.27",
  "redis>=5",
]`;
  const groups = `[dependency-groups]
test = ["pytest>=8"]

[tool.poetry.group.dev.dependencies]
ruff = "^0.6"`;
  // Table order and extra order both vary. The rows must not.
  return order === 'postgres-first'
    ? `${project}\n\n${groups}\n\n[project.optional-dependencies]\n${extras}\n`
    : `[project.optional-dependencies]\n${extras}\n\n${groups}\n\n${project}\n`;
}

function artifact(projects: ProjectScan[]): ScanArtifact {
  return {
    schemaVersion: '1.0',
    timestamp: '2026-02-19T00:00:00.000Z',
    vibgrateVersion: '0.0.1',
    rootPath: 'python-optional',
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

  async function exportOrder(order: 'postgres-first' | 'db-first') {
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

  it('marks psycopg optional, leaves httpx required, and ignores extra order', async () => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-python-optional-'));
    fs.writeFileSync(path.join(root, 'poetry.lock'), LOCKFILE);

    const first = await exportOrder('postgres-first');
    const second = await exportOrder('db-first');
    expect(JSON.stringify(second.cdx)).toBe(JSON.stringify(first.cdx));
    expect(JSON.stringify(second.spdx)).toBe(JSON.stringify(first.spdx));

    const project = first.projects[0]!;
    const rows = project.dependencies.map((dep) => [dep.package, dep.section, dep.currentSpec, dep.resolvedVersion]);
    rows.sort((a, b) => compareCodeUnits(String(a[0]), String(b[0])));
    expect(rows).toEqual([
      ['asyncpg', 'optionalDependencies', '>=0.29', '0.29.0'],
      ['httpx', 'dependencies', '>=0.27', '0.27.2'],
      ['psycopg', 'optionalDependencies', '>=3.1', '3.1.18'],
      ['pymysql', 'optionalDependencies', '>=2.0', '2.2.0'],
      ['redis', 'optionalDependencies', '>=4', '5.0.1'],
    ]);
    expect(project.dependencies.some((dep) => dep.package.toLowerCase() === 'pytest' || dep.package.toLowerCase() === 'ruff')).toBe(false);

    const cdx = first.cdx as {
      components: Array<{ name: string; scope?: string; properties: Array<{ name: string; value: string }> }>;
      dependencies?: unknown;
    };
    const byName = new Map(cdx.components.map((component) => [component.name, component]));
    const vibScope = (name: string): string | undefined =>
      byName.get(name)?.properties.find((property) => property.name === 'vibgrate:scope')?.value;

    expect(byName.get('psycopg')?.scope).toBe('optional');
    expect(byName.get('pymysql')?.scope).toBe('optional');
    expect(byName.get('asyncpg')?.scope).toBe('optional');
    expect(byName.get('redis')?.scope).toBe('optional');
    expect(byName.get('httpx')?.scope).toBeUndefined();
    expect(byName.get('pytest')?.scope).toBeUndefined();
    expect(byName.get('certifi')?.scope).toBeUndefined();
    expect(byName.has('ruff')).toBe(false);
    expect(vibScope('psycopg')).toBe('direct');
    expect(vibScope('httpx')).toBe('direct');
    expect(vibScope('pytest')).toBe('transitive');
    expect(vibScope('certifi')).toBe('transitive');
    expect(cdx.dependencies).toBeUndefined();

    const spdx = first.spdx as {
      packages: Array<{ name: string; annotations?: Array<{ comment?: string }> }>;
      relationships: Array<{ spdxElementId: string; relatedSpdxElementId: string; relationshipType: string }>;
    };
    const id = (name: string): string => `SPDXRef-Package-${spdx.packages.findIndex((pkg) => pkg.name === name) + 1}`;
    const optionalRel = (name: string) => ({
      spdxElementId: id(name),
      relatedSpdxElementId: 'SPDXRef-DOCUMENT',
      relationshipType: 'OPTIONAL_DEPENDENCY_OF',
    });
    expect(spdx.relationships).toEqual([
      optionalRel('asyncpg'),
      optionalRel('psycopg'),
      optionalRel('pymysql'),
      optionalRel('redis'),
    ]);
    expect(spdx.relationships.some((rel) => rel.spdxElementId === id('httpx') || rel.relatedSpdxElementId === id('httpx'))).toBe(false);
    expect(spdx.relationships.some((rel) => rel.relationshipType === 'DEV_DEPENDENCY_OF')).toBe(false);
    const httpx = spdx.packages.find((pkg) => pkg.name === 'httpx');
    expect(httpx?.annotations?.[0]?.comment).toContain('scope=direct');
  });
});
