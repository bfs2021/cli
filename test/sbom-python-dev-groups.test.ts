/**
 * PEP 735 `[dependency-groups]` and Poetry dependency groups are development
 * manifest rows. `{include-group = "..."}` is not expanded. A name that is
 * also in production stays a production row. A name in a dev group and an
 * optional extra, with no production listing, stays a development row. A
 * name in production, an optional extra, and a dev group stays optional.
 * An extra whose name is `dev` stays optional.
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

const GROUPS_LOCK = `[[package]]
name = "black"
version = "24.8.0"

[[package]]
name = "httpx"
version = "0.27.2"

[[package]]
name = "pytest"
version = "8.3.2"

[[package]]
name = "ruff"
version = "0.6.9"
`;

const PRECEDENCE_LOCK = `${GROUPS_LOCK}
[[package]]
name = "psycopg"
version = "3.1.18"
`;

const INCLUDE_LOCK = `[[package]]
name = "httpx"
version = "0.27.2"

[[package]]
name = "pytest"
version = "8.3.2"
`;

const POETRY_LOCK = `[[package]]
name = "coverage"
version = "7.6.1"
category = "dev"

[[package]]
name = "pytest"
version = "8.3.2"
category = "dev"

[[package]]
name = "requests"
version = "2.31.0"
category = "main"
`;

function artifact(projects: ProjectScan[], rootPath: string): ScanArtifact {
  return {
    schemaVersion: '1.0',
    timestamp: '2026-02-19T00:00:00.000Z',
    vibgrateVersion: '0.0.1',
    rootPath,
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

function groupsManifest(order: 'dev-first' | 'lint-first'): string {
  const dev = 'dev = ["pytest>=8"]';
  const lint = 'lint = ["ruff>=0.6"]';
  const groups = order === 'dev-first' ? `${dev}\n${lint}` : `${lint}\n${dev}`;
  return `[project]
name = "app"
requires-python = ">=3.11"
dependencies = ["httpx>=0.27"]

[project.optional-dependencies]
dev = ["black>=24"]

[dependency-groups]
${groups}
`;
}

const PRECEDENCE = `[project]
name = "app"
dependencies = ["httpx>=0.27", "black>=24"]

[project.optional-dependencies]
db = ["psycopg>=3.1"]
tools = ["black>=24"]

[dependency-groups]
dev = ["httpx>=1", "psycopg>=3.1", "black>=24", "pytest>=8", "coverage>=7"]
`;

function includeGroupManifest(order: 'dev-first' | 'typing-first'): string {
  const dev = `dev = [
  "pytest>=8",
  {include-group = "typing"},
  { include-group = "missing" },
]`;
  const typing = 'typing = ["mypy>=1.8"]';
  const groups = order === 'dev-first' ? `${dev}\n${typing}` : `${typing}\n${dev}`;
  return `[project]
name = "app"
dependencies = ["httpx>=0.27"]

[dependency-groups]
${groups}
`;
}

const POETRY_GROUPS = `[tool.poetry]
name = "app"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.11"
requests = "2.31.0"

[tool.poetry.group.dev.dependencies]
python = "^3.9"
requests = "^2.0.0"
pytest = "^8.0.0"

[tool.poetry.group.test.dependencies]
coverage = "7.6.1"
`;

const POETRY_LEGACY = `[tool.poetry]
name = "app"
version = "0.1.0"

[tool.poetry.dev-dependencies]
python = "^3.12"
pytest = "8.3.2"
`;

type Cdx = {
  components: Array<{ name: string; version?: string; scope?: string; properties: Array<{ name: string; value: string }> }>;
  dependencies?: unknown;
};

type Spdx = {
  packages: Array<{ name: string }>;
  relationships: Array<{ spdxElementId: string; relatedSpdxElementId: string; relationshipType: string }>;
};

function vibScope(cdx: Cdx, name: string): string | undefined {
  return cdx.components
    .find((component) => component.name === name)
    ?.properties.find((property) => property.name === 'vibgrate:scope')?.value;
}

function spdxId(spdx: Spdx, name: string): string {
  return `SPDXRef-Package-${spdx.packages.findIndex((pkg) => pkg.name === name) + 1}`;
}

describe('sbom export: Python dependency groups', () => {
  let root: string;

  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  async function exportAt(manifest: string, lockfile: string | undefined, rootPath: string) {
    fs.writeFileSync(path.join(root, 'pyproject.toml'), manifest);
    if (lockfile !== undefined) fs.writeFileSync(path.join(root, 'poetry.lock'), lockfile);
    const projects = await scan(root);
    const scanArtifact = artifact(projects, rootPath);
    const graph = collectLockfileGraph(scanArtifact, root);
    return {
      projects,
      cdx: toCycloneDx(scanArtifact, graph) as Cdx,
      spdx: toSpdx(scanArtifact, graph) as Spdx,
    };
  }

  it('exports a dependency-group package as a direct development dependency, independent of group order', async () => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-pyproject-groups-'));
    const first = await exportAt(groupsManifest('dev-first'), GROUPS_LOCK, 'pyproject-groups');
    const second = await exportAt(groupsManifest('lint-first'), GROUPS_LOCK, 'pyproject-groups');
    expect(JSON.stringify(second.cdx)).toBe(JSON.stringify(first.cdx));
    expect(JSON.stringify(second.spdx)).toBe(JSON.stringify(first.spdx));

    const byPackage = new Map(first.projects[0]!.dependencies.map((dep) => [dep.package, dep]));
    expect(byPackage.get('httpx')?.section).toBe('dependencies');
    expect(byPackage.get('httpx')?.currentSpec).toBe('>=0.27');
    expect(byPackage.get('pytest')?.section).toBe('devDependencies');
    expect(byPackage.get('pytest')?.currentSpec).toBe('>=8');
    expect(byPackage.get('ruff')?.section).toBe('devDependencies');
    expect(byPackage.get('ruff')?.currentSpec).toBe('>=0.6');
    expect(byPackage.get('black')?.section).toBe('optionalDependencies');
    expect(byPackage.get('black')?.currentSpec).toBe('>=24');

    const byName = new Map(first.cdx.components.map((component) => [component.name, component]));
    expect(byName.get('pytest')?.scope).toBe('excluded');
    expect(byName.get('ruff')?.scope).toBe('excluded');
    expect(byName.get('black')?.scope).toBe('optional');
    expect(byName.get('httpx')?.scope).toBeUndefined();
    expect(vibScope(first.cdx, 'pytest')).toBe('direct');
    expect(vibScope(first.cdx, 'ruff')).toBe('direct');
    expect(vibScope(first.cdx, 'black')).toBe('direct');
    expect(vibScope(first.cdx, 'httpx')).toBe('direct');
    expect(first.cdx.dependencies).toBeUndefined();

    expect(first.spdx.relationships).toEqual([
      {
        spdxElementId: spdxId(first.spdx, 'black'),
        relatedSpdxElementId: 'SPDXRef-DOCUMENT',
        relationshipType: 'OPTIONAL_DEPENDENCY_OF',
      },
      {
        spdxElementId: spdxId(first.spdx, 'pytest'),
        relatedSpdxElementId: 'SPDXRef-DOCUMENT',
        relationshipType: 'DEV_DEPENDENCY_OF',
      },
      {
        spdxElementId: spdxId(first.spdx, 'ruff'),
        relatedSpdxElementId: 'SPDXRef-DOCUMENT',
        relationshipType: 'DEV_DEPENDENCY_OF',
      },
    ]);
    expect(first.spdx.packages.map((pkg) => pkg.name)).toEqual(['black', 'httpx', 'pytest', 'ruff']);
  });

  it('keeps production over a dev group, development over an optional extra, and optional over all three', async () => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-pyproject-groups-precedence-'));
    const exported = await exportAt(PRECEDENCE, PRECEDENCE_LOCK, 'pyproject-groups-precedence');
    const byPackage = new Map(exported.projects[0]!.dependencies.map((dep) => [dep.package, dep]));
    expect(byPackage.get('httpx')?.section).toBe('dependencies');
    expect(byPackage.get('httpx')?.currentSpec).toBe('>=0.27');
    expect(byPackage.get('psycopg')?.section).toBe('devDependencies');
    expect(byPackage.get('psycopg')?.currentSpec).toBe('>=3.1');
    expect(byPackage.get('black')?.section).toBe('optionalDependencies');
    expect(byPackage.get('black')?.currentSpec).toBe('>=24');
    expect(byPackage.get('pytest')?.section).toBe('devDependencies');
    expect(byPackage.get('coverage')?.section).toBe('devDependencies');
    expect(byPackage.get('coverage')?.currentSpec).toBe('>=7');

    const byName = new Map(exported.cdx.components.map((component) => [component.name, component]));
    expect(byName.get('httpx')?.scope).toBeUndefined();
    expect(vibScope(exported.cdx, 'httpx')).toBe('direct');
    expect(byName.get('psycopg')?.scope).toBe('excluded');
    expect(vibScope(exported.cdx, 'psycopg')).toBe('direct');
    expect(byName.get('black')?.scope).toBe('optional');
    expect(vibScope(exported.cdx, 'black')).toBe('direct');
    expect(byName.get('pytest')?.scope).toBe('excluded');
    expect(vibScope(exported.cdx, 'pytest')).toBe('direct');
    expect(byName.get('coverage')?.version).toBe('unknown');
    expect(byName.get('coverage')?.scope).toBe('excluded');
    expect(vibScope(exported.cdx, 'coverage')).toBe('direct');
    expect(exported.cdx.dependencies).toBeUndefined();

    const dev = (name: string) => ({
      spdxElementId: spdxId(exported.spdx, name),
      relatedSpdxElementId: 'SPDXRef-DOCUMENT',
      relationshipType: 'DEV_DEPENDENCY_OF',
    });
    expect(exported.spdx.relationships).toEqual([
      {
        spdxElementId: spdxId(exported.spdx, 'black'),
        relatedSpdxElementId: 'SPDXRef-DOCUMENT',
        relationshipType: 'OPTIONAL_DEPENDENCY_OF',
      },
      dev('coverage'),
      dev('psycopg'),
      dev('pytest'),
    ]);
    expect(exported.spdx.relationships.some((rel) => rel.spdxElementId === spdxId(exported.spdx, 'httpx'))).toBe(false);
  });

  it('skips include-group entries and still reads each group array', async () => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-pyproject-include-group-'));
    const first = await exportAt(includeGroupManifest('dev-first'), INCLUDE_LOCK, 'pyproject-include-group');
    const second = await exportAt(includeGroupManifest('typing-first'), INCLUDE_LOCK, 'pyproject-include-group');
    expect(JSON.stringify(second.cdx)).toBe(JSON.stringify(first.cdx));
    expect(JSON.stringify(second.spdx)).toBe(JSON.stringify(first.spdx));

    const byPackage = new Map(first.projects[0]!.dependencies.map((dep) => [dep.package, dep]));
    expect(byPackage.get('httpx')?.section).toBe('dependencies');
    expect(byPackage.get('pytest')?.section).toBe('devDependencies');
    expect(byPackage.get('mypy')?.section).toBe('devDependencies');
    expect(byPackage.get('mypy')?.currentSpec).toBe('>=1.8');
    expect(byPackage.has('typing')).toBe(false);
    expect(byPackage.has('missing')).toBe(false);
    expect(byPackage.has('include-group')).toBe(false);

    const byName = new Map(first.cdx.components.map((component) => [component.name, component]));
    expect(byName.get('mypy')?.version).toBe('unknown');
    expect(byName.get('mypy')?.scope).toBe('excluded');
    expect(vibScope(first.cdx, 'mypy')).toBe('direct');
    expect(byName.get('pytest')?.scope).toBe('excluded');
    expect(vibScope(first.cdx, 'pytest')).toBe('direct');
    expect(byName.has('typing')).toBe(false);
    expect(byName.has('missing')).toBe(false);
  });

  it('exports a Poetry dependency group as a direct development dependency and keeps a production name', async () => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-poetry-groups-'));
    const exported = await exportAt(POETRY_GROUPS, POETRY_LOCK, 'poetry-groups');
    const project = exported.projects[0]!;
    expect(project.runtime).toBe('^3.11');
    const byPackage = new Map(project.dependencies.map((dep) => [dep.package, dep]));
    expect(byPackage.get('requests')?.section).toBe('dependencies');
    expect(byPackage.get('requests')?.currentSpec).toBe('==2.31.0');
    expect(byPackage.get('pytest')?.section).toBe('devDependencies');
    expect(byPackage.get('pytest')?.currentSpec).toBe('==^8.0.0');
    expect(byPackage.get('coverage')?.section).toBe('devDependencies');
    expect(byPackage.get('coverage')?.currentSpec).toBe('==7.6.1');
    expect(byPackage.has('python')).toBe(false);

    const byName = new Map(exported.cdx.components.map((component) => [component.name, component]));
    expect(byName.get('requests')?.scope).toBeUndefined();
    expect(vibScope(exported.cdx, 'requests')).toBe('direct');
    expect(byName.get('pytest')?.scope).toBe('excluded');
    expect(byName.get('pytest')?.version).toBe('8.3.2');
    expect(vibScope(exported.cdx, 'pytest')).toBe('direct');
    expect(byName.get('coverage')?.scope).toBe('excluded');
    expect(byName.get('coverage')?.version).toBe('7.6.1');
    expect(vibScope(exported.cdx, 'coverage')).toBe('direct');
    expect(byName.has('python')).toBe(false);
    expect(exported.cdx.dependencies).toBeUndefined();

    expect(exported.spdx.relationships).toEqual([
      {
        spdxElementId: spdxId(exported.spdx, 'coverage'),
        relatedSpdxElementId: 'SPDXRef-DOCUMENT',
        relationshipType: 'DEV_DEPENDENCY_OF',
      },
      {
        spdxElementId: spdxId(exported.spdx, 'pytest'),
        relatedSpdxElementId: 'SPDXRef-DOCUMENT',
        relationshipType: 'DEV_DEPENDENCY_OF',
      },
    ]);
    expect(exported.spdx.relationships.some((rel) => rel.spdxElementId === spdxId(exported.spdx, 'requests'))).toBe(false);
    expect(exported.spdx.packages.map((pkg) => pkg.name)).toEqual(['coverage', 'pytest', 'requests']);
  });

  it('reads the legacy Poetry dev-dependencies table and skips its python key', async () => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-poetry-legacy-dev-'));
    const exported = await exportAt(POETRY_LEGACY, undefined, 'poetry-legacy-dev');
    const project = exported.projects[0]!;
    expect(project.runtime).toBeUndefined();
    expect(project.dependencies.map((dep) => [dep.package, dep.section, dep.currentSpec])).toEqual([
      ['pytest', 'devDependencies', '==8.3.2'],
    ]);

    const byName = new Map(exported.cdx.components.map((component) => [component.name, component]));
    expect(byName.get('pytest')?.scope).toBe('excluded');
    expect(byName.get('pytest')?.version).toBe('8.3.2');
    expect(vibScope(exported.cdx, 'pytest')).toBe('direct');
    expect(byName.has('python')).toBe(false);
    expect(exported.spdx.relationships).toEqual([
      {
        spdxElementId: spdxId(exported.spdx, 'pytest'),
        relatedSpdxElementId: 'SPDXRef-DOCUMENT',
        relationshipType: 'DEV_DEPENDENCY_OF',
      },
    ]);
  });
});
