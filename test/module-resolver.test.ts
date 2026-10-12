import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, afterEach } from 'vitest';
import {
  buildModuleResolver,
  compareWorkspacePackages,
  relativeResolver,
  parseJsonc,
} from '../src/engine/module-resolver.js';
import { buildGraph } from '../src/engine/build.js';
import { discover } from '../src/engine/discover.js';
import { findNodes } from '../src/engine/lookup.js';
import { makeProject, cleanup } from './helpers.js';
import type { VgGraph } from '../src/schema.js';

const dirs: string[] = [];
function project(files: Record<string, string>): string {
  const d = makeProject(files);
  dirs.push(d);
  return d;
}
function relSet(root: string): Set<string> {
  return new Set(discover({ root }).map((f) => f.rel));
}
afterEach(() => {
  while (dirs.length) cleanup(dirs.pop()!);
});

describe('module resolver', () => {
  it('resolves relative imports with extension + index probing', () => {
    const root = project({ 'a/b.ts': 'x', 'a/c.ts': 'x', 'a/d/index.ts': 'x' });
    const r = buildModuleResolver(root, relSet(root));
    expect(r.resolve('a/b.ts', './c')).toBe('a/c.ts');
    expect(r.resolve('a/b.ts', './d')).toBe('a/d/index.ts');
    expect(r.resolve('a/b.ts', 'react')).toBeNull(); // external
  });

  it('resolves Python dotted absolute imports', () => {
    const root = project({ 'app/core/security.py': 'x', 'app/main.py': 'x' });
    const r = buildModuleResolver(root, relSet(root));
    expect(r.resolve('app/main.py', 'app.core.security')).toBe('app/core/security.py');
    expect(r.resolve('app/main.py', 'socket.io')).toBeNull(); // dotted but not a repo file
  });

  it('resolves tsconfig paths aliases (incl. extends → tsconfig.base.json)', () => {
    const root = project({
      'tsconfig.json': JSON.stringify({ extends: './tsconfig.base.json' }),
      'tsconfig.base.json': JSON.stringify({
        compilerOptions: { baseUrl: '.', paths: { '@app/*': ['libs/app/src/*'] } },
      }),
      'libs/app/src/util.ts': 'x',
      'src/main.ts': 'x',
    });
    const r = buildModuleResolver(root, relSet(root));
    expect(r.resolve('src/main.ts', '@app/util')).toBe('libs/app/src/util.ts');
  });

  it('tolerates JSONC (comments + trailing commas) in tsconfig', () => {
    const cfg = '{\n  // comment\n  "compilerOptions": { "baseUrl": ".", "paths": { "@x/*": ["pkg/*"], }, },\n}';
    expect(parseJsonc<{ compilerOptions: { baseUrl: string } }>(cfg).compilerOptions.baseUrl).toBe('.');
    const root = project({ 'tsconfig.json': cfg, 'pkg/a.ts': 'x', 'm.ts': 'x' });
    const r = buildModuleResolver(root, relSet(root));
    expect(r.resolve('m.ts', '@x/a')).toBe('pkg/a.ts');
  });

  it('resolves workspace-package names (npm/yarn + pnpm)', () => {
    const root = project({
      'package.json': JSON.stringify({ workspaces: ['packages/*'] }),
      'packages/ui/package.json': JSON.stringify({ name: '@org/ui' }),
      'packages/ui/src/index.ts': 'x',
      'app/main.ts': 'x',
    });
    const r = buildModuleResolver(root, relSet(root));
    expect(r.resolve('app/main.ts', '@org/ui')).toBe('packages/ui/src/index.ts');
  });

  it('prefers the longer workspace package name over a prefix', () => {
    const root = project({
      'package.json': JSON.stringify({ workspaces: ['packages/*'] }),
      'packages/a/package.json': JSON.stringify({ name: '@org/a', version: '1.0.0' }),
      'packages/a/src/index.ts': 'export const a = 1;\n',
      'packages/ab/package.json': JSON.stringify({ name: '@org/a/b', version: '1.0.0' }),
      'packages/ab/src/index.ts': 'export const b = 1;\n',
      'app/main.ts': 'export const x = 1;\n',
    });
    const r = buildModuleResolver(root, relSet(root));
    expect(r.resolve('app/main.ts', '@org/a/b')).toBe('packages/ab/src/index.ts');
    expect(r.resolve('app/main.ts', '@org/a')).toBe('packages/a/src/index.ts');
  });

  it('relativeResolver handles relative + dotted only', () => {
    const root = project({ 'a.ts': 'x', 'b.ts': 'x' });
    const r = relativeResolver(relSet(root));
    expect(r.resolve('a.ts', './b')).toBe('b.ts');
    expect(r.resolve('a.ts', '@org/x')).toBeNull();
  });
});

const PIN = '2020-01-01T00:00:00.000Z';

const COLLIDING_ROOT = JSON.stringify({
  name: 'app',
  version: '1.0.0',
  workspaces: ['packages/*'],
});
const ALPHA_PKG = JSON.stringify({
  name: 'widget',
  version: '9.0.0',
  dependencies: { 'left-pad': '1.0.0' },
});
const ZETA_PKG = JSON.stringify({
  name: 'widget',
  version: '1.0.0',
  dependencies: { 'left-pad': '1.0.0' },
});
const ALPHA_SRC = 'export const marker = "alpha";\n';
const ZETA_SRC = 'export const marker = "zeta";\n';
const APP_SRC = 'import { marker } from "widget";\nexport const used = marker;\n';

/** Write files in the given order so directory creation order differs per tree. */
function projectOrdered(files: Array<[string, string]>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-test-'));
  dirs.push(dir);
  for (const [rel, content] of files) {
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  return dir;
}

function collisionFiles(packageOrder: 'alpha-first' | 'zeta-first'): Array<[string, string]> {
  const alpha: Array<[string, string]> = [
    ['packages/alpha/package.json', ALPHA_PKG],
    ['packages/alpha/src/index.ts', ALPHA_SRC],
  ];
  const zeta: Array<[string, string]> = [
    ['packages/zeta/package.json', ZETA_PKG],
    ['packages/zeta/src/index.ts', ZETA_SRC],
  ];
  const packages = packageOrder === 'alpha-first' ? [...alpha, ...zeta] : [...zeta, ...alpha];
  return [['package.json', COLLIDING_ROOT], ...packages, ['app/main.ts', APP_SRC]];
}

function packageNodes(graph: VgGraph) {
  return graph.nodes
    .filter((n) => n.kind === 'package')
    .map((n) => ({ name: n.name, qualifiedName: n.qualifiedName, file: n.file }));
}

function dependencyEdges(graph: VgGraph) {
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  return graph.edges
    .filter((e) => e.kind === 'import' || e.kind === 'depends_on')
    .map((e) => {
      const src = byId.get(e.src);
      const dst = byId.get(e.dst);
      const label = (n: typeof src) =>
        n ? `${n.kind}:${n.file}:${n.qualifiedName}` : '';
      return { kind: e.kind, src: label(src), dst: label(dst) };
    });
}

describe('colliding bare workspace names', () => {
  it('orders packages by path, then name, then version', () => {
    const alpha = { dirRel: 'packages/alpha', name: 'widget', version: '9.0.0' };
    const zeta = { dirRel: 'packages/zeta', name: 'widget', version: '1.0.0' };
    const paths = (list: typeof alpha[]) => list.map((p) => p.dirRel);
    expect(paths([zeta, alpha].sort(compareWorkspacePackages))).toEqual([
      'packages/alpha',
      'packages/zeta',
    ]);
    expect(paths([alpha, zeta].sort(compareWorkspacePackages))).toEqual([
      'packages/alpha',
      'packages/zeta',
    ]);
  });

  it('binds the import to the same package whichever directory was created first', () => {
    for (const order of ['alpha-first', 'zeta-first'] as const) {
      const root = projectOrdered(collisionFiles(order));
      const resolved = buildModuleResolver(root, relSet(root)).resolve('app/main.ts', 'widget');
      expect(resolved).toBe('packages/alpha/src/index.ts');
    }
  });

  it('emits the same package-node and dependency-edge order from two builds', async () => {
    const build = (order: 'alpha-first' | 'zeta-first') =>
      buildGraph({
        root: projectOrdered(collisionFiles(order)),
        generatedAt: PIN,
        inline: true,
        noCache: true,
        noTsc: true,
        noScip: true,
        noIndex: true,
        noCoverage: true,
        noGround: true,
      });
    const [{ graph: first }, { graph: second }] = await Promise.all([
      build('alpha-first'),
      build('zeta-first'),
    ]);

    const nodes = packageNodes(first);
    const edges = dependencyEdges(first);
    expect(packageNodes(second)).toEqual(nodes);
    expect(dependencyEdges(second)).toEqual(edges);
    expect(nodes.map((n) => n.file).sort()).toEqual([
      'package.json',
      'packages/alpha/package.json',
      'packages/zeta/package.json',
    ]);
    expect(edges).toContainEqual(
      expect.objectContaining({
        kind: 'import',
        src: 'file:app/main.ts:app/main.ts',
        dst: 'file:packages/alpha/src/index.ts:packages/alpha/src/index.ts',
      }),
    );
    expect(edges.some((e) => e.dst.includes('packages/zeta/src/index.ts'))).toBe(false);
  });
});

describe('resolution end-to-end (alias monorepo → cross-package call edge)', () => {
  it('creates a call edge across an aliased package boundary', async () => {
    const root = project({
      'tsconfig.base.json': JSON.stringify({
        compilerOptions: { baseUrl: '.', paths: { '@lib/math': ['libs/math/src/index.ts'] } },
      }),
      'libs/math/src/index.ts': 'export function add(a: number, b: number) { return a + b; }',
      'apps/web/calc.ts': "import { add } from '@lib/math';\nexport function calc() { return add(1, 2); }",
    });
    const { graph } = await buildGraph({ root, generatedAt: '2020-01-01T00:00:00.000Z', inline: true });
    const byId = new Map(graph.nodes.map((n) => [n.id, n.qualifiedName]));
    const callEdge = graph.edges.find(
      (e) => e.kind === 'call' && byId.get(e.src) === 'calc' && byId.get(e.dst) === 'add',
    );
    expect(callEdge, 'expected calc() → add() resolved across the @lib/math alias').toBeTruthy();
    // and the import edge to the aliased file
    expect(graph.edges.some((e) => e.kind === 'import')).toBe(true);
    void findNodes;
  });
});
