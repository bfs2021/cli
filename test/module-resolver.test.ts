import { describe, it, expect, afterEach } from 'vitest';
import {
  buildModuleResolver,
  relativeResolver,
  parseJsonc,
  compareWorkspacePackageKey,
  workspaceDirsByName,
  type WorkspacePackageKey,
} from '../src/engine/module-resolver.js';
import { buildGraph } from '../src/engine/build.js';
import { discover } from '../src/engine/discover.js';
import { findNodes } from '../src/engine/lookup.js';
import { serializeGraph } from '../src/engine/serialize.js';
import { makeProject, cleanup } from './helpers.js';

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

  it('relativeResolver handles relative + dotted only', () => {
    const root = project({ 'a.ts': 'x', 'b.ts': 'x' });
    const r = relativeResolver(relSet(root));
    expect(r.resolve('a.ts', './b')).toBe('b.ts');
    expect(r.resolve('a.ts', '@org/x')).toBeNull();
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

const PIN = '2020-01-01T00:00:00.000Z';

/**
 * Two workspace copies of the bare name `shared`. `packages/zeta` is the
 * higher version and, on a name-sorted directory walk, the last entry — the
 * old map kept whichever copy the walk inserted last. The content key keeps
 * `packages/alpha` (smaller path) even though its version is lower.
 */
const COLLIDING_WORKSPACE: Record<string, string> = {
  'package.json': JSON.stringify({ name: 'app', workspaces: ['packages/*'] }),
  'packages/alpha/package.json': JSON.stringify({ name: 'shared', version: '0.1.0' }),
  'packages/alpha/src/index.ts': 'export function value(): string { return "alpha"; }\n',
  'packages/zeta/package.json': JSON.stringify({ name: 'shared', version: '9.9.9' }),
  'packages/zeta/src/index.ts': 'export function value(): string { return "zeta"; }\n',
  'app/main.ts': 'import { value } from "shared";\nexport function main(): string { return value(); }\n',
};

describe('workspace package name collisions', () => {
  it('keeps the smallest content key when the same bare name is offered in either walk order', () => {
    const alpha: WorkspacePackageKey = { dirRel: 'packages/alpha', name: 'shared', version: '0.1.0' };
    const zeta: WorkspacePackageKey = { dirRel: 'packages/zeta', name: 'shared', version: '9.9.9' };
    // These two orders are the two directory-walk orders. Last-write-wins would
    // point `shared` at a different directory in each list.
    const forward = workspaceDirsByName([alpha, zeta]);
    const reverse = workspaceDirsByName([zeta, alpha]);
    expect([...forward.entries()]).toEqual([...reverse.entries()]);
    expect(forward.get('shared')).toBe('packages/alpha');
    // Path outranks version: zeta's lower version would win if version were first.
    expect(
      compareWorkspacePackageKey(
        { dirRel: 'packages/zeta', name: 'shared', version: '0.0.1' },
        { dirRel: 'packages/alpha', name: 'shared', version: '9.9.9' },
      ),
    ).toBeGreaterThan(0);
  });

  it('prefers the longer package name over a path-length tie', () => {
    const root = project({
      'package.json': JSON.stringify({ workspaces: ['packages/*'] }),
      'packages/a/package.json': JSON.stringify({ name: '@org/a', version: '1.0.0' }),
      'packages/a/src/index.ts': 'export const short = 1;\n',
      'packages/ab/package.json': JSON.stringify({ name: '@org/a/b', version: '1.0.0' }),
      'packages/ab/src/index.ts': 'export const long = 1;\n',
      'app/main.ts': 'export const x = 1;\n',
    });
    const r = buildModuleResolver(root, relSet(root));
    expect(r.resolve('app/main.ts', '@org/a')).toBe('packages/a/src/index.ts');
    expect(r.resolve('app/main.ts', '@org/a/b')).toBe('packages/ab/src/index.ts');
  });

  it('builds the same graph.json for a colliding workspace name across two builds', async () => {
    const first = await buildSlice(project(COLLIDING_WORKSPACE));
    const second = await buildSlice(project(COLLIDING_WORKSPACE));
    // A name-sorted walk visits alpha, then zeta. Keeping the last directory
    // would import packages/zeta (also the higher version). Both builds must
    // import packages/alpha and serialize the same graph.json.
    expect(second.graphJson).toBe(first.graphJson);
    expect(first.importFiles).toEqual(['packages/alpha/src/index.ts']);
    expect(second.importFiles).toEqual(['packages/alpha/src/index.ts']);

    // Same tree written in the opposite order — the walk-order flip the
    // collision used to follow.
    const reversedEntries = Object.entries(COLLIDING_WORKSPACE).reverse();
    const flipped = await buildSlice(project(Object.fromEntries(reversedEntries)));
    expect(flipped.graphJson).toBe(first.graphJson);
    expect(flipped.importFiles).toEqual(['packages/alpha/src/index.ts']);
  });
});

async function buildSlice(root: string): Promise<{ graphJson: string; importFiles: string[] }> {
  const { graph } = await buildGraph({ root, generatedAt: PIN, inline: true, noCache: true });
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const fileOf = (id: string): string => byId.get(id)?.file ?? '';
  const importFiles = graph.edges
    .filter((e) => e.kind === 'import' && fileOf(e.src) === 'app/main.ts' && byId.get(e.dst)?.kind === 'file')
    .map((e) => fileOf(e.dst));
  return { graphJson: serializeGraph(graph), importFiles };
}
