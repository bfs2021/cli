import { afterEach, describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { buildGraph } from '../src/engine/build.js';
import { cleanup, makeProject } from './helpers.js';

const PIN = '2020-01-01T00:00:00.000Z';

/**
 * TypeScript, Python, Go, Java, and Rust, plus a workspace package, a
 * gitignored tree, and a dependency directory. `vg build` must list each
 * project directory once. Node's `fs` exports cannot be spied on, so the
 * count goes through the build's directory reader.
 */
const PROJECT: Record<string, string> = {
  'package.json': JSON.stringify({
    name: 'walk-once',
    private: true,
    workspaces: ['pkg/*'],
  }),
  'README.md': '# walk\n',
  'src/math.ts': 'export function add(a: number, b: number): number { return a + b; }\n',
  'src/order.ts': "import { add } from './math';\nexport function total(): number { return add(1, 2); }\n",
  'svc/app.py': 'def helper():\n    return 1\n',
  'svc/main.go': 'package svc\n\nfunc Run() int { return 1 }\n',
  'src/com/app/Main.java': 'package com.app;\npublic class Main {}\n',
  'pkg/lib/package.json': JSON.stringify({ name: '@walk/lib', version: '1.0.0' }),
  'pkg/lib/lib.rs': 'pub fn add(a: i32, b: i32) -> i32 { a + b }\n',
  'node_modules/left-pad/index.js': 'module.exports = 1;\n',
  '.gitignore': 'secret/\n',
  'secret/hidden.ts': 'export const x = 1;\n',
};

const dirs: string[] = [];
afterEach(() => {
  while (dirs.length) cleanup(dirs.pop()!);
});

describe('vg build directory walk', () => {
  it('reads each project directory once', async () => {
    const root = makeProject(PROJECT);
    dirs.push(root);
    const reads = new Map<string, number>();

    const { graph } = await buildGraph({
      root,
      generatedAt: PIN,
      inline: true,
      readDir(dir) {
        const key = path.resolve(dir);
        reads.set(key, (reads.get(key) ?? 0) + 1);
        return fs.readdirSync(dir, { withFileTypes: true });
      },
    });

    expect(graph.meta.languages).toEqual(expect.arrayContaining(['ts', 'py', 'go', 'java', 'rust']));

    const expected = [
      root,
      path.join(root, 'src'),
      path.join(root, 'src', 'com'),
      path.join(root, 'src', 'com', 'app'),
      path.join(root, 'svc'),
      path.join(root, 'pkg'),
      path.join(root, 'pkg', 'lib'),
    ];
    const counts = Object.fromEntries(
      [...reads.entries()].map(([dir, n]) => [path.relative(root, dir) || '.', n]),
    );
    for (const dir of expected) {
      expect(reads.get(dir), JSON.stringify(counts)).toBe(1);
    }
    expect(reads.has(path.join(root, 'node_modules')), JSON.stringify(counts)).toBe(false);
    expect(reads.has(path.join(root, 'node_modules', 'left-pad')), JSON.stringify(counts)).toBe(false);
    expect(reads.has(path.join(root, 'secret')), JSON.stringify(counts)).toBe(false);
    const repeated = [...reads.entries()].filter(([, n]) => n !== 1);
    expect(repeated, JSON.stringify(counts)).toEqual([]);
  });
});
