import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';

/**
 * The lines `vg review doc` prints for a bad `--also` path and for a cloud
 * flag under `--offline`. Docs quote these strings.
 */
const pkgRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const cli = path.join(pkgRoot, 'src/cli.ts');

function run(args: string[]): { status: number | null; stderr: string } {
  // cwd is the package so `tsx` resolves. `--also` paths below are absolute, or
  // a relative path that does not exist next to this package.
  const res = spawnSync(process.execPath, ['--import', 'tsx', cli, ...args], {
    cwd: pkgRoot,
    encoding: 'utf8',
    timeout: 60_000,
    env: { ...process.env, NO_COLOR: '1', FORCE_COLOR: '0', VIBGRATE_DSN: '' },
  });
  return { status: res.status, stderr: res.stderr ?? '' };
}

describe('vg review doc flag errors', () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
  });

  it('prints an actionable line for a missing --also path and a non-git directory', () => {
    const missing = run(['review', 'doc', '--also', '../no-such-client']);
    expect(missing.status).toBe(5);
    expect(missing.stderr).toContain(
      'error: --also ../no-such-client: no such directory — pass a git checkout of the other repository',
    );

    const plain = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-review-doc-plain-')));
    dirs.push(plain);
    const notGit = run(['review', 'doc', '--also', plain]);
    expect(notGit.status).toBe(5);
    expect(notGit.stderr).toContain(
      `error: --also ${plain}: ${plain} is not a git repository — pass a git checkout of the other repository (git must be on PATH)`,
    );
  });

  it('refuses --comments and --reply under --offline before any request', () => {
    const comments = run(['review', 'doc', '--comments', '--offline']);
    expect(comments.status).toBe(5);
    expect(comments.stderr).toContain(
      'error: `--comments` needs the network — drop `--offline` (or `--local`) to read comments, or drop `--comments` to stay on this machine',
    );

    const reply = run(['review', 'doc', '--reply', 'rdc_1', '--text', 'Because the base side was not built.', '--local']);
    expect(reply.status).toBe(5);
    expect(reply.stderr).toContain(
      'error: `--reply` needs the network — drop `--offline` (or `--local`) to post the reply, or drop `--reply` to stay on this machine',
    );
  });
});
