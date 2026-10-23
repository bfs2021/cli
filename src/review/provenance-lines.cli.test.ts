import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { newSession, saveSession } from '../code/session-store.js';

/**
 * The lines `vg why <file:line>` and `vg review trailer push` print. Docs quote
 * these strings.
 */
const pkgRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const cli = path.join(pkgRoot, 'src/cli.ts');

function git(cwd: string, ...args: string[]): void {
  const res = spawnSync('git', args, { cwd, encoding: 'utf8' });
  if (res.status !== 0) throw new Error(`git ${args.join(' ')}: ${res.stderr}`);
}

function run(args: string[]): { status: number | null; stderr: string } {
  const res = spawnSync(process.execPath, ['--import', 'tsx', cli, ...args], {
    cwd: pkgRoot,
    encoding: 'utf8',
    timeout: 60_000,
    env: { ...process.env, NO_COLOR: '1', FORCE_COLOR: '0', VIBGRATE_DSN: '' },
  });
  return { status: res.status, stderr: res.stderr ?? '' };
}

describe('vg why and trailer push lines', () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
  });

  it('prints the no-trailer line, the empty push, and the offline refusals', () => {
    const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-why-line-')));
    dirs.push(dir);
    git(dir, 'init', '-q', '-b', 'main');
    git(dir, 'config', 'user.email', 'dev@example.test');
    git(dir, 'config', 'user.name', 'Dev');
    git(dir, 'config', 'commit.gpgsign', 'false');
    fs.mkdirSync(path.join(dir, 'src'));
    fs.writeFileSync(path.join(dir, 'src/a.ts'), 'one\n');
    git(dir, 'add', 'src/a.ts');
    git(dir, 'commit', '-q', '-m', 'init');

    const plain = run(['-C', dir, 'why', 'src/a.ts:1']);
    expect(plain.status).toBe(0);
    expect(plain.stderr).toContain(
      '  no Vibgrate-Session trailer on this commit — turn it on for future commits with `vg review trailer on`',
    );

    const empty = run(['-C', dir, 'review', 'trailer', 'push']);
    expect(empty.status).toBe(0);
    expect(empty.stderr).toContain(
      '  no Vibgrate-Session trailer on commits no remote branch contains yet — nothing was sent. `vg review trailer on` adds the trailer to commits made after you turn it on.',
    );
    const emptyOffline = run(['-C', dir, 'review', 'trailer', 'push', '--offline']);
    expect(emptyOffline.status).toBe(0);
    expect(emptyOffline.stderr).toContain('nothing was sent');

    const session = newSession('sess_aaa111', 'anthropic', 'model-x', 1_790_000_000_000);
    session.tasks = [{ instruction: 'ask', summary: 'did', files: ['src/a.ts'], stopped: 'done', ts: 1_790_000_000_000 }];
    saveSession(dir, session);
    fs.writeFileSync(path.join(dir, 'src/a.ts'), 'one\ntwo\n');
    git(dir, 'add', 'src/a.ts');
    git(dir, 'commit', '-q', '-m', 'edit', '-m', 'Vibgrate-Session: sess_aaa111');

    // The session is on this machine, so a push would send it. --offline stops first.
    const pushOff = run(['-C', dir, 'review', 'trailer', 'push', '--offline']);
    expect(pushOff.status).toBe(5);
    expect(pushOff.stderr).toContain(
      'error: `vg review trailer push` needs the network — drop `--offline` (or `--local`) to share sessions, or leave the push off to keep them on this machine',
    );
    expect(pushOff.stderr).not.toContain('no DSN');

    // The trailer names a session that is no longer here, so --cloud would look it up.
    fs.rmSync(path.join(dir, '.vibgrate', 'code-sessions', 'sess_aaa111.json'));
    const cloudOff = run(['-C', dir, 'why', 'src/a.ts:2', '--cloud', '--offline']);
    expect(cloudOff.status).toBe(5);
    expect(cloudOff.stderr).toContain(
      'error: `--cloud` needs the network — drop `--offline` (or `--local`) to read a shared session, or drop `--cloud` to read only sessions on this machine',
    );
    expect(cloudOff.stderr).not.toContain('no DSN');
  });
});