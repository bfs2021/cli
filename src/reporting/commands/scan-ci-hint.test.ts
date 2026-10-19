// Owned by the public CLI. The post-scan "biggest drift driver" line and the
// `vg init --ci github` suggestion are an interactive hint. They must never
// show up in output a person or a tool consumes non-interactively: a pipe,
// `--format json`, `--format sarif`, the `--junit` file, or a run with CI=true.
//
// Lives here (not under src/core-open, which the vendor script wipes) so it
// survives re-vendoring. The formatter unit tests only check the panel when
// the caller passes `ciHint`; these tests check the scan's own decision.
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { runCoreScan, type ScanOptions } from '../../core-open/index.js';
import { scanCommand } from './scan.js';

const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');

const DRIVER = 'Biggest driver';
const INIT = 'init --ci github';
const PANEL = 'KEEP YOUR DRIFTSCORE FROM GETTING WORSE';

const CI_KEYS = ['CI', 'GITHUB_ACTIONS', 'GITLAB_CI', 'CIRCLECI', 'TRAVIS', 'BUILDKITE', 'JENKINS_URL', 'TF_BUILD'] as const;

const stripAnsi = (s: string): string => s.replace(/\x1b\[[0-9;]*m/g, '');

function assertNoHint(text: string): void {
  const plain = stripAnsi(text);
  expect(plain).not.toContain(DRIVER);
  expect(plain).not.toContain(INIT);
  expect(plain).not.toContain(PANEL);
}

function loggedDocument(spy: ReturnType<typeof vi.spyOn>): string | undefined {
  return spy.mock.calls
    .map((call: unknown[]) => String(call[0]))
    .find((line: string) => line.startsWith('{'));
}

function assertHasHint(text: string): void {
  const plain = stripAnsi(text);
  expect(plain).toContain(PANEL);
  expect(plain).toContain(DRIVER);
  expect(plain).toContain(INIT);
  // A trailing "." is a path argument and is a release-blocking docs defect.
  expect(plain).not.toContain('init --ci github .');
}

/** A pipe leaves `stdout.isTTY` unset. */
function setStdoutTty(value: boolean | undefined): void {
  Object.defineProperty(process.stdout, 'isTTY', {
    configurable: true,
    enumerable: true,
    writable: true,
    value,
  });
}

function clearCiEnv(): void {
  for (const key of CI_KEYS) vi.stubEnv(key, '');
}

describe('post-scan CI hint stays out of non-interactive output', () => {
  let dir: string;
  let logSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let stdoutWrite: ReturnType<typeof vi.spyOn>;
  let stderrWrite: ReturnType<typeof vi.spyOn>;
  let captured: string;
  let hadTty: boolean;
  let previousTty: boolean | undefined;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-ci-hint-'));
    // Node 16 is several LTS majors behind the bundled catalog, so the scan
    // measures a runtime driver. A current runtime would omit the driver line
    // and the absence checks would pass for the wrong reason.
    fs.writeFileSync(
      path.join(dir, 'package.json'),
      JSON.stringify({ name: 'hint-fixture', version: '1.0.0', engines: { node: '>=16.0.0' } }),
    );
    vi.stubEnv('VIBGRATE_DSN', '');
    clearCiEnv();
    captured = '';
    const record = (...args: unknown[]) => {
      captured += args.map(String).join(' ') + '\n';
    };
    logSpy = vi.spyOn(console, 'log').mockImplementation(record);
    errorSpy = vi.spyOn(console, 'error').mockImplementation(record);
    stdoutWrite = vi.spyOn(process.stdout, 'write').mockImplementation((chunk: unknown) => {
      captured += String(chunk);
      return true;
    });
    stderrWrite = vi.spyOn(process.stderr, 'write').mockImplementation((chunk: unknown) => {
      captured += String(chunk);
      return true;
    });
    hadTty = Object.prototype.hasOwnProperty.call(process.stdout, 'isTTY');
    previousTty = process.stdout.isTTY;
  });

  afterEach(() => {
    logSpy.mockRestore();
    errorSpy.mockRestore();
    stdoutWrite.mockRestore();
    stderrWrite.mockRestore();
    vi.unstubAllEnvs();
    if (hadTty) setStdoutTty(previousTty);
    else delete (process.stdout as { isTTY?: boolean }).isTTY;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  function textOpts(extra: Partial<ScanOptions> = {}): ScanOptions {
    return {
      format: 'text',
      concurrency: 4,
      offline: true,
      noLocalArtifacts: true,
      vibgrateVersion: 'test',
      ...extra,
    };
  }

  it('shows the driver and the init command on an interactive terminal', async () => {
    setStdoutTty(true);
    await runCoreScan(dir, textOpts());
    assertHasHint(captured);
    expect(captured).toContain('DriftScore');
  });

  it('omits the hint when stdout is a pipe', async () => {
    // A pipe leaves isTTY unset. CI is not set, so this is the pipe gate alone.
    delete (process.stdout as { isTTY?: boolean }).isTTY;
    await runCoreScan(dir, textOpts());
    expect(captured).toContain('DriftScore');
    assertNoHint(captured);
  });

  it('omits the hint when stdout.isTTY is false', async () => {
    setStdoutTty(false);
    await runCoreScan(dir, textOpts());
    expect(captured).toContain('DriftScore');
    assertNoHint(captured);
  });

  it('omits the hint when CI=true even if stdout is a terminal', async () => {
    setStdoutTty(true);
    vi.stubEnv('CI', 'true');
    await runCoreScan(dir, textOpts());
    expect(captured).toContain('DriftScore');
    assertNoHint(captured);
  });

  it('omits the hint from --format json even on a terminal', async () => {
    setStdoutTty(true);
    await runCoreScan(dir, textOpts({ format: 'json' }));
    assertNoHint(captured);
    const json = loggedDocument(logSpy);
    expect(json).toBeDefined();
    const artifact = JSON.parse(json!) as { drift?: { score?: number | null } };
    expect(artifact.drift?.score).not.toBeNull();
    expect(artifact.drift?.score).toBeGreaterThan(0);
  });

  it('omits the hint from SARIF even on a terminal', async () => {
    setStdoutTty(true);
    await runCoreScan(dir, textOpts({ format: 'sarif' }));
    assertNoHint(captured);
    const json = loggedDocument(logSpy);
    expect(json).toBeDefined();
    const sarif = JSON.parse(json!) as { version?: string; runs?: unknown[] };
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs?.length).toBeGreaterThan(0);
  });
});

describe('vg scan --junit does not carry the CI hint', () => {
  let dir: string;
  let logSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let stdoutWrite: ReturnType<typeof vi.spyOn>;
  let stderrWrite: ReturnType<typeof vi.spyOn>;
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let stdout: string;
  let stderr: string;
  let hadTty: boolean;
  let previousTty: boolean | undefined;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-ci-hint-junit-'));
    fs.writeFileSync(
      path.join(dir, 'package.json'),
      JSON.stringify({ name: 'hint-fixture', version: '1.0.0', engines: { node: '>=16.0.0' } }),
    );
    vi.stubEnv('VIBGRATE_DSN', '');
    vi.stubEnv('VIBGRATE_NO_KERNEL', '1');
    clearCiEnv();
    stdout = '';
    stderr = '';
    logSpy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      stdout += args.map(String).join(' ') + '\n';
    });
    errorSpy = vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
      stderr += args.map(String).join(' ') + '\n';
    });
    stdoutWrite = vi.spyOn(process.stdout, 'write').mockImplementation((chunk: unknown) => {
      stdout += String(chunk);
      return true;
    });
    stderrWrite = vi.spyOn(process.stderr, 'write').mockImplementation((chunk: unknown) => {
      stderr += String(chunk);
      return true;
    });
    exitSpy = vi.spyOn(process, 'exit').mockImplementation(((code?: number) => {
      throw new Error(`process.exit(${code}) called`);
    }) as never);
    hadTty = Object.prototype.hasOwnProperty.call(process.stdout, 'isTTY');
    previousTty = process.stdout.isTTY;
    setStdoutTty(true);
  });

  afterEach(() => {
    logSpy.mockRestore();
    errorSpy.mockRestore();
    stdoutWrite.mockRestore();
    stderrWrite.mockRestore();
    exitSpy.mockRestore();
    vi.unstubAllEnvs();
    if (hadTty) setStdoutTty(previousTty);
    else delete (process.stdout as { isTTY?: boolean }).isTTY;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  async function scan(args: string[]): Promise<void> {
    await scanCommand.parseAsync([
      'node',
      'scan',
      dir,
      '--offline',
      '--no-daemon',
      '--no-graph',
      '--no-local-artifacts',
      ...args,
    ]);
  }

  it('writes a JUnit file without the hint while the interactive text report still has it', async () => {
    const junit = path.join(dir, 'report.xml');
    await scan(['--junit', junit]);
    const xml = fs.readFileSync(junit, 'utf8');
    expect(xml.startsWith('<?xml')).toBe(true);
    assertNoHint(xml);
    assertNoHint(stderr);
    // The text report on this TTY does show the hint, so the file check is
    // not passing because the scan had nothing to say.
    assertHasHint(stdout);
  });

  it('omits the hint from stdout and the JUnit file when CI=true', async () => {
    vi.stubEnv('CI', 'true');
    const junit = path.join(dir, 'ci.xml');
    await scan(['--junit', junit]);
    expect(stdout).toContain('DriftScore');
    assertNoHint(stdout);
    assertNoHint(stderr);
    assertNoHint(fs.readFileSync(junit, 'utf8'));
  });

  it('omits the hint from JSON stdout and the JUnit file', async () => {
    const junit = path.join(dir, 'json.xml');
    await scan(['--format', 'json', '--junit', junit]);
    assertNoHint(stdout);
    assertNoHint(stderr);
    assertNoHint(fs.readFileSync(junit, 'utf8'));
    const json = stdout.trim();
    expect(json.startsWith('{')).toBe(true);
    expect(JSON.parse(json).schemaVersion).toBe('1.0');
  });

  it('omits the hint from SARIF stdout and the JUnit file', async () => {
    const junit = path.join(dir, 'sarif.xml');
    await scan(['--format', 'sarif', '--junit', junit]);
    assertNoHint(stdout);
    assertNoHint(stderr);
    assertNoHint(fs.readFileSync(junit, 'utf8'));
    const sarif = JSON.parse(stdout.trim()) as { version?: string };
    expect(sarif.version).toBe('2.1.0');
  });
});

describe('piped vg scan stdout', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-ci-hint-pipe-'));
  fs.writeFileSync(
    path.join(dir, 'package.json'),
    JSON.stringify({ name: 'hint-fixture', version: '1.0.0', engines: { node: '>=16.0.0' } }),
  );

  afterAll(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  function run(args: string[], env: Record<string, string> = {}): { stdout: string; stderr: string; status: number | null } {
    // spawnSync pipes stdio, so the child sees a real non-TTY stdout.
    const res = spawnSync(
      process.execPath,
      [
        '--import',
        'tsx',
        path.join(PACKAGE_ROOT, 'src/cli.ts'),
        'scan',
        dir,
        '--offline',
        '--no-graph',
        '--no-daemon',
        '--no-local-artifacts',
        ...args,
      ],
      {
        cwd: PACKAGE_ROOT,
        encoding: 'utf8',
        timeout: 45_000,
        env: {
          ...process.env,
          NO_COLOR: '1',
          VIBGRATE_NO_KERNEL: '1',
          VIBGRATE_DSN: '',
          CI: '',
          GITHUB_ACTIONS: '',
          GITLAB_CI: '',
          CIRCLECI: '',
          TRAVIS: '',
          BUILDKITE: '',
          JENKINS_URL: '',
          TF_BUILD: '',
          ...env,
        },
      },
    );
    return { stdout: res.stdout ?? '', stderr: res.stderr ?? '', status: res.status };
  }

  it('does not print the hint on a real stdout pipe', () => {
    const res = run([]);
    expect(res.status).toBe(0);
    expect(res.stdout).toContain('DriftScore');
    assertNoHint(res.stdout);
    assertNoHint(res.stderr);
  }, 60_000);

  it('does not print the hint on a real stdout pipe when CI=true', () => {
    const res = run([], { CI: 'true' });
    expect(res.status).toBe(0);
    expect(res.stdout).toContain('DriftScore');
    assertNoHint(res.stdout);
    assertNoHint(res.stderr);
  }, 60_000);

  it('does not print the hint in piped --format json', () => {
    const res = run(['--format', 'json']);
    expect(res.status).toBe(0);
    assertNoHint(res.stdout);
    assertNoHint(res.stderr);
    const artifact = JSON.parse(res.stdout) as { schemaVersion?: string; drift?: { score?: number | null } };
    expect(artifact.schemaVersion).toBe('1.0');
    expect(artifact.drift?.score).toBeGreaterThan(0);
  }, 60_000);

  it('does not print the hint in piped SARIF', () => {
    const res = run(['--format', 'sarif']);
    expect(res.status).toBe(0);
    assertNoHint(res.stdout);
    assertNoHint(res.stderr);
    const sarif = JSON.parse(res.stdout) as { version?: string };
    expect(sarif.version).toBe('2.1.0');
  }, 60_000);

  it('does not print the hint in a piped run that also writes JUnit', () => {
    const junit = path.join(dir, 'piped.xml');
    const res = run(['--junit', junit]);
    expect(res.status).toBe(0);
    assertNoHint(res.stdout);
    assertNoHint(res.stderr);
    assertNoHint(fs.readFileSync(junit, 'utf8'));
  }, 60_000);
});
