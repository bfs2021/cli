import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { parse } from 'yaml';

// Runs the Action's real "Run Vibgrate scan" script from action.yml with a stub
// `docker` on PATH, so the `fail-on-epss` validation is tested as shipped, offline.

const actionPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../action.yml');
const action = parse(readFileSync(actionPath, 'utf8')) as {
  runs: { steps: Array<{ id?: string; run?: string }> };
};
const scanScript = action.runs.steps.find((step) => step.id === 'scan')?.run ?? '';

const work = mkdtempSync(path.join(tmpdir(), 'vibgrate-action-epss-'));
const dockerArgsFile = path.join(work, 'docker-args');
const oldImageMarker = path.join(work, 'old-image');
writeFileSync(
  path.join(work, 'docker'),
  `#!/usr/bin/env bash
printf '%s\\n' "$@" > "${dockerArgsFile}"
if [[ " \$* " == *" --help "* ]]; then
  if [[ -f "${oldImageMarker}" ]]; then
    printf '%s\\n' 'Usage: vg scan --summary-out <file>'
  else
    printf '%s\\n' 'Usage: vg scan --summary-out <file> --fail-on-epss <threshold>'
  fi
fi
`,
);
chmodSync(path.join(work, 'docker'), 0o755);

afterAll(() => rmSync(work, { recursive: true, force: true }));

function runScan(failOnEpss: string, opts: { vulns?: string; args?: string; oldImage?: boolean } = {}) {
  rmSync(dockerArgsFile, { force: true });
  if (opts.oldImage) writeFileSync(oldImageMarker, '1');
  else rmSync(oldImageMarker, { force: true });
  const result = spawnSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', '-c', scanScript], {
    cwd: work,
    encoding: 'utf8',
    env: {
      PATH: `${work}:${process.env.PATH ?? ''}`,
      GITHUB_OUTPUT: path.join(work, 'github-output'),
      IMAGE: 'ghcr.io/vibgrate/cli',
      INPUT_TAG: 'test',
      INPUT_PATH: '.',
      INPUT_FORMAT: 'sarif',
      INPUT_OUTPUT: 'vibgrate.sarif',
      INPUT_FAIL_ON: '',
      INPUT_MAX_SCORE: '',
      INPUT_FAIL_ON_EPSS: failOnEpss,
      INPUT_BASELINE: '',
      INPUT_MAX_WORSENING: '',
      INPUT_SUMMARY: 'vibgrate-summary.json',
      INPUT_VULNS: opts.vulns ?? 'false',
      INPUT_ARGS: opts.args ?? '',
      VIBGRATE_DSN: '',
    },
  });
  const dockerArgs = existsSync(dockerArgsFile) ? readFileSync(dockerArgsFile, 'utf8').split('\n') : null;
  return { status: result.status, stdout: result.stdout, dockerArgs };
}

function epssArg(dockerArgs: string[] | null): string | undefined {
  const at = dockerArgs?.indexOf('--fail-on-epss') ?? -1;
  return at === -1 ? undefined : dockerArgs?.[at + 1];
}

describe('GitHub Action fail-on-epss input', () => {
  it('found the scan step in action.yml', () => {
    expect(scanScript).toContain('INPUT_FAIL_ON_EPSS');
  });

  it('passes 0.1 to --fail-on-epss when vulns is true, before caller args', () => {
    const { status, stdout, dockerArgs } = runScan('0.1', { vulns: 'true', args: '--offline' });
    expect(status).toBe(0);
    expect(stdout).not.toContain('::notice::image test predates --fail-on-epss');
    expect(epssArg(dockerArgs)).toBe('0.1');
    expect(dockerArgs).toContain('--vulns');
    const epssAt = dockerArgs?.indexOf('--fail-on-epss') ?? -1;
    const argsAt = dockerArgs?.indexOf('--offline') ?? -1;
    expect(epssAt).toBeGreaterThan(-1);
    expect(argsAt).toBeGreaterThan(epssAt);
  });

  it.each([
    ['0', '0'],
    ['1', '1'],
    [' 0.1 ', '0.1'],
  ])('passes fail-on-epss %j to --fail-on-epss as %j', (input, expected) => {
    const { status, dockerArgs } = runScan(input, { vulns: 'true' });
    expect(status).toBe(0);
    expect(epssArg(dockerArgs)).toBe(expected);
  });

  it('runs without an EPSS gate when fail-on-epss is empty', () => {
    const { status, stdout, dockerArgs } = runScan('');
    expect(status).toBe(0);
    expect(stdout).not.toContain('::error::');
    expect(dockerArgs).not.toBeNull();
    expect(dockerArgs).not.toContain('--fail-on-epss');
  });

  it.each(['abc', '-0.1', '1.5', '   '])('fails before the scan when fail-on-epss is %j', (input) => {
    const { status, stdout, dockerArgs } = runScan(input, { vulns: 'true' });
    expect(status).toBe(1);
    expect(stdout).toContain(`::error::fail-on-epss must be a number from 0 to 1 (got '${input}').`);
    expect(dockerArgs).toBeNull();
  });

  it('fails before the scan when fail-on-epss is set and vulns is not true', () => {
    const { status, stdout, dockerArgs } = runScan('0.1', { vulns: 'false' });
    expect(status).toBe(1);
    expect(stdout).toContain('::error::fail-on-epss needs vulnerability scanning — set vulns: true.');
    expect(dockerArgs).toBeNull();
  });

  it('prints a notice and omits the flag when the image predates --fail-on-epss', () => {
    const { status, stdout, dockerArgs } = runScan('0.1', { vulns: 'true', oldImage: true });
    expect(status).toBe(0);
    expect(stdout).toContain(
      '::notice::image test predates --fail-on-epss; the EPSS threshold was not passed to the scan. Use a newer image-tag to fail on EPSS.',
    );
    expect(dockerArgs).not.toBeNull();
    expect(dockerArgs).not.toContain('--fail-on-epss');
    expect(dockerArgs).toContain('--vulns');
  });
});
