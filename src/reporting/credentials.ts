/**
 * Local credential storage for `vibgrate login`.
 *
 * The DSN minted by the browser login flow is cached so subsequent
 * `scan`/`push` runs are authenticated without re-pasting a secret. Two stores
 * are supported; the file location resolves in this precedence:
 *   1. the `VIBGRATE_CREDENTIALS` environment variable — an explicit file path
 *      (CI / automation / custom setups)
 *   2. the project-local store `<project>/.vibgrate/credentials.json` when the
 *      caller opts in (`vg login --local`)
 *   3. an *existing* project-local store — once you have logged in `--local`,
 *      later commands in that project pick it up automatically
 *   4. the home store `~/.vibgrate/credentials.json` — the default, matching the
 *      usual convention for CLI credentials (`~/.aws/credentials`, `~/.npmrc`)
 *
 * DSN resolution precedence (which credential a command uses) is separate:
 *   1. an explicit `--dsn` flag
 *   2. the `VIBGRATE_DSN` environment variable (CI / automation)
 *   3. the stored login credential (resolved via the file precedence above)
 */
import * as os from 'node:os';
import * as path from 'node:path';
import * as fs from 'node:fs';
import { findGitRoot } from './utils/gitignore.js';

export interface StoredCredentials {
  dsn: string;
  workspaceId?: string;
  keyId?: string;
  ingestHost?: string;
  savedAt: string;
}

/** Options selecting which credential store a call operates on. */
export interface CredentialsLocationOpts {
  /**
   * Force the project-local store (`vg login --local`). Without this, writes go
   * to the home store unless `VIBGRATE_CREDENTIALS` is set.
   */
  local?: boolean;
  /**
   * Base directory used to locate the project-local store. Defaults to the git
   * work-tree root above `process.cwd()`, or `process.cwd()` when not in a repo.
   */
  cwd?: string;
}

const STORE_DIRNAME = '.vibgrate';
const STORE_FILENAME = 'credentials.json';

/** The home-directory store, `~/.vibgrate/credentials.json` (the default). */
export function homeCredentialsPath(): string {
  return path.join(os.homedir(), STORE_DIRNAME, STORE_FILENAME);
}

/**
 * The project-local store, `<project>/.vibgrate/credentials.json`, where
 * `<project>` is the git work-tree root above `cwd` (or `cwd` itself when not
 * inside a repo). Anchoring at the repo root means a `--local` login done at the
 * repo root is still found when a later command runs from a subdirectory.
 */
export function projectCredentialsPath(cwd: string = process.cwd()): string {
  const root = findGitRoot(cwd) ?? cwd;
  return path.join(root, STORE_DIRNAME, STORE_FILENAME);
}

/** Resolve the credentials file to use, honoring the file precedence above. */
export function credentialsPath(opts: CredentialsLocationOpts = {}): string {
  const override = process.env.VIBGRATE_CREDENTIALS?.trim();
  if (override) return path.resolve(override);
  const local = projectCredentialsPath(opts.cwd);
  if (opts.local) return local;
  if (fs.existsSync(local)) return local;
  return homeCredentialsPath();
}

export function credentialsDir(opts: CredentialsLocationOpts = {}): string {
  return path.dirname(credentialsPath(opts));
}

/**
 * The `.gitignore` line that keeps a credentials file out of version control,
 * expressed relative to `repoRoot`. Callers only apply this when the file
 * actually lives inside the repo (the project-local store), so the relative
 * path is well-defined; the fallback covers unusual layouts and is intentionally
 * specific — it must NOT shadow `.vibgrate/graph.json`, which `vg share` commits.
 */
export function gitignoreEntryForCredentials(
  repoRoot: string,
  credsFile: string = credentialsPath(),
): string {
  const rel = path.relative(repoRoot, credsFile);
  if (rel && !rel.startsWith('..') && !path.isAbsolute(rel)) {
    return rel.split(path.sep).join('/');
  }
  return `${STORE_DIRNAME}/${STORE_FILENAME}`;
}

export function readStoredCredentials(opts: CredentialsLocationOpts = {}): StoredCredentials | null {
  try {
    const raw = fs.readFileSync(credentialsPath(opts), 'utf8');
    const parsed = JSON.parse(raw) as StoredCredentials;
    return parsed && typeof parsed.dsn === 'string' && parsed.dsn ? parsed : null;
  } catch {
    return null;
  }
}

export function writeStoredCredentials(
  creds: StoredCredentials,
  opts: CredentialsLocationOpts = {},
): void {
  const file = credentialsPath(opts);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  // Created 0600 from the first byte — a default-umask write would leave the
  // token world-readable until the later chmod lands.
  fs.writeFileSync(file, JSON.stringify(creds, null, 2) + '\n', { encoding: 'utf8', mode: 0o600 });
  // Best-effort: restrict to the owner (no-op on platforms without POSIX perms).
  try {
    fs.chmodSync(file, 0o600);
  } catch {
    /* ignore */
  }
}

export function clearStoredCredentials(opts: CredentialsLocationOpts = {}): boolean {
  try {
    fs.rmSync(credentialsPath(opts));
    return true;
  } catch {
    return false;
  }
}

/**
 * Resolve the DSN to use for an authenticated operation, honoring the precedence
 * above. Returns undefined when no credential is available anywhere.
 */
export function resolveDsn(explicitDsn?: string): string | undefined {
  if (explicitDsn) return explicitDsn;
  if (process.env.VIBGRATE_DSN) return process.env.VIBGRATE_DSN;
  return readStoredCredentials()?.dsn ?? undefined;
}
