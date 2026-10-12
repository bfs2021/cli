// VENDORED from @vibgrate/core-open (packages/vibgrate-core-open) by
// scripts/vendor-core-open.mjs. Do not edit here — change the source package
// and re-run the vendor script. Apache-2.0.
/**
 * Shared credential redaction (GUARDRAILS §1.1): applied at INGEST, before
 * anything is stored or uploaded. One detector, reused by the VCS capture, the
 * graph builder (signatures/docs), and the push envelope — so every surface
 * scrubs the same shapes and a new token prefix is added in exactly one place.
 */

const SECRET_PATTERNS: RegExp[] = [
  // Vendor token prefixes (GitHub, GitLab, Slack, OpenAI/Stripe-style, npm, AWS).
  /\b(?:gh[opusr]_|github_pat_)[A-Za-z0-9_]{8,}\b/g,
  /\bglpat-[A-Za-z0-9_-]{8,}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{8,}\b/g,
  /\bsk-[A-Za-z0-9_-]{8,}\b/gi,
  /\b[sr]k_(?:live|test)_[A-Za-z0-9]{8,}\b/g,
  /\bnpm_[A-Za-z0-9]{16,}\b/g,
  /\b(?:AKIA|ASIA)[0-9A-Z]{12,}\b/g,
  // JWTs.
  /\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]+\b/g,
  // Authorization material.
  /\b(?:Bearer|Basic|VibgrateDSN)\s+[A-Za-z0-9+/._:=-]{8,}/g,
  /\b(?:authorization|api[_-]?key|apikey|access[_-]?token|client[_-]?secret|password|passwd|secret)\s*[:=]\s*['"]?[^'"\s]{6,}/gi,
  // PEM blocks.
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g,
  // Long base64/hex blobs (AWS secret keys and friends).
  /\b[A-Za-z0-9+/]{40,}={0,2}\b/g,
];

export const REDACTED = '[REDACTED]';

/**
 * Query-parameter names that carry credentials. Matched after percent-decoding
 * the key, so `access%5Ftoken` is the same name as `access_token`.
 */
const CREDENTIAL_QUERY_KEYS =
  /^(?:access[_-]?token|private[_-]?token|api[_-]?key|apikey|token|secret|password|passwd|auth|authorization|x-token|sig|signature|key)$/i;

/**
 * Names matched in `key=value` text outside of query parsing (headers, fragments).
 * Percent-encoded forms of these names are decoded and checked separately;
 * the plain forms stay on SECRET_PATTERNS.
 */
const ASSIGNMENT_KEYS =
  /^(?:authorization|api[_-]?key|apikey|access[_-]?token|client[_-]?secret|password|passwd|secret)$/i;

/** Cap so a pathological `%25%25…` key cannot loop. Double-encoding needs two passes. */
const MAX_KEY_DECODES = 4;

/**
 * Percent-decode a query or assignment key. Decoding repeats while the key
 * still contains `%`, up to a small cap, so a double-encoded name resolves.
 * A malformed escape stops the loop and the last successful form is matched.
 */
function decodeKey(raw: string): string {
  let key = raw;
  for (let n = 0; n < MAX_KEY_DECODES && key.includes('%'); n++) {
    try {
      const next = decodeURIComponent(key);
      if (next === key) break;
      key = next;
    } catch {
      break;
    }
  }
  return key;
}

function isCredentialQueryKey(raw: string): boolean {
  return CREDENTIAL_QUERY_KEYS.test(decodeKey(raw));
}

/**
 * Rewrite `key=value` assignments whose key is still percent-encoded
 * (`access%5Ftoken=…`, including a double-encoded `%255F`). Plain keys are
 * left for SECRET_PATTERNS so their existing match span stays the same.
 * The character before the key is kept; the key and value become [REDACTED].
 */
function redactPercentEncodedAssignments(text: string): string {
  // The key must contain a `%HH` escape. A broader `key=value` scan treats
  // `https:` as an assignment and swallows the rest of the URL, hiding a
  // later encoded key. The value stops at `&` and `#` for the same reason:
  // a greedy run would consume the next parameter or fragment.
  return text.replace(
    /(^|[^\w%])((?:[A-Za-z0-9_-]|%[0-9A-Fa-f]{2})*%[0-9A-Fa-f]{2}(?:[A-Za-z0-9_-]|%[0-9A-Fa-f]{2})*)(\s*[:=]\s*['"]?)([^'"\s&#]{6,})/g,
    (match, lead: string, key: string) => {
      if (!ASSIGNMENT_KEYS.test(decodeKey(key))) return match;
      return `${lead}${REDACTED}`;
    },
  );
}

/** Replace every credential-shaped substring with [REDACTED]. Deterministic. */
export function redactSecrets(text: string): string {
  let out = redactPercentEncodedAssignments(text);
  for (const re of SECRET_PATTERNS) out = out.replace(re, REDACTED);
  return out;
}

/** True when the text contains at least one credential-shaped substring. */
export function containsSecret(text: string): boolean {
  if (redactPercentEncodedAssignments(text) !== text) return true;
  return SECRET_PATTERNS.some((re) => {
    re.lastIndex = 0;
    const hit = re.test(text);
    re.lastIndex = 0;
    return hit;
  });
}

/**
 * Strip credentials from URLs in `text`: userinfo (`//user:token@host`) and
 * credential query parameters (`?access_token=…`, `?private_token=…`),
 * including percent-encoded key names (`?access%5Ftoken=…`).
 *
 * An unencoded URL cannot contain whitespace, so a query ends at the first
 * whitespace and everything after it is kept. Every `?` is visited, so a
 * second URL in the same message is scrubbed too. Benign parameters are
 * left exactly as written, in order.
 */
export function redactUrlCredentials(text: string): string {
  const noUser = text.replace(/\/\/[^@/]+@/g, '//');
  let out = '';
  let i = 0;
  while (i < noUser.length) {
    const q = noUser.indexOf('?', i);
    if (q === -1) {
      out += noUser.slice(i);
      break;
    }
    out += noUser.slice(i, q);
    const rest = noUser.slice(q + 1);
    const ws = rest.search(/\s/);
    const query = ws === -1 ? rest : rest.slice(0, ws);
    const kept = query.split('&').filter((pair) => !isCredentialQueryKey(pair.split('=')[0] ?? ''));
    if (kept.length > 0) out += `?${kept.join('&')}`;
    if (ws === -1) break;
    i = q + 1 + ws;
  }
  return out;
}

/**
 * Scrub text before it is printed or stored on an Error. URL userinfo and
 * credential query parameters go first, then token and header shapes.
 * Deterministic: the same input always yields the same output.
 */
export function redactForDisplay(text: string): string {
  return redactSecrets(redactUrlCredentials(text));
}
