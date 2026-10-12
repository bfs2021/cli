import { describe, it, expect } from 'vitest';
import { redactForDisplay } from '../src/core-open/utils/redact.js';

/**
 * `redactForDisplay` scrubs registry and upload error messages before they are
 * printed or stored on an Error. One row per input shape, and every row is
 * also checked for idempotency, since a message can pass through the helper
 * more than once on its way to the terminal.
 *
 * All tokens below are fake.
 */

interface Row {
  name: string;
  input: string;
  expected: string;
}

const rows: Row[] = [
  {
    name: 'userinfo in a registry URL',
    input: 'https://user:tok@registry.example/pkg',
    expected: 'https://registry.example/pkg',
  },
  {
    name: 'mixed-case Access_Token query key',
    input: 'https://registry.example/pkg?Access_Token=EXAMPLEFAKE1234',
    expected: 'https://registry.example/pkg',
  },
  {
    name: 'mixed-case PRIVATE-TOKEN query key',
    input: 'https://gitlab.example/api/v4/packages?PRIVATE-TOKEN=EXAMPLEFAKE1234',
    expected: 'https://gitlab.example/api/v4/packages',
  },
  {
    name: 'sig dropped, non-secret params kept in order',
    input: 'https://cdn.example/upload?part=1&sig=EXAMPLEFAKE1234&page=2',
    expected: 'https://cdn.example/upload?part=1&page=2',
  },
  {
    name: 'token in a URL fragment',
    input: 'https://host.example/cb#access_token=EXAMPLEFAKE1234',
    expected: 'https://host.example/cb#[REDACTED]',
  },
  {
    name: 'GitHub token inside a sentence',
    input: 'request failed with token ghp_EXAMPLEEXAMPLEEXAMPLE, check scopes',
    expected: 'request failed with token [REDACTED], check scopes',
  },
  {
    name: 'npm token inside a sentence',
    input: 'npm rejected npm_EXAMPLEEXAMPLEEXAMPLE for this package',
    expected: 'npm rejected [REDACTED] for this package',
  },
  {
    name: 'GitLab token inside a sentence',
    input: 'GitLab answered 401 for glpat-EXAMPLEEXAMPLE1234 today',
    expected: 'GitLab answered 401 for [REDACTED] today',
  },
  {
    name: 'Authorization: Bearer header',
    input: 'sent Authorization: Bearer EXAMPLEFAKEBEARER1234 and got 403',
    expected: 'sent [REDACTED] and got 403',
  },
  {
    name: 'URL with no secrets is unchanged',
    input: 'https://registry.npmjs.org/@vibgrate%2fcli?page=2&per_page=50#readme',
    expected: 'https://registry.npmjs.org/@vibgrate%2fcli?page=2&per_page=50#readme',
  },
];

describe('redactForDisplay', () => {
  it.each(rows)('$name', ({ input, expected }) => {
    expect(redactForDisplay(input)).toBe(expected);
  });

  it.each(rows)('is idempotent: $name', ({ input }) => {
    const once = redactForDisplay(input);
    expect(redactForDisplay(once)).toBe(once);
  });
});

describe('redactForDisplay credential query edges', () => {
  it('drops a percent-encoded credential query key', () => {
    const out = redactForDisplay('https://registry.example/pkg?access%5Ftoken=EXAMPLEFAKE1234&page=2');
    expect(out).toBe('https://registry.example/pkg?page=2');
    expect(out).not.toContain('EXAMPLEFAKE1234');
  });

  it('keeps the rest of a sentence after a URL with a credential query parameter', () => {
    expect(redactForDisplay('GET https://registry.example/pkg?token=EXAMPLEFAKE1234 failed: 401 Unauthorized')).toBe(
      'GET https://registry.example/pkg failed: 401 Unauthorized',
    );
  });
});
