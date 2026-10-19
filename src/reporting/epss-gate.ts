/**
 * `--fail-on-epss` / `failOnEpss` for a finished `vg scan`.
 *
 * Exit 2 when any advisory's EPSS score is at or above the threshold. A
 * missing score is not a score: it is never compared, and it is never read
 * as 0. A present 0 is a real score and is compared.
 *
 * The flag replaces `failOnEpss` in the project config, the same way
 * `--drift-budget` replaces `driftBudget`.
 */
import { compareCodeUnits } from '../core-open/utils/code-unit.js';
import type { VulnerabilityScanResult } from '../core-open/types.js';
import { CliError, ExitCode } from '../util/exit.js';

export interface EpssAdvisoryRef {
  ecosystem: string;
  package: string;
  version: string;
  id: string;
  /** Present only when the advisory carried a finite EPSS probability. */
  epss?: number;
}

export interface EpssGateInput {
  /**
   * How the vulnerability pass was sourced. `null` means that pass did not
   * run, so there is nothing to compare.
   */
  source: VulnerabilityScanResult['source'] | null;
  advisories: readonly EpssAdvisoryRef[];
  threshold: number;
  /** Which setting supplied the threshold. The flag replaces the config. */
  from: 'flag' | 'config';
}

export interface EpssGateResult {
  /** 2 when a scored advisory is at or above the threshold; otherwise 0. */
  exitCode: 0 | 2;
  /**
   * The stderr line. Set on a breach and when no score was compared.
   * Null when the gate passed on scores that were actually compared,
   * including a vulnerability pass that found no advisories.
   */
  message: string | null;
  /** True when no EPSS score was compared. That is a skip, not a pass and not a failure. */
  skipped: boolean;
  /** Scored advisories at or above the threshold, in a stable order. */
  breached: EpssAdvisoryRef[];
}

/** `--fail-on-epss`. Undefined when the flag was omitted. Throws before a scan on a bad value. */
export function parseEpssThreshold(value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  const trimmed = value.trim();
  const parsed = Number(trimmed);
  // Number('') is 0. A blank flag is not a threshold.
  if (trimmed === '' || !Number.isFinite(parsed) || parsed < 0 || parsed > 1) {
    throw new CliError('--fail-on-epss must be a number from 0 to 1.', ExitCode.ERROR);
  }
  return parsed;
}

export function epssAbsentMessage(threshold: number, from: EpssGateInput['from']): string {
  if (from === 'flag') return `EPSS is absent; --fail-on-epss ${threshold} was not compared.`;
  return `EPSS is absent; failOnEpss ${threshold} in the project config was not compared.`;
}

export function epssFailingMessage(count: number, threshold: number): string {
  const noun = count === 1 ? 'advisory' : 'advisories';
  return `Failing: ${count} ${noun} at or above EPSS ${threshold}.`;
}

export function epssAdvisoryRow(advisory: EpssAdvisoryRef): string {
  return `${advisory.ecosystem} ${advisory.package}@${advisory.version}  ${advisory.id}  EPSS ${advisory.epss}`;
}

function scoredEpss(advisory: EpssAdvisoryRef): number | null {
  return typeof advisory.epss === 'number' && Number.isFinite(advisory.epss) ? advisory.epss : null;
}

function compareAdvisories(a: EpssAdvisoryRef, b: EpssAdvisoryRef): number {
  return compareCodeUnits(a.ecosystem, b.ecosystem)
    || compareCodeUnits(a.package, b.package)
    || compareCodeUnits(a.version, b.version)
    || compareCodeUnits(a.id, b.id);
}

/** Advisories the gate can see. A missing `epss` is left off the ref, never stored as 0. */
export function advisoriesForEpssGate(vulns: VulnerabilityScanResult | undefined): {
  source: EpssGateInput['source'];
  advisories: EpssAdvisoryRef[];
} {
  if (!vulns) return { source: null, advisories: [] };
  const advisories: EpssAdvisoryRef[] = [];
  for (const pkg of vulns.packages) {
    for (const advisory of pkg.advisories) {
      const epss = typeof advisory.epss === 'number' && Number.isFinite(advisory.epss) ? advisory.epss : undefined;
      advisories.push({
        ecosystem: pkg.ecosystem,
        package: pkg.package,
        version: pkg.version,
        id: advisory.id,
        ...(epss !== undefined ? { epss } : {}),
      });
    }
  }
  return { source: vulns.source, advisories };
}

/**
 * Judge advisories against an EPSS threshold.
 *
 * A vulnerability pass that ran and found no advisories passes: nothing is
 * at or above the threshold. A pass that did not run, a feed that could not
 * be reached, or a set of advisories that all omit `epss` is not compared.
 */
export function evaluateEpssGate(input: EpssGateInput): EpssGateResult {
  const scored = input.advisories.filter((advisory) => scoredEpss(advisory) !== null);
  const measuredClean =
    (input.source === 'osv' || input.source === 'manifest') && input.advisories.length === 0;
  if (scored.length === 0 && !measuredClean) {
    return {
      exitCode: 0,
      message: epssAbsentMessage(input.threshold, input.from),
      skipped: true,
      breached: [],
    };
  }
  const breached = scored
    .filter((advisory) => (advisory.epss as number) >= input.threshold)
    .sort(compareAdvisories);
  if (breached.length > 0) {
    return {
      exitCode: 2,
      message: epssFailingMessage(breached.length, input.threshold),
      skipped: false,
      breached,
    };
  }
  return { exitCode: 0, message: null, skipped: false, breached: [] };
}
