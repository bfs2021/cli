/**
 * CLI-facing atomic writes. The replace itself lives in core-open so the
 * vendored engine and this package share one implementation. Failures that
 * the command should exit on are wrapped as {@link CliError} here.
 */

import { CliError, ExitCode } from './exit.js';
import { artifactWriteMessage } from '../core-open/utils/atomic-file.js';
import { setWriteFailureWrapper } from '../core-open/utils/fs.js';

export {
  artifactWriteMessage,
  atomicTempPath,
  isPidAlive,
  setAtomicWriteFaultForTests,
  sweepStrayAtomicTemps,
  writeAtomic,
  writeAtomicSync,
  type AtomicBytes,
  type SweepOptions,
} from '../core-open/utils/atomic-file.js';

/** Actionable write failure. The Node message, stack, and temp path stay out. */
export function artifactWriteError(filePath: string, cause: unknown): CliError {
  return new CliError(artifactWriteMessage(filePath, cause), ExitCode.ERROR);
}

setWriteFailureWrapper((filePath, cause) => artifactWriteError(filePath, cause));
