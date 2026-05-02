import { ComplianceApiClient, ScanOptions, GateOptions, ScanResult } from './api-client';
import { collectFiles } from './utils/fs';

export * from './api-client';
export * from './formatters/table';
export * from './formatters/prompt';
export * from './formatters/sarif';

interface ScanReturn {
  scanId?: string;
  passed: boolean;
  exitCode: number;
  findings: unknown[];
  report: unknown;
  summary: unknown;
  /**
   * Set when the server-side scanner threw and the API was configured to
   * fail closed (the default). When this is present, callers MUST treat
   * `passed: false` as "scanner unavailable — cannot certify compliance"
   * rather than "code is dirty." Mirrors the API's `ScannerErrorInfo`
   * shape; see `packages/compliance-code-scanner/api/src/domain/services/
   * compliance-scan.service.ts` (`ScannerErrorInfo`) for the field
   * contract.
   *
   * Without this surfaced to the CLI's --output JSON, a benchmark or CI
   * report shows `passed: false, findings: []` and the user can't tell
   * whether the code passed (no findings, all clean) from whether the
   * scanner failed (no findings because nothing got evaluated).
   */
  scannerError?: {
    code: 'SCANNER_GATE_THREW';
    message: string;
    errorClass?: string;
    errorCode?: string;
  };
}

/**
 * Scan a repository by collecting files and sending them to the API.
 *
 * Modes (selectable via `options.config`):
 *   - default: synchronous validate; auto-falls-back to chunked sessions
 *     if the server returns 413 with `suggestedEndpoint=/v1/compliance/scans`
 *   - `mode: 'async'`: kicks off a 202 async-validate and polls until
 *     terminal (returns same shape as default)
 *   - `mode: 'chunked'`: explicit chunked-session flow regardless of size
 */
export async function scan(params: {
  repoPath: string;
  frameworks?: string[];
  options?: ScanOptions;
}): Promise<ScanReturn> {
  const { repoPath, frameworks = ['soc2'], options = {} } = params;

  const files = await collectFiles(repoPath, options.include, options.exclude);

  if (Object.keys(files).length === 0) {
    return {
      passed: true,
      exitCode: 0,
      findings: [],
      report: null,
      summary: undefined,
    };
  }

  const client = new ComplianceApiClient(options.apiUrl, options.apiKey);
  const mode = (options.config?.mode as 'sync' | 'async' | 'chunked' | undefined) ?? 'sync';

  let response: ScanResult;
  if (mode === 'async') {
    response = await client.validateAndPoll(files, frameworks, options);
  } else if (mode === 'chunked') {
    response = await client.validateChunked(files, frameworks, options);
  } else {
    response = await client.validate(files, frameworks, options);
  }

  // Pull `scannerError` through if the API set it. Picking the field
  // explicitly (rather than `...response`) so the CLI's public surface
  // doesn't accidentally expose internal fields if the API adds them.
  const scannerError = (response as { scannerError?: ScanReturn['scannerError'] })
    .scannerError;

  // Exit code semantics:
  //   0 = passed (no actionable findings, no scanner error)
  //   1 = findings present, code not clean
  //   2 = scanner unavailable — could not certify either way; fail-closed
  // Distinguish (1) from (2) so CI policy can decide whether a non-zero
  // exit means "developer must fix code" or "operator must investigate
  // scanner."
  const exitCode = scannerError ? 2 : response.passed ? 0 : 1;

  // Surface scanner errors prominently to stderr so the user sees the
  // distinction between a clean pass and an undetermined result. The
  // JSON output already carries the structured field for programmatic
  // consumers; this is for humans running the CLI interactively.
  if (scannerError) {
    process.stderr.write(
      `⚠ Scanner error: ${scannerError.message}` +
        (scannerError.errorClass ? ` (errorClass=${scannerError.errorClass})` : '') +
        (scannerError.errorCode ? ` (errorCode=${scannerError.errorCode})` : '') +
        '\n',
    );
  }

  return {
    scanId: response.scanId,
    passed: response.passed,
    exitCode,
    findings: response.findings ?? [],
    report: (response as { report?: unknown }).report ?? null,
    summary: response.summary,
    ...(scannerError ? { scannerError } : {}),
  };
}

/**
 * Gate code strings directly without writing to disk (low-latency hook
 * endpoint, used by coding-agent post-edit hooks).
 */
export async function gate(options: GateOptions) {
  const { files, frameworks = ['soc2'], ...scanOpts } = options;

  const client = new ComplianceApiClient(options.apiUrl, options.apiKey);
  const response = await client.hook(files, frameworks, scanOpts);

  // Same scannerError plumbing as scan() above. Coding-agent hooks
  // especially need to distinguish "code is clean" from "scanner is
  // down" — agents should NOT proceed on the latter.
  const scannerError = (response as { scannerError?: ScanReturn['scannerError'] })
    .scannerError;
  const exitCode = scannerError ? 2 : response.passed ? 0 : 1;

  if (scannerError) {
    process.stderr.write(
      `⚠ Scanner error: ${scannerError.message}` +
        (scannerError.errorClass ? ` (errorClass=${scannerError.errorClass})` : '') +
        (scannerError.errorCode ? ` (errorCode=${scannerError.errorCode})` : '') +
        '\n',
    );
  }

  return {
    passed: response.passed,
    exitCode,
    findings: response.findings ?? [],
    prompt: response.prompt,
    summary: response.summary,
    ...(scannerError ? { scannerError } : {}),
  };
}
