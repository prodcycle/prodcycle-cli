from .api_client import ComplianceApiClient
from .utils.fs import collect_files
from .formatters.table import format_table
from .formatters.prompt import format_prompt
from .formatters.sarif import format_sarif

__version__ = "0.5.0"

__all__ = [
    'ComplianceApiClient',
    'scan',
    'gate',
    'format_table',
    'format_prompt',
    'format_sarif',
    '__version__',
]

def scan(repo_path: str, frameworks: list[str] = None, options: dict = None) -> dict:
    """Scan a repository.

    Modes (selectable via ``options['config']['mode']``):
      - default ``'sync'``: synchronous validate; auto-falls-back to chunked
        sessions on 413 with ``suggestedEndpoint='/v1/compliance/scans'``
      - ``'async'``: kicks off ``?async=true`` and polls until terminal
      - ``'chunked'``: explicit chunked-session flow regardless of size
    """
    if frameworks is None:
        frameworks = ['soc2']
    if options is None:
        options = {}

    include = options.get('include')
    exclude = options.get('exclude')

    files = collect_files(repo_path, include_patterns=include, exclude_patterns=exclude)

    if not files:
        return {
            'passed': True,
            'exitCode': 0,
            'findings': [],
            'report': None,
            'summary': {}
        }

    client = ComplianceApiClient(options.get('apiUrl'), options.get('apiKey'))
    mode = ((options.get('config') or {}).get('mode')) or 'sync'

    if mode == 'async':
        response = client.validate_and_poll(files, frameworks, options)
    elif mode == 'chunked':
        response = client.validate_chunked(files, frameworks, options)
    else:
        response = client.validate(files, frameworks, options)

    passed = response.get('passed', False)

    # Pull `scannerError` through if the API set it. Without surfacing
    # this, a CI report shows `passed: false, findings: []` and the
    # caller can't distinguish "code is dirty" from "scanner is down."
    # Mirrors the API's ScannerErrorInfo shape.
    scanner_error = response.get('scannerError')

    # Exit code semantics:
    #   0 = passed (no actionable findings, no scanner error)
    #   1 = findings present, code not clean
    #   2 = scanner unavailable — could not certify either way; fail-closed
    exit_code = 2 if scanner_error else (0 if passed else 1)

    if scanner_error:
        import sys
        msg = scanner_error.get('message', 'unknown scanner error')
        cls = scanner_error.get('errorClass')
        code = scanner_error.get('errorCode')
        suffix = ''
        if cls:
            suffix += f' (errorClass={cls})'
        if code:
            suffix += f' (errorCode={code})'
        sys.stderr.write(f'⚠ Scanner error: {msg}{suffix}\n')

    result = {
        'scanId': response.get('scanId'),
        'passed': passed,
        'exitCode': exit_code,
        'findings': response.get('findings', []),
        'report': response.get('report'),
        'summary': response.get('summary', {}),
    }
    if scanner_error:
        result['scannerError'] = scanner_error
    return result

def gate(files: dict, frameworks: list[str] = None, severity_threshold: str = "medium", fail_on: list[str] = None, config: dict = None, api_url: str = None, api_key: str = None) -> dict:
    if frameworks is None:
        frameworks = ['soc2']
    if fail_on is None:
        fail_on = ["critical", "high"]

    client = ComplianceApiClient(api_url, api_key)

    # Forward severityThreshold/failOn/config to the hook endpoint so callers
    # of the programmatic API can influence server-side filtering the same way
    # scan() does.
    response = client.hook(
        files,
        frameworks,
        options={
            "severityThreshold": severity_threshold,
            "failOn": fail_on,
            "config": config or {},
        },
    )

    passed = response.get('passed', False)

    # Same scannerError plumbing as scan() above. Coding-agent hooks
    # especially need to distinguish "code is clean" from "scanner is
    # down" — agents should NOT proceed on the latter.
    scanner_error = response.get('scannerError')
    exit_code = 2 if scanner_error else (0 if passed else 1)

    if scanner_error:
        import sys
        msg = scanner_error.get('message', 'unknown scanner error')
        cls = scanner_error.get('errorClass')
        code = scanner_error.get('errorCode')
        suffix = ''
        if cls:
            suffix += f' (errorClass={cls})'
        if code:
            suffix += f' (errorCode={code})'
        sys.stderr.write(f'⚠ Scanner error: {msg}{suffix}\n')

    result = {
        'passed': passed,
        'exitCode': exit_code,
        'findings': response.get('findings', []),
        'prompt': response.get('prompt', ''),
        'summary': response.get('summary', {}),
    }
    if scanner_error:
        result['scannerError'] = scanner_error
    return result

