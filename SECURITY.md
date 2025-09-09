# Security Policy

## Supported versions
This is a community project provided “as is”. We aim to keep `main` stable. No SLA.

## Reporting a vulnerability
Please **do not** open public issues for sensitive reports.
- Email: `security@yourdomain.example` (replace with your real inbox)
- Subject: `PAN Guard vulnerability`
- Include: version/commit, environment, PoC steps, expected vs. actual behavior, and impact.

We target initial response within **7 days** and coordinated disclosure within **90 days** of confirmation, unless otherwise agreed.

## Threat model (summary)
- **Tampering with the tool**: use the built-in **SEAL** (HMAC over script source). Keep `PAN_GUARD_KEY` secret.
- **Audit trail integrity**: configure `PANGUARD_AUDIT_KEY` and store audit files on append-only media; verify via `--verify-log`.
- **TOCTOU risks**: the tool re-checks size/mtime/sha256 before write; on mismatch it skips and records an audit event.
- **Scope control**: prefer the `pci-strict` profile; use allow-list globs; avoid running with elevated privileges.
- **False positives**: manage via FP ignore list; use **strict** FP (sha-locked) for precise exclusions.
- **Data loss**: `.bak` backups are enabled by default; test on copies and keep backups per your policy.
- **Binary formats**: `--binary-replace` is risky—enable only after format-specific testing.

## Operational guidance
- Run in a controlled environment with backups and version control.
- Limit the search path to the minimum necessary (principle of least privilege).
- Log to a secured location; rotate and protect access.
- Do not copy PAN-containing files into less-trusted systems for convenience.
