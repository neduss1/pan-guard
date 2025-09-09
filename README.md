# PAN Guard (open-source)

PAN discovery & masking tool (first4+last4) that helps teams reduce PCI DSS scope by locating Primary Account Numbers (PANs) across text, archives, and optional binary blobs — and masking them in-place. Bilingual UI (English/Українська). No external Python dependencies.

> ⚠️ **Compliance note:** This tool **does not make you PCI DSS/ISO 27001 compliant by itself**. It is a helper for data minimization and secure handling. Validate your policies, processes, and compensating controls.

## Features
- **Discovery** of Luhn-valid PANs in text files, OOXML/ZIP archives, and (optionally) binaries.
- **Masking policy**: keep first N + last N digits (defaults 4+4), preserve separators (`-`/space).
- **Two-step flow**: scan → ask before masking; or auto-mask mode.
- **False-positive (FP) ignore list** with *strict* (sha-locked) and non-strict modes.
- **TOCTOU guard**: verifies size/mtime/sha256 before applying changes.
- **Audit trail**: append-only NDJSON with **HMAC chain** (`PANGUARD_AUDIT_KEY`). Verifier included.
- **Profiles**: `pci-strict` (safe defaults), `safe-detect` (scan-only), `none` (custom).
- **Allow-list** for paths/globs; excludes system paths by default; avoids symlinks by default.
- **Cross-platform**, no external packages (pure stdlib).

## Quick start
```bash
# 1) Menu (English is default)
python3 pan_guard_pro.py

# 2) CLI (no menu), PCI-like profile, HMAC-audit
export PANGUARD_AUDIT_KEY='long_random_secret'
python3 pan_guard_pro.py --no-menu --path ./data --profile pci-strict --audit-log audit.ndjson
```

**Common flags**
- `--scan-all` to scan binaries (detect); `--binary-replace` to mask bytes in binaries (risky).
- `--rewrite-archives` to rewrite DOCX/XLSX/PPTX/ZIP and mask inside XML/text parts.
- `--log <file> --log-format ndjson|csv|json` to export findings summary.
- `--fp-add/--fp-add-strict/--fp-remove/--fp-list` to manage FP ignore list.
- `--profile pci-strict|safe-detect|none` to apply presets.

## Version
Current release: **v0.1.0**
```bash
python3 pan_guard_pro.py --version
```

## Security model (high level)
- **No network I/O**; operates on local filesystem paths you provide.
- **TOCTOU guard** prevents writing if file changed between scan & apply.
- **Backups (.bak)** before modification (toggleable).
- **Audit log** with HMAC chaining; `--verify-log` to check integrity.
- **SEAL** (HMAC over script) to detect tampering with the tool itself.

See [`SECURITY.md`](SECURITY.md) for threat model & disclosure policy.

## Limitations
- Discovery relies on pattern (+ Luhn + issuer heuristics). No parser can guarantee 100% coverage.
- Binary masking may corrupt proprietary formats; leave `--binary-replace` **off** unless you’ve tested.
- Archival rewriting currently supports standard ZIP/OOXML structures.

## License
**MIT** — see [`LICENSE`](LICENSE). Free for commercial & non-commercial use with attribution.

## Name & repo
Suggested repository name: **`pan-guard`**

---
Made with ❤️ to help teams reduce accidental PAN sprawl.
