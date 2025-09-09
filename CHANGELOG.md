# Changelog

All notable changes to this project will be documented in this file.
This project adheres to Semantic Versioning.

## [0.1.0] - 2025-09-09
### Added
- Initial open-source release.
- Bilingual UI (English/Українська), English by default.
- PAN discovery (Luhn + issuer heuristics) across text, ZIP/OOXML internals, and optional binaries.
- Masking policy: firstN + lastN (default 4+4), separator-preserving.
- Two-step flow: scan → ask to mask; auto-mask mode; CLI & menu.
- False-positive ignore list (loose & strict/sha-locked).
- TOCTOU guard (size/mtime/sha256) before writes; `.bak` backups.
- Audit log with HMAC chaining (`PANGUARD_AUDIT_KEY`) + `--verify-log`.
- Compliance profiles: `pci-strict`, `safe-detect`, `none`.
- Allow-list for paths/globs; avoids symlinks & system paths by default.

### Security
- SEAL mechanism (HMAC over script) to detect tampering with the tool itself.

