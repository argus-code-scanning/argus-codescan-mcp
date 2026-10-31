# Changelog

## 0.6.0

### Changed

- **Exit codes now follow `--fail-on` (behaviour change).** The npm CLI respects
  the `--fail-on` severity threshold when deciding its exit code. With the default
  `never`, findings no longer cause an exit code of 1; findings below an explicitly
  selected threshold also return 0. This changes existing CI behavior: configure an
  explicit `--fail-on` threshold if the build should fail on findings (#107).

### Added

- `argus-codescan review`: SAST and secrets on Git-changed or staged files (#88).

### Fixed

- Native SAST and secrets scans no longer follow symlinks out of the scanned
  project, and accept a single file as the target (#102).
- Patched vulnerable transitive dependencies (`js-yaml`, `brace-expansion` and
  others); `npm audit --omit=dev` reports no vulnerabilities (#98).
