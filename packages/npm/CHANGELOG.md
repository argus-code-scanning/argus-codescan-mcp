# Changelog

## Unreleased

### Changed

- The npm CLI now respects the `--fail-on` severity threshold when deciding
  its exit code. With the default `never`, findings no longer cause an exit
  code of 1; findings below an explicitly selected threshold also return 0.
  This changes existing CI behavior: configure an explicit `--fail-on`
  threshold if the build should fail on findings.