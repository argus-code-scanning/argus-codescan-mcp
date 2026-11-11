# Remote dependency sources

The built-in code scan and `argus scan malware PATH` inspect dependency fields in
`package.json`, `requirements*.txt`, `pyproject.toml`, and `composer.json`.
No packages are installed and no URLs are requested.

| Source | Severity |
| --- | --- |
| Plain HTTP dependency, including Git over HTTP | High |
| Direct HTTPS archive | Medium |
| Git source without a full 40- or 64-character commit hash | Low (review) |

Registry version constraints, local/workspace dependencies, HTTPS Composer registry
endpoints, and Git sources pinned to full commits are accepted. Branches, tags, and
abbreviated hashes can change and are reported for review. An HTTPS archive remains
a review finding even when a requirements file supplies a hash: verify that both
the publisher and the expected content are trusted.

Checks include npm development, optional and peer dependencies; Python optional
dependencies, dependency groups and Poetry tables; and Composer package dist/source
repositories. Metadata URLs such as homepages are excluded. Existing Composer HTTP
findings are retained without an additional duplicate remote-source finding.

These checks use parsed fields rather than text regexes. Malformed manifests are
ignored; this is not a manifest validator. Finding descriptions omit source values
to avoid exposing credentials embedded in URLs. Manifest ignore comments and
example-directory context cannot suppress or downgrade these supply-chain checks.
