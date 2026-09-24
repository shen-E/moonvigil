# Changelog

## Unreleased

- Added strict advisory database validation with field-level diagnostics.
- Rejected unsupported database schemas, unsafe range syntax, malformed fixed
  versions, invalid severities, duplicate IDs, and missing HTTP(S) evidence.
- Added deterministic stable-SemVer range matching and conservative
  `Uncomparable` handling.
- Added detailed terminal, JSON, and SARIF evidence with a report schema
  version, plus CLI artifact output validation.
- Added a reproducible WSL2 Ubuntu demonstration project and narration script.
- Aggregated missing-field and semantic advisory diagnostics; HTTP(S) references
  now require a valid non-empty authority and port.
- Added modern `moon.mod` and `moon.pkg` parsing with aliases, usage scopes, and
  legacy JSON fallback. Duplicate module declarations produce deterministic
  version-conflict evidence, and JSON reports use schema v2.
- Added compatibility tests from a commit-pinned public MoonBit parser manifest.
- Added explicit diagnostics for version conflicts across the scanned tree and
  wrong-type/missing advisory fields.

## 0.1.0
- Added offline parsing for `moon.mod.json` and `moon.pkg.json` manifests.
- Added deterministic three-part SemVer range matching and uncomparable-version reporting.
- Added terminal, JSON, SARIF 2.1.0, and CycloneDX-style SBOM output.
- Added a native CLI with `scan`, `sbom`, and `db validate` commands.
