# Baseline snapshot format

MoonVigil reads schema-v1 and schema-v2 baseline snapshots. New snapshots use
schema v2 and record the exact identity of an affected direct dependency plus
the advisory's affected range, severity, and fixed version. Schema v1 remains
valid for compatibility but does not carry risk evidence. Neither version
contains manifest paths, machine paths, aliases, project sources, or dependency
contents.

```json
{
  "schema_version": "2",
  "entries": [
    {
      "advisory_id": "MV-BASELINE-0001",
      "package_name": "example/fixture-library",
      "version": "1.2.3",
      "affected": ">=1.0.0 <2.0.0",
      "severity": "high",
      "fixed_version": "2.0.0"
    }
  ]
}
```

The empty `entries` array is valid. Both versions require a stable three-part
installed version; v2 additionally validates the range, severity, and fixed
version using the same rules as the advisory database. Entries are sorted
deterministically by advisory ID, package name, and version; exact duplicates
are removed when a snapshot is created from a report and rejected in an input
snapshot. Findings whose version cannot be compared are not included.

Library callers can use `baseline_from_report`, `parse_baseline`,
`validate_baseline`, `baseline_json`, and `apply_baseline`. The CLI accepts
`--baseline <file>` to compare the current scan with a snapshot and
`--baseline-output <file>` to explicitly write a new snapshot:

```sh
moon run cmd/main --target native -- scan fixtures/affected --baseline fixtures/baseline/empty.json
moon run cmd/main --target native -- scan fixtures/affected --baseline-output baseline.json
```

Matching uses the exact triple `(advisory_id, package_name, version)`. A
version change is therefore a new key. The report labels findings `new` or
`existing`, and reports baseline keys not present in current affected findings
as `no longer detected`; that label does not assert remediation because the
advisory database may also have changed. Uncomparable versions are excluded
from matching and never added to a snapshot.

Snapshots are opt-in and are not auto-discovered or updated. The `--baseline`
input path must be distinct from report and snapshot output paths.
With a baseline, exit code `1` means at least one new, unsuppressed finding met
the selected threshold (or any new finding when no explicit threshold is
configured). Existing findings and no-longer-detected entries do not gate.
