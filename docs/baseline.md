# Baseline snapshot format

MoonVigil's library can create and validate schema-v1 baseline snapshots. A
snapshot records only the exact identity of an affected direct dependency:
advisory ID, canonical package name, and stable three-part version. It contains
no manifest path, machine path, alias, project source, or dependency contents.

```json
{
  "schema_version": "1",
  "entries": [
    {
      "advisory_id": "MV-BASELINE-0001",
      "package_name": "example/fixture-library",
      "version": "1.2.3"
    }
  ]
}
```

The empty `entries` array is valid. Entries are sorted deterministically by
advisory ID, package name, and version; exact duplicates are removed when a
snapshot is created from a report and rejected in an input snapshot. Invalid
versions are rejected rather than normalized. Findings whose version cannot
be compared are not included.

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
