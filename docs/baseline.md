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
`validate_baseline`, and `baseline_json`. CLI baseline comparison and CI gate
integration are delivered in subsequent increments; until then the baseline
API is intended for tooling experiments and fixture validation.
