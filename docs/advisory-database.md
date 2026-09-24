# Advisory database format

MoonVigil reads advisories from a local JSON file and validates the complete
database before matching dependencies. Validation is offline and deterministic.

The root object must contain `schema_version: "1"` and an `advisories` array.
An empty array is valid. Every advisory must contain string fields `id`,
`package_name`, `affected`, `severity`, `summary`, and `fixed_version`, plus a
`references` array of strings.

IDs, package names, and summaries must be non-empty; IDs must be unique within
the database. Severity is one of `critical`, `high`, `medium`, `low`, or `info`.
Affected ranges use MoonVigil's stable three-component numeric version syntax.
`fixed_version` is either empty or a stable three-component version. At least
one reference must be a valid `http://` or `https://` URL with a non-empty
authority.

Both `db validate` and `scan --db` apply the same rules. Diagnostics identify
the advisory index, ID when available, field, and reason. Invalid databases
terminate with exit code `2`; they are never used to generate a scan report.
