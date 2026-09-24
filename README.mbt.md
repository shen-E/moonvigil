# MoonVigil

MoonVigil is an offline-first dependency vulnerability scanner for MoonBit
projects. It reads current `moon.mod` and `moon.pkg` manifests and retains
support for legacy `moon.mod.json` / `moon.pkg.json` files. If both formats are
present in one directory, the current format takes precedence. It matches
declared module versions against a local versioned advisory database and emits
terminal, JSON, SARIF, or CycloneDX-style SBOM output. No project metadata is
sent over the network.

Recursive scans normalize declarations by module name and version. Duplicate
declarations are reported once with a deterministic relative manifest location
as evidence. Package imports retain runtime, test, and white-box test scopes;
aliases do not change the canonical module name.

## Run

```sh
moon check --target native
moon test --target native
moon run cmd/main --target native -- db validate advisories.json
moon run cmd/main --target native -- scan fixtures/affected --db advisories.json
moon run cmd/main --target native -- scan fixtures/affected --db advisories.json --format sarif --output report.sarif
moon run cmd/main --target native -- sbom fixtures/affected --output bom.json
moon run cmd/main --target native -- scan fixtures/real/moonbitlang-parser --db fixtures/empty-database.json --format json
moon run cmd/main --target native -- scan fixtures/affected --policy fixtures/policy/exact-suppression.json --format json --output report.json
moon run cmd/main --target native -- scan fixtures/affected --fail-on critical
moon run cmd/main --target native -- scan fixtures/affected --baseline fixtures/baseline/empty.json
moon run cmd/main --target native -- scan fixtures/affected --baseline-output baseline.json
```

## Linux demonstration

The reproducible WSL2 Ubuntu demonstration is in [`demo/`](demo/README.md).
It builds and tests MoonVigil, scans a representative multi-manifest project,
and writes terminal, JSON, SARIF, and SBOM evidence without executing the
scanned project.

## Advisory database

`advisories.json` uses a compact OSV-inspired schema. Use an empty
`fixed_version` string when no fixed release is known. `affected` accepts
three-part numeric stable SemVer expressions using `<`, `<=`, `>`, `>=`, `=`,
or a bare exact version; spaces form an intersection and `||` forms a union.
`*` matches every comparable version. Pre-release, build-metadata, and invalid
versions or ranges are reported separately rather than treated as vulnerable.

Every database is validated before scanning. The supported database schema
version is "1"; advisory IDs must be unique; required fields are reported with
their advisory index and field name; package names and summaries must be
present; and severity must be one of critical, high, medium, low, or info.
Each advisory needs at least one HTTP(S) reference with a valid authority. A
fixed version is empty or a stable three-part version. The db validate command
reports all semantic issues found in one pass.

The JSON report schema is version 4 and includes dependency scopes, optional
policy evidence, and optional baseline comparison state. A pinned
public manifest fixture from moonbitlang/parser is provided under fixtures/real
to exercise real-world manifest syntax; its source commit and license are
documented alongside the fixture. This is compatibility evidence, not a claim
that the project has a known vulnerability.

## CI policy

Policy files are loaded only when explicitly passed with `--policy`; MoonVigil
does not auto-discover a policy. `--fail-on` can override the configured
severity threshold. Without a baseline, existing behavior is unchanged: any
affected dependency exits 1, no affected dependencies exit 0, and invalid
arguments or inputs exit 2. With a policy, only unsuppressed findings at or
above the threshold block; uncomparable versions never block.

When `--baseline <file>` is supplied, the default gate blocks only new affected
findings. Existing findings and snapshot keys no longer detected remain visible
but do not block. If a policy or `--fail-on` threshold is also supplied, that
severity threshold applies to new findings only; active suppressions continue
to suppress exact matching findings. Without a baseline, policy behavior is
unchanged.

Suppression rules require an advisory ID, canonical package name, exact stable
version, non-empty reason, and an ISO expiry date. A rule applies only to that
exact triple, stays active through its expiry date, and is rejected after
expiry. Suppressed findings remain in terminal, JSON, and SARIF reports.
Unmatched rules produce a warning but do not suppress anything. See
[`docs/ci-policy.md`](docs/ci-policy.md) for the schema and workflow details.

Baseline snapshots store advisory ID, canonical package name, and exact
version only—never project paths. When a snapshot is supplied, findings are
marked new or existing; keys in the snapshot that are no longer detected are
reported separately without assuming they were remediated. Use
`--baseline-output <file>` to explicitly write a current snapshot. See
[`docs/baseline.md`](docs/baseline.md) for the schema and comparison behavior.

At the time of this check, the [official OSV schema's defined ecosystem list](https://ossf.github.io/osv-schema/)
does not include MoonBit or Mooncakes. The pinned public fixture therefore
verifies real manifest parsing and inventory only; advisories from other
ecosystems are not matched by package-name coincidence, and no real MoonBit
vulnerability hit is claimed.

## Scope and security boundary

MoonVigil scans only declared direct dependencies from module manifests.
Package imports are used to annotate where a declared dependency is used. It
does not query the network, execute project code, infer lock files or
transitive dependencies, perform source-code SAST, or claim that an unknown
version is safe.

## Development

```sh
just check
just test
just build
```

The native CLI uses a tiny C bridge solely to return standard process exit
codes: `0` when no finding meets the configured gate, `1` when one or more
unsuppressed findings meet it, and `2` for invalid command arguments, paths,
databases, policies, or output files.
