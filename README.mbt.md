# MoonVigil

MoonVigil is an offline-first dependency vulnerability scanner for MoonBit JSON
manifests. It scans `moon.mod.json` and `moon.pkg.json`, matches dependencies
against a local versioned advisory database, and emits terminal, JSON, SARIF,
or CycloneDX-style SBOM output. No project metadata is sent over the network.

Recursive scans normalise declarations by package name and version. Duplicate
declarations are reported once with a deterministic manifest location as their
evidence source.

## Run

```sh
moon check --target native
moon test --target native
moon run cmd/main --target native -- db validate advisories.json
moon run cmd/main --target native -- scan fixtures/affected --db advisories.json
moon run cmd/main --target native -- scan fixtures/affected --db advisories.json --format sarif --output report.sarif
moon run cmd/main --target native -- sbom fixtures/affected
```

## Advisory database

`advisories.json` uses a compact OSV-inspired schema. Use an empty
`fixed_version` string when no fixed release is known. `affected` accepts a
three-part numeric SemVer range such as `>=0.1.0 <0.2.0`, or `*`. Versions that
cannot be compared are reported separately rather than treated as vulnerable.

## Scope and security boundary

The first release intentionally supports only MoonBit JSON manifests and a
local database. It does not query the network, execute project code, infer lock
files, perform source-code SAST, or claim that an unknown version is safe.

## Development

```sh
just check
just test
just build
```

The native CLI uses a tiny C bridge solely to return standard process exit
codes: `0` when no affected dependency is found, `1` when findings exist, and
`2` for invalid command usage.
