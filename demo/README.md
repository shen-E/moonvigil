# WSL2 Ubuntu demonstration

Run this demonstration from an Ubuntu 24.04 WSL shell:

```sh
./demo/wsl/run-demo.sh
```

For a predictable relative output directory, pass one explicitly:

```sh
./demo/wsl/run-demo.sh demo-artifacts
```

The script installs MoonBit and updates the package registry only if the
toolchain is missing, then builds and tests MoonVigil and validates the local
advisory database. It scans the local JSON manifests under `demo/project`
against the local `demo/advisories.json` database. The target project contains
no source code and is never executed.

The expected scan result is two affected dependencies and one uncomparable
branch version. The scan command therefore exits with code `1`; the script
expects and verifies that result. It writes `report.json`, `report.sarif`, and
`bom.json` to a temporary directory by default. Pass a relative output directory
such as `demo-artifacts` to keep the outputs easy to find; the script does not
print absolute machine-specific paths.

For a real-machine recording, prepare MoonBit and its package registry before
recording, use the normal Ubuntu terminal, and follow the narration outline.
Keep the recording focused on actual commands and reports; do not expose
absolute paths or local project metadata.

To exercise the modern manifest parser against pinned public project data,
run the compatibility scan from the repository root:

```sh
moon run cmd/main --target native -- scan fixtures/real/moonbitlang-parser --db fixtures/empty-database.json --format json
```

This validates manifest compatibility only; the empty local database is not
a real advisory dataset and its zero findings must not be read as a clean bill
of health.
