# WSL2 Ubuntu demonstration

Run this demonstration from an Ubuntu 24.04 WSL shell:

```sh
./demo/wsl/run-demo.sh
```

The script installs MoonBit only if it is missing, then builds and tests
MoonVigil. It scans the local JSON manifests under `demo/project` against the
local `demo/advisories.json` database. The target project contains no source
code and is never executed.

The expected scan result is two affected dependencies and one uncomparable
branch version. The scan command therefore exits with code `1`; the script
expects and verifies that result. It prints the path of a temporary directory
containing `report.json`, `report.sarif`, and `bom.json`.

Use `demo/narration.md` as the one-minute presentation outline.
