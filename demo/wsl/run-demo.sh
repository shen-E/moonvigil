#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
output_dir=${1:-"$(mktemp -d "${TMPDIR:-/tmp}/moonvigil-demo.XXXXXX")"}
mkdir -p "$output_dir"

if ! command -v moon >/dev/null 2>&1; then
  echo "MoonBit is not installed; installing the build toolchain."
  curl -fsSL https://cli.moonbitlang.com/install/unix.sh | bash
  export PATH="$HOME/.moon/bin:$PATH"
fi

cd "$project_root"
echo "MoonVigil scans local manifests and does not execute demo/project."
moon fmt --check
moon check --target native --warn-list +73
moon test --target native
moon build --target native

set +e
moon run cmd/main --target native -- scan demo/project --db demo/advisories.json
scan_exit=$?
set -e
if [ "$scan_exit" -ne 1 ]; then
  echo "Expected the demonstration scan to exit with 1, got $scan_exit." >&2
  exit 1
fi

moon run cmd/main --target native -- scan demo/project --db demo/advisories.json --format json --output "$output_dir/report.json" || scan_exit=$?
if [ "${scan_exit:-0}" -ne 1 ]; then
  echo "Expected JSON scan output to exit with 1." >&2
  exit 1
fi
moon run cmd/main --target native -- scan demo/project --db demo/advisories.json --format sarif --output "$output_dir/report.sarif" || scan_exit=$?
if [ "${scan_exit:-0}" -ne 1 ]; then
  echo "Expected SARIF scan output to exit with 1." >&2
  exit 1
fi
moon run cmd/main --target native -- sbom demo/project --output "$output_dir/bom.json"

echo "Demonstration artifacts: $output_dir"
