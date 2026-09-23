# One-minute demonstration script

1. Start in an Ubuntu 24.04 WSL shell and run `./demo/wsl/run-demo.sh`.
2. Explain that the script builds MoonVigil and scans only local JSON manifests
   with a local advisory database; it neither contacts a vulnerability service
   nor executes the target project.
3. Point out the terminal report: two affected dependencies include their
   range, fixed version, source location, and reference; the branch dependency
   is visible as `uncomparable` instead of being misclassified as safe.
4. Open the generated JSON report to show structured evidence, then the SARIF
   report to show CI and code-scanning integration data.
5. Open `bom.json` to show the CycloneDX-style inventory and conclude that the
   same scan is reproducible in CI or a Linux build environment.
