# September hackathon acceptance

MoonVigil 0.2.0 continues the offline scanner described in the original
proposal-stage README. It retains the existing MoonBit library/native CLI
layout, local advisory format, policy and baseline APIs, and 0/1/2 exit codes.

## Official criteria

This project belongs to the September 2026 MoonBit hackathon. The applicable
[September rules](https://github.com/moonbitlang/Hackathon2026/blob/efce40e26dc34e9abaeb4b81f83541abeadb9654/src/App.tsx)
are pinned because the live site changes for later events.

| Criterion | Project evidence |
| --- | --- |
| MoonBit is the primary implementation language | Parsing, inventory, version matching, advisory validation, policies, baselines, and report rendering are MoonBit. Native C only handles exit status, file identity, and link detection. Python orchestrates acceptance checks. |
| Public, traceable development | The public repository and its commits record the implementation; `CHANGELOG.md` records the 0.2.0 changes. |
| Documentation, examples, necessary tests | The root README, `demo/`, committed fixtures, MoonBit tests, and the acceptance command below provide runnable entry points. |
| Substantive work | This update fixes malformed-manifest false negatives, legacy and nested-module scope handling, output/input alias collisions, and machine-readable report compatibility. Each behavior has regression coverage. |
| License and attribution | Apache-2.0 is retained. The real parser manifest fixture includes its source commit and license in `fixtures/real/moonbitlang-parser/SOURCE.md`. Demo advisories are explicitly synthetic. |
| Explainable AI-assisted development | The implementation and tests expose each decision. The processing flow and boundaries are described below; test results record actual commands and assertions. |

## Reproduce

Install the native MoonBit toolchain (`moon 0.1.20261023` / `moonc v0.10.17`
was checked) and Python 3.8 or newer, then run from the repository root:

```sh
python scripts/acceptance.py
```

The script uses only Python's standard library. It runs `moon fmt --check`,
`moon check --target native --warn-list +73`, `moon test --target native`, and
`moon build --target native --release`. It then invokes the built executable
directly for every CLI case. A nonzero script exit means a build step, expected
exit code, output assertion, or execution failed.

`.acceptance-output/summary.json` records the exact toolchain, commands,
expected and actual exit codes, stdout/stderr, assertions, and any skipped link
checks. Sample terminal, JSON, SARIF, SBOM, and baseline artifacts are in the
same directory. Use `--output <directory>` to select a separate evidence
directory. CI runs the same script on Ubuntu, macOS, and Windows and uploads
its artifacts even when a check fails.

The checks cover new and legacy manifests, a pinned real-world manifest,
declaration deduplication, version conflicts, unknown versions, severity and
scope gates, expiring suppressions, baseline creation and comparison, advisory
risk changes, malformed inputs, exact CLI argument handling, input preservation
through path aliases and links, and traversal-loop rejection. Link creation
failures are recorded as skipped checks rather than reported as passes.

## Verified on 2026-10-27

| Environment | MoonBit tests | Acceptance commands | Assertions | Skipped link checks |
| --- | --- | --- | --- | --- |
| Windows native | 65 / 65 | 179 / 179 | 619 / 619 | 0 |
| Ubuntu 24.04 under WSL2 | 65 / 65 | 179 / 179 | 619 / 619 | 0 |
| GitHub CI Ubuntu | 65 / 65 | 179 / 179 | 619 / 619 | 0 |
| GitHub CI macOS | 65 / 65 | 179 / 179 | 619 / 619 | 0 |
| GitHub CI Windows | 65 / 65 | 179 / 179 | 619 / 619 | 0 |

The local run and [three-platform CI run](https://github.com/shen-E/moonvigil/actions/runs/40437944085)
used `moon 0.1.20261023 (3778465)` and
`moonc v0.10.17+d971670cd`. The toolchain emits existing deprecation and
unqualified-test-import warnings; build and type checks complete with zero
errors. CI records its installed toolchain in each run rather than assuming
that the official `latest` installer will remain at this version.

Six SARIF artifacts and one SBOM also passed the official SARIF 2.1.0 and
CycloneDX 1.5 JSON schemas, including URI format checks, using Python
`jsonschema 4.10.3`. The separate
[`schema-validation.json`](schema-validation.json) evidence
records schema source URLs, Git blob IDs, artifact SHA-256 hashes, and results.
Schema validation was an additional verification step; the standard-library
acceptance script checks report contents without installing that dependency.

The WSL shell demo also completed with exit 0 using an isolated installation:
its JSON report contains four dependencies, two affected findings, and one
uncomparable finding; SARIF contains three results, and the SBOM contains all
four dependency components.

## Implementation and boundaries

The CLI discovers exact manifest names while ignoring build and dependency
caches. A current-format manifest shadows its JSON predecessor in the same
directory. Module declarations provide versions; package imports provide
aliases and usage scopes. Imports attach within the nearest module boundary
before equal name/version declarations are merged into a sorted inventory.

The library validates the complete local advisory database, compares stable
three-part numeric versions, computes baseline changes, and applies the
configured severity, scope, and suppression gates. Report rendering retains
all findings regardless of the blocking decision. SARIF artifact paths are
URI-encoded; the CycloneDX 1.5 JSON SBOM includes its document version and
encoded package identifiers. `pkg:moonbit` is a project-specific package URL
type and does not imply a registered external advisory ecosystem.

Scanning performs no network requests and executes no target project code.
Only declared direct dependencies are scanned. Pre-release, build-metadata,
branch, and invalid versions remain uncomparable. Directory/manifest symlinks
and Windows reparse points are rejected; unrelated file symlinks are ignored.
Input/output collision checks assume files are not concurrently replaced
during the scan.

The real-world fixture validates compatibility with actual manifests. The
included advisory hits validate matching logic using synthetic data; they are
not claims of real MoonBit vulnerabilities.
