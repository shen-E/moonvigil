#!/usr/bin/env python3
"""Build MoonVigil once and verify its native CLI using only Python's stdlib."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
ADVISORY_ID = "MOONVIGIL-2026-0001"
SUPPRESSION_REASON = "Temporary compatibility exception for the policy fixture."


class Acceptance:
    def __init__(self, output, moon, timeout):
        self.output = output
        self.moon = moon
        self.timeout = timeout
        self.binary = None
        self.commands = []
        self.skipped = []
        self.artifacts = []
        self.replacements = [
            (str(ROOT), "."),
            (ROOT.as_posix(), "."),
            (str(Path.home()), "<home>"),
            (Path.home().as_posix(), "<home>"),
        ]
        try:
            output.relative_to(ROOT)
            inside_repository = True
        except ValueError:
            inside_repository = False
        if not inside_repository:
            self.replacements.insert(0, (str(output), "<output>"))
            self.replacements.insert(0, (output.as_posix(), "<output>"))

    def relative(self, path):
        try:
            return Path(os.path.relpath(path, ROOT)).as_posix()
        except ValueError:
            # Windows output directories may be on a different drive.
            return Path(path).as_posix()

    def clean(self, value):
        for source, replacement in sorted(
            self.replacements, key=lambda item: len(item[0]), reverse=True
        ):
            value = value.replace(source, replacement)
        return value

    def check(self, record, description, condition, actual=None, expected=None):
        assertion = {"description": description, "passed": bool(condition)}
        if actual is not None:
            assertion["actual"] = actual
        if expected is not None:
            assertion["expected"] = expected
        record["assertions"].append(assertion)

    def run(self, name, argv, expected, label=None, timeout=None):
        started = time.monotonic()
        record = {
            "name": name,
            "command": [label or argv[0], *[self.clean(str(arg)) for arg in argv[1:]]],
            "cwd": ".",
            "expected_exit": expected,
            "actual_exit": None,
            "assertions": [],
        }
        try:
            completed = subprocess.run(
                [str(arg) for arg in argv],
                cwd=ROOT,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout or self.timeout,
                check=False,
            )
            record["actual_exit"] = completed.returncode
            record["stdout"] = self.clean(completed.stdout)
            record["stderr"] = self.clean(completed.stderr)
        except subprocess.TimeoutExpired:
            record["error"] = "command timed out"
        except OSError as error:
            record["error"] = self.clean(str(error))
        record["duration_seconds"] = round(time.monotonic() - started, 3)
        self.check(
            record,
            "process exit code matches the command contract",
            record["actual_exit"] == expected,
            actual=record["actual_exit"],
            expected=expected,
        )
        self.commands.append(record)
        result = "PASS" if record["actual_exit"] == expected else "FAIL"
        print(f"{result} {name}: exit {record['actual_exit']} (expected {expected})", flush=True)
        return record

    def cli(self, name, args, expected, timeout=30):
        return self.run(name, [self.binary, *args], expected, "moonvigil", timeout)

    def artifact(self, name):
        path = self.output / name
        # Each report must be produced by this run, never accepted from a prior run.
        if path.exists() or path.is_symlink():
            if not path.is_file() or path.is_symlink():
                raise ValueError(f"artifact is not an ordinary file: {name}")
            path.unlink()
        return path

    def save_stdout(self, record, name):
        path = self.artifact(name)
        path.write_text(record.get("stdout", ""), encoding="utf-8")
        self.artifacts.append(name)
        record["artifact"] = name

    def read_json(self, record, path):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            self.check(record, "output is a JSON object", isinstance(value, dict))
            if not isinstance(value, dict):
                return {}
            self.artifacts.append(path.name)
            record["artifact"] = path.name
            return value
        except (OSError, ValueError) as error:
            self.check(record, "output is readable JSON", False, self.clean(str(error)))
            return {}

    def json_scan(self, name, target="fixtures/affected", expected=1, extra=(), database="advisories.json"):
        path = self.artifact(name + ".json")
        args = ["scan", target, "--db", database, *extra, "--format", "json", "--output", self.relative(path)]
        record = self.cli(name, args, expected)
        report = self.read_json(record, path)
        self.check(record, "JSON report schema is v6", report.get("schema_version") == "6")
        for field in ("dependencies", "findings", "uncomparable", "conflicts"):
            self.check(record, f"{field} is an array", isinstance(report.get(field), list))
        return record, report

    def sarif_scan(self, name, target="fixtures/affected", expected=1, extra=(), database="advisories.json"):
        path = self.artifact(name + ".sarif")
        record = self.cli(name + "-sarif", ["scan", target, "--db", database, *extra, "--format", "sarif", "--output", self.relative(path)], expected)
        report = self.read_json(record, path)
        self.check(record, "SARIF version is 2.1.0", report.get("version") == "2.1.0")
        runs = report.get("runs", [])
        self.check(record, "SARIF contains one run", isinstance(runs, list) and len(runs) == 1)
        run = runs[0] if isinstance(runs, list) and runs and isinstance(runs[0], dict) else {}
        self.check(record, "SARIF tool is MoonVigil", run.get("tool", {}).get("driver", {}).get("name") == "MoonVigil")
        self.check(record, "SARIF results is an array", isinstance(run.get("results"), list))
        return record, run

    def expect_policy(self, record, report, blocking, excluded=None, scopes=None):
        policy = report.get("policy") or {}
        self.check(record, "policy blocking count", policy.get("blocking_findings") == blocking, policy.get("blocking_findings"), blocking)
        if excluded is not None:
            self.check(record, "policy scope exclusion count", policy.get("scope_excluded_findings") == excluded, policy.get("scope_excluded_findings"), excluded)
        if scopes is not None:
            self.check(record, "effective policy scopes", policy.get("fail_on_scopes") == scopes, policy.get("fail_on_scopes"), scopes)

    def build(self):
        self.run("toolchain-version", [self.moon, "version", "--all"], 0, "moon")
        for name, args in (
            ("format", ["fmt", "--check"]),
            ("type-check", ["check", "--target", "native", "--warn-list", "+73"]),
            ("unit-tests", ["test", "--target", "native"]),
            ("release-build", ["build", "--target", "native", "--release"]),
        ):
            record = self.run(name, [self.moon, *args], 0, "moon")
        candidates = [ROOT / "_build/native/release/build/cmd/moonvigil" / name for name in ("moonvigil.exe", "moonvigil")]
        self.binary = next((path for path in candidates if path.is_file()), None)
        self.check(record, "native release executable exists", self.binary is not None)
        return record["actual_exit"] == 0 and self.binary is not None

    def fixtures(self):
        record = self.cli("help", ["--help"], 0)
        self.check(record, "help describes scan and SBOM commands", "scan" in record.get("stdout", "") and "sbom" in record.get("stdout", ""))
        record = self.cli("version", ["--version"], 0)
        self.check(record, "version identifies MoonVigil", "MoonVigil" in record.get("stdout", ""))
        self.cli("no-arguments-help", [], 0)
        self.cli("unknown-command", ["unknown"], 2)

        for database in ("advisories.json", "fixtures/empty-database.json"):
            self.cli("db-valid-" + Path(database).stem, ["db", "validate", database], 0)
        invalid_databases = sorted((ROOT / "fixtures").glob("invalid-*.json")) + [ROOT / "fixtures/duplicate-id.json"]
        for database in invalid_databases:
            self.cli("db-reject-" + database.stem, ["db", "validate", self.relative(database)], 2)
        self.cli("scan-invalid-database", ["scan", "fixtures/affected", "--db", "fixtures/invalid-severity.json"], 2)
        self.cli("db-extra-argument", ["db", "validate", "advisories.json", "unexpected"], 2)

        record, affected = self.json_scan("affected")
        self.check(record, "affected fixture has two direct dependencies", len(affected.get("dependencies", [])) == 2)
        self.check(record, "affected fixture has one matching advisory", [finding.get("advisory", {}).get("id") for finding in affected.get("findings", [])] == [ADVISORY_ID])
        record, repeat = self.json_scan("affected-repeat")
        self.check(record, "repeated scan is deterministic", repeat == affected)
        record = self.cli("affected-terminal", ["scan", "fixtures/affected", "--db", "advisories.json"], 1)
        self.check(record, "terminal shows finding evidence", all(text in record.get("stdout", "") for text in (ADVISORY_ID, "Affected: 1", "0.1.5", "0.2.0")))
        self.save_stdout(record, "affected.txt")
        record, unknown = self.sarif_scan("unknown", "fixtures/unknown-version", 0)
        results = unknown.get("results", [])
        self.check(record, "unknown version is a non-blocking note", len(results) == 1 and results[0].get("level") == "note" and results[0].get("properties", {}).get("matchStatus") == "uncomparable")
        record, report = self.json_scan("missing-import", "fixtures/missing-import", 0)
        self.check(record, "valid manifest without imports yields an empty inventory", report.get("dependencies") == [] and report.get("findings") == [])
        self.cli("missing-path", ["scan", "fixtures/not-found", "--db", "advisories.json"], 2)
        record, modern = self.json_scan("modern-preferred", "fixtures/modern-preferred", 0, database="fixtures/empty-database.json")
        self.check(record, "modern manifest overrides the legacy declaration", [(dep.get("name"), dep.get("version"), dep.get("source")) for dep in modern.get("dependencies", [])] == [("example/package", "1.2.3", "moon.mod")])
        self.check(record, "modern alias and test scope are retained", len(modern.get("dependencies", [])) == 1 and modern["dependencies"][0].get("aliases") == ["client"] and modern["dependencies"][0].get("scopes") == ["test"])
        record, real = self.json_scan("public-manifest", "fixtures/real/moonbitlang-parser", 0, database="fixtures/empty-database.json")
        self.check(record, "pinned public manifest has five dependencies and no advisory claims", len(real.get("dependencies", [])) == 5 and real.get("findings") == [])
        record, demo = self.json_scan("demo", "demo/project", 1, database="demo/advisories.json")
        self.check(record, "demo has two affected and one uncomparable dependency", len(demo.get("findings", [])) == 2 and len(demo.get("uncomparable", [])) == 1)
        self.sarif_scan("demo", "demo/project", 1, database="demo/advisories.json")
        path = self.artifact("sbom.json")
        record = self.cli("sbom", ["sbom", "fixtures/affected", "--output", self.relative(path)], 0)
        bom = self.read_json(record, path)
        self.check(record, "SBOM identifies its format and specification", bom.get("bomFormat") == "CycloneDX" and bom.get("specVersion") == "1.5")
        self.check(record, "SBOM includes its integer document version", type(bom.get("version")) is int and bom["version"] == 1)
        self.check(record, "SBOM components match the declared inventory", {(component.get("name"), component.get("version")) for component in bom.get("components", [])} == {(dep["name"], dep["version"]) for dep in affected.get("dependencies", [])})
        self.check(record, "SBOM components have package URLs", all(component.get("purl", "").startswith("pkg:moonbit/") for component in bom.get("components", [])))

        self.policies()
        self.scopes()
        self.baselines()
        self.invalid_options()

    def policies(self):
        suppression = ["--policy", "fixtures/policy/exact-suppression.json"]
        record, report = self.json_scan("suppressed", expected=0, extra=suppression)
        self.expect_policy(record, report, 0)
        policy = report.get("policy") or {}
        self.check(record, "suppressed finding remains visible with its reason", len(report.get("findings", [])) == 1 and policy.get("suppressed_findings") == 1 and report["findings"][0].get("suppression", {}).get("reason") == SUPPRESSION_REASON)
        record, sarif = self.sarif_scan("suppressed", expected=0, extra=suppression)
        suppressions = [item for result in sarif.get("results", []) for item in result.get("suppressions", [])]
        self.check(record, "SARIF records accepted external suppression", suppressions == [{"kind": "external", "status": "accepted", "justification": SUPPRESSION_REASON}])
        record = self.cli("suppressed-terminal", ["scan", "fixtures/affected", *suppression], 0)
        self.check(record, "terminal retains suppressed evidence", "[suppressed]" in record.get("stdout", "") and SUPPRESSION_REASON in record.get("stdout", ""))
        self.save_stdout(record, "suppressed.txt")
        self.cli("policy-high", ["scan", "fixtures/affected", "--policy", "fixtures/policy/high-gate.json"], 1)
        self.cli("critical-threshold", ["scan", "fixtures/affected", "--fail-on", "critical"], 0)
        self.cli("high-threshold", ["scan", "fixtures/affected", "--fail-on", "high"], 1)
        record = self.cli("unmatched-suppression", ["scan", "fixtures/affected", "--policy", "fixtures/policy/unmatched-suppression.json"], 1)
        self.check(record, "unmatched suppression warns without hiding findings", "Warning: suppression did not match" in record.get("stdout", ""))
        record, report = self.json_scan("unknown-policy", "fixtures/unknown-version", 0, ["--fail-on", "critical"])
        self.expect_policy(record, report, 0)
        self.check(record, "uncomparable finding remains separate", len(report.get("uncomparable", [])) == 1 and report["uncomparable"][0].get("status") == "Uncomparable")
        for name in ("expired-suppression", "malformed"):
            self.cli("policy-reject-" + name, ["scan", "fixtures/affected", "--policy", f"fixtures/policy/{name}.json"], 2)

    def scopes(self):
        for name, selected, blocking, excluded in (
            ("runtime", "runtime", 2, 4),
            ("test-unclassified", "test,unclassified", 3, 3),
            ("policy-override", "test", 2, 4),
        ):
            extra = ["--fail-on-scope", selected]
            if name == "policy-override":
                extra += ["--policy", "fixtures/policy/runtime-only-v2.json"]
            record, report = self.json_scan("scope-" + name, "fixtures/scopes", 1, extra, "fixtures/scopes/advisories.json")
            self.expect_policy(record, report, blocking, excluded, selected.split(","))
            self.check(record, "scope gate retains every affected finding", len(report.get("findings", [])) == 6)
        record = self.cli("scope-wbtest-terminal", ["scan", "fixtures/scopes", "--db", "fixtures/scopes/advisories.json", "--fail-on-scope", "wbtest"], 1)
        self.check(record, "white-box scope has one blocker and five exclusions", "scopes wbtest; 1 blocking, 5 out of scope" in record.get("stdout", ""))
        record, run = self.sarif_scan("scope-all", "fixtures/scopes", 1, ["--fail-on-scope", "all"], "fixtures/scopes/advisories.json")
        policy = run.get("properties", {}).get("policy", {})
        self.check(record, "all scopes retain six SARIF results", len(run.get("results", [])) == 6)
        self.check(record, "SARIF contains the effective scope gate", policy.get("scopeExcludedFindings") == 0 and policy.get("failOnScopes") == ["runtime", "test", "wbtest", "other", "unclassified"] and policy.get("blockingFindings") == 6)
        record, report = self.json_scan("scope-critical", "fixtures/scopes", 0, ["--fail-on-scope", "runtime", "--fail-on", "critical"], "fixtures/scopes/advisories.json")
        self.expect_policy(record, report, 0, 4, ["runtime"])
        record, report = self.json_scan("scope-baseline-existing", "fixtures/scopes", 0, ["--fail-on-scope", "runtime", "--baseline", "fixtures/scopes/baseline-existing.json"], "fixtures/scopes/advisories.json")
        self.expect_policy(record, report, 0, 4, ["runtime"])

    def baselines(self):
        for name, path, expected, status, counts in (
            ("new", "empty", 1, "New", (1, 0, 0)),
            ("updated", "risk-changed", 1, "Updated", (0, 0, 1)),
            ("legacy-existing", "affected", 0, "Existing", (0, 1, 0)),
        ):
            record, report = self.json_scan("baseline-" + name, expected=expected, extra=["--baseline", f"fixtures/baseline/{path}.json"])
            baseline = report.get("baseline") or {}
            self.check(record, "baseline state is attached to the finding", len(report.get("findings", [])) == 1 and report["findings"][0].get("baseline_status") == status)
            self.check(record, "baseline delta counts", tuple(baseline.get(field) for field in ("new_findings", "existing_findings", "updated_findings")) == counts)
            if name == "legacy-existing":
                self.check(record, "v1 baseline explicitly identifies missing risk evidence", baseline.get("legacy_snapshot") is True)
        record, run = self.sarif_scan("baseline-existing", expected=0, extra=["--baseline", "fixtures/baseline/affected.json"])
        self.check(record, "SARIF baseline state is unchanged", len(run.get("results", [])) == 1 and run["results"][0].get("baselineState") == "unchanged")
        record, report = self.json_scan("baseline-no-longer-detected", extra=["--baseline", "fixtures/baseline/initial.json"])
        entries = (report.get("baseline") or {}).get("no_longer_detected", [])
        self.check(record, "missing snapshot keys remain visible", any(entry.get("advisory_id") == "MV-BASELINE-0001" for entry in entries))
        snapshot_path = self.artifact("generated-baseline.json")
        self.json_scan("baseline-generation", extra=["--baseline-output", self.relative(snapshot_path)])
        record = self.cli("generated-baseline-valid", ["baseline", "validate", self.relative(snapshot_path)], 0)
        snapshot = self.read_json(record, snapshot_path)
        self.check(record, "generated baseline stores risk evidence without project paths", snapshot.get("schema_version") == "2" and len(snapshot.get("entries", [])) == 1 and all(field in snapshot["entries"][0] for field in ("affected", "severity", "fixed_version")) and "source" not in snapshot["entries"][0] and snapshot["entries"][0].get("advisory_id") == ADVISORY_ID)
        record, report = self.json_scan("baseline-repeated", expected=0, extra=["--baseline", self.relative(snapshot_path)])
        self.check(record, "generated baseline removes repeated blockers", len(report.get("findings", [])) == 1 and report["findings"][0].get("baseline_status") == "Existing")
        for name, baseline, extra, expected, blocking in (
            ("existing", "affected", ["--policy", "fixtures/policy/high-gate.json"], 0, 0),
            ("new", "empty", ["--policy", "fixtures/policy/high-gate.json"], 1, 1),
            ("critical", "empty", ["--fail-on", "critical"], 0, 0),
        ):
            record, report = self.json_scan("baseline-policy-" + name, expected=expected, extra=["--baseline", f"fixtures/baseline/{baseline}.json", *extra])
            self.expect_policy(record, report, blocking)
        extra = ["--baseline", "fixtures/baseline/empty.json", "--policy", "fixtures/policy/exact-suppression.json"]
        record = self.cli("baseline-suppressed-terminal", ["scan", "fixtures/affected", *extra], 0)
        self.check(record, "terminal reports a suppressed new finding", "[suppressed, new]" in record.get("stdout", ""))
        record, run = self.sarif_scan("baseline-suppressed", expected=0, extra=extra)
        self.check(record, "SARIF preserves both suppression and new state", len(run.get("results", [])) == 1 and run["results"][0].get("baselineState") == "new" and bool(run["results"][0].get("suppressions")))
        for name, version in (("initial", "1"), ("valid-v2", "2")):
            record = self.cli("baseline-validate-" + name, ["baseline", "validate", f"fixtures/baseline/{name}.json"], 0)
            self.check(record, "baseline validation reports schema and entry count", f"valid baseline v{version}: 1 entries" in record.get("stdout", ""))
            if version == "1":
                self.check(record, "legacy validation warns about absent risk evidence", "no advisory risk evidence" in record.get("stdout", ""))
        invalid = sorted((ROOT / "fixtures/baseline").glob("invalid-*.json"))
        invalid += [ROOT / "fixtures/baseline/duplicate-entry.json", ROOT / "fixtures/baseline/unsupported-version.json", ROOT / "fixtures/baseline/not-found.json"]
        for path in invalid:
            self.cli("baseline-reject-" + path.stem, ["baseline", "validate", self.relative(path)], 2)
        self.cli("scan-invalid-baseline", ["scan", "fixtures/affected", "--baseline", "fixtures/baseline/duplicate-entry.json"], 2)
        self.cli("baseline-extra-argument", ["baseline", "validate", "fixtures/baseline/initial.json", "unexpected"], 2)

    def invalid_options(self):
        valid_values = {
            "--db": "advisories.json",
            "--format": "json",
            "--output": self.relative(self.output / "invalid-option-output.json"),
            "--policy": "fixtures/policy/high-gate.json",
            "--fail-on": "high",
            "--fail-on-scope": "runtime",
            "--baseline": "fixtures/baseline/empty.json",
            "--baseline-output": self.relative(self.output / "invalid-option-baseline.json"),
        }
        for option, value in valid_values.items():
            name = option[2:]
            for suffix, args in (("missing", [option]), ("empty", [option, ""]), ("duplicate", [option, value, option, value])):
                self.cli(f"option-{name}-{suffix}", ["scan", "fixtures/affected", *args], 2)
        for name, args in (
            ("invalid-format", ["--format", "unsupported"]),
            ("invalid-threshold", ["--fail-on", "urgent"]),
            ("invalid-scope", ["--fail-on-scope", "runtime,unknown"]),
            ("duplicate-scope", ["--fail-on-scope", "runtime,runtime"]),
            ("empty-scope", ["--fail-on-scope", "runtime,"]),
            ("all-mixed-scope", ["--fail-on-scope", "all,test"]),
            ("unknown-option", ["--unknown", "value"]),
        ):
            self.cli(name, ["scan", "fixtures/affected", *args], 2)
        for name, args in (
            ("sbom-output-missing", ["--output"]),
            ("sbom-output-empty", ["--output", ""]),
            ("sbom-output-duplicate", ["--output", "unused.json", "--output", "unused.json"]),
            ("sbom-unknown-option", ["--format", "json"]),
        ):
            self.cli(name, ["sbom", "fixtures/affected", *args], 2)
        self.cli("output-directory", ["scan", "fixtures/affected", "--output", self.relative(self.output)], 2)
        self.cli("output-missing-parent", ["scan", "fixtures/affected", "--output", self.relative(self.output / "absent-parent/report.json")], 2)
        self.cli("empty-scan-path", ["scan", ""], 2)

    def input_protection(self):
        with tempfile.TemporaryDirectory(prefix=".acceptance-tmp-", dir=ROOT) as directory:
            temporary = Path(directory)
            self.replacements.insert(0, (temporary.name, "<temporary>"))
            project = temporary / "project"
            project.mkdir()
            (temporary / "aliases").mkdir()
            inputs = {
                "database": temporary / "advisories.json",
                "policy": temporary / "policy.json",
                "baseline": temporary / "baseline.json",
                "manifest": project / "moon.mod.json",
            }
            sources = {
                "database": ROOT / "advisories.json",
                "policy": ROOT / "fixtures/policy/high-gate.json",
                "baseline": ROOT / "fixtures/baseline/empty.json",
                "manifest": ROOT / "fixtures/affected/moon.mod.json",
            }
            original = {key: source.read_bytes() for key, source in sources.items()}
            for key, path in inputs.items():
                path.write_bytes(original[key])
            args = ["scan", self.relative(project), "--db", self.relative(inputs["database"]), "--policy", self.relative(inputs["policy"]), "--baseline", self.relative(inputs["baseline"])]

            def unchanged(record):
                for key, path in inputs.items():
                    actual = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else "missing"
                    expected = hashlib.sha256(original[key]).hexdigest()
                    self.check(record, f"{key} input bytes are unchanged", actual == expected, actual, expected)
                    if actual != expected:
                        path.write_bytes(original[key])

            for key, path in inputs.items():
                parent = self.relative(path.parent)
                aliases = {"dot": f"{parent}/./{path.name}", "parent": f"{self.relative(temporary)}/aliases/../{path.relative_to(temporary).as_posix()}"}
                for alias_name, alias in aliases.items():
                    for option in ("--output", "--baseline-output"):
                        record = self.cli(f"protect-{key}-{alias_name}-{option[2:]}", [*args, option, alias], 2)
                        unchanged(record)
                for option in ("--output", "--baseline-output"):
                    record = self.cli(f"protect-{key}-exact-{option[2:]}", [*args, option, self.relative(path)], 2)
                    unchanged(record)
            for alias_name, alias in (
                ("dot", f"{self.relative(temporary)}/./combined.json"),
                ("parent", f"{self.relative(temporary)}/aliases/../combined.json"),
            ):
                combined = temporary / "combined.json"
                record = self.cli("protect-report-baseline-" + alias_name, [*args, "--output", self.relative(combined), "--baseline-output", alias], 2)
                self.check(record, "conflicting output is not created", not combined.exists())
                unchanged(record)
                if combined.exists():
                    combined.unlink()
            for alias in (f"{self.relative(project)}/./moon.mod.json", f"{self.relative(temporary)}/aliases/../project/moon.mod.json"):
                record = self.cli("protect-sbom-manifest-" + ("parent" if "/../" in alias else "dot"), ["sbom", self.relative(project), "--output", alias], 2)
                unchanged(record)
            self.link_protection(temporary, project, inputs, args, unchanged)

            empty = temporary / "empty"
            empty.mkdir()
            wrong = temporary / "wrong"
            wrong.mkdir()
            (wrong / "notmoon.mod.json").write_bytes(original["manifest"])
            (wrong / "xmoon.mod").write_text('name = "fixture/wrong"\nimport { "example/insecure-http@0.1.5" }\n', encoding="utf-8")
            for command in ("scan", "sbom"):
                for name, path in (("empty-directory", empty), ("wrong-manifest-directory", wrong), ("wrong-json-name", wrong / "notmoon.mod.json"), ("wrong-modern-name", wrong / "xmoon.mod")):
                    self.cli(command + "-" + name, [command, self.relative(path)], 2)
            self.cli("direct-manifest-scan", ["scan", self.relative(inputs["manifest"]), "--db", "advisories.json"], 1)
            self.cli("direct-manifest-sbom", ["sbom", self.relative(inputs["manifest"])], 0)
            self.dynamic_scopes(temporary)

    def dynamic_scopes(self, temporary):
        def write_json(path, value):
            path.write_text(json.dumps(value), encoding="utf-8")

        def database(path, packages):
            write_json(path, {
                "schema_version": "1",
                "advisories": [
                    {
                        "id": "MV-DYNAMIC-" + name.rsplit("/", 1)[-1].upper(),
                        "package_name": name,
                        "affected": "*",
                        "severity": "high",
                        "summary": "Synthetic acceptance fixture",
                        "fixed_version": "",
                        "references": ["https://example.invalid/dynamic-fixture"],
                    }
                    for name in packages
                ],
            })

        legacy = temporary / "legacy-scopes"
        legacy.mkdir()
        packages = ["legacy/runtime", "legacy/test", "legacy/wb", "legacy/multi"]
        write_json(legacy / "moon.mod.json", {"name": "fixture/legacy-scopes", "import": dict.fromkeys(packages, "1.0.0")})
        write_json(legacy / "moon.pkg.json", {
            "import": ["legacy/runtime", {"path": "legacy/multi/core", "alias": "multi"}],
            "test-import": [{"path": "legacy/test/check", "alias": "checks"}, "legacy/multi/testing"],
            "wbtest-import": ["legacy/wb/private", {"path": "legacy/multi/private", "alias": "internal"}],
        })
        db = temporary / "legacy-advisories.json"
        database(db, packages)
        record, report = self.json_scan("legacy-package-scopes", self.relative(legacy), 1, ["--fail-on-scope", "runtime"], self.relative(db))
        self.expect_policy(record, report, 2, 2, ["runtime"])
        dependencies = {dep.get("name"): dep for dep in report.get("dependencies", [])}
        self.check(record, "legacy arrays annotate declared module versions", {name: dep.get("version") for name, dep in dependencies.items()} == dict.fromkeys(packages, "1.0.0"))
        self.check(record, "legacy import fields retain their distinct scopes", {name: set(dep.get("scopes", [])) for name, dep in dependencies.items()} == {
            "legacy/runtime": {"runtime"}, "legacy/test": {"test"}, "legacy/wb": {"wbtest"}, "legacy/multi": {"runtime", "test", "wbtest"},
        })
        self.check(record, "legacy object aliases remain attached to their module", dependencies.get("legacy/test", {}).get("aliases") == ["checks"] and dependencies.get("legacy/multi", {}).get("aliases") == ["internal", "multi", "testing"])

        modules = temporary / "nested-module-scopes"
        nested = modules / "nested"
        nested.mkdir(parents=True)
        (modules / "moon.mod").write_text('name = "fixture/root"\nimport { "example/shared@1.0.0" }\n', encoding="utf-8")
        (modules / "moon.pkg").write_text('import { "example/shared/api" }\n', encoding="utf-8")
        (nested / "moon.mod").write_text('name = "fixture/nested"\nimport { "example/shared@2.0.0" }\n', encoding="utf-8")
        (nested / "moon.pkg").write_text('import { "example/shared/checks" } for "test"\n', encoding="utf-8")
        db = temporary / "nested-advisories.json"
        database(db, ["example/shared"])
        for selected in ("runtime", "test"):
            record, report = self.json_scan("nested-module-" + selected, self.relative(modules), 1, ["--fail-on-scope", selected], self.relative(db))
            self.expect_policy(record, report, 1, 1, [selected])
            self.check(record, "nested versions retain their own module's usage scopes", {dep.get("version"): dep.get("scopes") for dep in report.get("dependencies", [])} == {"1.0.0": ["runtime"], "2.0.0": ["test"]})
            self.check(record, "both versions remain visible as conflict evidence", len(report.get("findings", [])) == 2 and len(report.get("conflicts", [])) == 1 and report["conflicts"][0].get("versions") == ["1.0.0", "2.0.0"])

    def link_protection(self, temporary, project, inputs, args, unchanged):
        for kind in ("hardlink", "symlink"):
            for key, source in inputs.items():
                link = temporary / f"{kind}-{key}.json"
                try:
                    if kind == "hardlink":
                        os.link(source, link)
                    else:
                        link.symlink_to(source)
                except (OSError, NotImplementedError) as error:
                    self.skipped.append({"name": f"{kind}-{key}", "reason": f"link creation unavailable: {type(error).__name__}, errno={getattr(error, 'errno', None)}, winerror={getattr(error, 'winerror', None)}"})
                    continue
                try:
                    for option in ("--output", "--baseline-output"):
                        record = self.cli(f"protect-{kind}-{key}-{option[2:]}", [*args, option, self.relative(link)], 2)
                        unchanged(record)
                finally:
                    link.unlink()
        for name, target in (("cycle", None), ("outside", project)):
            linked_project = temporary / ("directory-link-" + name)
            linked_project.mkdir()
            shutil.copyfile(inputs["manifest"], linked_project / "moon.mod.json")
            link = linked_project / "linked"
            try:
                link.symlink_to(target or linked_project, target_is_directory=True)
            except (OSError, NotImplementedError) as error:
                self.skipped.append({"name": "directory-symlink-" + name, "reason": f"link creation unavailable: {type(error).__name__}, errno={getattr(error, 'errno', None)}, winerror={getattr(error, 'winerror', None)}"})
                continue
            try:
                for command in ("scan", "sbom"):
                    self.cli(command + "-directory-symlink-" + name, [command, self.relative(linked_project)], 2, timeout=5)
                for command in ("scan", "sbom"):
                    self.cli(command + "-root-symlink-" + name, [command, self.relative(link)], 2, timeout=5)
            finally:
                link.unlink()

    def finish(self, error=None):
        failed = [record["name"] for record in self.commands if not all(item["passed"] for item in record["assertions"])]
        reproduce = ["python", "scripts/acceptance.py", "--output", self.clean(self.relative(self.output))]
        if self.moon != "moon":
            reproduce.extend(["--moon", self.clean(self.moon)])
        if self.timeout != 180:
            reproduce.extend(["--timeout", str(self.timeout)])
        summary = {
            "schema_version": 1,
            "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "platform": platform.system(),
            "python_version": platform.python_version(),
            "reproduce": reproduce,
            "passed": not failed and error is None,
            "command_count": len(self.commands),
            "assertion_count": sum(len(record["assertions"]) for record in self.commands),
            "failed_commands": failed,
            "skipped": self.skipped,
            "artifacts": sorted(set(self.artifacts)),
            "commands": self.commands,
        }
        if error is not None:
            summary["error"] = self.clean(str(error))
        if os.environ.get("MOON_HOME"):
            summary["environment"] = {"MOON_HOME": self.clean(os.environ["MOON_HOME"])}
        path = self.output / "summary.json"
        path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"{'PASS' if summary['passed'] else 'FAIL'}: {len(self.commands)} commands, {summary['assertion_count']} assertions, {len(self.skipped)} skipped link checks")
        if failed:
            print("Failed checks: " + ", ".join(failed))
        print("Summary: " + self.clean(self.relative(path)))
        return 0 if summary["passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default=".acceptance-output", help="artifact directory, relative to the repository by default")
    parser.add_argument("--moon", default="moon", help="MoonBit moon executable (default: moon on PATH)")
    parser.add_argument("--timeout", type=int, default=180, help="timeout in seconds for each build command (default: 180)")
    options = parser.parse_args()
    if options.timeout < 1:
        parser.error("--timeout must be positive")
    output = Path(options.output)
    if not output.is_absolute():
        output = ROOT / output
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    acceptance = Acceptance(output, options.moon, options.timeout)
    try:
        if acceptance.build():
            acceptance.fixtures()
            acceptance.input_protection()
        return acceptance.finish()
    except Exception as error:
        return acceptance.finish(error)


if __name__ == "__main__":
    sys.exit(main())
