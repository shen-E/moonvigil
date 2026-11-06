///|
test "parses a MoonBit JSON manifest" {
  let dependencies = @moonvigil.parse_manifest(
    "{\"import\":{\"example/insecure-http\":\"0.1.5\",\"safe/package\":\"1.0.0\"}}",
    source="fixture/moon.mod.json",
  )
  assert_eq(dependencies.length(), 2)
  assert_eq(dependencies[0].name, "example/insecure-http")
}

///|
test "normalizes duplicate declarations with a stable evidence location" {
  let declarations : Array[@moonvigil.Dependency] = [
    Dependency(name="safe/package", version="1.0.0", source="z/moon.pkg.json"),
    Dependency(
      name="example/insecure-http",
      version="0.1.5",
      source="b/moon.pkg.json",
    ),
    Dependency(
      name="example/insecure-http",
      version="0.1.5",
      source="a/moon.mod.json",
    ),
    Dependency(
      name="example/insecure-http",
      version="0.2.0",
      source="a/moon.mod.json",
    ),
  ]
  let inventory = @moonvigil.inventory_from_dependencies(declarations)
  let reversed = @moonvigil.inventory_from_dependencies([
    declarations[3],
    declarations[2],
    declarations[1],
    declarations[0],
  ])
  assert_eq(inventory.dependencies.length(), 3)
  assert_eq(inventory.dependencies[0].name, "example/insecure-http")
  assert_eq(inventory.dependencies[0].version, "0.1.5")
  assert_true(
    inventory.dependencies.any(fn(dependency) {
      dependency.name == "example/insecure-http" &&
      dependency.version == "0.1.5" &&
      dependency.source == "a/moon.mod.json"
    }),
  )
  assert_eq(inventory, reversed)
}

///|
test "accepts a manifest without an import field" {
  let dependencies = @moonvigil.parse_manifest(
    "{\"name\":\"fixture/no-import\"}",
    source="fixture/moon.mod.json",
  )
  assert_eq(dependencies.length(), 0)
}

///|
test "matches inclusive and exclusive range boundaries" {
  assert_true(@moonvigil.match_version("1.2.3", ">=1.2.3 <2.0.0") is Affected)
  assert_true(
    @moonvigil.match_version("1.2.2", ">=1.2.3 <2.0.0") is NotAffected,
  )
  assert_true(
    @moonvigil.match_version("2.0.0", ">=1.2.3 <2.0.0") is NotAffected,
  )
  assert_true(
    @moonvigil.match_version("1.0.0", ">1.0.0 <=1.2.0") is NotAffected,
  )
  assert_true(@moonvigil.match_version("1.0.1", ">1.0.0 <=1.2.0") is Affected)
  assert_true(@moonvigil.match_version("1.2.0", ">1.0.0 <=1.2.0") is Affected)
  assert_true(
    @moonvigil.match_version("1.2.1", ">1.0.0 <=1.2.0") is NotAffected,
  )
}

///|
test "matches exact and union ranges" {
  let affected = "=1.0.0 || >=2.0.0 <2.1.0"
  assert_true(@moonvigil.match_version("1.0.0", affected) is Affected)
  assert_true(@moonvigil.match_version("1.5.0", affected) is NotAffected)
  assert_true(@moonvigil.match_version("2.0.3", affected) is Affected)
  assert_true(@moonvigil.match_version("2.1.0", affected) is NotAffected)
  assert_true(@moonvigil.match_version("3.0.0", "3.0.0") is Affected)
}

///|
test "keeps unsupported versions and ranges uncomparable" {
  assert_true(@moonvigil.match_version("1.0.0-alpha", "*") is Uncomparable)
  assert_true(@moonvigil.match_version("1.0.0+build.7", "*") is Uncomparable)
  assert_true(@moonvigil.match_version("1.0", ">=1.0.0") is Uncomparable)
  assert_true(@moonvigil.match_version("1.0.0", ">=1.0") is Uncomparable)
  assert_true(@moonvigil.match_version("1.0.0", ">=1.0.0 || ") is Uncomparable)
}

///|
test "rejects version component overflow and non-canonical leading zeros" {
  assert_true(
    @moonvigil.match_version("2147483647.0.0", "=2147483647.0.0") is Affected,
  )
  assert_true(@moonvigil.match_version("2147483648.0.0", "*") is Uncomparable)
  assert_true(@moonvigil.match_version("99999999999.0.0", "*") is Uncomparable)
  assert_true(@moonvigil.match_version("01.0.0", "*") is Uncomparable)
  assert_true(
    @moonvigil.match_version("1.0.0", ">=2147483648.0.0") is Uncomparable,
  )
}

///|
test "matches an affected dependency and leaves a fixed version clean" {
  let database = @moonvigil.parse_database(
    "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-1\",\"package_name\":\"example/insecure-http\",\"affected\":\">=0.1.0 <0.2.0\",\"severity\":\"high\",\"summary\":\"fixture\",\"fixed_version\":\"0.2.0\",\"references\":[\"https://example.invalid/MV-1\"]}]}",
  )
  let report = @moonvigil.scan(
    [
      Dependency(
        name="example/insecure-http",
        version="0.1.5",
        source="fixture",
      ),
      Dependency(
        name="example/insecure-http",
        version="0.2.0",
        source="fixture",
      ),
    ],
    database,
  )
  assert_eq(report.findings.length(), 1)
  assert_true(@moonvigil.report_json(report).contains("MV-1"))
  assert_true(@moonvigil.report_sarif(report).contains("2.1.0"))
}

///|
test "baseline snapshots sort and deduplicate affected dependency keys" {
  let database = @moonvigil.parse_database(
    "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-B\",\"package_name\":\"example/b\",\"affected\":\"*\",\"severity\":\"high\",\"summary\":\"fixture\",\"fixed_version\":\"\",\"references\":[\"https://example.invalid/MV-B\"]},{\"id\":\"MV-A\",\"package_name\":\"example/a\",\"affected\":\"*\",\"severity\":\"low\",\"summary\":\"fixture\",\"fixed_version\":\"\",\"references\":[\"https://example.invalid/MV-A\"]}]}",
  )
  let report = @moonvigil.scan(
    [
      Dependency(name="example/b", version="1.0.0", source="z/moon.mod"),
      Dependency(name="example/a", version="2.0.0", source="a/moon.mod"),
      Dependency(name="example/a", version="2.0.0", source="b/moon.mod"),
      Dependency(name="example/b", version="main", source="c/moon.mod"),
    ],
    database,
  )
  let baseline = @moonvigil.baseline_from_report(report)
  assert_eq(baseline.entries.length(), 2)
  assert_eq(baseline.entries[0].advisory_id, "MV-A")
  assert_eq(baseline.entries[0].package_name, "example/a")
  assert_eq(baseline.entries[1].advisory_id, "MV-B")
  assert_eq(baseline.schema_version, "2")
  assert_eq(baseline.entries[0].affected, Some("*"))
  assert_eq(baseline.entries[0].severity, Some("low"))
  assert_eq(baseline.entries[0].fixed_version, Some(""))
  let serialized = @moonvigil.baseline_json(baseline)
  assert_true(serialized.contains("\"schema_version\": \"2\""))
  assert_false(serialized.contains("moon.mod"))
  assert_eq(@moonvigil.parse_baseline(serialized), baseline)
  assert_eq(
    @moonvigil.parse_baseline(
      @fs.read_file_to_string("fixtures/baseline/initial.json"),
    ).entries.length(),
    1,
  )
  assert_eq(
    @moonvigil.parse_baseline(
      @fs.read_file_to_string("fixtures/baseline/valid-v2.json"),
    ).schema_version,
    "2",
  )
  let legacy = @moonvigil.parse_baseline(
    @fs.read_file_to_string("fixtures/baseline/initial.json"),
  )
  assert_eq(legacy.entries[0].affected, None)
  assert_false(@moonvigil.baseline_json(legacy).contains("\"affected\""))
}

///|
test "accepts an empty baseline and rejects invalid schema or entry fields" {
  assert_eq(
    @moonvigil.parse_baseline("{\"schema_version\":\"1\",\"entries\":[]}").entries.length(),
    0,
  )
  assert_eq(
    @moonvigil.parse_baseline(
      @fs.read_file_to_string("fixtures/baseline/empty.json"),
    ).entries.length(),
    0,
  )
  let invalid = [
    "{\"schema_version\":\"3\",\"entries\":[]}", "{\"schema_version\":\"1\"}", "{\"schema_version\":\"1\",\"entries\":[{}]}",
    "{\"schema_version\":\"1\",\"entries\":[{\"advisory_id\":7,\"package_name\":\"example/a\",\"version\":\"1.0.0\"}]}",
    "{\"schema_version\":\"1\",\"entries\":[{\"advisory_id\":\"MV-1\",\"package_name\":\"example/a\",\"version\":\"main\"}]}",
    "{\"schema_version\":\"1\",\"entries\":[{\"advisory_id\":\"MV-1\",\"package_name\":\"example/a\",\"version\":\"1.0.0\"},{\"advisory_id\":\"MV-1\",\"package_name\":\"example/a\",\"version\":\"1.0.0\"}]}",
  ]
  for text in invalid {
    try @moonvigil.parse_baseline(text) catch {
      @moonvigil.BaselineValidationError::UnsupportedBaselineSchemaVersion(_) =>
        ()
      @moonvigil.BaselineValidationError::InvalidBaselineField(
        field=_,
        reason=_
      ) => ()
      @moonvigil.BaselineValidationError::InvalidBaselineEntry(
        index=_,
        field=_,
        reason=_
      ) => ()
      @moonvigil.BaselineValidationError::DuplicateBaselineEntry(
        index=_,
        advisory_id=_
      ) => ()
      _ => fail("expected a baseline validation error")
    } noraise {
      _ => fail("expected invalid baseline to be rejected")
    }
  }
  try
    @moonvigil.parse_baseline(
      @fs.read_file_to_string("fixtures/baseline/unsupported-version.json"),
    )
  catch {
    @moonvigil.BaselineValidationError::UnsupportedBaselineSchemaVersion("3") =>
      ()
    _ => fail("expected unsupported baseline schema")
  } noraise {
    _ => fail("expected invalid baseline schema to be rejected")
  }
  try
    @moonvigil.parse_baseline(
      @fs.read_file_to_string("fixtures/baseline/duplicate-entry.json"),
    )
  catch {
    @moonvigil.BaselineValidationError::DuplicateBaselineEntry(
      index=1,
      advisory_id=_
    ) => ()
    _ => fail("expected duplicate baseline entry")
  } noraise {
    _ => fail("expected duplicate baseline entry to be rejected")
  }
}

///|
test "rejects malformed v2 baseline risk evidence with field diagnostics" {
  let invalid = [
    "fixtures/baseline/invalid-v2-missing.json", "fixtures/baseline/invalid-v2-range.json",
    "fixtures/baseline/invalid-v2-severity.json", "fixtures/baseline/invalid-v2-fixed.json",
    "fixtures/baseline/invalid-v2-type.json",
  ]
  for path in invalid {
    try @moonvigil.parse_baseline(@fs.read_file_to_string(path)) catch {
      @moonvigil.BaselineValidationError::InvalidBaselineEntry(
        index=0,
        field=_,
        reason=_
      ) => ()
      _ => fail("expected a schema-v2 field validation error")
    } noraise {
      _ => fail("expected malformed schema-v2 evidence to be rejected")
    }
  }
}

///|
test "validates baselines built directly by library callers" {
  let invalid : @moonvigil.ScanBaseline = @json.from_json(
    @json.parse(
      "{\"schema_version\":\"1\",\"entries\":[{\"advisory_id\":\"MV-1\",\"package_name\":\"example/a\",\"version\":\"1.0.0-alpha\"}]}",
    ),
  )
  try @moonvigil.validate_baseline(invalid) catch {
    @moonvigil.BaselineValidationError::InvalidBaselineEntry(
      index=0,
      field="version",
      reason=_
    ) => ()
    _ => fail("expected direct baseline validation error")
  } noraise {
    _ => fail("expected direct baseline validation to reject a pre-release")
  }
}

///|
test "compares exact baseline keys and serializes every comparison state" {
  let database = @moonvigil.parse_database(
    "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-EXISTING\",\"package_name\":\"example/current\",\"affected\":\"*\",\"severity\":\"high\",\"summary\":\"existing fixture\",\"fixed_version\":\"\",\"references\":[\"https://example.invalid/MV-EXISTING\"]},{\"id\":\"MV-NEW\",\"package_name\":\"example/new\",\"affected\":\"*\",\"severity\":\"critical\",\"summary\":\"new fixture\",\"fixed_version\":\"\",\"references\":[\"https://example.invalid/MV-NEW\"]},{\"id\":\"MV-UNKNOWN\",\"package_name\":\"example/unknown\",\"affected\":\"*\",\"severity\":\"medium\",\"summary\":\"unknown fixture\",\"fixed_version\":\"\",\"references\":[\"https://example.invalid/MV-UNKNOWN\"]}]}",
  )
  let report = @moonvigil.scan(
    [
      Dependency(name="example/current", version="1.0.0", source="one/moon.mod"),
      Dependency(name="example/new", version="2.0.0", source="two/moon.mod"),
      Dependency(
        name="example/unknown",
        version="main",
        source="three/moon.mod",
      ),
    ],
    database,
  )
  let compared = @moonvigil.apply_baseline(
    report,
    @moonvigil.parse_baseline(
      "{\"schema_version\":\"1\",\"entries\":[{\"advisory_id\":\"MV-EXISTING\",\"package_name\":\"example/current\",\"version\":\"1.0.0\"},{\"advisory_id\":\"MV-NEW\",\"package_name\":\"example/new\",\"version\":\"1.0.0\"},{\"advisory_id\":\"MV-REMOVED\",\"package_name\":\"example/removed\",\"version\":\"3.0.0\"}]}",
    ),
  )
  assert_eq(compared.schema_version, "6")
  assert_true(compared.findings[0].baseline_status is Some(Existing))
  assert_true(compared.findings[1].baseline_status is Some(New))
  assert_eq(compared.uncomparable[0].baseline_status, None)
  let summary = compared.baseline.unwrap()
  assert_eq(summary.snapshot_entries, 3)
  assert_eq(summary.new_findings, 1)
  assert_eq(summary.existing_findings, 1)
  assert_eq(summary.updated_findings, 0)
  assert_true(summary.legacy_snapshot)
  assert_eq(summary.no_longer_detected.length(), 2)
  assert_eq(summary.no_longer_detected[0].advisory_id, "MV-NEW")
  assert_eq(summary.no_longer_detected[1].advisory_id, "MV-REMOVED")
  let json = @moonvigil.report_json(compared)
  let terminal = @moonvigil.report_terminal(compared)
  let sarif = @moonvigil.report_sarif(compared)
  assert_true(json.contains("\"schema_version\": \"6\""))
  assert_true(json.contains("\"legacy_snapshot\": true"))
  assert_true(json.contains("\"baseline_status\": \"Existing\""))
  assert_true(terminal.contains("[existing]"))
  assert_true(terminal.contains("[new]"))
  assert_true(
    terminal.contains("schema-v1 baseline has no advisory risk evidence"),
  )
  assert_true(terminal.contains("no longer detected: MV-REMOVED"))
  assert_true(sarif.contains("\"baselineState\": \"unchanged\""))
  assert_true(sarif.contains("\"baselineState\": \"new\""))
  assert_true(sarif.contains("\"legacySnapshot\": true"))
  assert_true(sarif.contains("\"moonvigilBaseline\""))
  let evaluated = @moonvigil.evaluate_policy(
    compared,
    @moonvigil.empty_policy(fail_on="high"),
    None,
    today="2026-09-25",
  )
  assert_true(evaluated.report.findings[0].baseline_status is Some(Existing))
}

///|
test "detects risk evidence updates and gates them using current severity" {
  let dependency = [
    @moonvigil.Dependency::Dependency(
      name="example/risk",
      version="1.0.0",
      source="moon.mod",
    ),
  ]
  let old_database = @moonvigil.parse_database(
    "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-RISK\",\"package_name\":\"example/risk\",\"affected\":\"*\",\"severity\":\"medium\",\"summary\":\"risk fixture\",\"fixed_version\":\"2.0.0\",\"references\":[\"https://example.invalid/MV-RISK\"]}]}",
  )
  let old_snapshot = @moonvigil.baseline_from_report(
    @moonvigil.scan(dependency, old_database),
  )
  assert_eq(old_snapshot.schema_version, "2")
  let unchanged = @moonvigil.apply_baseline(
    @moonvigil.scan(dependency, old_database),
    old_snapshot,
  )
  assert_true(unchanged.findings[0].baseline_status is Some(Existing))
  let higher_database = @moonvigil.parse_database(
    "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-RISK\",\"package_name\":\"example/risk\",\"affected\":\">=1.0.0 <2.0.0\",\"severity\":\"high\",\"summary\":\"risk fixture\",\"fixed_version\":\"2.0.0\",\"references\":[\"https://example.invalid/MV-RISK\"]}]}",
  )
  let updated = @moonvigil.apply_baseline(
    @moonvigil.scan(dependency, higher_database),
    old_snapshot,
  )
  assert_eq(updated.schema_version, "6")
  assert_true(updated.findings[0].baseline_status is Some(Updated))
  assert_eq(updated.baseline.unwrap().updated_findings, 1)
  let json = @moonvigil.report_json(updated)
  assert_true(json.contains("\"baseline_status\": \"Updated\""))
  assert_true(json.contains("\"updated_findings\": 1"))
  assert_true(@moonvigil.report_terminal(updated).contains("[updated]"))
  assert_true(
    @moonvigil.report_sarif(updated).contains("\"baselineState\": \"updated\""),
  )
  let high_gate = @moonvigil.evaluate_policy(
    updated,
    @moonvigil.empty_policy(fail_on="high"),
    None,
    today="2026-09-25",
  )
  assert_true(high_gate.should_fail)
  assert_eq(high_gate.report.policy.unwrap().blocking_findings, 1)

  let lower_database = @moonvigil.parse_database(
    "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-RISK\",\"package_name\":\"example/risk\",\"affected\":\"*\",\"severity\":\"low\",\"summary\":\"risk fixture\",\"fixed_version\":\"2.0.0\",\"references\":[\"https://example.invalid/MV-RISK\"]}]}",
  )
  let lower_update = @moonvigil.apply_baseline(
    @moonvigil.scan(dependency, lower_database),
    old_snapshot,
  )
  assert_true(lower_update.findings[0].baseline_status is Some(Updated))
  let lower_gate = @moonvigil.evaluate_policy(
    lower_update,
    @moonvigil.empty_policy(fail_on="high"),
    None,
    today="2026-09-25",
  )
  assert_false(lower_gate.should_fail)
  assert_eq(lower_gate.report.policy.unwrap().blocking_findings, 0)

  let fixed_version_database = @moonvigil.parse_database(
    "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-RISK\",\"package_name\":\"example/risk\",\"affected\":\"*\",\"severity\":\"medium\",\"summary\":\"risk fixture\",\"fixed_version\":\"3.0.0\",\"references\":[\"https://example.invalid/MV-RISK\"]}]}",
  )
  let fixed_update = @moonvigil.apply_baseline(
    @moonvigil.scan(dependency, fixed_version_database),
    old_snapshot,
  )
  assert_true(fixed_update.findings[0].baseline_status is Some(Updated))
}

///|
test "accepts a complete advisory database and an empty database" {
  let complete = @moonvigil.parse_database(
    "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-VALID\",\"package_name\":\"example/insecure-http\",\"affected\":\">=0.1.0 <0.2.0\",\"severity\":\"high\",\"summary\":\"fixture\",\"fixed_version\":\"0.2.0\",\"references\":[\"https://example.invalid/MV-VALID\"]}]}",
  )
  @moonvigil.validate_database(complete)
  let empty = @moonvigil.parse_database(
    "{\"schema_version\":\"1\",\"advisories\":[]}",
  )
  assert_eq(empty.advisories.length(), 0)
}

///|
test "scan rejects an advisory database constructed outside the parser" {
  let database : @moonvigil.AdvisoryDatabase = @json.from_json(
    @json.parse("{\"schema_version\":\"2\",\"advisories\":[]}"),
  )
  try @moonvigil.scan([], database) catch {
    @moonvigil.DatabaseValidationError::UnsupportedSchemaVersion("2") => ()
    _ => fail("scan must validate directly constructed databases")
  } noraise {
    _ => fail("scan must validate directly constructed databases")
  }
}

///|
test "validates reference authorities and rejects malformed URL endpoints" {
  @moonvigil.validate_database(
    database_with_reference("https://example.invalid/advisory"),
  )
  @moonvigil.validate_database(
    database_with_reference("http://localhost:8080/path"),
  )
  @moonvigil.validate_database(
    database_with_reference("https://[2001:db8::1]:443/advisory"),
  )
  let invalid_references = [
    "https://", "http:///path", "https://:443/advisory", "https://example.invalid:99999/advisory",
    "ftp://example.invalid/advisory",
  ]
  for reference in invalid_references {
    try @moonvigil.validate_database(database_with_reference(reference)) catch {
      @moonvigil.DatabaseValidationError::InvalidAdvisory(
        index=0,
        id="MV-URL",
        field="references",
        reason=_
      ) => ()
      _ => fail("expected invalid reference diagnostic")
    } noraise {
      _ => fail("expected invalid reference diagnostic")
    }
  }
}

///|
fn database_with_reference(
  reference : String,
) -> @moonvigil.AdvisoryDatabase raise {
  @moonvigil.parse_database(
    "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-URL\",\"package_name\":\"example/package\",\"affected\":\"1.0.0\",\"severity\":\"low\",\"summary\":\"reference validation fixture\",\"fixed_version\":\"\",\"references\":[\"\{reference}\"]}]}",
  )
}

///|
test "rejects unsupported schema versions" {
  try
    @moonvigil.parse_database("{\"schema_version\":\"2\",\"advisories\":[]}")
  catch {
    @moonvigil.DatabaseValidationError::UnsupportedSchemaVersion("2") => ()
    _ => fail("expected schema validation error")
  } noraise {
    _ => fail("expected schema validation error")
  }
}

///|
test "reports every missing advisory field with its stable location" {
  try
    @moonvigil.parse_database(
      "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-MISSING\",\"package_name\":\"example/package\"}]}",
    )
  catch {
    @moonvigil.DatabaseValidationError::MultipleInvalidAdvisories(issues) => {
      assert_eq(issues.length(), 5)
      assert_true(
        issues.all(fn(issue) {
          issue.index == 0 &&
          issue.id == "MV-MISSING" &&
          issue.reason == "is required"
        }),
      )
      assert_true(issues.any(fn(issue) { issue.field == "affected" }))
      assert_true(issues.any(fn(issue) { issue.field == "references" }))
    }
    _ => fail("expected aggregated missing-field diagnostics")
  } noraise {
    _ => fail("expected aggregated missing-field diagnostics")
  }
}

///|
test "aggregates independent semantic advisory errors" {
  try
    @moonvigil.parse_database(
      "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-BAD\",\"package_name\":\"\",\"affected\":\">=1.0\",\"severity\":\"urgent\",\"summary\":\"\",\"fixed_version\":\"2.0\",\"references\":[\"https://\"]}]}",
    )
  catch {
    @moonvigil.DatabaseValidationError::MultipleInvalidAdvisories(issues) => {
      assert_eq(issues.length(), 6)
      assert_true(issues.any(fn(issue) { issue.field == "package_name" }))
      assert_true(issues.any(fn(issue) { issue.field == "severity" }))
      assert_true(issues.any(fn(issue) { issue.field == "references" }))
    }
    _ => fail("expected aggregated semantic diagnostics")
  } noraise {
    _ => fail("expected aggregated semantic diagnostics")
  }
}

///|
test "reports wrong advisory field types before JSON decoding" {
  try
    @moonvigil.parse_database(
      "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-TYPES\",\"package_name\":\"example/package\",\"affected\":\"1.0.0\",\"severity\":7,\"summary\":false,\"fixed_version\":\"\",\"references\":\"https://example.invalid\"}]}",
    )
  catch {
    @moonvigil.DatabaseValidationError::MultipleInvalidAdvisories(issues) => {
      assert_eq(issues.length(), 3)
      assert_true(
        issues.any(fn(issue) {
          issue.field == "severity" && issue.reason == "must be a string"
        }),
      )
      assert_true(
        issues.any(fn(issue) {
          issue.field == "summary" && issue.reason == "must be a string"
        }),
      )
      assert_true(
        issues.any(fn(issue) {
          issue.field == "references" &&
          issue.reason == "must be an array of strings"
        }),
      )
    }
    _ => fail("expected field-type diagnostics")
  } noraise {
    _ => fail("expected field-type diagnostics")
  }
}

///|
test "rejects missing database-level schema metadata with a field diagnostic" {
  try @moonvigil.parse_database("{\"advisories\":[]}") catch {
    @moonvigil.DatabaseValidationError::InvalidDatabaseField(
      field="schema_version",
      reason="is required"
    ) => ()
    _ => fail("expected root-field diagnostic")
  } noraise {
    _ => fail("expected root-field diagnostic")
  }
}

///|
test "rejects invalid advisory fields with stable evidence" {
  let cases = [
    (
      "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"\",\"package_name\":\"example/a\",\"affected\":\"1.0.0\",\"severity\":\"low\",\"summary\":\"fixture\",\"fixed_version\":\"\",\"references\":[\"https://example.invalid/a\"]}]}",
      "id", 0,
    ),
    (
      "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-PACKAGE\",\"package_name\":\"\",\"affected\":\"1.0.0\",\"severity\":\"low\",\"summary\":\"fixture\",\"fixed_version\":\"\",\"references\":[\"https://example.invalid/a\"]}]}",
      "package_name", 0,
    ),
    (
      "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-SUMMARY\",\"package_name\":\"example/a\",\"affected\":\"1.0.0\",\"severity\":\"low\",\"summary\":\"\",\"fixed_version\":\"\",\"references\":[\"https://example.invalid/a\"]}]}",
      "summary", 0,
    ),
    (
      "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-DUP\",\"package_name\":\"example/a\",\"affected\":\"1.0.0\",\"severity\":\"low\",\"summary\":\"first\",\"fixed_version\":\"\",\"references\":[\"https://example.invalid/a\"]},{\"id\":\"MV-DUP\",\"package_name\":\"example/b\",\"affected\":\"1.0.0\",\"severity\":\"low\",\"summary\":\"second\",\"fixed_version\":\"\",\"references\":[\"https://example.invalid/b\"]}]}",
      "id", 1,
    ),
    (
      "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-SEVERITY\",\"package_name\":\"example/a\",\"affected\":\"1.0.0\",\"severity\":\"urgent\",\"summary\":\"fixture\",\"fixed_version\":\"\",\"references\":[\"https://example.invalid/a\"]}]}",
      "severity", 0,
    ),
    (
      "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-RANGE\",\"package_name\":\"example/a\",\"affected\":\">=1.0\",\"severity\":\"low\",\"summary\":\"fixture\",\"fixed_version\":\"\",\"references\":[\"https://example.invalid/a\"]}]}",
      "affected", 0,
    ),
    (
      "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-FIXED\",\"package_name\":\"example/a\",\"affected\":\"1.0.0\",\"severity\":\"low\",\"summary\":\"fixture\",\"fixed_version\":\"1.0\",\"references\":[\"https://example.invalid/a\"]}]}",
      "fixed_version", 0,
    ),
    (
      "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-REF\",\"package_name\":\"example/a\",\"affected\":\"1.0.0\",\"severity\":\"low\",\"summary\":\"fixture\",\"fixed_version\":\"\",\"references\":[]}]}",
      "references", 0,
    ),
  ]
  for pair in cases {
    let (text, field, expected_index) = pair
    try @moonvigil.parse_database(text) catch {
      @moonvigil.DatabaseValidationError::InvalidAdvisory(
        index=actual_index,
        id=_,
        field=actual,
        reason=_
      ) => {
        assert_eq(actual_index, expected_index)
        assert_eq(actual, field)
      }
      _ => fail("expected advisory validation error")
    } noraise {
      _ => fail("expected advisory validation error")
    }
  }
}

///|
test "reports an uncomparable version without an affected finding" {
  let database = @moonvigil.parse_database(
    "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-2\",\"package_name\":\"example/insecure-http\",\"affected\":\">=0.1.0 <0.2.0\",\"severity\":\"low\",\"summary\":\"fixture\",\"fixed_version\":\"\",\"references\":[\"https://example.invalid/MV-2\"]}]}",
  )
  let report = @moonvigil.scan(
    [Dependency(name="example/insecure-http", version="main", source="fixture")],
    database,
  )
  assert_eq(report.findings.length(), 0)
  assert_eq(report.uncomparable.length(), 1)
}

///|
test "serializes complete affected and uncomparable evidence" {
  let database = @moonvigil.parse_database(
    "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-3\",\"package_name\":\"example/insecure-http\",\"affected\":\">=1.0.0 <2.0.0\",\"severity\":\"high\",\"summary\":\"fixture summary\",\"fixed_version\":\"2.0.0\",\"references\":[\"https://example.invalid/MV-3\"]}]}",
  )
  let report = @moonvigil.scan(
    [
      Dependency(
        name="example/insecure-http",
        version="1.2.3",
        source="fixture/moon.mod.json",
      ),
      Dependency(
        name="example/insecure-http",
        version="main",
        source="fixture/moon.pkg.json",
      ),
    ],
    database,
  )
  let terminal = @moonvigil.report_terminal(report)
  let json = @moonvigil.report_json(report)
  let sarif = @moonvigil.report_sarif(report)
  assert_true(terminal.contains("affected: >=1.0.0 <2.0.0"))
  assert_true(terminal.contains("fixed: 2.0.0"))
  assert_true(terminal.contains("[uncomparable]"))
  assert_eq(report.schema_version, "6")
  assert_true(json.contains("\"schema_version\": \"6\""))
  assert_true(sarif.contains("installedVersion"))
  assert_true(sarif.contains("matchStatus"))
  assert_true(sarif.contains("uncomparable"))
}
