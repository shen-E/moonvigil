///|
test "parses a MoonBit JSON manifest" {
  let dependencies = parse_manifest(
    "{\"import\":{\"example/insecure-http\":\"0.1.5\",\"safe/package\":\"1.0.0\"}}",
    source="fixture/moon.mod.json",
  )
  assert_eq(dependencies.length(), 2)
  assert_eq(dependencies[0].name, "example/insecure-http")
}

///|
test "normalizes duplicate declarations with a stable evidence location" {
  let declarations : Array[Dependency] = [
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
  let inventory = inventory_from_dependencies(declarations)
  let reversed = inventory_from_dependencies([
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
  let dependencies = parse_manifest(
    "{\"name\":\"fixture/no-import\"}",
    source="fixture/moon.mod.json",
  )
  assert_eq(dependencies.length(), 0)
}

///|
test "matches inclusive and exclusive range boundaries" {
  assert_true(match_version("1.2.3", ">=1.2.3 <2.0.0") is Affected)
  assert_true(match_version("1.2.2", ">=1.2.3 <2.0.0") is NotAffected)
  assert_true(match_version("2.0.0", ">=1.2.3 <2.0.0") is NotAffected)
  assert_true(match_version("1.0.0", ">1.0.0 <=1.2.0") is NotAffected)
  assert_true(match_version("1.0.1", ">1.0.0 <=1.2.0") is Affected)
  assert_true(match_version("1.2.0", ">1.0.0 <=1.2.0") is Affected)
  assert_true(match_version("1.2.1", ">1.0.0 <=1.2.0") is NotAffected)
}

///|
test "matches exact and union ranges" {
  let affected = "=1.0.0 || >=2.0.0 <2.1.0"
  assert_true(match_version("1.0.0", affected) is Affected)
  assert_true(match_version("1.5.0", affected) is NotAffected)
  assert_true(match_version("2.0.3", affected) is Affected)
  assert_true(match_version("2.1.0", affected) is NotAffected)
  assert_true(match_version("3.0.0", "3.0.0") is Affected)
}

///|
test "keeps unsupported versions and ranges uncomparable" {
  assert_true(match_version("1.0.0-alpha", "*") is Uncomparable)
  assert_true(match_version("1.0.0+build.7", "*") is Uncomparable)
  assert_true(match_version("1.0", ">=1.0.0") is Uncomparable)
  assert_true(match_version("1.0.0", ">=1.0") is Uncomparable)
  assert_true(match_version("1.0.0", ">=1.0.0 || ") is Uncomparable)
}

///|
test "rejects version component overflow and non-canonical leading zeros" {
  assert_true(match_version("2147483647.0.0", "=2147483647.0.0") is Affected)
  assert_true(match_version("2147483648.0.0", "*") is Uncomparable)
  assert_true(match_version("99999999999.0.0", "*") is Uncomparable)
  assert_true(match_version("01.0.0", "*") is Uncomparable)
  assert_true(match_version("1.0.0", ">=2147483648.0.0") is Uncomparable)
}

///|
test "matches an affected dependency and leaves a fixed version clean" {
  let database = parse_database(
    "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-1\",\"package_name\":\"example/insecure-http\",\"affected\":\">=0.1.0 <0.2.0\",\"severity\":\"high\",\"summary\":\"fixture\",\"fixed_version\":\"0.2.0\",\"references\":[\"https://example.invalid/MV-1\"]}]}",
  )
  let report = scan(
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
  assert_true(report_json(report).contains("MV-1"))
  assert_true(report_sarif(report).contains("2.1.0"))
}

///|
test "accepts a complete advisory database and an empty database" {
  let complete = parse_database(
    "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-VALID\",\"package_name\":\"example/insecure-http\",\"affected\":\">=0.1.0 <0.2.0\",\"severity\":\"high\",\"summary\":\"fixture\",\"fixed_version\":\"0.2.0\",\"references\":[\"https://example.invalid/MV-VALID\"]}]}",
  )
  validate_database(complete)
  let empty = parse_database("{\"schema_version\":\"1\",\"advisories\":[]}")
  assert_eq(empty.advisories.length(), 0)
}

///|
test "scan rejects an advisory database constructed outside the parser" {
  let database : AdvisoryDatabase = @json.from_json(
    @json.parse("{\"schema_version\":\"2\",\"advisories\":[]}"),
  )
  try scan([], database) catch {
    DatabaseValidationError::UnsupportedSchemaVersion("2") => ()
    _ => fail("scan must validate directly constructed databases")
  } noraise {
    _ => fail("scan must validate directly constructed databases")
  }
}

///|
test "validates reference authorities and rejects malformed URL endpoints" {
  validate_database(database_with_reference("https://example.invalid/advisory"))
  validate_database(database_with_reference("http://localhost:8080/path"))
  validate_database(
    database_with_reference("https://[2001:db8::1]:443/advisory"),
  )
  let invalid_references = [
    "https://", "http:///path", "https://:443/advisory", "https://example.invalid:99999/advisory",
    "ftp://example.invalid/advisory",
  ]
  for reference in invalid_references {
    try validate_database(database_with_reference(reference)) catch {
      DatabaseValidationError::InvalidAdvisory(
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
fn database_with_reference(reference : String) -> AdvisoryDatabase raise {
  parse_database(
    "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-URL\",\"package_name\":\"example/package\",\"affected\":\"1.0.0\",\"severity\":\"low\",\"summary\":\"reference validation fixture\",\"fixed_version\":\"\",\"references\":[\"\{reference}\"]}]}",
  )
}

///|
test "rejects unsupported schema versions" {
  try parse_database("{\"schema_version\":\"2\",\"advisories\":[]}") catch {
    DatabaseValidationError::UnsupportedSchemaVersion("2") => ()
    _ => fail("expected schema validation error")
  } noraise {
    _ => fail("expected schema validation error")
  }
}

///|
test "reports every missing advisory field with its stable location" {
  try
    parse_database(
      "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-MISSING\",\"package_name\":\"example/package\"}]}",
    )
  catch {
    DatabaseValidationError::MultipleInvalidAdvisories(issues) => {
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
    parse_database(
      "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-BAD\",\"package_name\":\"\",\"affected\":\">=1.0\",\"severity\":\"urgent\",\"summary\":\"\",\"fixed_version\":\"2.0\",\"references\":[\"https://\"]}]}",
    )
  catch {
    DatabaseValidationError::MultipleInvalidAdvisories(issues) => {
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
    parse_database(
      "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-TYPES\",\"package_name\":\"example/package\",\"affected\":\"1.0.0\",\"severity\":7,\"summary\":false,\"fixed_version\":\"\",\"references\":\"https://example.invalid\"}]}",
    )
  catch {
    DatabaseValidationError::MultipleInvalidAdvisories(issues) => {
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
  try parse_database("{\"advisories\":[]}") catch {
    DatabaseValidationError::InvalidDatabaseField(
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
    try parse_database(text) catch {
      DatabaseValidationError::InvalidAdvisory(
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
  let database = parse_database(
    "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-2\",\"package_name\":\"example/insecure-http\",\"affected\":\">=0.1.0 <0.2.0\",\"severity\":\"low\",\"summary\":\"fixture\",\"fixed_version\":\"\",\"references\":[\"https://example.invalid/MV-2\"]}]}",
  )
  let report = scan(
    [Dependency(name="example/insecure-http", version="main", source="fixture")],
    database,
  )
  assert_eq(report.findings.length(), 0)
  assert_eq(report.uncomparable.length(), 1)
}

///|
test "serializes complete affected and uncomparable evidence" {
  let database = parse_database(
    "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-3\",\"package_name\":\"example/insecure-http\",\"affected\":\">=1.0.0 <2.0.0\",\"severity\":\"high\",\"summary\":\"fixture summary\",\"fixed_version\":\"2.0.0\",\"references\":[\"https://example.invalid/MV-3\"]}]}",
  )
  let report = scan(
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
  let terminal = report_terminal(report)
  let json = report_json(report)
  let sarif = report_sarif(report)
  assert_true(terminal.contains("affected: >=1.0.0 <2.0.0"))
  assert_true(terminal.contains("fixed: 2.0.0"))
  assert_true(terminal.contains("[uncomparable]"))
  assert_true(json.contains("schema_version"))
  assert_true(sarif.contains("installedVersion"))
  assert_true(sarif.contains("matchStatus"))
  assert_true(sarif.contains("uncomparable"))
}
