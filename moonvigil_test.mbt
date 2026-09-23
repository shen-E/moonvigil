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
test "matches an affected dependency and leaves a fixed version clean" {
  let database = parse_database(
    "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-1\",\"package_name\":\"example/insecure-http\",\"affected\":\">=0.1.0 <0.2.0\",\"severity\":\"high\",\"summary\":\"fixture\",\"fixed_version\":\"0.2.0\",\"references\":[]}]}",
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
test "reports an uncomparable version without an affected finding" {
  let database = parse_database(
    "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-2\",\"package_name\":\"example/insecure-http\",\"affected\":\">=0.1.0 <0.2.0\",\"severity\":\"low\",\"summary\":\"fixture\",\"fixed_version\":\"\",\"references\":[]}]}",
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
