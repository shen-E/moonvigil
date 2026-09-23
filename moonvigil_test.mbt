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
