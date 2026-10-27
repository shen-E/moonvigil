///|
test "inventory canonicalizes aliases and scopes independently of input order" {
  let runtime = Dependency(
    name="example/package",
    version="1.0.0",
    source="b/moon.mod",
    aliases=["z", "a", "a", ""],
    scopes=[Other, Runtime, Runtime],
  )
  let tests = Dependency(
    name="example/package",
    version="1.0.0",
    source="a/moon.mod",
    aliases=["test"],
    scopes=[WhiteboxTest, Test],
  )
  let forward = inventory_from_dependencies([runtime, tests])
  let reverse = inventory_from_dependencies([tests, runtime])
  assert_eq(forward, reverse)
  assert_eq(forward.dependencies[0].aliases, ["a", "test", "z"])
  assert_eq(forward.dependencies[0].scopes, [Runtime, Test, WhiteboxTest, Other])
  let single = inventory_from_dependencies([runtime]).dependencies[0]
  assert_eq(single.aliases, ["a", "z"])
  assert_eq(single.scopes, [Runtime, Other])
  assert_eq(sbom_json([runtime, tests]), sbom_json([tests, runtime]))
}

///|
test "SBOM includes its required document version and unique components" {
  let dependency = Dependency(
    name="example/package",
    version="1.0.0",
    source="moon.mod",
  )
  let bom = @json.parse(sbom_json([dependency, dependency]))
  guard bom is Object(fields) else { fail("expected a BOM object") }
  assert_eq(fields.get("bomFormat"), Some(Json::string("CycloneDX")))
  assert_eq(fields.get("specVersion"), Some(Json::string("1.5")))
  assert_eq(fields.get("version"), Some(Json::number(1)))
  guard fields.get("components") is Some(Array(components)) else {
    fail("expected components")
  }
  assert_eq(components.length(), 1)
  let empty = @json.parse(sbom_json([]))
  guard empty is Object(empty_fields) else { fail("expected an empty BOM") }
  assert_eq(empty_fields.get("version"), Some(Json::number(1)))
  assert_eq(empty_fields.get("components"), Some(Json::array([])))
}

///|
test "SBOM escapes package URL data and omits an absent version delimiter" {
  let bom = @json.parse(
    sbom_json([
      Dependency(
        name="example/package",
        version="main#revision?x=1+build/@ %😀",
        source="moon.mod",
      ),
      Dependency(name="owner name/工具", version="", source="moon.mod"),
    ]),
  )
  guard bom is Object(fields) else { fail("expected a BOM object") }
  guard fields.get("components") is Some(Array(components)) else {
    fail("expected components")
  }
  guard components[0] is Object(versioned) else { fail("expected a component") }
  assert_eq(
    versioned.get("purl"),
    Some(
      Json::string(
        "pkg:moonbit/example/package@main%23revision%3Fx%3D1%2Bbuild%2F%40%20%25%F0%9F%98%80",
      ),
    ),
  )
  guard components[1] is Object(unversioned) else {
    fail("expected a component")
  }
  assert_eq(
    unversioned.get("purl"),
    Some(Json::string("pkg:moonbit/owner%20name/%E5%B7%A5%E5%85%B7")),
  )
}

///|
test "SARIF emits escaped file URIs and one rule for repeated findings" {
  let database = parse_database(
    (
      #|{"schema_version":"1","advisories":[{"id":"MV-REPORT","package_name":"example/package","affected":"*","severity":"high","summary":"report fixture","fixed_version":"","references":["not a URL","https://example.invalid/MV-REPORT"]}]}
    ),
  )
  let sources = [
    "C:\\repo name\\模块#1\\moon.mod", "workspace name/moon.mod#fixture?100%.json",
    "/tmp/a#b/moon.mod", "\\\\server\\share name\\moon.mod",
  ]
  let report = scan(
    sources.mapi(fn(index, source) {
      Dependency(name="example/package", version="1.0.\{index}", source~)
    }),
    database,
  )
  let sarif = @json.parse(report_sarif(report))
  guard sarif is Object(root) else { fail("expected SARIF object") }
  guard root.get("runs") is Some(Array([Object(run)])) else {
    fail("expected a SARIF run")
  }
  guard run.get("results") is Some(Array(results)) else {
    fail("expected SARIF results")
  }
  let expected = [
    "file:///C:/repo%20name/%E6%A8%A1%E5%9D%97%231/moon.mod", "workspace%20name/moon.mod%23fixture%3F100%25.json",
    "file:///tmp/a%23b/moon.mod", "file://server/share%20name/moon.mod",
  ]
  assert_eq(results.length(), expected.length())
  for index, result in results {
    guard result is Object(fields) else { fail("expected a result") }
    guard fields.get("locations") is Some(Array([Object(location)])) &&
      location.get("physicalLocation") is Some(Object(physical)) &&
      physical.get("artifactLocation") is Some(Object(artifact)) else {
      fail("expected a physical artifact location")
    }
    assert_eq(artifact.get("uri"), Some(Json::string(expected[index])))
  }
  guard run.get("tool") is Some(Object(tool)) &&
    tool.get("driver") is Some(Object(driver)) &&
    driver.get("rules") is Some(Array([Object(rule)])) else {
    fail("expected exactly one rule")
  }
  assert_eq(rule.get("id"), Some(Json::string("MV-REPORT")))
  assert_eq(
    rule.get("helpUri"),
    Some(Json::string("https://example.invalid/MV-REPORT")),
  )
}

///|
test "legacy manifest object rejects unsupported dependency value types" {
  for value in ["null", "true", "42", "{}", "[]"] {
    try
      parse_manifest(
        "{\"import\":{\"example/package\":\{value}}}",
        source="moon.mod.json",
      )
    catch {
      ManifestParseError::InvalidManifest(
        source="moon.mod.json",
        line=1,
        reason~
      ) => assert_true(reason.contains("example/package"))
      _ => fail("expected a dependency version diagnostic")
    } noraise {
      _ => fail("an unsupported dependency value must not disappear")
    }
  }
  assert_eq(
    parse_manifest("{\"import\":[\"example/package\"]}", source="moon.pkg.json").length(),
    0,
  )
}

///|
test "SARIF omits malformed help URIs while retaining original references" {
  for
    (reference, valid) in [
      ("https://example.invalid/path with spaces", false),
      ("https://example.invalid/%zz", false),
      ("https://example.invalid/path#one#two", false),
      ("https://example.invalid/工具", false),
      ("https://example.invalid/path[1]", false),
      ("https://example.invalid/path%20with%20spaces?view=full#details", true),
    ] {
    let database = parse_database(
      "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-URI\",\"package_name\":\"example/package\",\"affected\":\"*\",\"severity\":\"low\",\"summary\":\"URI fixture\",\"fixed_version\":\"\",\"references\":[\{@json.to_json(reference).stringify()}]}]}",
    )
    let report = scan(
      [Dependency(name="example/package", version="1.0.0", source="moon.mod")],
      database,
    )
    guard @json.parse(report_sarif(report)) is Object(root) else {
      fail("expected SARIF object")
    }
    guard root.get("runs") is Some(Array([Object(run)])) &&
      run.get("tool") is Some(Object(tool)) &&
      tool.get("driver") is Some(Object(driver)) &&
      driver.get("rules") is Some(Array([Object(rule)])) else {
      fail("expected a rule")
    }
    assert_eq(
      rule.get("helpUri"),
      if valid {
        Some(Json::string(reference))
      } else {
        None
      },
    )
    guard run.get("results") is Some(Array([Object(result)])) &&
      result.get("properties") is Some(Object(properties)) else {
      fail("expected result evidence")
    }
    assert_eq(
      properties.get("references"),
      Some(Json::array([Json::string(reference)])),
    )
  }
}
