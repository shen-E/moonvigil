///|
test "parses current moon.mod imports with comments and multiline formatting" {
  let manifest =
    #|name = "fixture/app"
    #|version = "1.0.0"
    #|
    #|// Dependencies may span multiple lines and include comments.
    #|import {
    #|  "org/client@1.2.3", // pinned module
    #|  "org/without-version",
    #|}
    #|
  let dependencies = parse_moon_mod(manifest, source="moon.mod")
  assert_eq(dependencies.length(), 2)
  assert_eq(dependencies[0].name, "org/client")
  assert_eq(dependencies[0].version, "1.2.3")
  assert_eq(dependencies[0].source, "moon.mod")
  assert_eq(dependencies[1].name, "org/without-version")
  assert_eq(dependencies[1].version, "")
  assert_true(match_version(dependencies[1].version, "*") is Uncomparable)
}

///|
test "parses moon.pkg aliases and runtime, test, and wbtest groups" {
  let manifest =
    #|import {
    #|  "org/client/transport" @transport,
    #|  "moonbitlang/core/json",
    #|}
    #|import { "org/testing/helpers", } for "test"
    #|import {
    #|  "org/testing/private_helpers",
    #|} for "wbtest"
    #|
  let imports = parse_moon_pkg(manifest, source="pkg/moon.pkg")
  assert_eq(imports.length(), 4)
  assert_eq(imports[0].package_name, "org/client/transport")
  assert_eq(imports[0].alias_name, "transport")
  assert_true(imports[0].scope is Runtime)
  assert_eq(imports[1].alias_name, "json")
  assert_true(imports[1].scope is Runtime)
  assert_eq(imports[2].alias_name, "helpers")
  assert_true(imports[2].scope is Test)
  assert_eq(imports[3].alias_name, "private_helpers")
  assert_true(imports[3].scope is WhiteboxTest)
}

///|
test "maps package imports to the longest declared module and merges scopes" {
  let dependencies = parse_moon_mod(
    (
      #|import {
      #|  "org/client@1.2.3",
      #|  "org/client/codec@2.0.0",
      #|}
      #|
    ),
    source="moon.mod",
  )
  let usage_manifest =
    #|import { "org/client/http" @http, }
    #|import { "org/client/codec/json" @json, } for "test"
    #|
  let imports = parse_moon_pkg(usage_manifest, source="pkg/moon.pkg")
  let scoped = apply_package_imports(dependencies, imports)
  assert_eq(scoped[0].scopes.length(), 1)
  assert_true(scoped[0].scopes[0] is Runtime)
  assert_eq(scoped[0].aliases, ["http"])
  assert_eq(scoped[1].scopes.length(), 1)
  assert_true(scoped[1].scopes[0] is Test)
  assert_eq(scoped[1].aliases, ["json"])
  let report = report_json(
    scan(scoped, parse_database("{\"schema_version\":\"1\",\"advisories\":[]}")),
  )
  assert_true(report.contains("\"runtime\""))
  assert_true(report.contains("\"test\""))
}

///|
test "reports conflicting module versions and stable source evidence" {
  let dependencies = parse_moon_mod(
    "import { \"org/client@2.0.0\", }",
    source="z/moon.mod",
  )
  for
    dependency in parse_moon_mod(
      "import { \"org/client@1.0.0\", }",
      source="a/moon.mod",
    ) {
    dependencies.push(dependency)
  }
  let inventory = inventory_from_dependencies(dependencies)
  assert_eq(inventory.conflicts.length(), 1)
  assert_eq(inventory.conflicts[0].name, "org/client")
  assert_eq(inventory.conflicts[0].versions, ["1.0.0", "2.0.0"])
  assert_eq(inventory.conflicts[0].sources, ["a/moon.mod", "z/moon.mod"])
  let report = report_json(
    scan(
      dependencies,
      parse_database("{\"schema_version\":\"1\",\"advisories\":[]}"),
    ),
  )
  assert_true(report.contains("\"conflicts\""))
  assert_true(
    report_sarif(
      scan(
        dependencies,
        parse_database("{\"schema_version\":\"1\",\"advisories\":[]}"),
      ),
    ).contains("dependencyConflicts"),
  )
}

///|
test "rejects malformed modern import blocks with source evidence" {
  let broken =
    #|name = "fixture/app"
    #|import { "org/client@1.2.3"
  try parse_moon_mod(broken, source="broken/moon.mod") catch {
    ManifestParseError::InvalidManifest(source~, line=_, reason~) => {
      assert_eq(source, "broken/moon.mod")
      assert_eq(reason, "unterminated import block")
    }
    _ => fail("expected malformed manifest error")
  } noraise {
    _ => fail("expected malformed manifest error")
  }
}

///|
test "parses commit-pinned public MoonBit manifests offline" {
  let module_source = "fixtures/real/moonbitlang-parser/moon.mod"
  let package_source = "fixtures/real/moonbitlang-parser/moon.pkg"
  let dependencies = parse_moon_mod(
    @fs.read_file_to_string(module_source),
    source=module_source,
  )
  let imports = parse_moon_pkg(
    @fs.read_file_to_string(package_source),
    source=package_source,
  )
  let inventory = inventory_from_dependencies(dependencies).dependencies
  let scoped = apply_package_imports(inventory, imports)
  assert_eq(scoped.length(), 5)
  assert_true(
    scoped.any(fn(dependency) {
      dependency.name == "moonbitlang/x" &&
      dependency.version == "0.5.1" &&
      dependency.scopes is [Runtime]
    }),
  )
  assert_true(
    scoped.any(fn(dependency) {
      dependency.name == "moonbitlang/lexer" &&
      dependency.version == "0.4.0" &&
      dependency.scopes is [Runtime]
    }),
  )
  assert_true(
    scoped.any(fn(dependency) {
      dependency.name == "moonbitlang/async" &&
      dependency.version == "0.21.2" &&
      dependency.scopes.length() == 0
    }),
  )
  assert_true(
    scoped.all(fn(dependency) {
      !dependency.source.contains(":") && !dependency.source.contains("\\")
    }),
  )
}

///|
test "rejects malformed module dependency identities instead of truncating them" {
  for
    value in [
      "@1.2.3", "org/client@", "org/client@1.2.3@2.0.0", "org//client@1.2.3", "org/client/../other@1.2.3",
      "org/client @1.2.3",
    ] {
    let manifest = "name = \"fixture/app\"\nimport {\n  \"\{value}\",\n}"
    try parse_moon_mod(manifest, source="broken/moon.mod") catch {
      ManifestParseError::InvalidManifest(source~, line~, reason~) => {
        assert_eq(source, "broken/moon.mod")
        assert_eq(line, 3)
        assert_eq(reason, "invalid module dependency: \{value}")
      }
      _ => fail("expected invalid module dependency")
    } noraise {
      _ => fail("accepted invalid module dependency: \{value}")
    }
  }
}

///|
test "rejects malformed import entries and aliases with the offending line" {
  let malformed : Array[(String, Int32, String)] = [
    ("import \"org/client\"", 1, "expected { after import"),
    ("import {\n  org/client,\n}", 2, "expected a quoted import entry"),
    ("import {\n  \"\",\n}", 2, "empty import entry"),
    ("import {\n  ,\n}", 2, "expected a quoted import entry"),
    (
      "import {\n  \"org/client\"\n  \"org/other\"\n}", 3, "expected a comma or } after import entry",
    ),
    ("import {\n  \"org/client\" @,\n}", 2, "expected an alias after @"),
    ("import {\n  \"org/client\" @5bad,\n}", 2, "expected an alias after @"),
    (
      "import {\n  \"org/client\" @first @second,\n}", 2, "expected a comma or } after import entry",
    ),
    (
      "import { \"org/client\" } for test", 1, "expected a quoted scope after for",
    ),
    (
      "import { \"org/client\" } for \"\"", 1, "expected a quoted scope after for",
    ),
    (
      "import { \"org/client\" } for \"test\" + \"wbtest\"", 1, "unexpected token after import block",
    ),
  ]
  for (manifest, expected_line, expected_reason) in malformed {
    try parse_moon_pkg(manifest, source="broken/moon.pkg") catch {
      ManifestParseError::InvalidManifest(source~, line~, reason~) => {
        assert_eq(source, "broken/moon.pkg")
        assert_eq(line, expected_line)
        assert_eq(reason, expected_reason)
      }
      _ => fail("expected invalid import entry")
    } noraise {
      _ => fail("accepted malformed import entry: \{manifest}")
    }
  }
}

///|
test "rejects package aliases and scope qualifiers in module manifests" {
  for
    manifest in [
      "import { \"org/client@1.2.3\" @client, }", "import { \"org/client@1.2.3\", } for \"test\"",
      "import { \"org/client@1.2.3\", } for \"runtime\"",
    ] {
    try parse_moon_mod(manifest, source="moon.mod") catch {
      ManifestParseError::InvalidManifest(source~, line~, reason=_) => {
        assert_eq(source, "moon.mod")
        assert_eq(line, 1)
      }
      _ => fail("expected invalid module import qualifier")
    } noraise {
      _ => fail("accepted invalid module import qualifier")
    }
  }
}

///|
test "does not rewrite an escaped dependency into another module identity" {
  let manifest =
    #|import { "org/cli\ent@1.2.3", }
  try parse_moon_mod(manifest, source="moon.mod") catch {
    ManifestParseError::InvalidManifest(source~, line~, reason~) => {
      assert_eq(source, "moon.mod")
      assert_eq(line, 1)
      assert_eq(reason, "invalid string literal")
    }
    _ => fail("expected escaped dependency error")
  } noraise {
    _ => fail("escaped dependency was silently rewritten")
  }
}

///|
test "decodes valid escaped module identities without losing dependency matches" {
  let dependencies = parse_moon_mod(
    (
      #|import { "org\/cli\u0065nt@1.2.3", }
    ),
    source="moon.mod",
  )
  assert_eq(dependencies[0].name, "org/client")
  assert_eq(dependencies[0].version, "1.2.3")
  let imports = parse_moon_pkg(
    (
      #|import { "org\/cli\u0065nt\/http", }
    ),
    source="moon.pkg",
  )
  assert_eq(imports[0].package_name, "org/client/http")
  assert_eq(apply_package_imports(dependencies, imports)[0].scopes, [Runtime])
}

///|
test "preserves existing aliases and scopes when applying more package imports" {
  let dependencies = [
    Dependency(
      name="org/client",
      version="1.2.3",
      source="moon.mod.json",
      aliases=["legacy", "legacy"],
      scopes=[Test, Test],
    ),
  ]
  let imports = parse_moon_pkg(
    "import { \"org/client/http\" @http, }",
    source="moon.pkg",
  )
  let scoped = apply_package_imports(dependencies, imports)
  assert_eq(scoped[0].aliases, ["http", "legacy"])
  assert_eq(scoped[0].scopes, [Runtime, Test])
  assert_eq(scoped[0].source, "moon.mod.json")
  assert_eq(apply_package_imports(scoped, imports), scoped)
  assert_eq(apply_package_imports(scoped, []), scoped)
  assert_eq(dependencies[0].aliases, ["legacy", "legacy"])
  assert_eq(dependencies[0].scopes, [Test, Test])
}

///|
test "preserves custom scopes and accepts supported alias spelling" {
  let imports = parse_moon_pkg(
    (
      #|import {
      #|  "org/client/one" @foo-bar,
      #|  "org/client/two" @_helper,
      #|} for "custom"
    ),
    source="moon.pkg",
  )
  assert_eq(imports.length(), 2)
  assert_true(imports.all(fn(package_import) { package_import.scope is Other }))
  assert_eq(imports[0].alias_name, "foo-bar")
  assert_eq(imports[1].alias_name, "_helper")
  assert_eq(
    PackageImport(
      package_name="org/client/one",
      alias_name="foo-bar",
      scope=Other,
      source="moon.pkg",
    ),
    imports[0],
  )
}

///|
test "rejects version qualifiers and invalid path segments in package imports" {
  for
    path in ["org/client@1.2.3", "org//client", "org/client/", "org/../client"] {
    try parse_moon_pkg("import { \"\{path}\", }", source="moon.pkg") catch {
      ManifestParseError::InvalidManifest(source~, line~, reason~) => {
        assert_eq(source, "moon.pkg")
        assert_eq(line, 1)
        assert_eq(reason, "invalid package import: \{path}")
      }
      _ => fail("expected invalid package import path")
    } noraise {
      _ => fail("accepted invalid package import path")
    }
  }
}
