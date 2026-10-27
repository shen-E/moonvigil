///|
test "CLI validates every option and its value" {
  assert_true(options_are_valid(["--db", "advisories.json"], ["--db"]))
  for
    args in [
      ["--db"],
      ["--db", ""],
      ["--db", "--format"],
      ["--db", "a", "--db", "b"],
      ["--unknown", "a"],
    ] {
    assert_false(options_are_valid(args, ["--db"]))
  }
}

///|
test "CLI resolves equivalent output and input paths" {
  assert_true(paths_alias("advisories.json", "./fixtures/../advisories.json"))
  assert_true(paths_alias("new-report.json", "./new-report.json"))
  assert_false(paths_alias("new-report.json", "other-report.json"))
  try validate_output_paths(["./advisories.json"], ["advisories.json"]) catch {
    InvalidInput(_) => ()
    error => fail("unexpected error: \{error}")
  } noraise {
    _ => fail("expected input overwrite to be rejected")
  }
  try validate_output_paths(["moon.mod"], []) catch {
    InvalidInput(_) => ()
    error => fail("unexpected error: \{error}")
  } noraise {
    _ => fail("expected manifest overwrite to be rejected")
  }
}

///|
test "CLI uses exact manifest filenames and nearest module ownership" {
  assert_true(is_manifest_name("moon.mod"))
  assert_true(is_manifest_name("moon.pkg.json"))
  assert_false(is_manifest_name("wrongmoon.mod"))
  let modules = ["moon.mod", "nested/moon.mod.json", "nested/inner/moon.mod"]
  assert_eq(module_owner("cmd/moon.pkg", modules), "")
  assert_eq(module_owner("nested/cmd/moon.pkg", modules), "nested")
  assert_eq(module_owner("nested/inner/moon.pkg", modules), "nested/inner")
  assert_eq(module_owner("nested-other/moon.pkg", modules), "")
}

///|
test "legacy package imports retain aliases and test scopes" {
  let text =
    #|{"import":["example/lib/runtime"],
    #| "test-import":[{"path":"example/lib/test","alias":"checks"}],
    #| "wbtest-import":["example/lib/private"]}
  let imports = legacy_package_imports(text, source="moon.pkg.json")
  assert_eq(imports.length(), 3)
  assert_eq(imports[0].scope, @vigil.Runtime)
  assert_eq(imports[1].scope, @vigil.Test)
  assert_eq(imports[1].alias_name, "checks")
  assert_eq(imports[2].scope, @vigil.WhiteboxTest)
  assert_eq(imports[2].alias_name, "private")
  assert_eq(
    legacy_package_imports(
      "{\"import\":{\"example/lib\":\"1.0.0\"}}",
      source="moon.pkg.json",
    ).length(),
    0,
  )
}

///|
test "legacy package imports reject malformed entries" {
  for
    text in [
      "{\"import\":[false]}", "{\"import\":[\"\"]}", "{\"test-import\":false}", "{\"import\":[{\"alias\":\"missing-path\"}]}",
      "{\"import\":[{\"path\":\"example/lib\",\"alias\":1}]}",
    ] {
    try legacy_package_imports(text, source="moon.pkg.json") catch {
      InvalidInput(_) => ()
      error => fail("unexpected error: \{error}")
    } noraise {
      _ => fail("expected malformed package import to be rejected")
    }
  }
}
