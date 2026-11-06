///|
test "consumer parses modern manifests and preserves version matching" {
  let dependencies = @moonvigil.parse_moon_mod(
    "name = \"example/application\"\nimport { \"example/package@1.2.3\" }\n",
    source="moon.mod",
  )
  assert_eq(dependencies.length(), 1)
  assert_eq(dependencies[0].name, "example/package")
  assert_eq(dependencies[0].version, "1.2.3")
  assert_true(
    @moonvigil.match_version("1.2.3", ">=1.0.0 <2.0.0")
    is @moonvigil.FindingStatus::Affected,
  )
  assert_true(
    @moonvigil.match_version("2.0.0", ">=1.0.0 <2.0.0")
    is @moonvigil.FindingStatus::NotAffected,
  )
}

///|
test "consumer reports prerelease versions as uncomparable" {
  assert_true(
    @moonvigil.match_version("1.2.3-beta", "*")
    is @moonvigil.FindingStatus::Uncomparable,
  )
}
