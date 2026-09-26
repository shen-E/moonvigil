///|
test "policy schema v1 preserves all-scope gating by default" {
  let policy = parse_policy(
    "{\"schema_version\":\"1\",\"fail_on\":\"high\"}",
    today="2026-09-27",
  )
  assert_eq(policy.fail_on_scopes, [
    "runtime", "test", "wbtest", "other", "unclassified",
  ])
  let empty = empty_policy(fail_on="info")
  assert_eq(empty.schema_version, "2")
  assert_eq(empty.fail_on_scopes, policy.fail_on_scopes)
}

///|
test "policy schema v2 normalizes selected scopes deterministically" {
  let selected = parse_policy(
    "{\"schema_version\":\"2\",\"fail_on\":\"high\",\"fail_on_scopes\":[\"test\",\"runtime\"]}",
    today="2026-09-27",
  )
  assert_eq(selected.fail_on_scopes, ["runtime", "test"])
  let all = parse_policy(
    "{\"schema_version\":\"2\",\"fail_on\":\"high\",\"fail_on_scopes\":[\"all\"]}",
    today="2026-09-27",
  )
  assert_eq(all.fail_on_scopes, [
    "runtime", "test", "wbtest", "other", "unclassified",
  ])
}

///|
test "policy scopes reject missing empty duplicate and unknown values" {
  let invalid = [
    "{\"schema_version\":\"2\",\"fail_on\":\"high\"}", "{\"schema_version\":\"2\",\"fail_on\":\"high\",\"fail_on_scopes\":[]}",
    "{\"schema_version\":\"2\",\"fail_on\":\"high\",\"fail_on_scopes\":[\"\"]}",
    "{\"schema_version\":\"2\",\"fail_on\":\"high\",\"fail_on_scopes\":[\"runtime\",\"runtime\"]}",
    "{\"schema_version\":\"2\",\"fail_on\":\"high\",\"fail_on_scopes\":[\"all\",\"test\"]}",
    "{\"schema_version\":\"2\",\"fail_on\":\"high\",\"fail_on_scopes\":[\"production\"]}",
    "{\"schema_version\":\"2\",\"fail_on\":\"high\",\"fail_on_scopes\":[7]}", "{\"schema_version\":\"2\",\"fail_on\":\"high\",\"fail_on_scopes\":{}}",
    "{\"schema_version\":\"1\",\"fail_on\":\"high\",\"fail_on_scopes\":[\"runtime\"]}",
    "{\"schema_version\":\"3\",\"fail_on\":\"high\"}",
  ]
  for text in invalid {
    try parse_policy(text, today="2026-09-27") catch {
      PolicyValidationError::InvalidPolicyField(field=_, reason=_) => ()
      _ => fail("expected an invalid policy scope diagnostic")
    } noraise {
      _ => fail("expected malformed policy scopes to be rejected")
    }
  }
}
