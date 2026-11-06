///|
test "policy schema v1 preserves all-scope gating by default" {
  let policy = @moonvigil.parse_policy(
    "{\"schema_version\":\"1\",\"fail_on\":\"high\"}",
    today="2026-09-27",
  )
  assert_eq(policy.fail_on_scopes, [
    "runtime", "test", "wbtest", "other", "unclassified",
  ])
  let empty = @moonvigil.empty_policy(fail_on="info")
  assert_eq(empty.schema_version, "2")
  assert_eq(empty.fail_on_scopes, policy.fail_on_scopes)
}

///|
test "policy schema v2 normalizes selected scopes deterministically" {
  let selected = @moonvigil.parse_policy(
    "{\"schema_version\":\"2\",\"fail_on\":\"high\",\"fail_on_scopes\":[\"test\",\"runtime\"]}",
    today="2026-09-27",
  )
  assert_eq(selected.fail_on_scopes, ["runtime", "test"])
  let all = @moonvigil.parse_policy(
    "{\"schema_version\":\"2\",\"fail_on\":\"high\",\"fail_on_scopes\":[\"all\"]}",
    today="2026-09-27",
  )
  assert_eq(all.fail_on_scopes, [
    "runtime", "test", "wbtest", "other", "unclassified",
  ])
  let trimmed_all = @moonvigil.parse_policy(
    "{\"schema_version\":\"2\",\"fail_on\":\"high\",\"fail_on_scopes\":[\" all \"]}",
    today="2026-09-27",
  )
  assert_eq(trimmed_all.fail_on_scopes, all.fail_on_scopes)
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
    try @moonvigil.parse_policy(text, today="2026-09-27") catch {
      @moonvigil.PolicyValidationError::InvalidPolicyField(field=_, reason=_) =>
        ()
      _ => fail("expected an invalid policy scope diagnostic")
    } noraise {
      _ => fail("expected malformed policy scopes to be rejected")
    }
  }
}

///|
test "scope gates use any matching dependency scope and keep findings visible" {
  let report = scope_test_report()
  let policy = @moonvigil.empty_policy(fail_on="high")
  let runtime = @moonvigil.evaluate_policy_with_scopes(
    report,
    policy,
    None,
    Some(["runtime"]),
    today="2026-09-27",
  )
  assert_true(runtime.should_fail)
  assert_eq(runtime.report.findings.length(), 6)
  assert_eq(runtime.report.policy.unwrap().blocking_findings, 2)
  assert_eq(runtime.report.policy.unwrap().scope_excluded_findings, 4)
  assert_eq(runtime.report.policy.unwrap().fail_on_scopes, ["runtime"])
  assert_eq(runtime.report.schema_version, "6")
  assert_true(
    @moonvigil.report_json(runtime.report).contains("\"schema_version\": \"6\""),
  )
  assert_true(
    @moonvigil.report_json(runtime.report).contains(
      "\"scope_excluded_findings\": 4",
    ),
  )
  assert_true(
    @moonvigil.report_terminal(runtime.report).contains(
      "scopes runtime; 2 blocking, 4 out of scope",
    ),
  )
  assert_true(
    @moonvigil.report_sarif(runtime.report).contains(
      "\"scopeExcludedFindings\": 4",
    ),
  )

  let test_and_unclassified = @moonvigil.evaluate_policy_with_scopes(
    report,
    policy,
    None,
    Some(["test", "unclassified"]),
    today="2026-09-27",
  )
  assert_eq(test_and_unclassified.report.policy.unwrap().blocking_findings, 3)
  assert_eq(
    test_and_unclassified.report.policy.unwrap().scope_excluded_findings,
    3,
  )

  let all = @moonvigil.evaluate_policy_with_scopes(
    report,
    policy,
    None,
    Some(["all"]),
    today="2026-09-27",
  )
  assert_eq(all.report.policy.unwrap().blocking_findings, 6)
  assert_eq(all.report.policy.unwrap().scope_excluded_findings, 0)
}

///|
test "scope exclusions do not hide suppressions or change baseline eligibility" {
  let report = scope_test_report()
  let policy = @moonvigil.parse_policy(
    "{\"schema_version\":\"2\",\"fail_on\":\"high\",\"fail_on_scopes\":[\"runtime\"],\"suppressions\":[{\"advisory_id\":\"MV-SCOPE-TEST\",\"package_name\":\"scope/test\",\"version\":\"1.0.0\",\"reason\":\"scope test suppression\",\"expires_on\":\"2099-12-31\"}]}",
    today="2026-09-27",
  )
  let suppressed = @moonvigil.evaluate_policy_with_scopes(
    report,
    policy,
    None,
    None,
    today="2026-09-27",
  )
  assert_eq(suppressed.report.findings.length(), 6)
  assert_eq(suppressed.report.policy.unwrap().blocking_findings, 2)
  assert_eq(suppressed.report.policy.unwrap().scope_excluded_findings, 4)
  assert_eq(suppressed.report.policy.unwrap().suppressed_findings, 1)
  assert_true(suppressed.report.findings[1].suppression is Some(_))

  let with_baseline = @moonvigil.apply_baseline(
    report,
    @moonvigil.parse_baseline(
      "{\"schema_version\":\"1\",\"entries\":[{\"advisory_id\":\"MV-SCOPE-RUNTIME\",\"package_name\":\"scope/runtime\",\"version\":\"1.0.0\"},{\"advisory_id\":\"MV-SCOPE-TEST\",\"package_name\":\"scope/test\",\"version\":\"1.0.0\"},{\"advisory_id\":\"MV-SCOPE-MULTI\",\"package_name\":\"scope/multi\",\"version\":\"1.0.0\"},{\"advisory_id\":\"MV-SCOPE-WBTEST\",\"package_name\":\"scope/wbtest\",\"version\":\"1.0.0\"},{\"advisory_id\":\"MV-SCOPE-OTHER\",\"package_name\":\"scope/other\",\"version\":\"1.0.0\"},{\"advisory_id\":\"MV-SCOPE-UNCLASSIFIED\",\"package_name\":\"scope/unclassified\",\"version\":\"1.0.0\"}]}",
    ),
  )
  let baseline_result = @moonvigil.evaluate_policy_with_scopes(
    with_baseline,
    @moonvigil.empty_policy(fail_on="high"),
    None,
    Some(["runtime"]),
    today="2026-09-27",
  )
  assert_false(baseline_result.should_fail)
  assert_eq(baseline_result.report.policy.unwrap().blocking_findings, 0)
  assert_eq(baseline_result.report.policy.unwrap().scope_excluded_findings, 4)
}

///|
fn scope_test_report() -> @moonvigil.ScanReport raise {
  let database = @moonvigil.parse_database(
    "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-SCOPE-RUNTIME\",\"package_name\":\"scope/runtime\",\"affected\":\"*\",\"severity\":\"high\",\"summary\":\"runtime scope fixture\",\"fixed_version\":\"\",\"references\":[\"https://example.invalid/MV-SCOPE-RUNTIME\"]},{\"id\":\"MV-SCOPE-TEST\",\"package_name\":\"scope/test\",\"affected\":\"*\",\"severity\":\"high\",\"summary\":\"test scope fixture\",\"fixed_version\":\"\",\"references\":[\"https://example.invalid/MV-SCOPE-TEST\"]},{\"id\":\"MV-SCOPE-MULTI\",\"package_name\":\"scope/multi\",\"affected\":\"*\",\"severity\":\"high\",\"summary\":\"multi scope fixture\",\"fixed_version\":\"\",\"references\":[\"https://example.invalid/MV-SCOPE-MULTI\"]},{\"id\":\"MV-SCOPE-WBTEST\",\"package_name\":\"scope/wbtest\",\"affected\":\"*\",\"severity\":\"high\",\"summary\":\"whitebox scope fixture\",\"fixed_version\":\"\",\"references\":[\"https://example.invalid/MV-SCOPE-WBTEST\"]},{\"id\":\"MV-SCOPE-OTHER\",\"package_name\":\"scope/other\",\"affected\":\"*\",\"severity\":\"high\",\"summary\":\"other scope fixture\",\"fixed_version\":\"\",\"references\":[\"https://example.invalid/MV-SCOPE-OTHER\"]},{\"id\":\"MV-SCOPE-UNCLASSIFIED\",\"package_name\":\"scope/unclassified\",\"affected\":\"*\",\"severity\":\"high\",\"summary\":\"unclassified scope fixture\",\"fixed_version\":\"\",\"references\":[\"https://example.invalid/MV-SCOPE-UNCLASSIFIED\"]}]}",
  )
  @moonvigil.scan(
    [
      Dependency(name="scope/runtime", version="1.0.0", source="moon.mod", scopes=[
        Runtime,
      ]),
      Dependency(name="scope/test", version="1.0.0", source="moon.mod", scopes=[
        Test,
      ]),
      Dependency(name="scope/multi", version="1.0.0", source="moon.mod", scopes=[
        Runtime,
        Test,
      ]),
      Dependency(name="scope/wbtest", version="1.0.0", source="moon.mod", scopes=[
        WhiteboxTest,
      ]),
      Dependency(name="scope/other", version="1.0.0", source="moon.mod", scopes=[
        Other,
      ]),
      Dependency(name="scope/unclassified", version="1.0.0", source="moon.mod"),
    ],
    database,
  )
}
