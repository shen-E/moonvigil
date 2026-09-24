///|
test "severity gate includes the selected level and every higher level" {
  let severities = ["critical", "high", "medium", "low", "info"]
  for threshold_index, threshold in severities {
    let policy = parse_policy(
      "{\"schema_version\":\"1\",\"fail_on\":\"\{threshold}\",\"suppressions\":[]}",
      today="2026-09-24",
    )
    for finding_index, severity in severities {
      let report = policy_test_report(
        "MV-POLICY", "example/p", severity, "1.0.0",
      )
      let evaluated = evaluate_policy(report, policy, None, today="2026-09-24")
      assert_eq(evaluated.should_fail, finding_index <= threshold_index)
    }
  }
}

///|
test "command threshold overrides the policy threshold in both directions" {
  let report = policy_test_report("MV-POLICY", "example/p", "high", "1.0.0")
  let policy = parse_policy(
    "{\"schema_version\":\"1\",\"fail_on\":\"critical\"}",
    today="2026-09-24",
  )
  let raised = evaluate_policy(report, policy, Some("high"), today="2026-09-24")
  let lowered = evaluate_policy(
    report,
    policy,
    Some("critical"),
    today="2026-09-24",
  )
  assert_true(raised.should_fail)
  assert_false(lowered.should_fail)
}

///|
test "rejects an invalid command threshold" {
  let report = policy_test_report("MV-POLICY", "example/p", "high", "1.0.0")
  let policy = empty_policy(fail_on="high")
  try
    evaluate_policy(report, policy, Some("urgent"), today="2026-09-24")
  catch {
    PolicyValidationError::InvalidPolicyField(field="fail_on", reason=_) => ()
    _ => fail("expected invalid threshold diagnostic")
  } noraise {
    _ => fail("expected invalid threshold diagnostic")
  }
}

///|
test "uncomparable versions never block policy gates" {
  let database = parse_database(
    "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"MV-POLICY\",\"package_name\":\"example/p\",\"affected\":\"*\",\"severity\":\"critical\",\"summary\":\"policy fixture\",\"fixed_version\":\"\",\"references\":[\"https://example.invalid/MV-POLICY\"]}]}",
  )
  let dependency = Dependency::Dependency(
    name="example/p",
    version="main",
    source="moon.mod",
  )
  let report = scan([dependency], database)
  assert_eq(report.uncomparable.length(), 1)
  let policy = empty_policy(fail_on="critical")
  let evaluated = evaluate_policy(report, policy, None, today="2026-09-24")
  assert_false(evaluated.should_fail)
  assert_eq(evaluated.report.uncomparable.length(), 1)
}

///|
test "exact advisory package and version suppression remains auditable" {
  let report = policy_test_report("MV-POLICY", "example/p", "high", "1.0.0")
  let policy = parse_policy(
    policy_text("MV-POLICY", "example/p", "1.0.0", "2026-09-24"),
    today="2026-09-24",
  )
  let evaluated = evaluate_policy(report, policy, None, today="2026-09-24")
  assert_false(evaluated.should_fail)
  assert_eq(evaluated.report.findings.length(), 1)
  assert_true(evaluated.report.findings[0].suppression is Some(_))
  assert_eq(evaluated.report.policy.unwrap().suppressed_findings, 1)
  let json = report_json(evaluated.report)
  let terminal = report_terminal(evaluated.report)
  let sarif = report_sarif(evaluated.report)
  assert_true(json.contains("\"schema_version\": \"4\""))
  assert_true(json.contains("short-lived compatibility exception"))
  assert_true(terminal.contains("[suppressed]"))
  assert_true(terminal.contains("short-lived compatibility exception"))
  assert_true(sarif.contains("\"kind\": \"external\""))
  assert_true(sarif.contains("\"status\": \"accepted\""))
  assert_true(
    sarif.contains("\"justification\": \"short-lived compatibility exception\""),
  )
}

///|
test "suppression key mismatches remain visible and warn without suppressing" {
  let cases = [
    ("MV-OTHER", "example/p", "1.0.0"),
    ("MV-POLICY", "example/other", "1.0.0"),
    ("MV-POLICY", "example/p", "1.0.1"),
  ]
  for pair in cases {
    let (advisory_id, package_name, version) = pair
    let report = policy_test_report("MV-POLICY", "example/p", "high", "1.0.0")
    let policy = parse_policy(
      policy_text(advisory_id, package_name, version, "2099-12-31"),
      today="2026-09-24",
    )
    let evaluated = evaluate_policy(report, policy, None, today="2026-09-24")
    assert_true(evaluated.should_fail)
    assert_true(evaluated.report.findings[0].suppression is None)
    assert_eq(
      evaluated.report.policy.unwrap().unmatched_suppressions.length(),
      1,
    )
    assert_true(
      report_terminal(evaluated.report).contains(
        "Warning: suppression did not match",
      ),
    )
  }
}

///|
test "suppression expiry is inclusive and invalid or expired dates fail" {
  let valid_today = parse_policy(
    policy_text("MV-POLICY", "example/p", "1.0.0", "2026-09-24"),
    today="2026-09-24",
  )
  assert_eq(valid_today.suppressions.length(), 1)
  try
    parse_policy(
      policy_text("MV-POLICY", "example/p", "1.0.0", "2026-09-23"),
      today="2026-09-24",
    )
  catch {
    PolicyValidationError::ExpiredSuppression(
      index=0,
      advisory_id="MV-POLICY",
      expires_on="2026-09-23"
    ) => ()
    _ => fail("expected expired suppression error")
  } noraise {
    _ => fail("expected expired suppression error")
  }
  try
    parse_policy(
      policy_text("MV-POLICY", "example/p", "1.0.0", "2026-02-30"),
      today="2026-09-24",
    )
  catch {
    PolicyValidationError::InvalidPolicyField(
      field="suppressions[0].expires_on",
      reason=_
    ) => ()
    _ => fail("expected invalid date error")
  } noraise {
    _ => fail("expected invalid date error")
  }
  let leap_day = parse_policy(
    policy_text("MV-POLICY", "example/p", "1.0.0", "2024-02-29"),
    today="2024-02-29",
  )
  assert_eq(leap_day.suppressions.length(), 1)
  try
    parse_policy(
      "{\"schema_version\":\"1\",\"fail_on\":\"high\"}",
      today="2023-02-29",
    )
  catch {
    PolicyValidationError::InvalidPolicyField(field="today", reason=_) => ()
    _ => fail("expected invalid current-date error")
  } noraise {
    _ => fail("expected invalid current-date error")
  }
}

///|
test "validates policy schema severity required fields version and duplicate rules" {
  let invalid_policies = [
    "{\"schema_version\":\"2\",\"fail_on\":\"high\"}", "{\"schema_version\":\"1\",\"fail_on\":\"urgent\"}",
    "{\"schema_version\":\"1\"}", "{\"schema_version\":\"1\",\"fail_on\":\"high\",\"suppressions\":[{\"advisory_id\":\"MV-POLICY\",\"package_name\":\"example/p\",\"version\":\"1.0\",\"reason\":\"r\",\"expires_on\":\"2099-12-31\"}]}",
    "{\"schema_version\":\"1\",\"fail_on\":\"high\",\"suppressions\":[{\"advisory_id\":\"MV-POLICY\",\"package_name\":\"example/p\",\"version\":\"1.0.0\",\"reason\":\" \",\"expires_on\":\"2099-12-31\"}]}",
    "{\"schema_version\":\"1\",\"fail_on\":[],\"suppressions\":[]}", "{\"schema_version\":\"1\",\"fail_on\":\"high\",\"suppressions\":{}}",
    "{\"schema_version\":\"1\",\"fail_on\":\"high\",\"suppressions\":[1]}", "{\"schema_version\":\"1\",\"fail_on\":\"high\",\"suppressions\":[{\"advisory_id\":\"MV-POLICY\",\"package_name\":\"example/p\",\"version\":\"1.0.0\",\"expires_on\":\"2099-12-31\"}]}",
  ]
  for text in invalid_policies {
    try parse_policy(text, today="2026-09-24") catch {
      PolicyValidationError::InvalidPolicyField(field=_, reason=_) => ()
      _ => fail("expected invalid policy field")
    } noraise {
      _ => fail("expected invalid policy field")
    }
  }
  let duplicate_rule = "{\"schema_version\":\"1\",\"fail_on\":\"high\",\"suppressions\":[{\"advisory_id\":\"MV-POLICY\",\"package_name\":\"example/p\",\"version\":\"1.0.0\",\"reason\":\"first\",\"expires_on\":\"2099-12-31\"},{\"advisory_id\":\"MV-POLICY\",\"package_name\":\"example/p\",\"version\":\"1.0.0\",\"reason\":\"duplicate\",\"expires_on\":\"2099-12-31\"}]}"
  try parse_policy(duplicate_rule, today="2026-09-24") catch {
    PolicyValidationError::InvalidPolicyField(field="suppressions[1]", reason=_) =>
      ()
    _ => fail("expected duplicate suppression error")
  } noraise {
    _ => fail("expected duplicate suppression error")
  }
}

///|
fn policy_test_report(
  advisory_id : String,
  package_name : String,
  severity : String,
  version : String,
) -> ScanReport raise {
  let database = parse_database(
    "{\"schema_version\":\"1\",\"advisories\":[{\"id\":\"\{advisory_id}\",\"package_name\":\"\{package_name}\",\"affected\":\"1.0.0\",\"severity\":\"\{severity}\",\"summary\":\"policy fixture\",\"fixed_version\":\"\",\"references\":[\"https://example.invalid/\{advisory_id}\"]}]}",
  )
  scan([Dependency(name=package_name, version~, source="moon.mod")], database)
}

///|
fn policy_text(
  advisory_id : String,
  package_name : String,
  version : String,
  expires_on : String,
) -> String {
  "{\"schema_version\":\"1\",\"fail_on\":\"high\",\"suppressions\":[{\"advisory_id\":\"\{advisory_id}\",\"package_name\":\"\{package_name}\",\"version\":\"\{version}\",\"reason\":\"short-lived compatibility exception\",\"expires_on\":\"\{expires_on}\"}]}"
}
