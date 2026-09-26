///|
/// A narrowly scoped, auditable suppression rule.
pub struct PolicySuppression {
  advisory_id : String
  package_name : String
  version : String
  reason : String
  expires_on : String
} derive(Debug, Eq, ToJson)

///|
/// CI policy for severity gating and exact-version suppressions.
pub struct ScanPolicy {
  schema_version : String
  fail_on : String
  fail_on_scopes : Array[String]
  suppressions : Array[PolicySuppression]
} derive(Debug, Eq, ToJson)

///|
/// Policy outcome attached to a scan report.
pub struct PolicySummary {
  fail_on : String
  fail_on_scopes : Array[String]
  blocking_findings : Int
  scope_excluded_findings : Int
  suppressed_findings : Int
  unmatched_suppressions : Array[PolicySuppression]
} derive(Debug, Eq, ToJson)

///|
pub struct PolicyEvaluation {
  report : ScanReport
  should_fail : Bool
} derive(Debug, Eq)

///|
pub(all) suberror PolicyValidationError {
  InvalidPolicyField(field~ : String, reason~ : String)
  ExpiredSuppression(index~ : Int, advisory_id~ : String, expires_on~ : String)
} derive(Debug, Eq)

///|
/// Parse and validate a schema-v1 policy using a UTC date supplied by the caller.
/// Suppression expiries are inclusive: a rule remains active through expires_on.
pub fn parse_policy(text : String, today~ : String) -> ScanPolicy raise {
  let root = match @json.parse(text) {
    Object(fields) => fields
    _ =>
      raise PolicyValidationError::InvalidPolicyField(
        field="$",
        reason="must be a JSON object",
      )
  }
  let schema_version = policy_string_field(root, "schema_version")
  let fail_on = policy_string_field(root, "fail_on")
  let fail_on_scopes = match schema_version {
    "1" =>
      match root.get("fail_on_scopes") {
        Some(_) =>
          raise PolicyValidationError::InvalidPolicyField(
            field="fail_on_scopes",
            reason="is not supported by schema version 1",
          )
        None => all_policy_scopes()
      }
    "2" => parse_policy_scopes_field(root)
    _ =>
      raise PolicyValidationError::InvalidPolicyField(
        field="schema_version",
        reason="must be \"1\" or \"2\"",
      )
  }
  let suppressions : Array[PolicySuppression] = match root.get("suppressions") {
    None => []
    Some(Array(items)) => {
      let parsed : Array[PolicySuppression] = []
      for index, item in items {
        match item {
          Object(fields) =>
            parsed.push({
              advisory_id: policy_string_field(
                fields,
                "suppressions[\{index}].advisory_id",
                key="advisory_id",
              ),
              package_name: policy_string_field(
                fields,
                "suppressions[\{index}].package_name",
                key="package_name",
              ),
              version: policy_string_field(
                fields,
                "suppressions[\{index}].version",
                key="version",
              ),
              reason: policy_string_field(
                fields,
                "suppressions[\{index}].reason",
                key="reason",
              ),
              expires_on: policy_string_field(
                fields,
                "suppressions[\{index}].expires_on",
                key="expires_on",
              ),
            })
          _ =>
            raise PolicyValidationError::InvalidPolicyField(
              field="suppressions[\{index}]",
              reason="must be an object",
            )
        }
      }
      parsed
    }
    _ =>
      raise PolicyValidationError::InvalidPolicyField(
        field="suppressions",
        reason="must be an array",
      )
  }
  let policy = { schema_version, fail_on, fail_on_scopes, suppressions }
  validate_policy(policy, today~)
  policy
}

///|
/// Validate a policy, including ISO date validity and expiration.
pub fn validate_policy(policy : ScanPolicy, today~ : String) -> Unit raise {
  if policy.schema_version != "1" && policy.schema_version != "2" {
    raise PolicyValidationError::InvalidPolicyField(
      field="schema_version",
      reason="must be \"1\" or \"2\"",
    )
  }
  if !is_policy_severity(policy.fail_on) {
    raise PolicyValidationError::InvalidPolicyField(
      field="fail_on",
      reason="must be one of critical, high, medium, low, info",
    )
  }
  let normalized_scopes = normalize_policy_scopes(policy.fail_on_scopes)
  if !string_arrays_equal(normalized_scopes, policy.fail_on_scopes) {
    raise PolicyValidationError::InvalidPolicyField(
      field="fail_on_scopes",
      reason="must be unique and use canonical scope order",
    )
  }
  if policy.schema_version == "1" &&
    !string_arrays_equal(policy.fail_on_scopes, all_policy_scopes()) {
    raise PolicyValidationError::InvalidPolicyField(
      field="fail_on_scopes",
      reason="schema version 1 always gates all scopes",
    )
  }
  if !is_iso_date(today) {
    raise PolicyValidationError::InvalidPolicyField(
      field="today",
      reason="must be a valid ISO date in YYYY-MM-DD form",
    )
  }
  for index, suppression in policy.suppressions {
    let prefix = "suppressions[\{index}]"
    if suppression.advisory_id.trim() == "" {
      raise PolicyValidationError::InvalidPolicyField(
        field="\{prefix}.advisory_id",
        reason="must not be empty",
      )
    }
    if suppression.package_name.trim() == "" {
      raise PolicyValidationError::InvalidPolicyField(
        field="\{prefix}.package_name",
        reason="must not be empty",
      )
    }
    if !is_stable_version(suppression.version) {
      raise PolicyValidationError::InvalidPolicyField(
        field="\{prefix}.version",
        reason="must be a stable three-part version",
      )
    }
    if suppression.reason.trim() == "" {
      raise PolicyValidationError::InvalidPolicyField(
        field="\{prefix}.reason",
        reason="must not be empty",
      )
    }
    if !is_iso_date(suppression.expires_on) {
      raise PolicyValidationError::InvalidPolicyField(
        field="\{prefix}.expires_on",
        reason="must be a valid ISO date in YYYY-MM-DD form",
      )
    }
    if lexicographic_compare(suppression.expires_on, today) < 0 {
      raise PolicyValidationError::ExpiredSuppression(
        index~,
        advisory_id=suppression.advisory_id,
        expires_on=suppression.expires_on,
      )
    }
    for previous_index in 0..<index {
      if same_suppression_key(suppression, policy.suppressions[previous_index]) {
        raise PolicyValidationError::InvalidPolicyField(
          field=prefix,
          reason="duplicates an earlier exact-match suppression",
        )
      }
    }
  }
}

///|
/// Make an empty policy for callers that only want a command-line severity gate.
pub fn empty_policy(fail_on~ : String) -> ScanPolicy {
  {
    schema_version: "2",
    fail_on,
    fail_on_scopes: all_policy_scopes(),
    suppressions: [],
  }
}

///|
fn parse_policy_scopes_field(fields : Map[String, Json]) -> Array[String] raise {
  match fields.get("fail_on_scopes") {
    Some(Array(items)) => {
      let scopes : Array[String] = []
      for index, item in items {
        match item {
          String(scope) => scopes.push(scope)
          _ =>
            raise PolicyValidationError::InvalidPolicyField(
              field="fail_on_scopes[\{index}]",
              reason="must be a string",
            )
        }
      }
      normalize_policy_scopes(scopes)
    }
    None =>
      raise PolicyValidationError::InvalidPolicyField(
        field="fail_on_scopes",
        reason="is required by schema version 2",
      )
    _ =>
      raise PolicyValidationError::InvalidPolicyField(
        field="fail_on_scopes",
        reason="must be an array of scope names",
      )
  }
}

///|
fn normalize_policy_scopes(scopes : Array[String]) -> Array[String] raise {
  let trimmed = scopes.map(fn(scope) { scope.trim().to_owned() })
  if trimmed.length() == 1 && trimmed[0] == "all" {
    return all_policy_scopes()
  }
  if trimmed.length() == 0 {
    raise PolicyValidationError::InvalidPolicyField(
      field="fail_on_scopes",
      reason="must contain at least one scope",
    )
  }
  let seen : Map[String, Bool] = Map([])
  for index, normalized in trimmed {
    if normalized == "" {
      raise PolicyValidationError::InvalidPolicyField(
        field="fail_on_scopes[\{index}]",
        reason="must not be empty",
      )
    }
    if normalized == "all" {
      raise PolicyValidationError::InvalidPolicyField(
        field="fail_on_scopes[\{index}]",
        reason="all must be the only value",
      )
    }
    if !is_policy_scope(normalized) {
      raise PolicyValidationError::InvalidPolicyField(
        field="fail_on_scopes[\{index}]",
        reason="must be runtime, test, wbtest, other, unclassified, or all",
      )
    }
    if seen.contains(normalized) {
      raise PolicyValidationError::InvalidPolicyField(
        field="fail_on_scopes[\{index}]",
        reason="duplicates an earlier scope",
      )
    }
    seen[normalized] = true
  }
  all_policy_scopes().filter(fn(scope) { seen.contains(scope) })
}

///|
fn all_policy_scopes() -> Array[String] {
  ["runtime", "test", "wbtest", "other", "unclassified"]
}

///|
fn is_policy_scope(scope : String) -> Bool {
  scope == "runtime" ||
  scope == "test" ||
  scope == "wbtest" ||
  scope == "other" ||
  scope == "unclassified"
}

///|
fn string_arrays_equal(left : Array[String], right : Array[String]) -> Bool {
  if left.length() != right.length() {
    return false
  }
  for index in 0..<left.length() {
    if left[index] != right[index] {
      return false
    }
  }
  true
}

///|
/// Apply threshold and exact-match suppressions while retaining every finding.
pub fn evaluate_policy(
  report : ScanReport,
  policy : ScanPolicy,
  fail_on_override : String?,
  today~ : String,
) -> PolicyEvaluation raise {
  evaluate_policy_with_scopes(report, policy, fail_on_override, None, today~)
}

///|
/// Apply severity, scope, baseline, and exact-match suppression rules while
/// retaining all findings in the report. A scope override replaces policy
/// scopes for this evaluation only.
pub fn evaluate_policy_with_scopes(
  report : ScanReport,
  policy : ScanPolicy,
  fail_on_override : String?,
  fail_on_scopes_override : Array[String]?,
  today~ : String,
) -> PolicyEvaluation raise {
  validate_policy(policy, today~)
  let fail_on = match fail_on_override {
    Some(value) if is_policy_severity(value) => value
    Some(_) =>
      raise PolicyValidationError::InvalidPolicyField(
        field="fail_on",
        reason="override must be one of critical, high, medium, low, info",
      )
    None => policy.fail_on
  }
  let fail_on_scopes = match fail_on_scopes_override {
    Some(scopes) => normalize_policy_scopes(scopes)
    None => policy.fail_on_scopes
  }
  let matched : Array[Bool] = policy.suppressions.map(fn(_) { false })
  let findings : Array[Finding] = []
  let mut suppressed_findings = 0
  let mut scope_excluded_findings = 0
  let mut blocking_findings = 0
  for finding in report.findings {
    let finding_scopes = finding.dependency.scopes.map(dependency_scope_name)
    let effective_finding_scopes = if finding_scopes.length() == 0 {
      ["unclassified"]
    } else {
      finding_scopes
    }
    let mut in_scope = false
    for scope in effective_finding_scopes {
      if fail_on_scopes.contains(scope) {
        in_scope = true
      }
    }
    if !in_scope {
      scope_excluded_findings += 1
    }
    let mut selected : PolicySuppression? = None
    for index, suppression in policy.suppressions {
      if selected is None && suppression_matches(suppression, finding) {
        selected = Some(suppression)
        matched[index] = true
      }
    }
    if selected is Some(_) {
      suppressed_findings += 1
    } else {
      let baseline_allows_gate = match report.baseline {
        Some(_) =>
          match finding.baseline_status {
            Some(New) | Some(Updated) => true
            _ => false
          }
        None => true
      }
      if in_scope &&
        baseline_allows_gate &&
        policy_severity_rank(finding.advisory.severity) >=
        policy_severity_rank(fail_on) {
        blocking_findings += 1
      }
    }
    findings.push({
      dependency: finding.dependency,
      advisory: finding.advisory,
      status: finding.status,
      suppression: selected,
      baseline_status: finding.baseline_status,
    })
  }
  let unmatched_suppressions : Array[PolicySuppression] = []
  for index, suppression in policy.suppressions {
    if !matched[index] {
      unmatched_suppressions.push(suppression)
    }
  }
  let policy_summary = {
    fail_on,
    fail_on_scopes,
    blocking_findings,
    scope_excluded_findings,
    suppressed_findings,
    unmatched_suppressions,
  }
  let evaluated_report = {
    schema_version: "6",
    dependencies: report.dependencies,
    findings,
    uncomparable: report.uncomparable,
    conflicts: report.conflicts,
    policy: Some(policy_summary),
    baseline: report.baseline,
  }
  { report: evaluated_report, should_fail: blocking_findings > 0 }
}

///|
fn policy_string_field(
  fields : Map[String, Json],
  field : String,
  key? : String = "",
) -> String raise {
  let lookup = if key == "" { field } else { key }
  match fields.get(lookup) {
    Some(String(value)) => value
    None =>
      raise PolicyValidationError::InvalidPolicyField(
        field~,
        reason="is required",
      )
    _ =>
      raise PolicyValidationError::InvalidPolicyField(
        field~,
        reason="must be a string",
      )
  }
}

///|
fn is_policy_severity(value : String) -> Bool {
  match value {
    "critical" | "high" | "medium" | "low" | "info" => true
    _ => false
  }
}

///|
fn policy_severity_rank(value : String) -> Int {
  match value {
    "critical" => 5
    "high" => 4
    "medium" => 3
    "low" => 2
    _ => 1
  }
}

///|
fn same_suppression_key(
  left : PolicySuppression,
  right : PolicySuppression,
) -> Bool {
  left.advisory_id == right.advisory_id &&
  left.package_name == right.package_name &&
  left.version == right.version
}

///|
fn suppression_matches(
  suppression : PolicySuppression,
  finding : Finding,
) -> Bool {
  suppression.advisory_id == finding.advisory.id &&
  suppression.package_name == finding.dependency.name &&
  suppression.version == finding.dependency.version
}

///|
fn is_iso_date(value : String) -> Bool {
  if value.length() != 10 {
    return false
  }
  let chars = value.to_array()
  if chars[4] != '-' || chars[7] != '-' {
    return false
  }
  match
    (
      date_number(chars, 0, 4),
      date_number(chars, 5, 2),
      date_number(chars, 8, 2),
    ) {
    (Some(year), Some(month), Some(day)) => {
      if year == 0 || month < 1 || month > 12 {
        return false
      }
      let days_in_month = match month {
        2 if is_leap_year(year) => 29
        2 => 28
        4 | 6 | 9 | 11 => 30
        _ => 31
      }
      day >= 1 && day <= days_in_month
    }
    _ => false
  }
}

///|
fn date_number(chars : Array[Char], start : Int, length : Int) -> Int? {
  let mut value = 0
  for index in start..<(start + length) {
    match digit_value(chars[index]) {
      Some(digit) => value = value * 10 + digit
      None => return None
    }
  }
  Some(value)
}

///|
fn is_leap_year(year : Int) -> Bool {
  year % 400 == 0 || (year % 4 == 0 && year % 100 != 0)
}
