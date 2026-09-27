///|
/// A semantic validation failure in a local advisory database.
pub(all) struct DatabaseIssue {
  index : Int
  id : String
  field : String
  reason : String
} derive(Debug, Eq)

///|
pub(all) suberror DatabaseValidationError {
  UnsupportedSchemaVersion(String)
  InvalidDatabaseField(field~ : String, reason~ : String)
  InvalidAdvisory(index~ : Int, id~ : String, field~ : String, reason~ : String)
  MultipleInvalidAdvisories(Array[DatabaseIssue])
} derive(Debug, Eq)

///|
/// Validate the supported advisory database schema and semantic constraints.
pub fn validate_database(database : AdvisoryDatabase) -> Unit raise {
  if database.schema_version != "1" {
    raise DatabaseValidationError::UnsupportedSchemaVersion(
      database.schema_version,
    )
  }
  let seen_ids : Map[String, Bool] = Map([])
  let issues : Array[DatabaseIssue] = []
  for index, advisory in database.advisories {
    let id = advisory.id.trim().to_owned()
    let display_id = if id == "" { "<missing>" } else { id }
    if id == "" {
      issues.push({
        index,
        id: display_id,
        field: "id",
        reason: "must not be empty",
      })
    } else if seen_ids.contains(id) {
      issues.push({
        index,
        id: display_id,
        field: "id",
        reason: "must be unique",
      })
    } else {
      seen_ids[id] = true
    }
    if advisory.package_name.trim() == "" {
      issues.push({
        index,
        id: display_id,
        field: "package_name",
        reason: "must not be empty",
      })
    }
    if advisory.summary.trim() == "" {
      issues.push({
        index,
        id: display_id,
        field: "summary",
        reason: "must not be empty",
      })
    }
    if !is_supported_severity(advisory.severity) {
      issues.push({
        index,
        id: display_id,
        field: "severity",
        reason: "must be one of critical, high, medium, low, info",
      })
    }
    if !is_supported_affected_range(advisory.affected) {
      issues.push({
        index,
        id: display_id,
        field: "affected",
        reason: "must use a supported stable three-part version range",
      })
    }
    if advisory.fixed_version.trim() != "" &&
      !is_stable_version(advisory.fixed_version) {
      issues.push({
        index,
        id: display_id,
        field: "fixed_version",
        reason: "must be empty or a stable three-part version",
      })
    }
    if advisory.references.length() == 0 ||
      !advisory.references.any(is_http_reference) {
      issues.push({
        index,
        id: display_id,
        field: "references",
        reason: "must include at least one valid HTTP(S) reference",
      })
    }
  }
  raise_database_issues(issues)
}

///|
fn validate_database_shape(json : Json) -> Unit raise {
  match json {
    Object(root) => {
      match root.get("schema_version") {
        Some(String(_)) => ()
        None =>
          raise DatabaseValidationError::InvalidDatabaseField(
            field="schema_version",
            reason="is required",
          )
        _ =>
          raise DatabaseValidationError::InvalidDatabaseField(
            field="schema_version",
            reason="must be a string",
          )
      }
      match root.get("advisories") {
        Some(Array(advisories)) => {
          let issues : Array[DatabaseIssue] = []
          for index, item in advisories {
            match item {
              Object(fields) => {
                let id = match fields.get("id") {
                  Some(String(value)) if value.trim() != "" => value
                  _ => "<missing>"
                }
                for
                  field in [
                    "id", "package_name", "affected", "severity", "summary", "fixed_version",
                  ] {
                  validate_database_string_field(
                    fields,
                    index~,
                    id~,
                    field,
                    issues,
                  )
                }
                validate_database_references_field(fields, index~, id~, issues)
              }
              _ =>
                issues.push({
                  index,
                  id: "<missing>",
                  field: "$",
                  reason: "must be an advisory object",
                })
            }
          }
          raise_database_issues(issues)
        }
        None =>
          raise DatabaseValidationError::InvalidDatabaseField(
            field="advisories",
            reason="is required and must be an array",
          )
        _ =>
          raise DatabaseValidationError::InvalidDatabaseField(
            field="advisories",
            reason="must be an array",
          )
      }
    }
    _ =>
      raise DatabaseValidationError::InvalidDatabaseField(
        field="$",
        reason="must be a JSON object",
      )
  }
}

///|
fn validate_database_string_field(
  fields : Map[String, Json],
  index~ : Int,
  id~ : String,
  field : String,
  issues : Array[DatabaseIssue],
) -> Unit {
  match fields.get(field) {
    None => issues.push({ index, id, field, reason: "is required", })
    Some(String(_)) => ()
    _ => issues.push({ index, id, field, reason: "must be a string", })
  }
}

///|
fn validate_database_references_field(
  fields : Map[String, Json],
  index~ : Int,
  id~ : String,
  issues : Array[DatabaseIssue],
) -> Unit {
  match fields.get("references") {
    None =>
      issues.push({ index, id, field: "references", reason: "is required", })
    Some(Array(references)) =>
      if references.any(fn(reference) {
          match reference {
            String(_) => false
            _ => true
          }
        }) {
        issues.push({
          index,
          id,
          field: "references",
          reason: "must contain only strings",
        })
      }
    _ =>
      issues.push({
        index,
        id,
        field: "references",
        reason: "must be an array of strings",
      })
  }
}

///|
fn raise_database_issues(issues : Array[DatabaseIssue]) -> Unit raise {
  if issues.length() == 1 {
    let issue = issues[0]
    raise DatabaseValidationError::InvalidAdvisory(
      index=issue.index,
      id=issue.id,
      field=issue.field,
      reason=issue.reason,
    )
  } else if issues.length() > 1 {
    raise DatabaseValidationError::MultipleInvalidAdvisories(issues)
  }
}

///|
fn is_supported_severity(value : String) -> Bool {
  match value {
    "critical" | "high" | "medium" | "low" | "info" => true
    _ => false
  }
}

///|
fn is_http_reference(reference : String) -> Bool {
  let normalized = reference.trim().to_owned().to_lower()
  if normalized.has_prefix("https://") {
    has_url_authority(normalized[8:].to_owned())
  } else if normalized.has_prefix("http://") {
    has_url_authority(normalized[7:].to_owned())
  } else {
    false
  }
}

///|
fn has_url_authority(rest : String) -> Bool {
  let authority = rest.split("/").to_array()[0].to_owned()
  let authority = authority.split("?").to_array()[0].to_owned()
  let authority = authority.split("#").to_array()[0].to_owned()
  let endpoint = authority.split("@").to_array().last().unwrap_or("").to_owned()
  if endpoint == "" || endpoint.contains(" ") || endpoint.contains("\\") {
    return false
  }
  if endpoint.has_prefix("[") {
    let bracketed = endpoint.split("]").to_array()
    if bracketed.length() < 2 || bracketed[0].length() < 4 {
      return false
    }
    let host = bracketed[0][1:].to_owned()
    if !host.contains(":") {
      return false
    }
    let suffix = bracketed[1].to_owned()
    suffix == "" ||
    (suffix.has_prefix(":") && valid_url_port(suffix[1:].to_owned()))
  } else {
    let parts = endpoint.split(":").to_array()
    let host = parts[0].to_owned()
    if !valid_url_host(host) || parts.length() > 2 {
      return false
    }
    parts.length() == 1 || valid_url_port(parts[1].to_owned())
  }
}

///|
fn valid_url_host(host : String) -> Bool {
  if host == "" ||
    host == "." ||
    host.has_prefix(".") ||
    host.has_suffix(".") ||
    host.contains("..") {
    return false
  }
  for char in host {
    match char {
      'a'..='z' | '0'..='9' | '.' | '-' => ()
      _ => return false
    }
  }
  true
}

///|
fn valid_url_port(port : String) -> Bool {
  if port == "" || port.length() > 5 {
    return false
  }
  let mut value = 0
  for char in port {
    match digit_value(char) {
      Some(digit) => value = value * 10 + digit
      None => return false
    }
  }
  value > 0 && value <= 65535
}
