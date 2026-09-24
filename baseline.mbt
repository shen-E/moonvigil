///|
/// A portable baseline key. It deliberately contains no project paths.
pub struct BaselineEntry {
  advisory_id : String
  package_name : String
  version : String
} derive(Debug, Eq, ToJson, FromJson)

///|
/// A validated, versioned snapshot of affected direct dependencies.
pub struct ScanBaseline {
  schema_version : String
  entries : Array[BaselineEntry]
} derive(Debug, Eq, ToJson, FromJson)

///|
pub(all) suberror BaselineValidationError {
  UnsupportedBaselineSchemaVersion(String)
  InvalidBaselineField(field~ : String, reason~ : String)
  InvalidBaselineEntry(index~ : Int, field~ : String, reason~ : String)
  DuplicateBaselineEntry(index~ : Int, advisory_id~ : String)
} derive(Debug, Eq)

///|
/// Parse and strictly validate a schema-v1 baseline snapshot.
pub fn parse_baseline(text : String) -> ScanBaseline raise {
  let json = @json.parse(text)
  validate_baseline_shape(json)
  let baseline : ScanBaseline = @json.from_json(json)
  validate_baseline(baseline)
  baseline
}

///|
/// Validate a baseline created by a caller or deserializer.
pub fn validate_baseline(baseline : ScanBaseline) -> Unit raise {
  if baseline.schema_version != "1" {
    raise BaselineValidationError::UnsupportedBaselineSchemaVersion(
      baseline.schema_version,
    )
  }
  for index, entry in baseline.entries {
    if entry.advisory_id.trim() == "" {
      raise BaselineValidationError::InvalidBaselineEntry(
        index~,
        field="advisory_id",
        reason="must not be empty",
      )
    }
    if entry.package_name.trim() == "" {
      raise BaselineValidationError::InvalidBaselineEntry(
        index~,
        field="package_name",
        reason="must not be empty",
      )
    }
    if !is_stable_version(entry.version) {
      raise BaselineValidationError::InvalidBaselineEntry(
        index~,
        field="version",
        reason="must be a stable three-part version",
      )
    }
    for previous_index in 0..<index {
      if baseline_entry_equal(entry, baseline.entries[previous_index]) {
        raise BaselineValidationError::DuplicateBaselineEntry(
          index~,
          advisory_id=entry.advisory_id,
        )
      }
    }
  }
}

///|
/// Build a deterministic snapshot from affected findings only.
/// Uncomparable versions are omitted because they cannot be matched safely.
pub fn baseline_from_report(report : ScanReport) -> ScanBaseline {
  let entries : Array[BaselineEntry] = []
  for finding in report.findings {
    if finding.status is Affected {
      let entry = {
        advisory_id: finding.advisory.id,
        package_name: finding.dependency.name,
        version: finding.dependency.version,
      }
      if !entries.any(fn(existing) { baseline_entry_equal(existing, entry) }) {
        entries.push(entry)
      }
    }
  }
  entries.sort_by(baseline_entry_compare)
  { schema_version: "1", entries }
}

///|
/// Serialize a validated snapshot as stable, indented JSON.
pub fn baseline_json(baseline : ScanBaseline) -> String raise {
  validate_baseline(baseline)
  @json.to_json(baseline).stringify(indent=2)
}

///|
fn validate_baseline_shape(json : Json) -> Unit raise {
  match json {
    Object(root) => {
      match root.get("schema_version") {
        Some(String(_)) => ()
        None =>
          raise BaselineValidationError::InvalidBaselineField(
            field="schema_version",
            reason="is required",
          )
        _ =>
          raise BaselineValidationError::InvalidBaselineField(
            field="schema_version",
            reason="must be a string",
          )
      }
      match root.get("entries") {
        Some(Array(entries)) =>
          for index, entry in entries {
            match entry {
              Object(fields) =>
                for field in ["advisory_id", "package_name", "version"] {
                  match fields.get(field) {
                    Some(String(_)) => ()
                    None =>
                      raise BaselineValidationError::InvalidBaselineEntry(
                        index~,
                        field~,
                        reason="is required",
                      )
                    _ =>
                      raise BaselineValidationError::InvalidBaselineEntry(
                        index~,
                        field~,
                        reason="must be a string",
                      )
                  }
                }
              _ =>
                raise BaselineValidationError::InvalidBaselineEntry(
                  index~,
                  field="$",
                  reason="must be an object",
                )
            }
          }
        None =>
          raise BaselineValidationError::InvalidBaselineField(
            field="entries",
            reason="is required and must be an array",
          )
        _ =>
          raise BaselineValidationError::InvalidBaselineField(
            field="entries",
            reason="must be an array",
          )
      }
    }
    _ =>
      raise BaselineValidationError::InvalidBaselineField(
        field="$",
        reason="must be a JSON object",
      )
  }
}

///|
fn baseline_entry_equal(left : BaselineEntry, right : BaselineEntry) -> Bool {
  left.advisory_id == right.advisory_id &&
  left.package_name == right.package_name &&
  left.version == right.version
}

///|
fn baseline_entry_compare(left : BaselineEntry, right : BaselineEntry) -> Int {
  let advisory = lexicographic_compare(left.advisory_id, right.advisory_id)
  if advisory != 0 {
    return advisory
  }
  let package_order = lexicographic_compare(
    left.package_name,
    right.package_name,
  )
  if package_order != 0 {
    return package_order
  }
  lexicographic_compare(left.version, right.version)
}
