///|
/// Offline dependency vulnerability matching for MoonBit projects.
pub struct Dependency {
  name : String
  version : String
  source : String
} derive(Debug, Eq, ToJson)

///|
pub fn Dependency::Dependency(
  name~ : String,
  version~ : String,
  source~ : String,
) -> Dependency {
  { name, version, source }
}

///|
/// A deterministic, de-duplicated dependency inventory.
pub struct Inventory {
  dependencies : Array[Dependency]
} derive(Debug, Eq, ToJson)

///|
/// Normalise declarations into a deterministic inventory.
///
/// Declarations with the same package name and version are represented once.
/// A canonical manifest path becomes the evidence location.
pub fn inventory_from_dependencies(
  dependencies : Array[Dependency],
) -> Inventory {
  let normalized : Array[Dependency] = []
  for dependency in dependencies {
    let mut duplicate : Int? = None
    for index in 0..<normalized.length() {
      let existing = normalized[index]
      if existing.name == dependency.name &&
        existing.version == dependency.version {
        duplicate = Some(index)
      }
    }
    match duplicate {
      Some(index) =>
        if dependency.source.compare(normalized[index].source) < 0 {
          normalized[index] = dependency
        }
      None => normalized.push(dependency)
    }
  }
  let ordered : Array[Dependency] = []
  for dependency in normalized {
    let mut insert_at = ordered.length()
    for index in 0..<ordered.length() {
      if insert_at == ordered.length() &&
        dependency_compare(dependency, ordered[index]) < 0 {
        insert_at = index
      }
    }
    ordered.insert(insert_at, dependency)
  }
  { dependencies: ordered }
}

///|
fn dependency_compare(left : Dependency, right : Dependency) -> Int {
  let by_name = left.name.compare(right.name)
  if by_name != 0 {
    by_name
  } else {
    let by_version = left.version.compare(right.version)
    if by_version != 0 {
      by_version
    } else {
      left.source.compare(right.source)
    }
  }
}

///|
pub struct Advisory {
  id : String
  package_name : String
  affected : String
  severity : String
  summary : String
  fixed_version : String
  references : Array[String]
} derive(Debug, Eq, ToJson, FromJson)

///|
pub struct AdvisoryDatabase {
  schema_version : String
  advisories : Array[Advisory]
} derive(Debug, Eq, ToJson, FromJson)

///|
pub enum FindingStatus {
  Affected
  NotAffected
  Uncomparable
} derive(Debug, Eq, ToJson)

///|
pub struct Finding {
  dependency : Dependency
  advisory : Advisory
  status : FindingStatus
} derive(Debug, Eq, ToJson)

///|
pub struct ScanReport {
  schema_version : String
  dependencies : Array[Dependency]
  findings : Array[Finding]
  uncomparable : Array[Finding]
} derive(Debug, Eq, ToJson)

///|
pub fn parse_database(text : String) -> AdvisoryDatabase raise {
  @json.from_json(@json.parse(text))
}

///|
pub fn parse_manifest(
  text : String,
  source~ : String,
) -> Array[Dependency] raise {
  let object : Map[String, Json] = @json.from_json(@json.parse(text))
  let result : Array[Dependency] = []
  match object.get("import") {
    Some(Object(imports)) =>
      for name, value in imports {
        match value {
          String(version) => result.push({ name, version, source })
          _ => ()
        }
      }
    _ => ()
  }
  result
}

///|
pub fn scan(
  dependencies : Array[Dependency],
  database : AdvisoryDatabase,
) -> ScanReport {
  let findings : Array[Finding] = []
  let uncomparable : Array[Finding] = []
  for dependency in dependencies {
    for advisory in database.advisories {
      if dependency.name == advisory.package_name {
        let status = match_version(dependency.version, advisory.affected)
        let finding = { dependency, advisory, status }
        match status {
          Affected => findings.push(finding)
          Uncomparable => uncomparable.push(finding)
          NotAffected => ()
        }
      }
    }
  }
  { schema_version: "1", dependencies, findings, uncomparable }
}

///|
pub fn report_json(report : ScanReport) -> String {
  @json.to_json(report).stringify(indent=2)
}

///|
pub fn report_terminal(report : ScanReport) -> String {
  let lines = [
    "MoonVigil offline scan",
    "Report schema: v\{report.schema_version}",
    "Dependencies: \{report.dependencies.length()}",
    "Affected: \{report.findings.length()}",
    "Uncomparable: \{report.uncomparable.length()}",
  ]
  for finding in report.findings {
    lines.push(terminal_finding(finding, "affected"))
  }
  for finding in report.uncomparable {
    lines.push(terminal_finding(finding, "uncomparable"))
  }
  lines.join("\n")
}

///|
pub fn report_sarif(report : ScanReport) -> String {
  let results : Array[Json] = []
  let rules : Array[Json] = []
  let seen_rules : Map[String, Bool] = Map([])
  for finding in report.findings {
    results.push(sarif_result(finding))
    add_sarif_rule(rules, seen_rules, finding.advisory)
  }
  for finding in report.uncomparable {
    results.push(sarif_result(finding))
    add_sarif_rule(rules, seen_rules, finding.advisory)
  }
  Json::object({
    "version": Json::string("2.1.0"),
    "$schema": Json::string("https://json.schemastore.org/sarif-2.1.0.json"),
    "runs": Json::array([
      Json::object({
        "tool": Json::object({
          "driver": Json::object({
            "name": Json::string("MoonVigil"),
            "rules": Json::array(rules),
          }),
        }),
        "results": Json::array(results),
      }),
    ]),
  }).stringify(indent=2)
}

///|
fn terminal_finding(finding : Finding, status : String) -> String {
  let fixed_version = if finding.advisory.fixed_version == "" {
    "not available"
  } else {
    finding.advisory.fixed_version
  }
  let references = if finding.advisory.references.length() == 0 {
    "none"
  } else {
    finding.advisory.references.join(", ")
  }
  (
    $|[\{status}] [\{finding.advisory.severity}] \{finding.advisory.id}
    $|  package: \{finding.dependency.name}
    $|  installed: \{finding.dependency.version}
    $|  affected: \{finding.advisory.affected}
    $|  fixed: \{fixed_version}
    $|  source: \{finding.dependency.source}
    $|  summary: \{finding.advisory.summary}
    $|  references: \{references}
  )
}

///|
fn sarif_result(finding : Finding) -> Json {
  let level = match finding.status {
    Affected => sarif_level(finding.advisory.severity)
    Uncomparable => "note"
    NotAffected => "none"
  }
  let message = match finding.status {
    Affected => finding.advisory.summary
    Uncomparable =>
      "MoonVigil could not compare the installed version against this advisory range."
    NotAffected => finding.advisory.summary
  }
  Json::object({
    "ruleId": Json::string(finding.advisory.id),
    "level": Json::string(level),
    "message": Json::object({ "text": Json::string(message) }),
    "locations": Json::array([
      Json::object({
        "physicalLocation": Json::object({
          "artifactLocation": Json::object({
            "uri": Json::string(finding.dependency.source),
          }),
        }),
      }),
    ]),
    "properties": Json::object({
      "package": Json::string(finding.dependency.name),
      "installedVersion": Json::string(finding.dependency.version),
      "affectedRange": Json::string(finding.advisory.affected),
      "fixedVersion": Json::string(finding.advisory.fixed_version),
      "references": Json::array(finding.advisory.references.map(Json::string)),
      "matchStatus": Json::string(match_status_name(finding.status)),
    }),
  })
}

///|
fn add_sarif_rule(
  rules : Array[Json],
  seen_rules : Map[String, Bool],
  advisory : Advisory,
) -> Unit {
  if !seen_rules.contains(advisory.id) {
    seen_rules[advisory.id] = true
    let rule : Map[String, Json] = {
      "id": Json::string(advisory.id),
      "shortDescription": Json::object({
        "text": Json::string(advisory.summary),
      }),
      "fullDescription": Json::object({ "text": Json::string(advisory.summary) }),
    }
    if advisory.references.length() > 0 {
      rule["helpUri"] = Json::string(advisory.references[0])
    }
    rules.push(Json::object(rule))
  }
}

///|
fn match_status_name(status : FindingStatus) -> String {
  match status {
    Affected => "affected"
    NotAffected => "not_affected"
    Uncomparable => "uncomparable"
  }
}

///|
pub fn sbom_json(dependencies : Array[Dependency]) -> String {
  let components = dependencies.map(fn(dependency) {
    Json::object({
      "type": Json::string("library"),
      "name": Json::string(dependency.name),
      "version": Json::string(dependency.version),
      "purl": Json::string(
        "pkg:moonbit/\{dependency.name}@\{dependency.version}",
      ),
    })
  })
  Json::object({
    "bomFormat": Json::string("CycloneDX"),
    "specVersion": Json::string("1.5"),
    "components": Json::array(components),
  }).stringify(indent=2)
}

///|
fn sarif_level(severity : String) -> String {
  match severity.to_lower() {
    "critical" | "high" => "error"
    "medium" => "warning"
    _ => "note"
  }
}
