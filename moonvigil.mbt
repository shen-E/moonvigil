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
  { dependencies, findings, uncomparable }
}

///|
pub fn report_json(report : ScanReport) -> String {
  @json.to_json(report).stringify(indent=2)
}

///|
pub fn report_terminal(report : ScanReport) -> String {
  let lines = [
    "MoonVigil offline scan",
    "Dependencies: \{report.dependencies.length()}",
    "Affected: \{report.findings.length()}",
    "Uncomparable: \{report.uncomparable.length()}",
  ]
  let details = report.findings.map(fn(finding) {
    "[\{finding.advisory.severity}] \{finding.advisory.id} \{finding.dependency.name}@\{finding.dependency.version}: \{finding.advisory.summary}"
  })
  lines.append(details)
  lines.join("\n")
}

///|
pub fn report_sarif(report : ScanReport) -> String {
  let results = report.findings.map(fn(finding) {
    Json::object({
      "ruleId": Json::string(finding.advisory.id),
      "level": Json::string(sarif_level(finding.advisory.severity)),
      "message": Json::object({ "text": Json::string(finding.advisory.summary) }),
      "locations": Json::array([
        Json::object({
          "physicalLocation": Json::object({
            "artifactLocation": Json::object({
              "uri": Json::string(finding.dependency.source),
            }),
          }),
        }),
      ]),
    })
  })
  Json::object({
    "version": Json::string("2.1.0"),
    "$schema": Json::string("https://json.schemastore.org/sarif-2.1.0.json"),
    "runs": Json::array([
      Json::object({
        "tool": Json::object({
          "driver": Json::object({ "name": Json::string("MoonVigil") }),
        }),
        "results": Json::array(results),
      }),
    ]),
  }).stringify(indent=2)
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
