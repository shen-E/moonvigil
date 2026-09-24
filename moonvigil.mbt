///|
/// Offline dependency vulnerability matching for MoonBit projects.
pub struct Dependency {
  name : String
  version : String
  source : String
  aliases : Array[String]
  scopes : Array[DependencyScope]
} derive(Debug, Eq, ToJson)

///|
pub fn Dependency::Dependency(
  name~ : String,
  version~ : String,
  source~ : String,
  aliases? : Array[String] = [],
  scopes? : Array[DependencyScope] = [],
) -> Dependency {
  { name, version, source, aliases, scopes, }
}

///|
/// A declared module with multiple versions in the scanned project tree.
pub struct DependencyConflict {
  name : String
  versions : Array[String]
  sources : Array[String]
} derive(Debug, Eq, ToJson)

///|
/// A deterministic, de-duplicated dependency inventory.
pub struct Inventory {
  dependencies : Array[Dependency]
  conflicts : Array[DependencyConflict]
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
      Some(index) => {
        let existing = normalized[index]
        let aliases = merge_strings(existing.aliases, dependency.aliases)
        let scopes = merge_scopes(existing.scopes, dependency.scopes)
        let source = if lexicographic_compare(
            dependency.source,
            existing.source,
          ) <
          0 {
          dependency.source
        } else {
          existing.source
        }
        normalized[index] = Dependency(
          name=existing.name,
          version=existing.version,
          source~,
          aliases~,
          scopes~,
        )
      }
      None => normalized.push(dependency)
    }
  }
  normalized.sort_by(dependency_compare)
  { dependencies: normalized, conflicts: dependency_conflicts(normalized), }
}

///|
/// Find modules declared at more than one version and sort their evidence.
pub fn dependency_conflicts(
  dependencies : Array[Dependency],
) -> Array[DependencyConflict] {
  let conflicts : Array[DependencyConflict] = []
  let seen : Map[String, Bool] = Map([])
  for dependency in dependencies {
    if !seen.contains(dependency.name) {
      seen[dependency.name] = true
      let versions : Array[String] = []
      let sources : Array[String] = []
      for candidate in dependencies {
        if candidate.name == dependency.name {
          if !versions.contains(candidate.version) {
            versions.push(candidate.version)
          }
          if !sources.contains(candidate.source) {
            sources.push(candidate.source)
          }
        }
      }
      if versions.length() > 1 {
        versions.sort_by(lexicographic_compare)
        sources.sort_by(lexicographic_compare)
        conflicts.push({ name: dependency.name, versions, sources, })
      }
    }
  }
  conflicts
}

///|
fn merge_scopes(
  left : Array[DependencyScope],
  right : Array[DependencyScope],
) -> Array[DependencyScope] {
  let result : Array[DependencyScope] = []
  for scope in left {
    if !result.any(fn(existing) { existing == scope }) {
      result.push(scope)
    }
  }
  for scope in right {
    if !result.any(fn(existing) { existing == scope }) {
      result.push(scope)
    }
  }
  result
}

///|
fn merge_strings(left : Array[String], right : Array[String]) -> Array[String] {
  let result : Array[String] = []
  for value in left {
    if value != "" && !result.contains(value) {
      result.push(value)
    }
  }
  for value in right {
    if value != "" && !result.contains(value) {
      result.push(value)
    }
  }
  result.sort_by(lexicographic_compare)
  result
}

///|
fn dependency_compare(left : Dependency, right : Dependency) -> Int {
  let by_name = lexicographic_compare(left.name, right.name)
  if by_name != 0 {
    by_name
  } else {
    let by_version = lexicographic_compare(left.version, right.version)
    if by_version != 0 {
      by_version
    } else {
      lexicographic_compare(left.source, right.source)
    }
  }
}

///|
fn lexicographic_compare(left : String, right : String) -> Int {
  let left_chars = left.to_array()
  let right_chars = right.to_array()
  let common_length = if left_chars.length() < right_chars.length() {
    left_chars.length()
  } else {
    right_chars.length()
  }
  for index in 0..<common_length {
    let compared = left_chars[index].compare(right_chars[index])
    if compared != 0 {
      return compared
    }
  }
  if left_chars.length() < right_chars.length() {
    -1
  } else if left_chars.length() > right_chars.length() {
    1
  } else {
    0
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
  conflicts : Array[DependencyConflict]
} derive(Debug, Eq, ToJson)

///|
pub fn parse_database(text : String) -> AdvisoryDatabase raise {
  let json = @json.parse(text)
  validate_database_shape(json)
  let database : AdvisoryDatabase = @json.from_json(json)
  validate_database(database)
  database
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
          String(version) =>
            result.push({ name, version, source, aliases: [], scopes: [], })
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
) -> ScanReport raise {
  validate_database(database)
  let findings : Array[Finding] = []
  let uncomparable : Array[Finding] = []
  for dependency in dependencies {
    for advisory in database.advisories {
      if dependency.name == advisory.package_name {
        let status = match_version(dependency.version, advisory.affected)
        let finding = { dependency, advisory, status, }
        match status {
          Affected => findings.push(finding)
          Uncomparable => uncomparable.push(finding)
          NotAffected => ()
        }
      }
    }
  }
  {
    schema_version: "2",
    dependencies,
    findings,
    uncomparable,
    conflicts: dependency_conflicts(dependencies),
  }
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
    "Conflicting modules: \{report.conflicts.length()}",
  ]
  for conflict in report.conflicts {
    let versions = conflict.versions.join(", ")
    let sources = conflict.sources.join(", ")
    lines.push(
      "dependency conflict: \{conflict.name} versions \{versions} (sources: \{sources})",
    )
  }
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
  let run_properties : Map[String, Json] = {
    "dependencyConflicts": Json::array(
      report.conflicts.map(dependency_conflict_json),
    ),
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
        "properties": Json::object(run_properties),
      }),
    ]),
  }).stringify(indent=2)
}

///|
fn dependency_conflict_json(conflict : DependencyConflict) -> Json {
  Json::object({
    "package": Json::string(conflict.name),
    "versions": Json::array(conflict.versions.map(Json::string)),
    "sources": Json::array(conflict.sources.map(Json::string)),
  })
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
    $|  aliases: \{finding.dependency.aliases.join(", ")}
    $|  scopes: \{dependency_scopes_text(finding.dependency.scopes)}
    $|  summary: \{finding.advisory.summary}
    $|  references: \{references}
  )
}

///|
fn dependency_scopes_text(scopes : Array[DependencyScope]) -> String {
  if scopes.length() == 0 {
    "unclassified"
  } else {
    scopes.map(dependency_scope_name).join(", ")
  }
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
  let properties : Map[String, Json] = {
    "package": Json::string(finding.dependency.name),
    "installedVersion": Json::string(finding.dependency.version),
    "affectedRange": Json::string(finding.advisory.affected),
    "fixedVersion": Json::string(finding.advisory.fixed_version),
    "aliases": Json::array(finding.dependency.aliases.map(Json::string)),
    "scopes": Json::array(
      finding.dependency.scopes.map(fn(scope) {
        Json::string(dependency_scope_name(scope))
      }),
    ),
    "references": Json::array(finding.advisory.references.map(Json::string)),
    "matchStatus": Json::string(match_status_name(finding.status)),
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
    "properties": Json::object(properties),
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
      "properties": Json::array(dependency_properties(dependency)),
    })
  })
  Json::object({
    "bomFormat": Json::string("CycloneDX"),
    "specVersion": Json::string("1.5"),
    "components": Json::array(components),
  }).stringify(indent=2)
}

///|
fn dependency_properties(dependency : Dependency) -> Array[Json] {
  let properties : Array[Json] = []
  for alias_name in dependency.aliases {
    properties.push(
      Json::object({
        "name": Json::string("moonvigil:import-alias"),
        "value": Json::string(alias_name),
      }),
    )
  }
  for scope in dependency.scopes {
    properties.push(
      Json::object({
        "name": Json::string("moonvigil:dependency-scope"),
        "value": Json::string(dependency_scope_name(scope)),
      }),
    )
  }
  properties
}

///|
fn sarif_level(severity : String) -> String {
  match severity.to_lower() {
    "critical" | "high" => "error"
    "medium" => "warning"
    _ => "note"
  }
}
