///|
fn main {
  dispatch(@env.args()) catch {
    @vigil.BaselineValidationError::UnsupportedBaselineSchemaVersion(version) => {
      println(
        "MoonVigil error: baseline schema_version must be \"1\", got \"\{version}\"",
      )
      exit_with_status(2)
    }
    @vigil.BaselineValidationError::InvalidBaselineField(field~, reason~) => {
      println("MoonVigil error: baseline field \{field}: \{reason}")
      exit_with_status(2)
    }
    @vigil.BaselineValidationError::InvalidBaselineEntry(
      index~,
      field~,
      reason~
    ) => {
      println(
        "MoonVigil error: baseline entry #\{index} field \{field}: \{reason}",
      )
      exit_with_status(2)
    }
    @vigil.BaselineValidationError::DuplicateBaselineEntry(index~, advisory_id~) => {
      println(
        "MoonVigil error: baseline entry #\{index} duplicates \{advisory_id}",
      )
      exit_with_status(2)
    }
    @vigil.DatabaseValidationError::UnsupportedSchemaVersion(version) => {
      println(
        "MoonVigil error: advisory database schema_version must be \"1\", got \"\{version}\"",
      )
      exit_with_status(2)
    }
    @vigil.DatabaseValidationError::InvalidDatabaseField(field~, reason~) => {
      println("MoonVigil error: advisory database field \{field}: \{reason}")
      exit_with_status(2)
    }
    @vigil.DatabaseValidationError::InvalidAdvisory(
      index~,
      id~,
      field~,
      reason~
    ) => {
      println(
        "MoonVigil error: advisory #\{index} (\{id}) field \{field}: \{reason}",
      )
      exit_with_status(2)
    }
    @vigil.DatabaseValidationError::MultipleInvalidAdvisories(issues) => {
      for issue in issues {
        println(
          "MoonVigil error: advisory #\{issue.index} (\{issue.id}) field \{issue.field}: \{issue.reason}",
        )
      }
      exit_with_status(2)
    }
    @vigil.ManifestParseError::InvalidManifest(source~, line~, reason~) => {
      println("MoonVigil error: \{source}:\{line}: \{reason}")
      exit_with_status(2)
    }
    @vigil.PolicyValidationError::InvalidPolicyField(field~, reason~) => {
      println("MoonVigil error: policy field \{field}: \{reason}")
      exit_with_status(2)
    }
    @vigil.PolicyValidationError::ExpiredSuppression(
      index~,
      advisory_id~,
      expires_on~
    ) => {
      println(
        "MoonVigil error: suppression #\{index} (\{advisory_id}) expired on \{expires_on}",
      )
      exit_with_status(2)
    }
    error => {
      println("MoonVigil error: \{error}")
      exit_with_status(2)
    }
  }
}

///|
fn dispatch(args : Array[String]) -> Unit raise {
  match args {
    [_, "scan", path, .. rest] => scan_command(path, rest.to_owned())
    [_, "sbom", path, .. rest] => sbom_command(path, rest.to_owned())
    [_, "db", "validate", database, ..] => validate_database(database)
    _ => {
      print_usage()
      exit_with_status(2)
    }
  }
}

///|
fn scan_command(path : String, rest : Array[String]) -> Unit raise {
  if !options_are_valid(rest, [
      "--db", "--format", "--output", "--policy", "--fail-on", "--baseline", "--baseline-output",
    ]) {
    println("MoonVigil error: invalid scan option or missing option value")
    print_usage()
    exit_with_status(2)
  }
  if !@fs.path_exists(path) {
    println("MoonVigil error: scan path does not exist: \{path}")
    exit_with_status(2)
  }
  let database_path = option_value(rest, "--db").unwrap_or("advisories.json")
  let format_name = option_value(rest, "--format").unwrap_or("terminal")
  let output = option_value(rest, "--output")
  let policy_path = option_value(rest, "--policy")
  let fail_on_override = option_value(rest, "--fail-on")
  let baseline_path = option_value(rest, "--baseline")
  let baseline_output_path = option_value(rest, "--baseline-output")
  let baseline_conflicts_with_output = match baseline_path {
    Some(input_path) => {
      let report_conflict = match output {
        Some(report_path) => report_path == input_path
        None => false
      }
      let snapshot_conflict = match baseline_output_path {
        Some(snapshot_path) => snapshot_path == input_path
        None => false
      }
      report_conflict || snapshot_conflict
    }
    None => false
  }
  let outputs_conflict = match (output, baseline_output_path) {
    (Some(report_path), Some(snapshot_path)) => report_path == snapshot_path
    _ => false
  }
  if baseline_conflicts_with_output || outputs_conflict {
    println("MoonVigil error: baseline and output paths must be distinct")
    exit_with_status(2)
  }
  let database = read_database(database_path)
  let dependencies = discover_dependencies(path)
  let base_report = @vigil.scan(dependencies, database)
  let compared_report = match baseline_path {
    Some(file) =>
      @vigil.apply_baseline(
        base_report,
        @vigil.parse_baseline(@fs.read_file_to_string(file)),
      )
    None => base_report
  }
  let report = match (policy_path, fail_on_override) {
    (Some(policy_file), threshold_override) => {
      let today = utc_today()
      let policy = @vigil.parse_policy(
        @fs.read_file_to_string(policy_file),
        today~,
      )
      @vigil.evaluate_policy(
        compared_report,
        policy,
        threshold_override,
        today~,
      ).report
    }
    (None, Some(threshold)) => {
      let today = utc_today()
      let policy = @vigil.empty_policy(fail_on="info")
      @vigil.evaluate_policy(compared_report, policy, Some(threshold), today~).report
    }
    (None, None) => compared_report
  }
  let content = match format_name {
    "terminal" => @vigil.report_terminal(report)
    "json" => @vigil.report_json(report)
    "sarif" => @vigil.report_sarif(report)
    _ => {
      println("MoonVigil error: unsupported format: \{format_name}")
      exit_with_status(2)
      ""
    }
  }
  write_or_print(content, output)
  match baseline_output_path {
    Some(file) =>
      write_or_print(
        @vigil.baseline_json(@vigil.baseline_from_report(base_report)),
        Some(file),
      )
    None => ()
  }
  let blocking = match report.policy {
    Some(policy) => policy.blocking_findings > 0
    None =>
      match report.baseline {
        Some(baseline) => baseline.new_findings > 0
        None => report.findings.length() > 0
      }
  }
  exit_with_status(if blocking { 1 } else { 0 })
}

///|
fn sbom_command(path : String, rest : Array[String]) -> Unit raise {
  if !options_are_valid(rest, ["--output"]) {
    println("MoonVigil error: invalid sbom option or missing option value")
    print_usage()
    exit_with_status(2)
  }
  if !@fs.path_exists(path) {
    println("MoonVigil error: sbom path does not exist: \{path}")
    exit_with_status(2)
  }
  write_or_print(
    @vigil.sbom_json(discover_dependencies(path)),
    option_value(rest, "--output"),
  )
}

///|
fn validate_database(path : String) -> Unit raise {
  let database = read_database(path)
  println(
    "valid advisory database v\{database.schema_version}: \{database.advisories.length()} advisories",
  )
}

///|
fn read_database(path : String) -> @vigil.AdvisoryDatabase raise {
  @vigil.parse_database(@fs.read_file_to_string(path))
}

///|
fn write_or_print(content : String, output : String?) -> Unit raise {
  match output {
    Some(file) => ignore(@fs.write_string_to_file(file, content))
    None => println(content)
  }
}

///|
fn discover_dependencies(path : String) -> Array[@vigil.Dependency] raise {
  let manifests : Array[String] = []
  collect_manifests(path, manifests)
  let dependencies : Array[@vigil.Dependency] = []
  let package_imports : Array[@vigil.PackageImport] = []
  for manifest in manifests {
    let source = relative_manifest_path(path, manifest)
    let text = @fs.read_file_to_string(manifest)
    if manifest.has_suffix("moon.mod") {
      for dependency in @vigil.parse_moon_mod(text, source~) {
        dependencies.push(dependency)
      }
    } else if manifest.has_suffix("moon.pkg") {
      for package_import in @vigil.parse_moon_pkg(text, source~) {
        package_imports.push(package_import)
      }
    } else {
      for dependency in @vigil.parse_manifest(text, source~) {
        dependencies.push(dependency)
      }
    }
  }
  let inventory = @vigil.inventory_from_dependencies(dependencies).dependencies
  @vigil.apply_package_imports(inventory, package_imports)
}

///|
fn collect_manifests(path : String, manifests : Array[String]) -> Unit raise {
  if @fs.is_file(path) {
    if (
        path.has_suffix("moon.mod") ||
        path.has_suffix("moon.pkg") ||
        path.has_suffix("moon.mod.json") ||
        path.has_suffix("moon.pkg.json")
      ) &&
      !is_shadowed_legacy_manifest(path) {
      manifests.push(path)
    }
  } else if @fs.is_dir(path) {
    let entries = @fs.read_dir(path).to_owned()
    entries.sort()
    for entry in entries {
      if !is_ignored_directory(entry) {
        collect_manifests("\{path}/\{entry}", manifests)
      }
    }
  }
}

///|
fn is_shadowed_legacy_manifest(path : String) -> Bool {
  if !path.has_suffix(".json") {
    return false
  }
  let parts = normalize_path_separators(path).split("/").to_array()
  if parts.length() < 2 {
    return false
  }
  let mut parent = parts[0].to_owned()
  for index in 1..<(parts.length() - 1) {
    parent = "\{parent}/\{parts[index]}"
  }
  let modern_name = if path.has_suffix("moon.mod.json") {
    "moon.mod"
  } else if path.has_suffix("moon.pkg.json") {
    "moon.pkg"
  } else {
    ""
  }
  modern_name != "" && @fs.path_exists("\{parent}/\{modern_name}")
}

///|
fn relative_manifest_path(root : String, manifest : String) -> String {
  let normalized_root = normalize_path_separators(root)
  let normalized_manifest = normalize_path_separators(manifest)
  if normalized_manifest.has_prefix("\{normalized_root}/") {
    normalized_manifest[normalized_root.length() + 1:].to_owned()
  } else if normalized_manifest == normalized_root {
    normalized_manifest
    .split("/")
    .to_array()
    .last()
    .unwrap_or("manifest")
    .to_owned()
  } else {
    normalized_manifest
  }
}

///|
fn normalize_path_separators(path : String) -> String {
  path.split("\\").to_array().join("/")
}

///|
fn is_ignored_directory(entry : String) -> Bool {
  entry == ".git" ||
  entry == ".mooncakes" ||
  entry == ".repos" ||
  entry == "_build"
}

///|
fn option_value(args : Array[String], option : String) -> String? {
  for index in 0..<args.length() {
    if args[index] == option && index + 1 < args.length() {
      return Some(args[index + 1])
    }
  }
  None
}

///|
fn options_are_valid(args : Array[String], allowed : Array[String]) -> Bool {
  let seen : Map[String, Bool] = Map([])
  let mut index = 0
  while index < args.length() {
    let option = args[index]
    if !allowed.contains(option) ||
      seen.contains(option) ||
      index + 1 >= args.length() ||
      args[index + 1].has_prefix("--") {
      return false
    }
    seen[option] = true
    index += 2
  }
  true
}

///|
fn utc_today() -> String {
  let days_since_epoch = (@env.now() / 86400000UL).to_int()
  let shifted_days = days_since_epoch + 719468
  let era = shifted_days / 146097
  let day_of_era = shifted_days - era * 146097
  let year_of_era = (
      day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096
    ) /
    365
  let mut year = year_of_era + era * 400
  let day_of_year = day_of_era -
    (365 * year_of_era + year_of_era / 4 - year_of_era / 100)
  let month_part = (5 * day_of_year + 2) / 153
  let day = day_of_year - (153 * month_part + 2) / 5 + 1
  let month = if month_part < 10 { month_part + 3 } else { month_part - 9 }
  if month <= 2 {
    year += 1
  }
  "\{year}-\{two_digits(month)}-\{two_digits(day)}"
}

///|
fn two_digits(value : Int) -> String {
  if value < 10 {
    "0\{value}"
  } else {
    value.to_string()
  }
}

///|
fn print_usage() -> Unit {
  println("MoonVigil — offline MoonBit dependency scanner")
  println(
    "  moon run cmd/main -- scan <path> [--db advisories.json] [--format terminal|json|sarif] [--output file] [--policy file] [--fail-on critical|high|medium|low|info] [--baseline file] [--baseline-output file]",
  )
  println("  moon run cmd/main -- sbom <path> [--output file]")
  println("  moon run cmd/main -- db validate <advisories.json>")
}
