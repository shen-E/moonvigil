///|
fn main {
  dispatch(@env.args()) catch {
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
  if !@fs.path_exists(path) {
    println("MoonVigil error: scan path does not exist: \{path}")
    exit_with_status(2)
  }
  let database_path = option_value(rest, "--db").unwrap_or("advisories.json")
  let format_name = option_value(rest, "--format").unwrap_or("terminal")
  let output = option_value(rest, "--output")
  let database = read_database(database_path)
  let dependencies = discover_dependencies(path)
  let report = @vigil.scan(dependencies, database)
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
  exit_with_status(if report.findings.length() > 0 { 1 } else { 0 })
}

///|
fn sbom_command(path : String, rest : Array[String]) -> Unit raise {
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
fn print_usage() -> Unit {
  println("MoonVigil — offline MoonBit dependency scanner")
  println(
    "  moon run cmd/main -- scan <path> [--db advisories.json] [--format terminal|json|sarif] [--output file]",
  )
  println("  moon run cmd/main -- sbom <path> [--output file]")
  println("  moon run cmd/main -- db validate <advisories.json>")
}
