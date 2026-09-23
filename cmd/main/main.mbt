///|
fn main {
  let args = @env.args()
  match args {
    [_, "scan", path, .. rest] => scan_command(path, rest.to_owned())
    [_, "sbom", path, ..] => sbom_command(path)
    [_, "db", "validate", database, ..] => validate_database(database)
    _ => {
      print_usage()
      native_exit(2)
    }
  }
}

///|
fn scan_command(path : String, rest : Array[String]) -> Unit {
  let database_path = option_value(rest, "--db").unwrap_or("advisories.json")
  let format = option_value(rest, "--format").unwrap_or("terminal")
  let output = option_value(rest, "--output")
  let database = try! read_database(database_path)
  let dependencies = try! discover_dependencies(path)
  let report = @vigil.scan(dependencies, database)
  let content = match format {
    "terminal" => @vigil.report_terminal(report)
    "json" => @vigil.report_json(report)
    "sarif" => @vigil.report_sarif(report)
    _ => @vigil.report_terminal(report)
  }
  match output {
    Some(file) => ignore(try! @fs.write_string_to_file(file, content))
    None => println(content)
  }
  exit_with_status(if report.findings.length() > 0 { 1 } else { 0 })
}

///|
fn sbom_command(path : String) -> Unit {
  println(@vigil.sbom_json(try! discover_dependencies(path)))
}

///|
fn validate_database(path : String) -> Unit {
  let database = try! read_database(path)
  println(
    "valid advisory database v\{database.schema_version}: \{database.advisories.length()} advisories",
  )
}

///|
fn read_database(path : String) -> @vigil.AdvisoryDatabase raise {
  @vigil.parse_database(@fs.read_file_to_string(path))
}

///|
fn discover_dependencies(path : String) -> Array[@vigil.Dependency] raise {
  let manifests : Array[String] = []
  collect_manifests(path, manifests)
  let dependencies : Array[@vigil.Dependency] = []
  for manifest in manifests {
    let parsed = @vigil.parse_manifest(
      @fs.read_file_to_string(manifest),
      source=manifest,
    )
    for dependency in parsed {
      dependencies.push(dependency)
    }
  }
  @vigil.inventory_from_dependencies(dependencies).dependencies
}

///|
fn collect_manifests(path : String, manifests : Array[String]) -> Unit raise {
  if @fs.is_file(path) {
    if path.has_suffix("moon.mod.json") || path.has_suffix("moon.pkg.json") {
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
  println("  moon run cmd/main -- sbom <path>")
  println("  moon run cmd/main -- db validate <advisories.json>")
}
