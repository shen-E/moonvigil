///|
/// Legacy package imports annotate module declarations without inventing versions.
fn legacy_package_imports(
  text : String,
  source~ : String,
) -> Array[@vigil.PackageImport] raise {
  let object : Map[String, Json] = @json.from_json(@json.parse(text))
  let imports : Array[@vigil.PackageImport] = []
  for
    (field, scope) in [
      ("import", @vigil.Runtime),
      ("test-import", @vigil.Test),
      ("wbtest-import", @vigil.WhiteboxTest),
    ] {
    match object.get(field) {
      None => ()
      // Older fixtures also contain direct version declarations in this field.
      Some(Object(_)) if field == "import" => ()
      Some(Array(entries)) =>
        for entry in entries {
          let (name, alias_name) = match entry {
            String(name) => (name, "")
            Object(fields) => {
              let name = match fields.get("path") {
                Some(String(value)) if value != "" => value
                _ =>
                  raise InvalidInput(
                    "\{source}: \{field} entry requires a non-empty path",
                  )
              }
              let alias_name = match fields.get("alias") {
                None => ""
                Some(String(value)) => value
                _ =>
                  raise InvalidInput(
                    "\{source}: \{field} alias must be a string",
                  )
              }
              (name, alias_name)
            }
            _ =>
              raise InvalidInput(
                "\{source}: \{field} entries must be paths or import objects",
              )
          }
          if name == "" {
            raise InvalidInput(
              "\{source}: \{field} import path must not be empty",
            )
          }
          let alias_name = if alias_name == "" {
            name.split("/").to_array().last().unwrap_or("").to_owned()
          } else {
            alias_name
          }
          imports.push(
            @vigil.PackageImport(
              package_name=name,
              alias_name~,
              scope~,
              source~,
            ),
          )
        }
      _ =>
        raise InvalidInput(
          "\{source}: \{field} must be an array of package imports",
        )
    }
  }
  imports
}

///|
/// Bind package usage to the closest module so nested projects keep their scope.
fn module_owner(source : String, module_sources : Array[String]) -> String {
  let mut owner = ""
  for manifest in module_sources {
    let directory = normalize_path_separators(
      @path.Path(manifest).dirname().to_string(),
    )
    if directory != "." &&
      directory.length() > owner.length() &&
      source.has_prefix("\{directory}/") {
      owner = directory
    }
  }
  owner
}
