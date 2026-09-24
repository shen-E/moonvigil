///|
/// The dependency usage context recorded in a MoonBit package manifest.
pub enum DependencyScope {
  Runtime
  Test
  WhiteboxTest
  Other
} derive(Debug, Eq)

///|
impl ToJson for DependencyScope with fn to_json(self) {
  Json::string(dependency_scope_name(self))
}

///|
/// A package import declared in a modern `moon.pkg` manifest.
pub struct PackageImport {
  package_name : String
  alias_name : String
  scope : DependencyScope
  source : String
} derive(Debug, Eq, ToJson)

///|
priv enum ManifestToken {
  Word(String)
  Literal(String)
  LeftBrace
  RightBrace
  At
  Comma
  Newline
  Other
}

///|
priv struct ManifestEntry {
  value : String
  alias_name : String
}

///|
priv struct ManifestImportBlock {
  entries : Array[ManifestEntry]
  scope : String
}

///|
pub(all) suberror ManifestParseError {
  InvalidManifest(source~ : String, line~ : Int, reason~ : String)
} derive(Debug, Eq)

///|
/// Parse direct module dependencies from modern `moon.mod` syntax.
///
/// Versions absent from a declaration are retained as empty so matching reports
/// them as uncomparable instead of silently considering them safe.
pub fn parse_moon_mod(
  text : String,
  source~ : String,
) -> Array[Dependency] raise {
  let blocks = parse_import_blocks(text, source~)
  let dependencies : Array[Dependency] = []
  for block in blocks {
    for entry in block.entries {
      let pieces = entry.value.split("@").to_array()
      let name = pieces[0].to_owned()
      let version = if pieces.length() > 1 { pieces[1].to_owned() } else { "" }
      if name != "" {
        dependencies.push(Dependency(name~, version~, source~))
      }
    }
  }
  dependencies
}

///|
/// Parse package imports, aliases, and test scope from modern `moon.pkg` syntax.
pub fn parse_moon_pkg(
  text : String,
  source~ : String,
) -> Array[PackageImport] raise {
  let blocks = parse_import_blocks(text, source~)
  let imports : Array[PackageImport] = []
  for block in blocks {
    let scope = dependency_scope(block.scope)
    for entry in block.entries {
      if entry.value != "" {
        let alias_name = if entry.alias_name != "" {
          entry.alias_name
        } else {
          entry.value.split("/").to_array().last().unwrap_or("").to_owned()
        }
        imports.push({ package_name: entry.value, alias_name, scope, source })
      }
    }
  }
  imports
}

///|
/// Attach package usage scopes to their declared module dependencies.
///
/// Package aliases never affect the canonical module identity. A package import
/// is associated with the longest matching declared module path.
pub fn apply_package_imports(
  dependencies : Array[Dependency],
  imports : Array[PackageImport],
) -> Array[Dependency] {
  dependencies.map(fn(dependency) {
    let scopes : Array[DependencyScope] = []
    let aliases : Array[String] = []
    for package_import in imports {
      match matching_module(dependencies, package_import.package_name) {
        Some(name) if name == dependency.name => {
          if !scopes.any(fn(scope) { scope == package_import.scope }) {
            scopes.push(package_import.scope)
          }
          if package_import.alias_name != "" &&
            !aliases.contains(package_import.alias_name) {
            aliases.push(package_import.alias_name)
          }
        }
        _ => ()
      }
    }
    aliases.sort_by(lexicographic_compare)
    Dependency(
      name=dependency.name,
      version=dependency.version,
      source=dependency.source,
      aliases~,
      scopes~,
    )
  })
}

///|
pub fn dependency_scope_name(scope : DependencyScope) -> String {
  match scope {
    Runtime => "runtime"
    Test => "test"
    WhiteboxTest => "wbtest"
    Other => "other"
  }
}

///|
fn matching_module(
  dependencies : Array[Dependency],
  package_name : String,
) -> String? {
  let mut best : String? = None
  for dependency in dependencies {
    let is_match = package_name == dependency.name ||
      package_name.has_prefix("\{dependency.name}/")
    if is_match {
      match best {
        Some(name) if name.length() >= dependency.name.length() => ()
        _ => best = Some(dependency.name)
      }
    }
  }
  best
}

///|
fn dependency_scope(value : String) -> DependencyScope {
  match value {
    "runtime" => Runtime
    "test" => Test
    "wbtest" => WhiteboxTest
    _ => Other
  }
}

///|
fn parse_import_blocks(
  text : String,
  source~ : String,
) -> Array[ManifestImportBlock] raise ManifestParseError {
  let tokens = tokenize_manifest(text, source~)
  let blocks : Array[ManifestImportBlock] = []
  let mut index = 0
  while index < tokens.length() {
    match tokens[index] {
      Word(word) if word == "import" => {
        let opening = skip_newlines(tokens, index + 1)
        if opening < tokens.length() && tokens[opening] is LeftBrace {
          let entries : Array[ManifestEntry] = []
          let mut cursor = opening + 1
          let mut closed = false
          while cursor < tokens.length() && !closed {
            match tokens[cursor] {
              RightBrace => {
                closed = true
                cursor += 1
              }
              Literal(value) => {
                cursor += 1
                let after_value = skip_newlines(tokens, cursor)
                let alias_name = if after_value < tokens.length() &&
                  tokens[after_value] is At {
                  match tokens.get(after_value + 1) {
                    Some(Word(name)) => {
                      cursor = after_value + 2
                      name
                    }
                    _ => {
                      cursor = after_value + 1
                      ""
                    }
                  }
                } else {
                  cursor = after_value
                  ""
                }
                entries.push({ value, alias_name })
              }
              Comma | Other => cursor += 1
              _ => cursor += 1
            }
          }
          if !closed {
            raise InvalidManifest(
              source~,
              line=1,
              reason="unterminated import block",
            )
          }
          let after_block = skip_newlines(tokens, cursor)
          let (scope, next_index) = match tokens.get(after_block) {
            Some(Word(keyword)) if keyword == "for" =>
              match tokens.get(after_block + 1) {
                Some(Literal(value)) => (value, after_block + 2)
                _ => ("runtime", after_block + 1)
              }
            _ => ("runtime", after_block)
          }
          blocks.push({ entries, scope })
          index = next_index
        } else {
          index = opening
        }
      }
      _ => index += 1
    }
  }
  blocks
}

///|
fn skip_newlines(tokens : Array[ManifestToken], start : Int) -> Int {
  let mut index = start
  while index < tokens.length() && tokens[index] is Newline {
    index += 1
  }
  index
}

///|
fn tokenize_manifest(
  text : String,
  source~ : String,
) -> Array[ManifestToken] raise ManifestParseError {
  let chars = text.to_array()
  let tokens : Array[ManifestToken] = []
  let mut index = 0
  let mut line = 1
  while index < chars.length() {
    let char = chars[index]
    if char == '/' && index + 1 < chars.length() && chars[index + 1] == '/' {
      while index < chars.length() && chars[index] != '\n' {
        index += 1
      }
    } else if char == '/' &&
      index + 1 < chars.length() &&
      chars[index + 1] == '*' {
      index += 2
      let mut closed = false
      while index + 1 < chars.length() && !closed {
        if chars[index] == '*' && chars[index + 1] == '/' {
          index += 2
          closed = true
        } else {
          if chars[index] == '\n' {
            line += 1
          }
          index += 1
        }
      }
      if !closed {
        raise InvalidManifest(
          source~,
          line~,
          reason="unterminated block comment",
        )
      }
    } else if char == '\n' {
      tokens.push(Newline)
      line += 1
      index += 1
    } else if char == '"' {
      index += 1
      let value = StringBuilder()
      let mut closed = false
      while index < chars.length() && !closed {
        match chars[index] {
          '"' => {
            closed = true
            index += 1
          }
          '\\' => {
            if index + 1 >= chars.length() {
              raise InvalidManifest(
                source~,
                line~,
                reason="unterminated string escape",
              )
            }
            match chars[index + 1] {
              '"' => value.write_char('"')
              '\\' => value.write_char('\\')
              'n' => value.write_char('\n')
              other => value.write_char(other)
            }
            index += 2
          }
          '\n' =>
            raise InvalidManifest(
              source~,
              line~,
              reason="newline in string literal",
            )
          other => {
            value.write_char(other)
            index += 1
          }
        }
      }
      if !closed {
        raise InvalidManifest(
          source~,
          line~,
          reason="unterminated string literal",
        )
      }
      tokens.push(Literal(value.to_string()))
    } else if char == '{' {
      tokens.push(LeftBrace)
      index += 1
    } else if char == '}' {
      tokens.push(RightBrace)
      index += 1
    } else if char == '@' {
      tokens.push(At)
      index += 1
    } else if char == ',' {
      tokens.push(Comma)
      index += 1
    } else if char.is_whitespace() {
      index += 1
    } else if is_identifier_char(char) {
      let word = StringBuilder()
      while index < chars.length() && is_identifier_char(chars[index]) {
        word.write_char(chars[index])
        index += 1
      }
      tokens.push(Word(word.to_string()))
    } else {
      tokens.push(Other)
      index += 1
    }
  }
  tokens
}

///|
fn is_identifier_char(char : Char) -> Bool {
  match char {
    'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' => true
    _ => false
  }
}
