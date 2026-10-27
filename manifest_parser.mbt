///|
/// The dependency usage context recorded in a MoonBit package manifest.
pub(all) enum DependencyScope {
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
pub fn PackageImport::PackageImport(
  package_name~ : String,
  alias_name~ : String,
  scope~ : DependencyScope,
  source~ : String,
) -> PackageImport {
  { package_name, alias_name, scope, source, }
}

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
priv struct LocatedManifestToken {
  token : ManifestToken
  line : Int32
}

///|
priv struct ManifestEntry {
  value : String
  alias_name : String
  line : Int32
}

///|
priv struct ManifestImportBlock {
  entries : Array[ManifestEntry]
  scope : String
  has_scope : Bool
  line : Int32
}

///|
pub(all) suberror ManifestParseError {
  InvalidManifest(source~ : String, line~ : Int32, reason~ : String)
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
    if block.has_scope {
      raise InvalidManifest(
        source~,
        line=block.line,
        reason="module dependencies cannot have a package import scope",
      )
    }
    for entry in block.entries {
      if entry.alias_name != "" {
        raise InvalidManifest(
          source~,
          line=entry.line,
          reason="module dependencies cannot have a package alias",
        )
      }
      let pieces = entry.value.split("@").to_array()
      let name = pieces[0].to_owned()
      let version = if pieces.length() > 1 { pieces[1].to_owned() } else { "" }
      if pieces.length() > 2 ||
        !valid_import_path(name) ||
        (pieces.length() == 2 && version == "") {
        raise InvalidManifest(
          source~,
          line=entry.line,
          reason="invalid module dependency: \{entry.value}",
        )
      }
      dependencies.push(Dependency(name~, version~, source~))
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
      if !valid_import_path(entry.value) {
        raise InvalidManifest(
          source~,
          line=entry.line,
          reason="invalid package import: \{entry.value}",
        )
      }
      let alias_name = if entry.alias_name != "" {
        entry.alias_name
      } else {
        entry.value.split("/").to_array().last().unwrap_or("").to_owned()
      }
      imports.push({ package_name: entry.value, alias_name, scope, source, })
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
    let scopes = merge_scopes(dependency.scopes, [])
    let aliases = merge_strings(dependency.aliases, [])
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
      scopes=merge_scopes(scopes, []),
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
    match tokens[index].token {
      Word(word) if word == "import" => {
        let opening = skip_newlines(tokens, index + 1)
        if opening < tokens.length() && tokens[opening].token is LeftBrace {
          let entries : Array[ManifestEntry] = []
          let mut cursor = skip_newlines(tokens, opening + 1)
          let mut closed = false
          while cursor < tokens.length() && !closed {
            match tokens[cursor].token {
              RightBrace => {
                closed = true
                cursor += 1
              }
              Literal(value) => {
                let entry_line = tokens[cursor].line
                if value == "" {
                  raise InvalidManifest(
                    source~,
                    line=entry_line,
                    reason="empty import entry",
                  )
                }
                cursor += 1
                let after_value = skip_newlines(tokens, cursor)
                let alias_name = if after_value < tokens.length() &&
                  tokens[after_value].token is At {
                  let alias_index = skip_newlines(tokens, after_value + 1)
                  match tokens.get(alias_index) {
                    Some({ token: Word(name), .. }) if valid_import_alias(name) => {
                      cursor = alias_index + 1
                      name
                    }
                    _ =>
                      raise manifest_token_error(
                        tokens,
                        after_value,
                        source~,
                        reason="expected an alias after @",
                      )
                  }
                } else {
                  cursor = after_value
                  ""
                }
                entries.push({ value, alias_name, line: entry_line, })
                cursor = skip_newlines(tokens, cursor)
                match tokens.get(cursor) {
                  Some({ token: Comma, .. }) =>
                    cursor = skip_newlines(tokens, cursor + 1)
                  Some({ token: RightBrace, .. }) => ()
                  None => ()
                  _ =>
                    raise manifest_token_error(
                      tokens,
                      cursor,
                      source~,
                      reason="expected a comma or } after import entry",
                    )
                }
              }
              _ =>
                raise manifest_token_error(
                  tokens,
                  cursor,
                  source~,
                  reason="expected a quoted import entry",
                )
            }
          }
          if !closed {
            raise InvalidManifest(
              source~,
              line=tokens[opening].line,
              reason="unterminated import block",
            )
          }
          let after_block = skip_newlines(tokens, cursor)
          let (scope, has_scope, next_index) = match tokens.get(after_block) {
            Some({ token: Word(keyword), .. }) if keyword == "for" => {
              let scope_index = skip_newlines(tokens, after_block + 1)
              match tokens.get(scope_index) {
                Some({ token: Literal(value), .. }) if value != "" =>
                  (value, true, scope_index + 1)
                _ =>
                  raise manifest_token_error(
                    tokens,
                    after_block,
                    source~,
                    reason="expected a quoted scope after for",
                  )
              }
            }
            _ => ("runtime", false, after_block)
          }
          match tokens.get(next_index) {
            Some({ token: Newline, .. }) | None => ()
            Some({ token: Word(keyword), .. }) if keyword != "for" => ()
            _ =>
              raise manifest_token_error(
                tokens,
                next_index,
                source~,
                reason="unexpected token after import block",
              )
          }
          blocks.push({ entries, scope, has_scope, line: tokens[index].line, })
          index = next_index
        } else {
          raise manifest_token_error(
            tokens,
            index,
            source~,
            reason="expected { after import",
          )
        }
      }
      _ => index += 1
    }
  }
  blocks
}

///|
fn skip_newlines(tokens : Array[LocatedManifestToken], start : Int32) -> Int32 {
  let mut index = start
  while index < tokens.length() && tokens[index].token is Newline {
    index += 1
  }
  index
}

///|
fn tokenize_manifest(
  text : String,
  source~ : String,
) -> Array[LocatedManifestToken] raise ManifestParseError {
  let chars = text.to_array()
  let tokens : Array[LocatedManifestToken] = []
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
      tokens.push({ token: Newline, line, })
      line += 1
      index += 1
    } else if char == '"' {
      let string_line = line
      index += 1
      let value = StringBuilder()
      value.write_char('"')
      let mut closed = false
      while index < chars.length() && !closed {
        match chars[index] {
          '"' => {
            value.write_char('"')
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
            value.write_char('\\')
            value.write_char(chars[index + 1])
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
      // Manifest strings use JSON escapes, including Unicode and escaped '/'.
      // Decode them once instead of dropping unknown escape characters.
      let decoded = @json.parse(value.to_string()) catch {
        _ =>
          raise InvalidManifest(
            source~,
            line=string_line,
            reason="invalid string literal",
          )
      }
      match decoded {
        String(value) =>
          tokens.push({ token: Literal(value), line: string_line, })
        _ =>
          raise InvalidManifest(
            source~,
            line=string_line,
            reason="invalid string literal",
          )
      }
    } else if char == '{' {
      tokens.push({ token: LeftBrace, line, })
      index += 1
    } else if char == '}' {
      tokens.push({ token: RightBrace, line, })
      index += 1
    } else if char == '@' {
      tokens.push({ token: At, line, })
      index += 1
    } else if char == ',' {
      tokens.push({ token: Comma, line, })
      index += 1
    } else if char.is_whitespace() {
      index += 1
    } else if is_identifier_char(char) {
      let word = StringBuilder()
      while index < chars.length() && is_identifier_char(chars[index]) {
        word.write_char(chars[index])
        index += 1
      }
      tokens.push({ token: Word(word.to_string()), line, })
    } else {
      tokens.push({ token: Other, line, })
      index += 1
    }
  }
  tokens
}

///|
fn is_identifier_char(char : Char) -> Bool {
  match char {
    'a'..<='z' | 'A'..<='Z' | '0'..<='9' | '_' | '-' => true
    _ => false
  }
}

///|
fn valid_import_alias(value : String) -> Bool {
  let chars = value.to_array()
  chars.length() > 0 &&
  (chars[0].is_ascii_alphabetic() || chars[0] == '_') &&
  chars.all(is_identifier_char)
}

///|
fn valid_import_path(value : String) -> Bool {
  value != "" &&
  !value
  .to_array()
  .any(fn(char) { char.is_whitespace() || char == '\\' || char == '@' }) &&
  value.split("/").all(fn(part) { part != "" && part != "." && part != ".." })
}

///|
fn manifest_token_error(
  tokens : Array[LocatedManifestToken],
  index : Int32,
  source~ : String,
  reason~ : String,
) -> ManifestParseError {
  let line = match tokens.get(index) {
    Some(token) => token.line
    None => 1
  }
  InvalidManifest(source~, line~, reason~)
}
