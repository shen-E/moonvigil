///|
#borrow(left, right)
extern "C" fn native_same_file(left : Bytes, right : Bytes) -> Int32 = "moonvigil_same_file"

///|
#borrow(path)
extern "C" fn native_is_link(path : Bytes) -> Int32 = "moonvigil_is_link"

///|
priv suberror CliError {
  InvalidInput(String)
}

///|
fn paths_alias(left : String, right : String) -> Bool {
  let a = @path.Path(left).resolve()
  let b = @path.Path(right).resolve()
  if a == b || native_same_file(@utf8.encode(left), @utf8.encode(right)) != 0 {
    return true
  }
  // Also compare existing parent directories for outputs not created yet.
  let same_name = if @path.sep == '\\' {
    a.basename().equal_ignore_ascii_case(b.basename())
  } else {
    a.basename() == b.basename()
  }
  same_name &&
  native_same_file(
    @utf8.encode(@path.Path(left).dirname().to_string()),
    @utf8.encode(@path.Path(right).dirname().to_string()),
  ) !=
  0
}

///|
fn validate_output_paths(
  outputs : Array[String],
  inputs : Array[String],
) -> Unit raise {
  for index in 0..<outputs.length() {
    let output = outputs[index]
    if output == "" || (@fs.path_exists(output) && @fs.is_dir(output)) {
      raise InvalidInput("output must name a file: \{output}")
    }
    let name = @path.Path(output).basename().to_owned()
    if is_manifest_name(name) {
      raise InvalidInput(
        "output cannot overwrite a project manifest: \{output}",
      )
    }
    for input in inputs {
      if paths_alias(output, input) {
        raise InvalidInput("output and input paths must be distinct: \{output}")
      }
    }
    for previous in 0..<index {
      if paths_alias(output, outputs[previous]) {
        raise InvalidInput("report and baseline output paths must be distinct")
      }
    }
    let parent = @path.Path(output).resolve().dirname().to_string()
    if !@fs.is_dir(parent) {
      raise InvalidInput("output parent directory does not exist: \{parent}")
    }
  }
}

///|
fn is_manifest_name(name : String) -> Bool {
  name == "moon.mod" ||
  name == "moon.pkg" ||
  name == "moon.mod.json" ||
  name == "moon.pkg.json"
}
