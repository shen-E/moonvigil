///|
priv enum VersionComparator {
  Less(Array[Int])
  LessOrEqual(Array[Int])
  Greater(Array[Int])
  GreaterOrEqual(Array[Int])
  Equal(Array[Int])
}

///|
/// Match a stable three-part numeric version against an affected range.
///
/// Supported comparators are `<`, `<=`, `>`, `>=`, `=`, and bare exact
/// versions. Space-separated terms form an intersection and `||` forms a
/// union. Pre-release versions, build metadata, and malformed ranges return
/// `Uncomparable` rather than being treated as vulnerable.
pub fn match_version(version : String, affected : String) -> FindingStatus {
  match (parse_version(version), parse_ranges(affected)) {
    (Some(current), Some(ranges)) => {
      for range in ranges {
        if range.all(fn(comparator) { matches_comparator(current, comparator) }) {
          return Affected
        }
      }
      NotAffected
    }
    _ => Uncomparable
  }
}

///|
fn is_supported_affected_range(affected : String) -> Bool {
  parse_ranges(affected) is Some(_)
}

///|
fn is_stable_version(version : String) -> Bool {
  parse_version(version) is Some(_)
}

///|
fn parse_ranges(text : String) -> Array[Array[VersionComparator]]? {
  let ranges : Array[Array[VersionComparator]] = []
  for alternative in text.split("||") {
    let expression = alternative.trim().to_owned()
    if expression == "" {
      return None
    }
    if expression == "*" {
      ranges.push([])
      continue
    }
    let comparators : Array[VersionComparator] = []
    for part in expression.split(" ") {
      let term = part.trim().to_owned()
      if term != "" {
        match parse_comparator(term) {
          Some(comparator) => comparators.push(comparator)
          None => return None
        }
      }
    }
    if comparators.length() == 0 {
      return None
    }
    ranges.push(comparators)
  }
  Some(ranges)
}

///|
fn parse_comparator(text : String) -> VersionComparator? {
  if text.has_prefix(">=") {
    parse_version(text[2:].to_owned()).map(fn(version) {
      GreaterOrEqual(version)
    })
  } else if text.has_prefix("<=") {
    parse_version(text[2:].to_owned()).map(fn(version) { LessOrEqual(version) })
  } else if text.has_prefix(">") {
    parse_version(text[1:].to_owned()).map(fn(version) { Greater(version) })
  } else if text.has_prefix("<") {
    parse_version(text[1:].to_owned()).map(fn(version) { Less(version) })
  } else if text.has_prefix("=") {
    parse_version(text[1:].to_owned()).map(fn(version) { Equal(version) })
  } else {
    parse_version(text).map(fn(version) { Equal(version) })
  }
}

///|
fn parse_version(version : String) -> Array[Int]? {
  let raw = version.trim().to_owned()
  if raw.contains("-") || raw.contains("+") {
    return None
  }
  let pieces = raw.split(".").to_array()
  if pieces.length() != 3 {
    return None
  }
  let values : Array[Int] = []
  for piece in pieces {
    match parse_numeric_component(piece.to_owned()) {
      Some(value) => values.push(value)
      None => return None
    }
  }
  Some(values)
}

///|
fn parse_numeric_component(component : String) -> Int? {
  if component == "" ||
    component.length() > 10 ||
    (component.length() > 1 && component[0] == '0') {
    return None
  }
  let mut value = 0
  for char in component {
    match digit_value(char) {
      Some(digit) => {
        if value > 214748364 || (value == 214748364 && digit > 7) {
          return None
        }
        value = value * 10 + digit
      }
      None => return None
    }
  }
  Some(value)
}

///|
fn digit_value(char : Char) -> Int? {
  match char {
    '0' => Some(0)
    '1' => Some(1)
    '2' => Some(2)
    '3' => Some(3)
    '4' => Some(4)
    '5' => Some(5)
    '6' => Some(6)
    '7' => Some(7)
    '8' => Some(8)
    '9' => Some(9)
    _ => None
  }
}

///|
fn matches_comparator(
  version : Array[Int],
  comparator : VersionComparator,
) -> Bool {
  match comparator {
    Less(bound) => compare_versions(version, bound) < 0
    LessOrEqual(bound) => compare_versions(version, bound) <= 0
    Greater(bound) => compare_versions(version, bound) > 0
    GreaterOrEqual(bound) => compare_versions(version, bound) >= 0
    Equal(bound) => compare_versions(version, bound) == 0
  }
}

///|
fn compare_versions(left : Array[Int], right : Array[Int]) -> Int {
  for index in 0..<3 {
    if left[index] < right[index] {
      return -1
    }
    if left[index] > right[index] {
      return 1
    }
  }
  0
}
