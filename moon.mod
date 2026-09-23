// Learn more about moon.mod configuration:
// https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html
//
// To add a dependency, run this command in your terminal:
//   moon add moonbitlang/x
//
// Or manually declare it in `import`, for example:
// import {
//   "moonbitlang/x@0.4.6",
// }

name = "moonvigil/moonvigil"

version = "0.1.0"

readme = "README.mbt.md"

repository = ""

license = "Apache-2.0"

keywords = [ "moonbit", "security", "scanner", "dependencies", "supply-chain" ]

preferred_target = "native"

description = "Offline dependency vulnerability scanner for MoonBit projects."

import {
  "moonbitlang/x@0.5.5",
}
