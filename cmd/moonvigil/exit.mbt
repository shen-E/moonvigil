///|
extern "C" fn native_exit(code : Int32) = "moonvigil_exit"

///|
fn exit_with_status(code : Int32) -> Unit {
  if code != 0 {
    native_exit(code)
  }
}
