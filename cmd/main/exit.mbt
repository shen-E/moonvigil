///|
extern "C" fn native_exit(code : Int) = "moonvigil_exit"

///|
fn exit_with_status(code : Int) -> Unit {
  if code != 0 {
    native_exit(code)
  }
}
