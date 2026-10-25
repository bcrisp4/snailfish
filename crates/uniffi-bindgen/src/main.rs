//! The UniFFI binding generator at the pinned UniFFI version.
//! Run `make bindings-python` or `make bindings-swift`, not this binary directly.

fn main() {
    uniffi::uniffi_bindgen_main();
}
