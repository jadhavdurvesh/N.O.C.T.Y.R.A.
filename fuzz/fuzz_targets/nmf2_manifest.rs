#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // Manifest validation is intentionally exercised without password KDF work.
    let _ = noctyra_container::validate_directory_manifest(&mut Cursor::new(data));
});
