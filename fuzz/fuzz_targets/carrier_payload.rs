#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(carrier) = noctyra_image::CarrierImage::load(data) {
        let _ = noctyra_steganography::extract(&carrier);
    }
});
