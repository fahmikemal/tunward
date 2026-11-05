#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| tunward::fuzz::tunnel_envelope(data));
