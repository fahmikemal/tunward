#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| tunward::fuzz::allow_list(data));
