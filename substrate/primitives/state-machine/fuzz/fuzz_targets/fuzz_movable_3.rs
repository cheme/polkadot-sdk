#![no_main]
use sp_state_machine::fuzz::{Ops, fuzz_movable, FuzzConf};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: Vec<Ops>| {
	let conf = FuzzConf {
		content_size: 277,
		do_hash: true,
		set_at: true,
	};
	fuzz_movable(&data[..], conf);
});
