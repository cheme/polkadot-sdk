// This file is part of Substrate.

// Copyright (C) 2017-2022 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Transient storage plugin example.
//! Used in test.
use core::ffi::c_void;
use log::debug;
use sc_client_db::{ErrorCode, TransientStorageHook};
use sp_blockchain::Result as ClientResult;
use sp_runtime::{
	testing::{Block as RawBlock, ExtrinsicWrapper},
	traits::{Block as BlockT, NumberFor},
};
use sp_state_machine::{BlobsCollection, OrdMapsCollection};

// We don't import automatically as upgrade of version
// don't necessarilly change ffi prototype but can requires
// changes.
#[no_mangle]
#[used]
pub static PLUGIN_VERSION: u8 = 1;

type Block = RawBlock<ExtrinsicWrapper<u64>>;
type BlockHash = <Block as BlockT>::Hash;

struct DebugAndTest;

// We implement the hook to ensure the right types are used.
impl TransientStorageHook<Block> for DebugAndTest {
	fn add_transient_changes(
		&mut self,
		hash: &BlockHash,
		parent_hash: &BlockHash,
		number: &NumberFor<Block>,
		btrees_changes: &OrdMapsCollection,
		blobs_changes: &BlobsCollection,
	) -> ClientResult<()> {
		debug!("add changes: {:?}", (hash, parent_hash, number, btrees_changes, blobs_changes));

		let mut success = true;
		let ref_btree = sc_client_db::test_btrees_collection();
		if btrees_changes.len() != ref_btree.len() {
			success = false;
		}
		for (btree, data) in btrees_changes.iter() {
			let Some(data2) = ref_btree.get(&btree.infos.name) else {
				success = false;
				break
			};
			for (k, v) in data {
				let Some(v2) = data2.data.get(k) else {
					success = false;
					break
				};
				if v.as_ref() != Some(v2) {
					success = false;
				}
			}
		}
		let ref_blob = sc_client_db::test_blobs_collection();
		if blobs_changes.len() != ref_blob.len() {
			success = false;
		}
		for (blob, data) in blobs_changes.iter() {
			let Some(data2) = ref_blob.get(&blob.infos.name) else {
				success = false;
				break
			};
			if data.as_ref() != data2.data {
				success = false;
			}
		}

		if success {
			Ok(())
		} else {
			Err(sp_blockchain::Error::Storage("".into()))
		}
	}

	fn canonicalize(
		&mut self,
		hash: &BlockHash,
		parent_hash: &BlockHash,
		number: &NumberFor<Block>,
	) -> ClientResult<()> {
		debug!("cannonicalize: {:?}", (hash, parent_hash, number));
		Ok(())
	}

	fn drop_or_prune(
		&mut self,
		hash: &BlockHash,
		parent_hash: &BlockHash,
		number: &NumberFor<Block>,
	) -> ClientResult<()> {
		debug!("drop_or_prune: {:?}", (hash, parent_hash, number));
		Ok(())
	}

	fn commited_transient_changes(
		&mut self,
		hash: &BlockHash,
		parent_hash: &BlockHash,
		number: &NumberFor<Block>,
	) -> ClientResult<()> {
		debug!("commited_transient_changes: {:?}", (hash, parent_hash, number));
		Ok(())
	}

	fn rollbacked_transient_changes(
		&mut self,
		hash: &BlockHash,
		parent_hash: &BlockHash,
		number: &NumberFor<Block>,
	) -> ClientResult<()> {
		debug!("rollbacked_transient_changes: {:?}", (hash, parent_hash, number));
		Ok(())
	}
}

// TODO have a macro generate the boiler plate in client-db

#[no_mangle]
pub extern "C" fn add_transient_changes(
	hash: *const c_void,
	parent_hash: *const c_void,
	number: *const c_void,
	btrees: *const c_void,
	blobs: *const c_void,
) -> ErrorCode {
	let mut instance = DebugAndTest;
	let hash: *const BlockHash = hash.cast();
	let parent_hash: *const BlockHash = parent_hash.cast();
	let number: *const NumberFor<Block> = number.cast();
	let btrees: *const OrdMapsCollection = btrees.cast();
	let blobs: *const BlobsCollection = blobs.cast();
	match instance.add_transient_changes(
		unsafe { hash.as_ref().expect("not null ptr") },
		unsafe { parent_hash.as_ref().expect("not null ptr") },
		unsafe { number.as_ref().expect("not null ptr") },
		unsafe { btrees.as_ref().expect("not null ptr") },
		unsafe { blobs.as_ref().expect("not null ptr") },
	) {
		Ok(()) => 0,
		Err(_) => 1,
	}
}

#[no_mangle]
pub extern "C" fn canonicalize(
	hash: *const c_void,
	parent_hash: *const c_void,
	number: *const c_void,
) -> ErrorCode {
	let mut instance = DebugAndTest;
	let hash: *const BlockHash = hash.cast();
	let parent_hash: *const BlockHash = parent_hash.cast();
	let number: *const NumberFor<Block> = number.cast();
	match instance.canonicalize(
		unsafe { hash.as_ref().expect("not null ptr") },
		unsafe { parent_hash.as_ref().expect("not null ptr") },
		unsafe { number.as_ref().expect("not null ptr") },
	) {
		Ok(()) => 0,
		Err(_) => 1,
	}
}

#[no_mangle]
pub extern "C" fn drop_or_prune(
	hash: *const c_void,
	parent_hash: *const c_void,
	number: *const c_void,
) -> ErrorCode {
	let mut instance = DebugAndTest;
	let hash: *const BlockHash = hash.cast();
	let parent_hash: *const BlockHash = parent_hash.cast();
	let number: *const NumberFor<Block> = number.cast();
	match instance.drop_or_prune(
		unsafe { hash.as_ref().expect("not null ptr") },
		unsafe { parent_hash.as_ref().expect("not null ptr") },
		unsafe { number.as_ref().expect("not null ptr") },
	) {
		Ok(()) => 0,
		Err(_) => 1,
	}
}

#[no_mangle]
pub extern "C" fn commited_transient_changes(
	hash: *const c_void,
	parent_hash: *const c_void,
	number: *const c_void,
) -> ErrorCode {
	let mut instance = DebugAndTest;
	let hash: *const BlockHash = hash.cast();
	let parent_hash: *const BlockHash = parent_hash.cast();
	let number: *const NumberFor<Block> = number.cast();
	match instance.commited_transient_changes(
		unsafe { hash.as_ref().expect("not null ptr") },
		unsafe { parent_hash.as_ref().expect("not null ptr") },
		unsafe { number.as_ref().expect("not null ptr") },
	) {
		Ok(()) => 0,
		Err(_) => 1,
	}
}

#[no_mangle]
pub extern "C" fn rollbacked_transient_changes(
	hash: *const c_void,
	parent_hash: *const c_void,
	number: *const c_void,
) -> ErrorCode {
	let mut instance = DebugAndTest;
	let hash: *const BlockHash = hash.cast();
	let parent_hash: *const BlockHash = parent_hash.cast();
	let number: *const NumberFor<Block> = number.cast();
	match instance.rollbacked_transient_changes(
		unsafe { hash.as_ref().expect("not null ptr") },
		unsafe { parent_hash.as_ref().expect("not null ptr") },
		unsafe { number.as_ref().expect("not null ptr") },
	) {
		Ok(()) => 0,
		Err(_) => 1,
	}
}
