// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Operation on runtime child storages.
//!
//! This module is a currently only a variant of unhashed with additional `child_info`.
// NOTE: could replace unhashed by having only one kind of storage (top trie being the child info
// of null length parent storage key).

use codec::{Codec, Decode, Encode};
pub use sp_core::storage::{
	transient::{Hash32Algorithm, Root32Structure},
	ChildInfo, ChildType, StateVersion,
};
pub use sp_io::{KillStorageResult, MultiRemovalResults};
use sp_std::prelude::*;

/// Return the value of the item in storage under `key`, or `None` if there is no explicit entry.
pub fn get<T: Decode + Sized>(child_info: &ChildInfo, key: &[u8]) -> Option<T> {
	match child_info.child_type() {
		ChildType::Default => {
			let storage_key = child_info.storage_key();
			sp_io::default_child_storage::get(storage_key, key).and_then(|v| {
				Decode::decode(&mut &v[..]).map(Some).unwrap_or_else(|_| {
					// TODO #3700: error should be handleable.
					log::error!(
						target: "runtime::storage",
						"Corrupted state in child trie at {:?}/{:?}",
						storage_key,
						key,
					);
					None
				})
			})
		},
		ChildType::OrderedMap => {
			let storage_key = child_info.storage_key();
			crate::storage::map_get_item(storage_key, key, None, 0).and_then(|v| {
				Decode::decode(&mut &v[..]).map(Some).unwrap_or_else(|_| {
					// TODO #3700: error should be handleable.
					log::error!(
						target: "runtime::storage",
						"Corrupted state in child trie at {:?}/{:?}",
						child_info.storage_key(),
						key,
					);
					None
				})
			})
		},
		ChildType::Blob => None,
	}
}

/// Decode a fix or bounded size value from a blob at a given position.
pub fn read_blob<T: Decode + Sized>(
	child_info: &ChildInfo,
	entry_size: u32,
	entry_number: u32,
) -> Option<T> {
	match child_info.child_type() {
		ChildType::Default => None,
		ChildType::OrderedMap => None,
		ChildType::Blob => {
			let storage_key = child_info.storage_key();
			let mut buf = vec![0u8; entry_size as usize];
			if let Some(s) =
				crate::storage::blob_read(storage_key, &mut buf[..], entry_number * entry_size)
			{
				Decode::decode(&mut &buf[..s as usize]).map(Some).unwrap_or_else(|_| {
					// TODO #3700: error should be handleable.
					log::error!(
						target: "runtime::storage",
						"Invalid entry encoding in blob at {:?}/{:?}",
						storage_key,
						entry_number,
					);
					None
				})
			} else {
				None
			}
		},
	}
}

/// Return the value of the item in storage under `key`, or the type's default if there is no
/// explicit entry.
pub fn get_or_default<T: Decode + Sized + Default>(child_info: &ChildInfo, key: &[u8]) -> T {
	get(child_info, key).unwrap_or_default()
}

/// Return the value of the item in storage under `key`, or `default_value` if there is no
/// explicit entry.
pub fn get_or<T: Decode + Sized>(child_info: &ChildInfo, key: &[u8], default_value: T) -> T {
	get(child_info, key).unwrap_or(default_value)
}

/// Return the value of the item in storage under `key`, or `default_value()` if there is no
/// explicit entry.
pub fn get_or_else<T: Decode + Sized, F: FnOnce() -> T>(
	child_info: &ChildInfo,
	key: &[u8],
	default_value: F,
) -> T {
	get(child_info, key).unwrap_or_else(default_value)
}

/// Put `value` in storage under `key`.
pub fn put<T: Encode>(child_info: &ChildInfo, key: &[u8], value: &T) {
	match child_info.child_type() {
		ChildType::Default => value.using_encoded(|slice| {
			sp_io::default_child_storage::set(child_info.storage_key(), key, slice)
		}),
		ChildType::OrderedMap => value.using_encoded(|slice| {
			crate::storage::map_insert_item(child_info.storage_key(), key, slice);
		}),
		ChildType::Blob => (),
	}
}

/// Push a value to a append only child state.
pub fn push<T: Encode>(child_info: &ChildInfo, value: &T) -> bool {
	match child_info.child_type() {
		ChildType::Default => false,
		ChildType::OrderedMap => false,
		ChildType::Blob => value.using_encoded(|slice| {
			if let Some(at) = crate::storage::blob_len(child_info.storage_key()) {
				crate::storage::blob_set(child_info.storage_key(), slice, at)
			} else {
				false
			}
		}),
	}
}

/// Remove `key` from storage, returning its value if it had an explicit entry or `None` otherwise.
pub fn take<T: Decode + Sized>(child_info: &ChildInfo, key: &[u8]) -> Option<T> {
	let r = get(child_info, key);
	if r.is_some() {
		kill(child_info, key);
	}
	r
}

/// Remove `key` from storage, returning its value, or, if there was no explicit entry in storage,
/// the default for its type.
pub fn take_or_default<T: Codec + Sized + Default>(child_info: &ChildInfo, key: &[u8]) -> T {
	take(child_info, key).unwrap_or_default()
}

/// Return the value of the item in storage under `key`, or `default_value` if there is no
/// explicit entry. Ensure there is no explicit entry on return.
pub fn take_or<T: Codec + Sized>(child_info: &ChildInfo, key: &[u8], default_value: T) -> T {
	take(child_info, key).unwrap_or(default_value)
}

/// Return the value of the item in storage under `key`, or `default_value()` if there is no
/// explicit entry. Ensure there is no explicit entry on return.
pub fn take_or_else<T: Codec + Sized, F: FnOnce() -> T>(
	child_info: &ChildInfo,
	key: &[u8],
	default_value: F,
) -> T {
	take(child_info, key).unwrap_or_else(default_value)
}

/// Check to see if `key` has an explicit entry in storage.
pub fn exists(child_info: &ChildInfo, key: &[u8]) -> bool {
	match child_info.child_type() {
		ChildType::Default => sp_io::default_child_storage::exists(child_info.storage_key(), key),
		ChildType::OrderedMap => crate::storage::map_contains_item(child_info.storage_key(), key),
		ChildType::Blob => false,
	}
}

/// Remove all `storage_key` key/values
///
/// Deletes all keys from the overlay and up to `limit` keys from the backend if
/// it is set to `Some`. No limit is applied when `limit` is set to `None`.
///
/// The limit can be used to partially delete a child trie in case it is too large
/// to delete in one go (block).
///
/// # Note
///
/// Please note that keys that are residing in the overlay for that child trie when
/// issuing this call are all deleted without counting towards the `limit`. Only keys
/// written during the current block are part of the overlay. Deleting with a `limit`
/// mostly makes sense with an empty overlay for that child trie.
///
/// Calling this function multiple times per block for the same `storage_key` does
/// not make much sense because it is not cumulative when called inside the same block.
/// Use this function to distribute the deletion of a single child trie across multiple
/// blocks.
#[deprecated = "Use `clear_storage` instead"]
pub fn kill_storage(child_info: &ChildInfo, limit: Option<u32>) -> KillStorageResult {
	match child_info.child_type() {
		ChildType::Default =>
			sp_io::default_child_storage::storage_kill(child_info.storage_key(), limit),
		ChildType::OrderedMap =>
			if limit.is_some() {
				KillStorageResult::SomeRemaining(0)
			} else {
				crate::storage::map_delete(child_info.storage_key());
				KillStorageResult::AllRemoved(0)
			},
		ChildType::Blob => unimplemented!(),
	}
}

/// Partially clear the child storage of each key-value pair.
///
/// # Limit
///
/// A *limit* should always be provided through `maybe_limit`. This is one fewer than the
/// maximum number of backend iterations which may be done by this operation and as such
/// represents the maximum number of backend deletions which may happen. A *limit* of zero
/// implies that no keys will be deleted, though there may be a single iteration done.
///
/// The limit can be used to partially delete storage items in case it is too large or costly
/// to delete all in a single operation.
///
/// # Cursor
///
/// A *cursor* may be passed in to this operation with `maybe_cursor`. `None` should only be
/// passed once (in the initial call) for any attempt to clear storage. In general, subsequent calls
/// operating on the same prefix should pass `Some` and this value should be equal to the
/// previous call result's `maybe_cursor` field. The only exception to this is when you can
/// guarantee that the subsequent call is in a new block; in this case the previous call's result
/// cursor need not be passed in an a `None` may be passed instead. This exception may be useful
/// then making this call solely from a block-hook such as `on_initialize`.
///
/// Returns [`MultiRemovalResults`](sp_io::MultiRemovalResults) to inform about the result. Once the
/// resultant `maybe_cursor` field is `None`, then no further items remain to be deleted.
///
/// NOTE: After the initial call for any given child storage, it is important that no keys further
/// keys are inserted. If so, then they may or may not be deleted by subsequent calls.
///
/// # Note
///
/// Please note that keys which are residing in the overlay for the child are deleted without
/// counting towards the `limit`.
pub fn clear_storage(
	child_info: &ChildInfo,
	maybe_limit: Option<u32>,
	maybe_cursor: Option<&[u8]>,
) -> MultiRemovalResults {
	// TODO: Once the network has upgraded to include the new host functions, this code can be
	// enabled.
	// sp_io::default_child_storage::storage_kill(prefix, maybe_limit, maybe_cursor)
	let r = match child_info.child_type() {
		ChildType::Default =>
			sp_io::default_child_storage::storage_kill(child_info.storage_key(), maybe_limit),
		ChildType::OrderedMap => {
			let maybe_cursor = maybe_cursor.map(Vec::from);
			if maybe_limit.is_none() && maybe_cursor.is_none() {
				if let Some(s) = crate::storage::map_count(child_info.storage_key()) {
					if crate::storage::map_delete(child_info.storage_key()) {
						return MultiRemovalResults { maybe_cursor, backend: 0, unique: s, loops: 0 }
					}
				}
			}
			return MultiRemovalResults { maybe_cursor, backend: 0, unique: 0, loops: 0 }
		},
		ChildType::Blob => unimplemented!("cursor wrong type but could fit u64 in it"),
	};
	use sp_io::KillStorageResult::*;
	let (maybe_cursor, backend) = match r {
		AllRemoved(db) => (None, db),
		SomeRemaining(db) => (Some(child_info.storage_key().to_vec()), db),
	};
	MultiRemovalResults { maybe_cursor, backend, unique: backend, loops: backend }
}

/// Ensure `key` has no explicit entry in storage.
pub fn kill(child_info: &ChildInfo, key: &[u8]) {
	match child_info.child_type() {
		ChildType::Default => {
			sp_io::default_child_storage::clear(child_info.storage_key(), key);
		},
		ChildType::OrderedMap => {
			crate::storage::map_remove_item(child_info.storage_key(), key);
		},
		ChildType::Blob => (),
	}
}

/// Get a Vec of bytes from storage.
pub fn get_raw(child_info: &ChildInfo, key: &[u8]) -> Option<Vec<u8>> {
	match child_info.child_type() {
		ChildType::Default => sp_io::default_child_storage::get(child_info.storage_key(), key),
		ChildType::OrderedMap =>
			crate::storage::map_get_item(child_info.storage_key(), key, None, 0).map(Into::into),
		ChildType::Blob => None,
	}
	.map(Into::into)
}

/// Put a raw byte slice into storage.
pub fn put_raw(child_info: &ChildInfo, key: &[u8], value: &[u8]) {
	match child_info.child_type() {
		ChildType::Default =>
			sp_io::default_child_storage::set(child_info.storage_key(), key, value),
		ChildType::OrderedMap => {
			crate::storage::map_insert_item(child_info.storage_key(), key, value);
		},
		ChildType::Blob => (),
	}
}

struct HasherIoBlake;

impl sp_core::Hasher for HasherIoBlake {
	const LENGTH: usize = 32;
	type Out = [u8; 32];
	type StdHasher = hash256_std_hasher::Hash256StdHasher;

	fn hash(x: &[u8]) -> Self::Out {
		sp_io::hashing::blake2_256(x)
	}
}

/// Calculate current child root value.
pub fn root(child_info: &ChildInfo, version: StateVersion) -> Option<Vec<u8>> {
	match &child_info {
		ChildInfo::Default(..) =>
			Some(sp_io::default_child_storage::root(child_info.storage_key(), version)),
		ChildInfo::OrderedMap(ordmap) => ordmap.algorithm.clone().and_then(|algorithm| {
			crate::storage::map_root32::<HasherIoBlake>(child_info.storage_key(), algorithm.into())
				.map(Into::into)
		}),
		ChildInfo::Blob(blob) => blob.algorithm.clone().and_then(|algorithm| match algorithm {
			Hash32Algorithm::Blake2b256 =>
				crate::storage::blob_hash32(child_info.storage_key(), algorithm.into())
					.map(Into::into),
		}),
	}
}

/// Return the length in bytes of the value without reading it. `None` if it does not exist.
pub fn len(child_info: &ChildInfo, key: &[u8]) -> Option<u32> {
	match child_info.child_type() {
		ChildType::Default => {
			let mut buffer = [0; 0];
			sp_io::default_child_storage::read(child_info.storage_key(), key, &mut buffer, 0)
		},
		ChildType::OrderedMap => {
			let mut buffer = [0; 0];
			crate::storage::map_read_item(child_info.storage_key(), key, &mut buffer, 0)
		},
		ChildType::Blob => None,
	}
}
