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

#![cfg_attr(not(feature = "std"), no_std)]

//! Substrate externalities abstraction
//!
//! The externalities mainly provide access to storage and to registered extensions. Extensions
//! are for example the keystore or the offchain externalities. These externalities are used to
//! access the node from the runtime via the runtime interfaces.
//!
//! This crate exposes the main [`Externalities`] trait.

use sp_std::{
	any::{Any, TypeId},
	borrow::Cow,
	boxed::Box,
	vec::Vec,
};

use sp_storage::{
	transient::{Hash32Algorithm, HasherHandle, Root32Structure},
	ChildInfo, StateVersion, TrackedStorageKey,
};

pub use extensions::{Extension, ExtensionStore, Extensions};
pub use scope_limited::{set_and_run_with_externalities, with_externalities};

mod extensions;
mod scope_limited;

/// Externalities error.
#[derive(Debug)]
pub enum Error {
	/// Same extension cannot be registered twice.
	ExtensionAlreadyRegistered,
	/// Extensions are not supported.
	ExtensionsAreNotSupported,
	/// Extension `TypeId` is not registered.
	ExtensionIsNotRegistered(TypeId),
	/// Failed to update storage,
	StorageUpdateFailed(&'static str),
}

/// Results concerning an operation to remove many keys.
#[derive(codec::Encode, codec::Decode)]
#[must_use]
pub struct MultiRemovalResults {
	/// A continuation cursor which, if `Some` must be provided to the subsequent removal call.
	/// If `None` then all removals are complete and no further calls are needed.
	pub maybe_cursor: Option<Vec<u8>>,
	/// The number of items removed from the backend database.
	pub backend: u32,
	/// The number of unique keys removed, taking into account both the backend and the overlay.
	pub unique: u32,
	/// The number of iterations (each requiring a storage seek/read) which were done.
	pub loops: u32,
}

impl MultiRemovalResults {
	/// Deconstruct into the internal components.
	///
	/// Returns `(maybe_cursor, backend, unique, loops)`.
	pub fn deconstruct(self) -> (Option<Vec<u8>>, u32, u32, u32) {
		(self.maybe_cursor, self.backend, self.unique, self.loops)
	}
}

/// The Substrate externalities.
///
/// Provides access to the storage and to other registered extensions.
pub trait Externalities: ExtensionStore {
	/// Write a key value pair to the offchain storage database.
	fn set_offchain_storage(&mut self, key: &[u8], value: Option<&[u8]>);

	/// Read runtime storage.
	///
	/// If a range is specified, only range of this value is returned.
	/// When out of range, returned value is truncated.
	fn storage(&mut self, key: &[u8], start: u32, limit: Option<u32>) -> Option<Cow<[u8]>>;

	/// Get storage value hash.
	///
	/// This may be optimized for large values.
	fn storage_hash(&mut self, key: &[u8]) -> Option<Vec<u8>>;

	/// Get child storage value hash.
	///
	/// This may be optimized for large values.
	///
	/// Returns an `Option` that holds the SCALE encoded hash.
	fn child_storage_hash(&mut self, child_info: &ChildInfo, key: &[u8]) -> Option<Vec<u8>>;

	/// Read child runtime storage.
	///
	/// If a range is specified, only range of this value is returned.
	/// When out of range, returned value is truncated.
	///
	/// Returns an `Option` that holds the value or part of the value.
	fn child_storage<'a>(
		&'a mut self,
		child_info: &ChildInfo,
		key: &[u8],
		start: u32,
		limit: Option<u32>,
	) -> Option<Cow<'a, [u8]>>;

	/// Set storage entry `key` of current contract being called (effective immediately).
	fn set_storage(&mut self, key: Vec<u8>, value: Vec<u8>) {
		self.place_storage(key, Some(value));
	}

	/// Set child storage entry `key` of current contract being called (effective immediately).
	///
	/// Return false if ignored.
	fn set_child_storage(&mut self, child_info: &ChildInfo, key: &[u8], value: &[u8]) -> bool {
		self.place_child_storage(child_info, key, Some(value))
	}

	/// Clear a storage entry (`key`) of current contract being called (effective immediately).
	fn clear_storage(&mut self, key: &[u8]) {
		self.place_storage(key.to_vec(), None);
	}

	/// Clear a child storage entry (`key`) of current contract being called (effective
	/// immediately).
	///
	/// Return false if operation ignored.
	fn clear_child_storage(&mut self, child_info: &ChildInfo, key: &[u8]) -> bool {
		self.place_child_storage(child_info, key, None)
	}

	/// Whether a storage entry exists.
	fn exists_storage(&mut self, key: &[u8]) -> bool {
		self.storage(key, 0, Some(0)).is_some()
	}

	/// Whether a child storage entry exists.
	fn exists_child_storage(&mut self, child_info: &ChildInfo, key: &[u8]) -> bool {
		self.child_storage(child_info, key, 0, Some(0)).is_some()
	}

	/// Get size of a value.
	fn child_storage_len(&mut self, child_info: &ChildInfo, key: &[u8]) -> Option<u32>;

	/// Returns the key immediately following the given key, if it exists.
	fn next_storage_key(&mut self, key: &[u8]) -> Option<Vec<u8>>;

	/// Returns the keys immediately following the given key, in child storage.
	fn next_child_storage_key(
		&mut self,
		child_info: &ChildInfo,
		key: &[u8],
		count: u32,
	) -> Option<Vec<Vec<u8>>>;

	/// Clear an entire child storage.
	///
	/// Deletes all keys from the overlay and up to `maybe_limit` keys from the backend. No
	/// limit is applied if `maybe_limit` is `None`. Returns the cursor for the next call as `Some`
	/// if the child trie deletion operation is incomplete. In this case, it should be passed into
	/// the next call to avoid unaccounted iterations on the backend. Returns also the the number
	/// of keys that were removed from the backend, the number of unique keys removed in total
	/// (including from the overlay) and the number of backend iterations done.
	///
	/// As long as `maybe_cursor` is passed from the result of the previous call, then the number of
	/// iterations done will only ever be one more than the number of keys removed.
	///
	/// For transient storages, `maybe_limit` and `maybe_cursor` are ignored.
	///
	/// # Note
	///
	/// An implementation is free to delete more keys than the specified limit as long as
	/// it is able to do that in constant time.
	fn kill_child_storage(
		&mut self,
		child_info: &ChildInfo,
		maybe_limit: Option<u32>,
		maybe_cursor: Option<&[u8]>,
	) -> MultiRemovalResults;

	/// Clear storage entries which keys are start with the given prefix.
	///
	/// `maybe_limit`, `maybe_cursor` and result works as for `kill_child_storage`.
	fn clear_prefix(
		&mut self,
		prefix: &[u8],
		maybe_limit: Option<u32>,
		maybe_cursor: Option<&[u8]>,
	) -> MultiRemovalResults;

	/// Clear child storage entries which keys are start with the given prefix.
	///
	/// `maybe_limit`, `maybe_cursor` and result works as for `kill_child_storage`.
	fn clear_child_prefix(
		&mut self,
		child_info: &ChildInfo,
		prefix: &[u8],
		maybe_limit: Option<u32>,
		maybe_cursor: Option<&[u8]>,
	) -> MultiRemovalResults;

	/// Set or clear a storage entry (`key`) of current contract being called (effective
	/// immediately).
	fn place_storage(&mut self, key: Vec<u8>, value: Option<Vec<u8>>);

	/// Set or clear a child storage entry.
	///
	/// Return false if ignored (storage need to be initialize or storage do not support change).
	/// Removal of a missing value is not seen as ignored.
	fn place_child_storage(
		&mut self,
		child_info: &ChildInfo,
		key: &[u8],
		value: Option<&[u8]>,
	) -> bool;

	/// Get the trie root of the current storage map.
	///
	/// This will also update all child storage keys in the top-level storage map.
	///
	/// The returned hash is defined by the `Block` and is SCALE encoded.
	fn storage_root(&mut self, state_version: StateVersion) -> Vec<u8>;

	/// Get the trie root of a child storage map.
	///
	///
	///
	/// For default child storage:
	///
	/// This will also update the value of the child storage keys in the top-level storage map.
	///
	/// If the storage root equals the default hash as defined by the trie, the key in the top-level
	/// storage map will be removed.
	///
	/// Returns empty root for missing storage.
	///
	/// For transient storage only return root or hash if the storage exists.
	fn child_storage_root(
		&mut self,
		child_info: &ChildInfo,
		state_version: StateVersion,
	) -> Option<Vec<u8>>;

	/// Append storage item.
	///
	/// This assumes specific format of the storage item. Also there is no way to undo this
	/// operation.
	fn storage_append(&mut self, key: Vec<u8>, value: Vec<u8>);

	/// Start a new nested transaction.
	///
	/// This allows to either commit or roll back all changes made after this call to the
	/// top changes or the default child changes. For every transaction there cam be a
	/// matching call to either `storage_rollback_transaction` or `storage_commit_transaction`.
	/// Any transactions that are still open after returning from runtime are committed
	/// automatically.
	///
	/// Changes made without any open transaction are committed immediately.
	fn storage_start_transaction(&mut self);

	/// Rollback the last transaction started by `storage_start_transaction`.
	///
	/// Any changes made during that storage transaction are discarded. Returns an error when
	/// no transaction is open that can be closed.
	fn storage_rollback_transaction(&mut self) -> Result<(), ()>;

	/// Commit the last transaction started by `storage_start_transaction`.
	///
	/// Any changes made during that storage transaction are committed. Returns an error when
	/// no transaction is open that can be closed.
	fn storage_commit_transaction(&mut self) -> Result<(), ()>;

	/// Index specified transaction slice and store it.
	fn storage_index_transaction(&mut self, _index: u32, _hash: &[u8], _size: u32) {
		unimplemented!("storage_index_transaction");
	}

	/// Renew existing piece of transaction storage.
	fn storage_renew_transaction_index(&mut self, _index: u32, _hash: &[u8]) {
		unimplemented!("storage_renew_transaction_index");
	}

	/// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	/// Benchmarking related functionality and shouldn't be used anywhere else!
	/// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	///
	/// Wipes all changes from caches and the database.
	///
	/// The state will be reset to genesis.
	fn wipe(&mut self);

	/// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	/// Benchmarking related functionality and shouldn't be used anywhere else!
	/// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	///
	/// Commits all changes to the database and clears all caches.
	fn commit(&mut self);

	/// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	/// Benchmarking related functionality and shouldn't be used anywhere else!
	/// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	///
	/// Gets the current read/write count for the benchmarking process.
	fn read_write_count(&self) -> (u32, u32, u32, u32);

	/// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	/// Benchmarking related functionality and shouldn't be used anywhere else!
	/// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	///
	/// Resets read/write count for the benchmarking process.
	fn reset_read_write_count(&mut self);

	/// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	/// Benchmarking related functionality and shouldn't be used anywhere else!
	/// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	///
	/// Gets the current DB tracking whitelist.
	fn get_whitelist(&self) -> Vec<TrackedStorageKey>;

	/// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	/// Benchmarking related functionality and shouldn't be used anywhere else!
	/// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	///
	/// Adds new storage keys to the DB tracking whitelist.
	fn set_whitelist(&mut self, new: Vec<TrackedStorageKey>);

	/// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	/// Benchmarking related functionality and shouldn't be used anywhere else!
	/// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	///
	/// Returns estimated proof size for the state queries so far.
	/// Proof is reset on commit and wipe.
	fn proof_size(&self) -> Option<u32> {
		None
	}

	/// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	/// Benchmarking related functionality and shouldn't be used anywhere else!
	/// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	///
	/// Get all the keys that have been read or written to during the benchmark.
	fn get_read_and_written_keys(&self) -> Vec<(Vec<u8>, u32, u32, bool)>;

	/// Put a chunk to be archive.
	fn blob_archive_chunk(&mut self, name: &[u8], chunk: &[u8]);

	/// Put a blob hash to be archive.
	fn blob_archive_hash(&mut self, name: &[u8], hash: &[u8], algo: Hash32Algorithm);

	/// Put a map key value to be archive.
	fn map_archive_item(&mut self, name: &[u8], key: &[u8], value: &[u8]);

	/// Put a map root to be archive.
	fn map_archive_root(&mut self, name: &[u8], root: &[u8], structure: Root32Structure);

	/// Get hasher state handle initiated with given data.
	/// See sp_io::hashing::get_hasher.
	fn get_hasher(&mut self, algorithm: Hash32Algorithm) -> Option<HasherHandle>;

	/// Drop a given hasher instance.
	/// If hasher handle is undefined, all hashers instance
	/// will be drop.
	fn drop_hasher(&mut self, hasher: Option<HasherHandle>);

	/// Update hashing with given data.
	/// Return true if successful.
	/// Return false if missing hasher.
	fn hasher_update(&mut self, hasher: HasherHandle, data: &[u8]) -> bool;

	/// Finalize hashing, dropping the stored hasher and returning
	/// the resulting hash if successful.
	/// Return None if missing hasher.
	fn hasher_finalize(&mut self, hasher: HasherHandle) -> Option<[u8; 32]>;
}

/// Extension for the [`Externalities`] trait.
pub trait ExternalitiesExt {
	/// Tries to find a registered extension and returns a mutable reference.
	fn extension<T: Any + Extension>(&mut self) -> Option<&mut T>;

	/// Register extension `ext`.
	///
	/// Should return error if extension is already registered or extensions are not supported.
	fn register_extension<T: Extension>(&mut self, ext: T) -> Result<(), Error>;

	/// Deregister and drop extension of `T` type.
	///
	/// Should return error if extension of type `T` is not registered or
	/// extensions are not supported.
	fn deregister_extension<T: Extension>(&mut self) -> Result<(), Error>;
}

impl ExternalitiesExt for &mut dyn Externalities {
	fn extension<T: Any + Extension>(&mut self) -> Option<&mut T> {
		self.extension_by_type_id(TypeId::of::<T>()).and_then(<dyn Any>::downcast_mut)
	}

	fn register_extension<T: Extension>(&mut self, ext: T) -> Result<(), Error> {
		self.register_extension_with_type_id(TypeId::of::<T>(), Box::new(ext))
	}

	fn deregister_extension<T: Extension>(&mut self) -> Result<(), Error> {
		self.deregister_extension_by_type_id(TypeId::of::<T>())
	}
}

/// Utility to extract a slice with range externality logic: bound check for start, largest for
/// end.
pub fn range_slice(value: Option<&[u8]>, start: u32, limit: Option<u32>) -> Option<&[u8]> {
	value.map(|value| {
		let start = start as usize;
		if start < value.len() {
			if let Some(limit) = limit {
				let end = start + limit as usize;
				if end < value.len() {
					&value[start..end]
				} else {
					&value[start..]
				}
			} else {
				&value[start..]
			}
		} else {
			&value[0..0]
		}
	})
}

/// Utility to extract range from accessed value.
pub fn result_from_slice(
	value: Option<&[u8]>,
	start: u32,
	limit: Option<u32>,
) -> Option<Cow<[u8]>> {
	range_slice(value, start, limit).map(|s| s.into())
}

/// Utility to extract range from accessed value.
pub fn result_from_vec(
	value: Option<Vec<u8>>,
	start: u32,
	limit: Option<u32>,
) -> Option<Cow<'static, [u8]>> {
	value.map(|mut value| {
		let start = start as usize;
		if let Some(limit) = limit {
			let end = start + limit as usize;
			if end < value.len() {
				value.truncate(end);
			}
		}
		if start < value.len() {
			value = value.split_off(start);
		}
		value.into()
	})
}

/// Utility to extract range from accessed value.
pub fn result_from_cow(
	value: Option<Cow<[u8]>>,
	start: u32,
	limit: Option<u32>,
) -> Option<Cow<[u8]>> {
	match value? {
		Cow::Owned(owned) => result_from_vec(Some(owned), start, limit),
		Cow::Borrowed(borrowed) => result_from_slice(Some(borrowed), start, limit),
	}
}
