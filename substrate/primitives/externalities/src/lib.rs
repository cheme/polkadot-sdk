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
	transient::{Hash32Algorithm, HasherHandle, Mode as TransientMode, Root32Structure},
	Blob as BlobInfo, ChildInfo, OrderedMap as OrdMapInfo, StateVersion, TrackedStorageKey,
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

	/// Change a storage storage definition. If no storage exists a new empty one is created.
	///
	/// Return false if ignored (eg for default child trie).
	/// Return true if unchanged.
	fn update_storage_info(&mut self, info: ChildInfo, clear_existing: bool) -> bool;

	/// Check if a given storage was created.
	fn storage_exists(&mut self, info: &ChildInfo) -> bool;

	/// Copy a storage current content and definition under a different name.
	/// Overwrite target if a target exists.
	///
	/// Return false if source do not exist.
	/// Return false if storage do not support this operation.
	fn storage_clone(&mut self, info: &ChildInfo, target_name: &[u8]) -> bool;

	/// Move a storage current content and definition under a different name.
	/// Overwrite target if a target exists.
	///
	/// Return false if source do not exist.
	/// Return false if storage do not support this operation.
	fn storage_move(&mut self, info: &ChildInfo, target_name: &[u8]) -> bool;

	/// Create a new empty blob.
	/// Clear possibly existing blob.
	fn blob_new(&mut self, name: &[u8], mode: TransientMode) {
		self.update_storage_info(
			ChildInfo::Blob(BlobInfo { name: name.to_vec(), mode: Some(mode), algorithm: None }),
			true,
		);
	}

	/// Returns true iff the blob name is present in execution state.
	fn blob_exists(&mut self, name: &[u8]) -> bool {
		let info = blob_info_from_name(name);
		self.storage_exists(&info)
	}

	/// Delete blob if present, return false otherwise.
	fn blob_delete(&mut self, name: &[u8]) -> bool {
		if self.blob_exists(name) {
			let info = blob_info_from_name(name);
			let _ = self.kill_child_storage(&info, None, None);
			true
		} else {
			false
		}
	}

	/// Clone blob value under a different name.
	/// If origin does not exist, this does nothing and return false.
	/// Target content is overwritten.
	fn blob_clone(&mut self, name: &[u8], target_name: &[u8]) -> bool {
		let info = blob_info_from_name(name);
		self.storage_clone(&info, target_name)
	}

	/// Move blob value under a different name.
	/// If origin does not exist, this does nothing and return false.
	/// If target exists, it is overwritten.
	fn blob_rename(&mut self, name: &[u8], target_name: &[u8]) -> bool {
		let info = blob_info_from_name(name);
		self.storage_move(&info, target_name)
	}

	/// Get value bytes for the blob.
	/// All bytes if `limit` is `None`, or up to `limit` bytes.
	/// Read bytes starting at a given offset, if offset is out of range, return
	/// an empty bytes vector.
	/// Returns `None` if the blob does not exist.
	fn blob_get(
		&mut self,
		name: &[u8],
		limit: Option<u32>,
		value_offset: u32,
	) -> Option<Cow<[u8]>> {
		let info = blob_info_from_name(name);
		self.child_storage(&info, &[], value_offset, limit)
	}

	/// Write value into a blob.
	///
	/// If data is present at offset, it is overwritten by new value.
	/// If new value is written beyond blob size, the value is appended
	/// to the blob.
	///
	/// If blob does not exist, the operation is ignored and false
	/// is returned.
	///
	/// If offset is bigger than current blog size the operation is
	/// ignored and false is returned.
	///
	/// If size of resulting blob is over u32::MAX bytes, this is ignored
	/// and return false.
	fn blob_set(&mut self, name: &[u8], value: &[u8], offset: u32) -> bool;

	/// Truncate blob to a given size.
	/// If blob is smaller or already this size, do nothing and return false.
	/// If blob is missing return false.
	fn blob_truncate(&mut self, name: &[u8], new_size: u32) -> bool;

	/// Returns size of the blob for a given name, or `None` if the blob does not exist.
	fn blob_len(&mut self, name: &[u8]) -> Option<u32>;

	/// If blob exists, return it's hash for a given algorithm.
	fn blob_hash32(&mut self, name: &[u8], algorithm: Hash32Algorithm) -> Option<[u8; 32]> {
		let info = ChildInfo::Blob(BlobInfo {
			name: name.to_vec(),
			mode: None,
			algorithm: Some(algorithm),
		});
		// update structure to apply
		if !self.update_storage_info(info.clone(), false) {
			return None
		}
		let hash = self.child_storage_root(&info, StateVersion::V1)?;
		let mut result = [0u8; 32];
		result.copy_from_slice(hash.as_slice());
		Some(result)
	}

	/// Create a new empty transient map.
	/// Clear possibly existing map.
	fn map_new(&mut self, name: &[u8], mode: TransientMode) {
		self.update_storage_info(
			ChildInfo::OrderedMap(OrdMapInfo {
				name: name.to_vec(),
				mode: Some(mode),
				algorithm: None,
			}),
			true,
		);
	}

	/// Returns true iff the map name is present in execution state.
	fn map_exists(&mut self, name: &[u8]) -> bool {
		let info = ordered_map_info_from_name(name);
		self.storage_exists(&info)
	}

	/// Delete ordered map if present or return false.
	fn map_delete(&mut self, name: &[u8]) -> bool {
		if self.map_exists(name) {
			let info = ordered_map_info_from_name(name);
			let _ = self.kill_child_storage(&info, None, None);
			true
		} else {
			false
		}
	}

	/// Clone ordered map content under a different name.
	/// If origin does not exist, this does nothing and return false.
	/// Target content is overwritten.
	fn map_clone(&mut self, name: &[u8], target_name: &[u8]) -> bool {
		let info = ordered_map_info_from_name(name);
		self.storage_clone(&info, target_name)
	}

	/// Move ordered map under a different name.
	/// If origin does not exist, this does nothing and return false.
	/// If target exists, it is overwritten.
	fn map_rename(&mut self, name: &[u8], target_name: &[u8]) -> bool {
		let info = ordered_map_info_from_name(name);
		self.storage_move(&info, target_name)
	}

	/// Inserts a single (key, value) pair into map name, and overwriting the item if it did.
	///
	/// If map do not exist this operatio is skipped and operation return false.
	fn map_insert_item(&mut self, name: &[u8], key: &[u8], value: &[u8]) -> bool {
		let info = ordered_map_info_from_name(name);
		self.place_child_storage(&info, key, Some(value))
	}

	/// Removes the pair with the given key from the map name, if the map exists and contains the
	/// item. Does nothing and return false otherwise.
	fn map_remove_item(&mut self, name: &[u8], key: &[u8]) -> bool {
		let info = ordered_map_info_from_name(name);
		self.place_child_storage(&info, key, None)
	}

	/// Returns true iff the map name existsa and contains key.
	fn map_contains_item(&mut self, name: &[u8], key: &[u8]) -> bool {
		let info = ordered_map_info_from_name(name);
		self.exists_child_storage(&info, key)
	}

	/// Returns Some iff the map name exists and contains key.
	/// If so, the inner value is that associated with key.
	/// If limit is specified, only that many bytes are returned.
	/// Offset start bytes are also skipped from return value.
	fn map_get_item(
		&mut self,
		name: &[u8],
		key: &[u8],
		limit: Option<u32>,
		value_offset: u32,
	) -> Option<Cow<[u8]>> {
		let info = ordered_map_info_from_name(name);
		self.child_storage(&info, key, value_offset, limit)
	}

	/// Returns Some iff the map name exists and contains key. If so, the inner value is the length
	/// of the value associated with key.
	fn map_len_item(&mut self, name: &[u8], key: &[u8]) -> Option<u32> {
		let info = ordered_map_info_from_name(name);
		self.child_storage_len(&info, key)
	}

	/// Returns Some iff the map name exists and contains key. If so, the inner value is the value
	/// associated with key when hashed with algorithm.
	fn map_hash32_item(
		&mut self,
		name: &[u8],
		key: &[u8],
		algorithm: Hash32Algorithm,
	) -> Option<[u8; 32]>;

	/// Returns Some iff the map name exists, None otherwise. If Some, then the inner value is the
	/// number of items in the map name.
	fn map_count(&mut self, name: &[u8]) -> Option<u32>;

	/// Calculates and returns the root of the data structure structure containing the items held in
	/// the map name. Returns None if map name does not exist.
	fn map_root32(&mut self, name: &[u8], algorithm: Root32Structure) -> Option<[u8; 32]> {
		let info = ChildInfo::OrderedMap(OrdMapInfo {
			name: name.to_vec(),
			mode: None,
			algorithm: Some(algorithm),
		});
		// update structure to apply
		if !self.update_storage_info(info.clone(), false) {
			return None
		}
		let root = self.child_storage_root(&info, StateVersion::V1)?;
		let mut result = [0u8; 32];
		result.copy_from_slice(root.as_slice());
		Some(result)
	}

	/// Returns up to the next count keys in map name immediately following key. If fewer items
	/// exist after key than count, then only the remaining items are returned. If the map name does
	/// not exist then None is returned.
	fn map_next_keys(&mut self, name: &[u8], key: &[u8], count: u32) -> Option<Vec<Vec<u8>>> {
		let info = ordered_map_info_from_name(name);
		self.next_child_storage_key(&info, key, count)
	}

	/// Returns Some of a Vec of all items in the map name, sorted; or None if the map name does not
	/// exist.
	fn map_dump(&mut self, name: &[u8]) -> Option<Vec<(Vec<u8>, Vec<u8>)>>;

	/// Returns Some of a Vec of all pairs of keys and values in the map name hashed with algorithm
	/// and in order of the (unhashed) key; or None if the map name does not exist.
	/// TODO question hashing key (except for equality checking, issue here is we don't have
	/// preimage).
	fn map_dump_hashed(
		&mut self,
		name: &[u8],
		algorithm: Hash32Algorithm,
	) -> Option<Vec<([u8; 32], [u8; 32])>>;

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

pub fn blob_info_from_name(name: &[u8]) -> ChildInfo {
	ChildInfo::Blob(BlobInfo { name: name.to_vec(), mode: None, algorithm: None })
}

pub fn ordered_map_info_from_name(name: &[u8]) -> ChildInfo {
	ChildInfo::OrderedMap(OrdMapInfo { name: name.to_vec(), mode: None, algorithm: None })
}
