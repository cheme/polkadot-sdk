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

//! Trie-based state machine backend essence used to read values
//! from storage.

use crate::{
	backend::{BackendTransaction, IterArgs, StorageIterator},
	trie_backend::{AsDB, TrieCacheProvider},
	warn, StorageKey, StorageValue,
};
#[cfg(feature = "std")]
use alloc::sync::Arc;
use alloc::{boxed::Box, vec::Vec};
use codec::Codec;
#[cfg(feature = "std")]
use parking_lot::RwLock;
use core::marker::PhantomData;
#[cfg(feature = "std")]
use parking_lot::RwLock;
use sp_core::storage::{ChildInfo, ChildType, StateVersion};
use sp_trie::{
	child_delta_trie_root, delta_trie_root, empty_child_trie_root,
	read_child_trie_first_descedant_value, read_child_trie_hash, read_child_trie_value,
	read_trie_first_descendant_value, read_trie_value, read_trie_value_with_location,
	trie_types::{TrieDBBuilder, TrieError},
	ChildChangeset, DBValue, KeySpacedDB, MerkleValue, NodeCodec, Trie, TrieCache,
	TrieDBRawIterator, TrieRecorder, TrieRecorderProvider,
};
#[cfg(feature = "std")]
use std::collections::HashMap;
use trie_db::node_db::{Hasher, NodeDB, Prefix};
// In this module, we only use layout for read operation and empty root,
// where V1 and V0 are equivalent.
use sp_trie::LayoutV1 as Layout;

type Root<H> = sp_trie::Root<Layout<H, DBLocation>>;

#[cfg(not(feature = "std"))]
macro_rules! format {
	( $message:expr, $( $arg:expr )* ) => {
		{
			$( let _ = &$arg; )*
			crate::DefaultError
		}
	};
}

type Result<V> = core::result::Result<V, crate::DefaultError>;
type DBLocation = sp_trie::DBLocation;

/// Local cache for child root.
#[cfg(feature = "std")]
pub(crate) struct Cache<H> {
	pub child_root: HashMap<Vec<u8>, Option<(H, DBLocation)>>,
}

#[cfg(feature = "std")]
impl<H> Cache<H> {
	fn new() -> Self {
		Cache { child_root: HashMap::new() }
	}
}

enum IterState {
	Pending,
	FinishedComplete,
	FinishedIncomplete,
}

/// A raw iterator over the storage.
pub struct RawIter<H, C, R>
where
	H: Hasher,
{
	stop_on_incomplete_database: bool,
	skip_if_first: Option<StorageKey>,
	root: Root<H>,
	child_info: Option<ChildInfo>,
	trie_iter: TrieDBRawIterator<Layout<H, DBLocation>>,
	state: IterState,
	_phantom: PhantomData<(C, R)>,
}

impl<H, C, R> RawIter<H, C, R>
where
	H: Hasher,
	H::Out: Codec + Ord,
	C: TrieCacheProvider<H> + Send + Sync,
	R: TrieRecorderProvider<H, DBLocation> + Send + Sync,
{
	#[inline]
	fn prepare<RE>(
		&mut self,
		backend: &TrieBackendEssence<H, C, R>,
		callback: impl FnOnce(
			&sp_trie::TrieDB<Layout<H, DBLocation>>,
			&mut TrieDBRawIterator<Layout<H, DBLocation>>,
		) -> Option<core::result::Result<RE, Box<TrieError<<H as Hasher>::Out>>>>,
	) -> Option<Result<RE>> {
		if !matches!(self.state, IterState::Pending) {
			return None
		}

		let result = backend.with_trie_db(self.root, self.child_info.as_ref(), |db| {
			callback(&db, &mut self.trie_iter)
		});
		match result {
			Some(Ok(key_value)) => Some(Ok(key_value)),
			None => {
				self.state = IterState::FinishedComplete;
				None
			},
			Some(Err(error)) => {
				self.state = IterState::FinishedIncomplete;
				if matches!(*error, TrieError::IncompleteDatabase(_)) &&
					self.stop_on_incomplete_database
				{
					None
				} else {
					Some(Err(format!("TrieDB iteration error: {}", error)))
				}
			},
		}
	}
}

impl<H, C, R> Default for RawIter<H, C, R>
where
	H: Hasher,
{
	fn default() -> Self {
		Self {
			stop_on_incomplete_database: false,
			skip_if_first: None,
			child_info: None,
			root: Default::default(),
			trie_iter: TrieDBRawIterator::empty(),
			state: IterState::FinishedComplete,
			_phantom: Default::default(),
		}
	}
}

impl<H, C, R> StorageIterator<H> for RawIter<H, C, R>
where
	H: Hasher,
	H::Out: Codec + Ord,
	C: TrieCacheProvider<H> + Send + Sync,
	R: TrieRecorderProvider<H, DBLocation> + Send + Sync,
{
	type Backend = crate::TrieBackend<H, C, R>;
	type Error = crate::DefaultError;

	#[inline]
	fn next_key(&mut self, backend: &Self::Backend) -> Option<Result<StorageKey>> {
		let skip_if_first = self.skip_if_first.take();
		self.prepare(&backend.essence, |trie, trie_iter| {
			let mut result = trie_iter.next_key(&trie);
			if let Some(skipped_key) = skip_if_first {
				if let Some(Ok(ref key)) = result {
					if *key == skipped_key {
						result = trie_iter.next_key(&trie);
					}
				}
			}
			result
		})
	}

	#[inline]
	fn next_pair(&mut self, backend: &Self::Backend) -> Option<Result<(StorageKey, StorageValue)>> {
		let skip_if_first = self.skip_if_first.take();
		self.prepare(&backend.essence, |trie, trie_iter| {
			let mut result = trie_iter.next_item(&trie);
			if let Some(skipped_key) = skip_if_first {
				if let Some(Ok((ref key, _))) = result {
					if *key == skipped_key {
						result = trie_iter.next_item(&trie);
					}
				}
			}
			result
		})
	}

	fn was_complete(&self) -> bool {
		matches!(self.state, IterState::FinishedComplete)
	}
}

/// Patricia trie-based pairs storage essence.
pub struct TrieBackendEssence<H: Hasher, C, R> {
	pub(crate) storage: Box<dyn AsDB<H>>,
	root: H::Out,
	empty: H::Out,
	#[cfg(feature = "std")]
	pub(crate) cache: RwLock<Cache<H::Out>>,
	pub(crate) trie_node_cache: Option<C>,
	#[cfg(feature = "std")]
	pub(crate) recorder: RwLock<Option<R>>,
	#[cfg(not(feature = "std"))]
	pub(crate) recorder: Option<R>,
}

impl<H, C, R> TrieBackendEssence<H, C, R>
where
	H: Hasher,
	R: TrieRecorderProvider<H, DBLocation>,
{
	/// Create new trie-based backend.
	pub fn new(storage: Box<dyn AsDB<H>>, root: H::Out) -> Self {
		Self::new_with_cache(storage, root, None)
	}

	/// Create new trie-based backend.
	pub fn new_with_cache(storage: Box<dyn AsDB<H>>, root: H::Out, cache: Option<C>) -> Self {
		TrieBackendEssence {
			storage,
			root,
			empty: H::hash(&[0u8]),
			#[cfg(feature = "std")]
			cache: RwLock::new(Cache::new()),
			trie_node_cache: cache,
			#[cfg(feature = "std")]
			recorder: RwLock::new(None),
			#[cfg(not(feature = "std"))]
			recorder: None,
		}
	}

	/// Create new trie-based backend.
	pub fn new_with_cache_and_recorder(
		storage: Box<dyn AsDB<H>>,
		root: H::Out,
		cache: Option<C>,
		recorder: Option<R>,
	) -> Self {
		TrieBackendEssence {
			storage,
			root,
			empty: H::hash(&[0u8]),
			#[cfg(feature = "std")]
			cache: RwLock::new(Cache::new()),
			trie_node_cache: cache,
			#[cfg(feature = "std")]
			recorder: RwLock::new(recorder),
			#[cfg(not(feature = "std"))]
			recorder,
		}
	}

	/// Get backend storage reference.
	pub fn backend_storage(&self) -> &dyn AsDB<H> {
		&*self.storage
	}

	pub fn backend_storage_mut(&mut self) -> &mut dyn AsDB<H> {
		&mut *self.storage
	}
	/// Get trie root.
	pub fn root(&self) -> &H::Out {
		&self.root
	}

	/// Set trie root. This is useful for testing.
	pub fn set_root(&mut self, root: H::Out) {
		// If root did change so can have cached content.
		self.reset_cache();
		self.root = root;
	}

	/// Set recorder. Returns old recorder if any.
	#[cfg(feature = "std")]
	pub fn set_recorder(&self, recorder: Option<R>) -> Option<R> {
		if recorder.is_some() {
			// TODO try without reset.
			self.reset_cache();
		}
		core::mem::replace(&mut *self.recorder.write(), recorder)
	}

	#[cfg(feature = "std")]
	fn reset_cache(&self) {
		*self.cache.write() = Cache::new();
	}

	#[cfg(not(feature = "std"))]
	fn reset_cache(&self) {}
}

impl<H, C, R> TrieBackendEssence<H, C, R>
where
	H: Hasher,
	C: TrieCacheProvider<H>,
	R: TrieRecorderProvider<H, DBLocation>,
{
	/// Call the given closure passing it the recorder and the cache.
	///
	/// If the given `storage_root` is `None`, `self.root` will be used.
	#[inline]
	fn with_recorder_and_cache<RE>(
		&self,
		storage_root: Option<H::Out>,
		callback: impl FnOnce(
			Option<&mut dyn TrieRecorder<H::Out, DBLocation>>,
			Option<&mut dyn TrieCache<NodeCodec<H>, DBLocation>>,
		) -> RE,
	) -> RE {
		let storage_root = storage_root.unwrap_or_else(|| self.root);
		let mut cache = self.trie_node_cache.as_ref().map(|c| c.as_trie_db_cache(storage_root));
		let cache = cache.as_mut().map(|c| c as _);

		#[cfg(feature = "std")]
		let recorder = self.recorder.read();
		#[cfg(not(feature = "std"))]
		let recorder = &self.recorder;
		let mut recorder = recorder.as_ref().map(|r| r.as_trie_recorder(storage_root));
		let recorder = match recorder.as_mut() {
			Some(recorder) => Some(recorder as &mut dyn TrieRecorder<H::Out, DBLocation>),
			None => None,
		};
		callback(recorder, cache)
	}

	/// Call the given closure passing it the recorder and the cache.
	///
	/// This function must only be used when the operation in `callback` is
	/// calculating a `storage_root`. It is expected that `callback` returns
	/// the new storage root. This is required to register the changes in the cache
	/// for the correct storage root. The given `storage_root` corresponds to the root of the "old"
	/// trie. If the value is not given, `self.root` is used.
	fn with_recorder_and_cache_for_storage_root<RE>(
		&self,
		storage_root: Option<H::Out>,
		callback: impl FnOnce(
			Option<&mut dyn TrieRecorder<H::Out, DBLocation>>,
			Option<&mut dyn TrieCache<NodeCodec<H>, DBLocation>>,
		) -> (Option<H::Out>, RE),
	) -> RE {
		let storage_root = storage_root.unwrap_or_else(|| self.root);
		#[cfg(feature = "std")]
		let recorder = self.recorder.read();
		#[cfg(not(feature = "std"))]
		let recorder = &self.recorder;
		let mut recorder = recorder.as_ref().map(|r| r.as_trie_recorder(storage_root));
		let recorder = match recorder.as_mut() {
			Some(recorder) => Some(recorder as &mut dyn TrieRecorder<H::Out, DBLocation>),
			None => None,
		};

		let result = if let Some(local_cache) = self.trie_node_cache.as_ref() {
			let mut cache = local_cache.as_trie_db_mut_cache();

			let (new_root, r) = callback(recorder, Some(&mut cache));

			if let Some(new_root) = new_root {
				local_cache.merge(cache, new_root);
			}

			r
		} else {
			callback(recorder, None).1
		};

		result
	}
}

impl<H, C, R> TrieBackendEssence<H, C, R>
where
	H: Hasher,
	H::Out: Codec + Ord,
	C: TrieCacheProvider<H> + Send + Sync,
	R: TrieRecorderProvider<H, DBLocation> + Send + Sync,
{
	/// Calls the given closure with a [`TrieDb`] constructed for the given
	/// storage root and (optionally) child trie.
	#[inline]
	fn with_trie_db<RE>(
		&self,
		root: Root<H>,
		child_info: Option<&ChildInfo>,
		callback: impl FnOnce(&sp_trie::TrieDB<Layout<H, DBLocation>>) -> RE,
	) -> RE {
		let backend = self as &dyn NodeDB<H, Vec<u8>, DBLocation>;
		let db = child_info
			.as_ref()
			.map(|child_info| KeySpacedDB::new(backend, child_info.keyspace()));
		let db = db.as_ref().map(|db| db as &dyn NodeDB<_, _, _>).unwrap_or(backend);

		self.with_recorder_and_cache(Some(root.0), |recorder, cache| {
			let trie = TrieDBBuilder::<H>::new_with_db_location(db, &root.0, root.1)
				.with_optional_recorder(recorder)
				.with_optional_cache(cache)
				.build();

			callback(&trie)
		})
	}

	/// Returns the next key in the trie i.e. the minimum key that is strictly superior to `key` in
	/// lexicographic order.
	///
	/// Will always traverse the trie from scratch in search of the key, which is slow.
	/// Used only when debug assertions are enabled to crosscheck the results of finding
	/// the next key through an iterator.
	#[cfg(debug_assertions)]
	pub fn next_storage_key_slow(&self, key: &[u8]) -> Result<Option<StorageKey>> {
		self.next_storage_key_from_root(&(self.root, Default::default()), None, key)
	}

	/// Access the root of the child storage in its parent trie
	fn child_root(&self, child_info: &ChildInfo) -> Result<Option<Root<H>>> {
		#[cfg(feature = "std")]
		{
			if let Some(result) = self.cache.read().child_root.get(child_info.storage_key()) {
				return Ok(*result)
			}
		}

		let map_e = |e| format!("Trie lookup with location error: {}", e);
		let result = self.with_recorder_and_cache(None, |recorder, cache| {
			read_trie_value_with_location::<Layout<H, DBLocation>, _>(
				self,
				&self.root,
				child_info.prefixed_storage_key().as_slice(),
				recorder,
				cache,
			)
			.map_err(map_e)
		});

		let result = result?.map(|r| {
			let mut hash = H::Out::default();

			// root is fetched from DB, not writable by runtime, so it's always valid.
			hash.as_mut().copy_from_slice(&r.0[..]);

			(hash, r.1)
		});

		#[cfg(feature = "std")]
		{
			self.cache.write().child_root.insert(child_info.storage_key().to_vec(), result);
		}

		Ok(result)
	}

	/// Return the next key in the child trie i.e. the minimum key that is strictly superior to
	/// `key` in lexicographic order.
	pub fn next_child_storage_key(
		&self,
		child_info: &ChildInfo,
		key: &[u8],
	) -> Result<Option<StorageKey>> {
		let child_root = match self.child_root(child_info)? {
			Some(child_root) => child_root,
			None => return Ok(None),
		};

		self.next_storage_key_from_root(&child_root, Some(child_info), key)
	}

	/// Return next key from main trie or child trie by providing corresponding root.
	fn next_storage_key_from_root(
		&self,
		root: &Root<H>,
		child_info: Option<&ChildInfo>,
		key: &[u8],
	) -> Result<Option<StorageKey>> {
		self.with_trie_db(*root, child_info, |trie| {
			let mut iter = trie.key_iter().map_err(|e| format!("TrieDB iteration error: {}", e))?;

			// The key just after the one given in input, basically `key++0`.
			// Note: We are sure this is the next key if:
			// * size of key has no limit (i.e. we can always add 0 to the path),
			// * and no keys can be inserted between `key` and `key++0` (this is ensured by sp-io).
			let mut potential_next_key = Vec::with_capacity(key.len() + 1);
			potential_next_key.extend_from_slice(key);
			potential_next_key.push(0);

			iter.seek(&potential_next_key)
				.map_err(|e| format!("TrieDB iterator seek error: {}", e))?;

			let next_element = iter.next();

			let next_key = if let Some(next_element) = next_element {
				let next_key =
					next_element.map_err(|e| format!("TrieDB iterator next error: {}", e))?;
				Some(next_key)
			} else {
				None
			};

			Ok(next_key)
		})
	}

	/// Returns the hash value
	pub fn storage_hash(&self, key: &[u8]) -> Result<Option<H::Out>> {
		let map_e = |e| format!("Trie lookup error: {}", e);

		self.with_recorder_and_cache(None, |recorder, cache| {
			TrieDBBuilder::new(self, &self.root)
				.with_optional_cache(cache)
				.with_optional_recorder(recorder)
				.build()
				.get_hash(key)
				.map_err(map_e)
		})
	}

	/// Get the value of storage at given key.
	pub fn storage(&self, key: &[u8]) -> Result<Option<StorageValue>> {
		let map_e = |e| format!("Trie lookup error: {}", e);

		self.with_recorder_and_cache(None, |recorder, cache| {
			read_trie_value::<Layout<H, DBLocation>, _>(self, &self.root, key, recorder, cache)
				.map_err(map_e)
		})
	}

	/// Returns the hash value
	pub fn child_storage_hash(&self, child_info: &ChildInfo, key: &[u8]) -> Result<Option<H::Out>> {
		let child_root = match self.child_root(child_info)? {
			Some(root) => root,
			None => return Ok(None),
		};

		let map_e = |e| format!("Trie lookup error: {}", e);

		self.with_recorder_and_cache(Some(child_root.0), |recorder, cache| {
			read_child_trie_hash::<Layout<H, DBLocation>>(
				child_info.keyspace(),
				self,
				&child_root,
				key,
				recorder,
				cache,
			)
			.map_err(map_e)
		})
	}

	/// Get the value of child storage at given key.
	pub fn child_storage(
		&self,
		child_info: &ChildInfo,
		key: &[u8],
	) -> Result<Option<StorageValue>> {
		let child_root = match self.child_root(child_info)? {
			Some(root) => root,
			None => return Ok(None),
		};

		let map_e = |e| format!("Trie lookup error: {}", e);

		self.with_recorder_and_cache(Some(child_root.0), |recorder, cache| {
			read_child_trie_value::<Layout<H, DBLocation>>(
				child_info.keyspace(),
				self,
				&child_root,
				key,
				recorder,
				cache,
			)
			.map_err(map_e)
		})
	}

	/// Get the closest merkle value at given key.
	pub fn closest_merkle_value(&self, key: &[u8]) -> Result<Option<MerkleValue<H::Out>>> {
		let map_e = |e| format!("Trie lookup error: {}", e);

		self.with_recorder_and_cache(None, |recorder, cache| {
			read_trie_first_descendant_value::<Layout<H, DBLocation>, _>(
				self, &self.root, key, recorder, cache,
			)
			.map_err(map_e)
		})
	}

	/// Get the child closest merkle value at given key.
	pub fn child_closest_merkle_value(
		&self,
		child_info: &ChildInfo,
		key: &[u8],
	) -> Result<Option<MerkleValue<H::Out>>> {
		let Some(child_root) = self.child_root(child_info)? else { return Ok(None) };

		let map_e = |e| format!("Trie lookup error: {}", e);

		self.with_recorder_and_cache(Some(child_root.0), |recorder, cache| {
			read_child_trie_first_descedant_value::<Layout<H, DBLocation>, _>(
				child_info.keyspace(),
				self,
				&child_root,
				key,
				recorder,
				cache,
			)
			.map_err(map_e)
		})
	}

	/// Create a raw iterator over the storage.
	pub fn raw_iter(&self, args: IterArgs) -> Result<RawIter<H, C, R>> {
		let root = if let Some(child_info) = args.child_info.as_ref() {
			let root = match self.child_root(&child_info)? {
				Some(root) => root,
				None => return Ok(Default::default()),
			};
			root
		} else {
			(self.root, Default::default())
		};

		if self.root == Default::default() {
			// A special-case for an empty storage root.
			return Ok(Default::default())
		}

		let trie_iter = self
			.with_trie_db(root, args.child_info.as_ref(), |db| {
				let prefix = args.prefix.as_deref().unwrap_or(&[]);
				if let Some(start_at) = args.start_at {
					TrieDBRawIterator::new_prefixed_then_seek(db, prefix, &start_at)
				} else {
					TrieDBRawIterator::new_prefixed(db, prefix)
				}
			})
			.map_err(|e| format!("TrieDB iteration error: {}", e))?;

		Ok(RawIter {
			stop_on_incomplete_database: args.stop_on_incomplete_database,
			skip_if_first: if args.start_at_exclusive {
				args.start_at.map(|key| key.to_vec())
			} else {
				None
			},
			child_info: args.child_info,
			root,
			trie_iter,
			state: IterState::Pending,
			_phantom: Default::default(),
		})
	}

	/// Return the storage root after applying the given `delta`.
	pub fn storage_root<'a>(
		&self,
		delta: impl Iterator<Item = (&'a [u8], Option<&'a [u8]>, Option<ChildChangeset<H::Out>>)>,
		state_version: StateVersion,
	) -> BackendTransaction<H::Out> {
		self.with_recorder_and_cache_for_storage_root(None, |recorder, cache| {
			let backend = self as &dyn NodeDB<H, Vec<u8>, DBLocation>;
			let commit = match state_version {
				StateVersion::V0 =>
					delta_trie_root::<sp_trie::LayoutV0<H, DBLocation>, _, _, _, _>(
						backend,
						(self.root, Default::default()),
						delta,
						recorder,
						cache,
						None,
					),
				StateVersion::V1 =>
					delta_trie_root::<sp_trie::LayoutV1<H, DBLocation>, _, _, _, _>(
						backend,
						(self.root, Default::default()),
						delta,
						recorder,
						cache,
						None,
					),
			};

			match commit {
				Ok(commit) => (Some(commit.root_hash()), commit),
				Err(e) => {
					warn!(target: "trie", "Failed to write to trie: {}", e);
					(None, BackendTransaction::unchanged(self.root))
				},
			}
		})
	}

	/// Returns the child storage root for the child trie `child_info` after applying the given
	/// `delta`.
	pub fn child_storage_root<'a>(
		&self,
		child_info: &ChildInfo,
		delta: impl Iterator<Item = (&'a [u8], Option<&'a [u8]>)>,
		state_version: StateVersion,
	) -> (BackendTransaction<H::Out>, bool) {
		let default_root = match child_info.child_type() {
			ChildType::ParentKeyId => empty_child_trie_root::<sp_trie::LayoutV1<H, DBLocation>>(),
		};
		let child_root = match self.child_root(child_info) {
			Ok(Some(root)) => root,
			Ok(None) => (default_root, Default::default()),
			Err(e) => {
				warn!(target: "trie", "Failed to read child storage root: {}", e);
				(default_root, Default::default())
			},
		};

		let commit =
			self.with_recorder_and_cache_for_storage_root(Some(child_root.0), |recorder, cache| {
				let backend = self as &dyn NodeDB<H, Vec<u8>, DBLocation>;
				match match state_version {
					StateVersion::V0 =>
						child_delta_trie_root::<sp_trie::LayoutV0<H, DBLocation>, _, _, _, _, _>(
							child_info.keyspace(),
							backend,
							child_root.0,
							child_root.1,
							delta,
							recorder,
							cache,
						),
					StateVersion::V1 =>
						child_delta_trie_root::<sp_trie::LayoutV1<H, DBLocation>, _, _, _, _, _>(
							child_info.keyspace(),
							backend,
							child_root.0,
							child_root.1,
							delta,
							recorder,
							cache,
						),
				} {
					Ok(commit) => (Some(commit.root_hash()), commit),
					Err(e) => {
						warn!(target: "trie", "Failed to write to trie: {}", e);
						(None, BackendTransaction::unchanged(self.root))
					},
				}
			});

		let is_default = commit.root_hash() == default_root;

		(commit, is_default)
	}
}

impl<H, C, R> NodeDB<H, DBValue, DBLocation> for TrieBackendEssence<H, C, R>
where
	H: Hasher,
	C: TrieCacheProvider<H> + Send + Sync,
	R: TrieRecorderProvider<H, DBLocation> + Send + Sync,
{
	fn get(
		&self,
		key: &H::Out,
		prefix: Prefix,
		location: DBLocation,
	) -> Option<(DBValue, Vec<DBLocation>)> {
		if *key == self.empty {
			return Some(([0u8].to_vec(), Default::default()))
		}
		self.storage.get(key, prefix, location)
	}

	fn contains(&self, key: &H::Out, prefix: Prefix, location: DBLocation) -> bool {
		if *key == self.empty {
			return true
		}
		self.storage.contains(key, prefix, location)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::{Backend, TrieBackend};
	use sp_core::Blake2Hasher;
	use sp_trie::{
		cache::LocalTrieCache, trie_types::TrieDBMutBuilderV1 as TrieDBMutBuilder, KeySpacedDB,
		PrefixedMemoryDB,
	};

	#[test]
	fn next_storage_key_and_next_child_storage_key_work() {
		// TODO also test on mem-tree-db
		let child_info = ChildInfo::new_default(b"MyChild");
		let child_info = &child_info;
		// Contains values
		let mut mdb = PrefixedMemoryDB::<Blake2Hasher>::default();
		let mut trie = TrieDBMutBuilder::new(&mdb).build();
		trie.insert(b"3", &[1]).expect("insert failed");
		trie.insert(b"4", &[1]).expect("insert failed");
		trie.insert(b"6", &[1]).expect("insert failed");
		let mut _root_1 = trie.commit().apply_to(&mut mdb);
		let kdb = KeySpacedDB::new(&mdb, child_info.keyspace());
		// implicitly assert child trie root is same
		// as top trie (contents must remain the same).
		let mut trie = TrieDBMutBuilder::new(&kdb).build();
		trie.insert(b"3", &[1]).expect("insert failed");
		trie.insert(b"4", &[1]).expect("insert failed");
		trie.insert(b"6", &[1]).expect("insert failed");
		let commit = trie.commit_with_keyspace(child_info.keyspace());
		let root_1 = commit.apply_to(&mut mdb);

		// Contains child trie
		let mut trie = TrieDBMutBuilder::new(&mut mdb).build();
		trie.insert(child_info.prefixed_storage_key().as_slice(), root_1.as_ref())
			.expect("insert failed");
		let root_2 = trie.commit().apply_to(&mut mdb);

		let essence_1 = TrieBackendEssence::<
			_,
			LocalTrieCache<_, _>,
			sp_trie::recorder::Recorder<_, _>,
		>::new(Box::new(mdb), root_1);
		let essence_1 = TrieBackend::from_essence(essence_1);

		assert_eq!(essence_1.next_storage_key(b"2"), Ok(Some(b"3".to_vec())));
		assert_eq!(essence_1.next_storage_key(b"3"), Ok(Some(b"4".to_vec())));
		assert_eq!(essence_1.next_storage_key(b"4"), Ok(Some(b"6".to_vec())));
		assert_eq!(essence_1.next_storage_key(b"5"), Ok(Some(b"6".to_vec())));
		assert_eq!(essence_1.next_storage_key(b"6"), Ok(None));

		let mdb = essence_1.backend_storage().as_prefixed_mem_db().unwrap().clone();
		let essence_2 = TrieBackendEssence::<
			_,
			LocalTrieCache<_, DBLocation>,
			sp_trie::recorder::Recorder<_, _>,
		>::new(Box::new(mdb), root_2);

		assert_eq!(essence_2.next_child_storage_key(child_info, b"2"), Ok(Some(b"3".to_vec())));
		assert_eq!(essence_2.next_child_storage_key(child_info, b"3"), Ok(Some(b"4".to_vec())));
		assert_eq!(essence_2.next_child_storage_key(child_info, b"4"), Ok(Some(b"6".to_vec())));
		assert_eq!(essence_2.next_child_storage_key(child_info, b"5"), Ok(Some(b"6".to_vec())));
		assert_eq!(essence_2.next_child_storage_key(child_info, b"6"), Ok(None));
	}
}
