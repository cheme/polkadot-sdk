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

//! The overlayed changes to state.

mod changeset;
mod offchain;

use self::changeset::{OriginEntry, OverlayedChangeSet, OverlayedChangeSetBlob, OverlayedInfos};
use crate::{backend::Backend, stats::StateMachineStats, warn, BackendTransaction, DefaultError};
use codec::{Decode, Encode};
use hash_db::Hasher;
pub use offchain::OffchainChanges;
#[cfg(feature = "std")]
use sp_core::HashersExternalities;
use sp_core::{
	offchain::OffchainOverlayedChange,
	storage::{
		Blob as BlobInfo, ChildInfo, DefaultChild, Name, OrderedMap as OrdMapInfo, StateVersion,
		TransientInfo, BLOB_CHUNK_SIZE,
	},
};
#[cfg(feature = "std")]
use sp_externalities::{Extension, Extensions};
#[cfg(not(feature = "std"))]
use sp_std::collections::btree_map::BTreeMap as Map;
use sp_std::{borrow::Cow, sync::Arc, vec::Vec};
use sp_trie::{empty_child_trie_root, LayoutV1};
#[cfg(feature = "std")]
use std::collections::{hash_map::Entry as MapEntry, HashMap as Map};
#[cfg(feature = "std")]
use std::{
	any::{Any, TypeId},
	boxed::Box,
};

pub use self::changeset::{
	AlreadyInRuntime, NoOpenTransaction, NotInRuntime, OverlayedContext, OverlayedValue,
};

/// Storage key.
pub type StorageKey = Vec<u8>;

/// Storage value.
pub type StorageValue = Vec<u8>;

/// Blob value.
pub type Blob = Vec<u8>;

/// In memory array of storage values.
pub type StorageCollection = Vec<(StorageKey, Option<StorageValue>)>;

/// In memory arrays of storage values for multiple child tries.
pub type ChildStorageCollection = Vec<(StorageKey, StorageCollection)>;

/// In memory changes for ordered maps.
pub type OrdMapsCollection = Vec<(OrdMapMeta, StorageCollection)>;

/// In memory changes for blobs.
pub type BlobsCollection = Vec<(BlobMeta, Blob)>;

/// In memory array of storage values.
pub type OffchainChangesCollection = Vec<((Vec<u8>, Vec<u8>), OffchainOverlayedChange)>;

/// The set of changes that are overlaid onto the backend.
///
/// It allows changes to be modified using nestable transactions.
///
/// TODO move all children, orderemaps, blobs under their own struct when possible.
pub struct Changes<H: Hasher> {
	/// Context of execution.
	context: OverlayedContext,
	/// Top level storage changes.
	top: OverlayedChangeSet,
	/// Child storage changes. The map key is the child storage key without the common prefix.
	children: Map<StorageKey, ChildChanges>,
	/// Ordered maps changes. The map key is the child storage key without the common prefix.
	ordered_maps: Map<Name, OrdMapChanges>,
	/// Blobs changes. The map key is the child storage key without the common prefix.
	pub(crate) blobs: Map<Name, BlobChanges>,
	/// Offchain related changes.
	offchain: OffchainChanges,
	/// Transaction index changes,
	transaction_index_ops: Vec<IndexOperation>,
	/// Collect statistic on this execution.
	stats: StateMachineStats,
	#[cfg(feature = "std")]
	pub(crate) hashers: HashersExternalities,
	/// Caches the "storage transaction" that is created while calling `storage_root`.
	///
	/// This transaction can be applied to the backend to persist the state changes.
	storage_transaction_cache: Option<StorageTransactionCache<H>>,
}

/// Changes for movable transient stoarge.
///
/// Rollback of movable storage work by storing a deleted storage state with `set_last_removed` into
/// the layer origin when origin is not `Empty` or not already storing a previous removed state. (if
/// empty, the rollback will remove all content). Also moved storage are tracked by there previous
/// location, so rollback can bring back state to the right place. Function `set_moved_to` is used
/// on the origin of the current layer of the source storage. Target state origin will be as
/// previously describe if existing and removed, `Empty` otherwhise. Origin tracking is done by
/// `set_moved_from`, and store into `moved_from_current`. If `moved_from_current` is already define
/// (moving twice to same target in same transaction), we first use `set_other_moved_from` to keep
/// trace of current state. If origin of the source storage is Empty, we do not track origin
/// (rollback will just clear source and revert target to its removed state (or clear if no state).
#[derive(Debug, Clone)]
pub(crate) struct MovableStorage<C, M> {
	changes: Arc<C>,
	infos: OverlayedInfos<MovableMeta<M>, Arc<C>>,
}

/// Changes for blob storage.
pub(crate) type BlobChanges = MovableStorage<OverlayedChangeSetBlob, BlobInfo>;

/// Changes for ordered map storage.
pub(crate) type OrdMapChanges = MovableStorage<OverlayedChangeSet, OrdMapInfo>;

/// Info attached to a transient movable storage.
#[derive(Debug, Clone)]
pub struct MovableMeta<M> {
	pub infos: M,
	pub size: usize,
	pub cached_hash: Option<Vec<u8>>,
	pub removed: bool,
}

/// Info attached to a transient ordered map storage.
pub type OrdMapMeta = MovableMeta<OrdMapInfo>;

/// Info attached to a transient blob storage.
pub type BlobMeta = MovableMeta<BlobInfo>;

impl<M> From<M> for MovableMeta<M> {
	fn from(infos: M) -> Self {
		Self { infos, size: 0, cached_hash: None, removed: false }
	}
}

/// Default child storage.
#[derive(Debug, Clone)]
struct ChildChanges {
	changes: OverlayedChangeSet,
	infos: DefaultChild,
}

impl<H: Hasher> Default for Changes<H> {
	fn default() -> Self {
		Self {
			context: Default::default(),
			top: Default::default(),
			children: Default::default(),
			ordered_maps: Default::default(),
			blobs: Default::default(),
			offchain: Default::default(),
			transaction_index_ops: Default::default(),
			stats: Default::default(),
			#[cfg(feature = "std")]
			hashers: Default::default(),
			storage_transaction_cache: None,
		}
	}
}

impl<H: Hasher> Clone for Changes<H> {
	fn clone(&self) -> Self {
		Self {
			context: self.context.clone(),
			top: self.top.clone(),
			children: self.children.clone(),
			ordered_maps: self.ordered_maps.clone(),
			blobs: self.blobs.clone(),
			offchain: self.offchain.clone(),
			transaction_index_ops: self.transaction_index_ops.clone(),
			stats: self.stats.clone(),
			#[cfg(feature = "std")]
			hashers: self.hashers.clone(),
			storage_transaction_cache: self.storage_transaction_cache.clone(),
		}
	}
}

impl<H: Hasher> sp_std::fmt::Debug for Changes<H> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("Changes")
			.field("context", &self.context)
			.field("top", &self.top)
			.field("children", &self.children)
			.field("ordered_maps", &self.ordered_maps)
			.field("blobs", &self.blobs)
			.field("offchain", &self.offchain)
			.field("transaction_index_ops", &self.transaction_index_ops)
			.field("stats", &self.stats)
			.field("storage_transaction_cache", &self.storage_transaction_cache)
			.finish()
	}
}

/// Transaction index operation.
#[derive(Debug, Clone)]
pub enum IndexOperation {
	/// Insert transaction into index.
	Insert {
		/// Extrinsic index in the current block.
		extrinsic: u32,
		/// Data content hash.
		hash: Vec<u8>,
		/// Indexed data size.
		size: u32,
	},
	/// Renew existing transaction storage.
	Renew {
		/// Extrinsic index in the current block.
		extrinsic: u32,
		/// Referenced index hash.
		hash: Vec<u8>,
	},
}

/// A storage changes structure that can be generated by the data collected in [`Changes`].
///
/// This contains all the changes to the storage and transactions to apply theses changes to the
/// backend.
pub struct StorageChanges<H: Hasher> {
	/// All changes to the main storage.
	///
	/// A value of `None` means that it was deleted.
	pub main_storage_changes: StorageCollection,
	/// All changes to the child storages.
	pub child_storage_changes: ChildStorageCollection,
	/// All changes to the ordered map storages.
	pub ordered_maps_changes: OrdMapsCollection,
	/// All changes to the blob storages.
	pub blobs_changes: BlobsCollection,
	/// Offchain state changes to write to the offchain database.
	pub offchain_storage_changes: OffchainChangesCollection,
	/// A transaction for the backend that contains all changes from
	/// [`main_storage_changes`](StorageChanges::main_storage_changes) and from
	/// [`child_storage_changes`](StorageChanges::child_storage_changes).
	/// [`offchain_storage_changes`](StorageChanges::offchain_storage_changes).
	pub transaction: BackendTransaction<H>,
	/// The storage root after applying the transaction.
	pub transaction_storage_root: H::Out,
	/// Changes to the transaction index,
	#[cfg(feature = "std")]
	pub transaction_index_changes: Vec<IndexOperation>,
}

#[cfg(feature = "std")]
impl<H: Hasher> StorageChanges<H> {
	/// Deconstruct into the inner values
	pub fn into_inner(
		self,
	) -> (
		StorageCollection,
		ChildStorageCollection,
		OrdMapsCollection,
		BlobsCollection,
		OffchainChangesCollection,
		BackendTransaction<H>,
		H::Out,
		Vec<IndexOperation>,
	) {
		(
			self.main_storage_changes,
			self.child_storage_changes,
			self.ordered_maps_changes,
			self.blobs_changes,
			self.offchain_storage_changes,
			self.transaction,
			self.transaction_storage_root,
			self.transaction_index_changes,
		)
	}
}

impl<H: Hasher> Default for StorageChanges<H> {
	fn default() -> Self {
		Self {
			main_storage_changes: Default::default(),
			child_storage_changes: Default::default(),
			ordered_maps_changes: Default::default(),
			blobs_changes: Default::default(),
			offchain_storage_changes: Default::default(),
			transaction: Default::default(),
			transaction_storage_root: Default::default(),
			#[cfg(feature = "std")]
			transaction_index_changes: Default::default(),
		}
	}
}

/// Storage transactions are calculated as part of the `storage_root`.
/// These transactions can be reused for importing the block into the
/// storage. So, we cache them to not require a recomputation of those transactions.
struct StorageTransactionCache<H: Hasher> {
	/// Contains the changes for the main and the child storages as one transaction.
	transaction: BackendTransaction<H>,
	/// The storage root after applying the transaction.
	transaction_storage_root: H::Out,
}

impl<H: Hasher> StorageTransactionCache<H> {
	fn into_inner(self) -> (BackendTransaction<H>, H::Out) {
		(self.transaction, self.transaction_storage_root)
	}
}

impl<H: Hasher> Clone for StorageTransactionCache<H> {
	fn clone(&self) -> Self {
		Self {
			transaction: self.transaction.clone(),
			transaction_storage_root: self.transaction_storage_root,
		}
	}
}

impl<H: Hasher> sp_std::fmt::Debug for StorageTransactionCache<H> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let mut debug = f.debug_struct("StorageTransactionCache");

		#[cfg(feature = "std")]
		debug.field("transaction_storage_root", &self.transaction_storage_root);

		#[cfg(not(feature = "std"))]
		debug.field("transaction_storage_root", &self.transaction_storage_root.as_ref());

		debug.finish()
	}
}

impl<H: Hasher> Changes<H> {
	/// Whether no changes are contained in the top nor in any of the child changes.
	pub fn is_empty(&self) -> bool {
		self.top.is_empty() && self.children.is_empty()
	}

	/// Returns a double-Option: None if the key is unknown (i.e. and the query should be referred
	/// to the backend); Some(None) if the key has been deleted. Some(Some(...)) for a key whose
	/// value has been set.
	pub fn storage(&self, key: &[u8]) -> Option<Option<&[u8]>> {
		self.top.storage(key, 0, None, &self.stats)
	}

	/// Should be called when there are changes that require to reset the
	/// `storage_transaction_cache`.
	fn mark_dirty(&mut self) {
		self.storage_transaction_cache = None;
	}

	/// Returns mutable reference to current value.
	/// If there is no value in the overlay, the given callback is used to initiate the value.
	/// Warning this function registers a change, so the mutable reference MUST be modified.
	///
	/// Can be rolled back or committed when called inside a transaction.
	#[must_use = "A change was registered, so this value MUST be modified."]
	pub fn value_mut_or_insert_with(
		&mut self,
		key: &[u8],
		init: impl Fn() -> StorageValue,
	) -> &mut StorageValue {
		self.mark_dirty();

		let value = self.top.modify(key.to_vec(), init);

		// if the value was deleted initialise it back with an empty vec
		value.get_or_insert_with(StorageValue::default)
	}

	/// Returns a double-Option: None if the key is unknown (i.e. and the query should be referred
	/// to the backend); Some(None) if the key has been deleted. Some(Some(...)) for a key whose
	/// value has been set.
	pub fn child_storage(
		&self,
		child_info: &ChildInfo,
		key: &[u8],
		start: u32,
		limit: Option<u32>,
	) -> Option<Option<Cow<[u8]>>> {
		let value = match child_info {
			ChildInfo::Default(_) => {
				let map = self.children.get(child_info.storage_key())?;
				map.changes.storage(key, start, limit, &self.stats)?.map(Cow::Borrowed)
			},
			ChildInfo::OrderedMap(info) => {
				let map = self.ordered_maps.get(&info.name)?;
				if map.infos.value_ref().removed {
					return Some(None)
				}
				map.changes.storage(key, start, limit, &self.stats)?.map(Cow::Borrowed)
			},
			ChildInfo::Blob(info) => {
				if key.len() > 0 {
					crate::warn!(target: "runtime", "Access blob with non null key.");
					return None
				}

				// semantic is key is index in blob and return value is at most a full blob chunk.
				let map = self.blobs.get(&info.name)?;
				let infos = map.infos.value_ref();
				if infos.removed {
					return Some(None)
				}
				Some(map.changes.storage(start, limit, infos.size, &self.stats))
			},
		};
		Some(value)
	}

	/// Return size of a given blob when defined.
	pub fn blob_len(&self, name: &[u8]) -> Option<u32> {
		let blob = self.blobs.get(name)?;
		let infos = blob.infos.value_ref();
		if infos.removed {
			None
		} else {
			Some(infos.size as u32)
		}
	}

	/// Return iterator on chunks if defined.
	pub fn blob_chunks(&self, name: &[u8]) -> Option<(impl Iterator<Item = &[u8]>, &BlobMeta)> {
		self.blobs.get(name).and_then(|blob| blob.chunks())
	}

	fn blob_chunks_into_committed(
		mut blob: Arc<OverlayedChangeSetBlob>,
		infos: OverlayedInfos<BlobMeta, Arc<OverlayedChangeSetBlob>>,
	) -> Option<(BlobMeta, impl Iterator<Item = [u8; BLOB_CHUNK_SIZE]>)> {
		let infos = infos.into_value();

		if !matches!(infos.infos.mode, Some(sp_core::storage::transient::Mode::Archive)) {
			return None
		}

		let (chunk_end, chunk_end_offset) = blob_chunk_end_index(infos.size);

		let nb_chunk = if chunk_end == 0 && chunk_end_offset == 0 { 0 } else { chunk_end + 1 };
		let iter = sp_std::mem::take(unsafe { rc_mut_unchecked(&mut blob) })
			.into_iter()
			.enumerate()
			.filter_map(move |(at, entry)| {
				let at = at as u32;
				if at < nb_chunk {
					Some(entry.into_value())
				} else {
					None
				}
			});

		Some((infos, iter))
	}

	/// Return size of a given map when defined.
	pub fn map_count(&self, name: &[u8]) -> Option<u32> {
		let ordmap = self.ordered_maps.get(name)?;
		let infos = ordmap.infos.value_ref();
		(!infos.removed).then(|| infos.size as u32)
	}

	/// Length of value at a given storage key.
	pub fn child_storage_len(&self, child_info: &ChildInfo, key: &[u8]) -> Option<Option<u32>> {
		let value = match child_info {
			ChildInfo::Default(_) => {
				let map = self.children.get(child_info.storage_key())?;
				map.changes.get(key)?.value().map(|v| v.len() as u32)
			},
			ChildInfo::OrderedMap(info) => {
				let map = self.ordered_maps.get(&info.name)?;
				let info = map.infos.value_ref();
				if info.removed {
					return Some(None)
				}
				map.changes.get(key)?.value().map(|v| v.len() as u32)
			},
			ChildInfo::Blob(info) => {
				if key.len() > 0 {
					crate::warn!(target: "runtime", "Access blob with non null key.");
					return None
				}

				self.blob_len(&info.name)
			},
		};
		Some(value)
	}

	/// Set a new value for the specified key.
	///
	/// Can be rolled back or committed when called inside a transaction.
	pub fn set_storage(&mut self, key: StorageKey, val: Option<StorageValue>) {
		self.mark_dirty();

		let size_write = val.as_ref().map(|x| x.len() as u64).unwrap_or(0);
		self.stats.tally_write_overlay(size_write);
		self.top.set(key, val);
	}

	/// Set a new value for the specified key and child.
	///
	/// `None` can be used to delete a value specified by the given key.
	///
	/// Can be rolled back or committed when called inside a transaction.
	///
	/// Return true if value was set.
	pub(crate) fn set_child_storage(
		&mut self,
		child_info: &ChildInfo,
		key: &[u8],
		val: Option<&[u8]>,
	) -> bool {
		self.mark_dirty();

		let size_write = val.as_ref().map(|x| x.len() as u64).unwrap_or(0);
		self.stats.tally_write_overlay(size_write);

		match child_info {
			ChildInfo::Default(info) => {
				let storage_key = child_info.storage_key().to_vec();
				let child = self.children.entry(storage_key).or_insert_with(|| ChildChanges {
					changes: self.context.spawn_child(),
					infos: info.clone(),
				});
				let updatable = child.infos.try_update(&info);
				debug_assert!(updatable);
				child.changes.set(key.to_vec(), val.map(Vec::from));
				true
			},
			ChildInfo::OrderedMap(infos) => {
				let Some(OrdMapChanges { changes, infos }) = self.ordered_maps.get_mut(&infos.name)
				else {
					return false
				};
				if infos.value_ref().removed {
					return false
				}
				let has_root = infos.value_ref().cached_hash.is_some();
				let (existing, changed) = changes
					.get(key)
					.map(|v| {
						(v.value_ref().is_some(), v.value_ref().as_ref().map(Vec::as_slice) == val)
					})
					.unwrap_or((false, true));
				if (has_root && changed) ||
					(existing && val.is_none()) ||
					(!existing && val.is_some())
				{
					let infos = infos.modify_value(&self.context);
					if changed {
						infos.cached_hash = None;
					}
					if val.is_some() {
						infos.size += 1;
					} else {
						infos.size -= 1;
					}
				}
				unsafe { rc_mut_unchecked(changes) }.set(key.to_vec(), val.map(Vec::from));
				true
			},
			ChildInfo::Blob(_) => {
				crate::warn!(target: "runtime", "Attempt to use set child on a blob, ignoring.");
				false
			},
		}
	}

	pub(crate) fn blob_set(&mut self, name: &[u8], value: &[u8], offset: u32) -> bool {
		let Some(previous_len) = self.blob_len(name) else { return false };

		if offset > previous_len {
			return false
		};

		let Some(BlobChanges { changes, infos }) = self.blobs.get_mut(name) else { return false };

		let end = offset as usize + value.len();
		if end > u32::MAX as usize {
			return false
		}

		if value.len() == 0 {
			return true
		}

		let update_size = end as u32 > previous_len;
		if update_size || infos.value_ref().cached_hash.is_some() {
			let info = infos.modify_value(&self.context);
			info.cached_hash = None;
			if update_size {
				info.size = end;
			}
		}

		if unsafe { rc_mut_unchecked(changes) }.set(value, offset) {
			self.stats.tally_write_overlay(value.len() as u64);
			true
		} else {
			false
		}
	}

	pub(crate) fn blob_truncate(&mut self, name: &[u8], new_len: u32) -> bool {
		let Some(previous_len) = self.blob_len(name) else { return false };

		let Some(blob) = self.blobs.get_mut(name) else { return false };
		if new_len >= previous_len {
			return false
		};

		let (chunk_start, chunk_start_offset) = blob_chunk_start_index(new_len as usize);
		let chunk_start = if chunk_start_offset == 0 { chunk_start } else { chunk_start + 1 };

		unsafe { rc_mut_unchecked(&mut blob.changes) }.truncate_clean(chunk_start);

		let info = blob.infos.modify_value(&self.context);
		info.cached_hash = None;
		info.size = new_len as usize;

		true
	}

	/// Clear child storage of given storage key.
	///
	/// Can be rolled back or committed when called inside a transaction.
	pub(crate) fn clear_child_storage(&mut self, child_info: &ChildInfo) -> u32 {
		self.mark_dirty();

		let storage_key = child_info.storage_key().to_vec();
		let context = &self.context;
		match child_info {
			ChildInfo::Default(info) => {
				let child = self
					.children
					.entry(storage_key)
					// could also return None here, but this does not impact
					// this kind of child trie where empty trie is never stored.
					.or_insert_with(|| ChildChanges {
						changes: context.spawn_child(),
						infos: info.clone(),
					});
				let updatable = child.infos.try_update(&info);
				debug_assert!(updatable);
				child.changes.clear_where(|_, _| true)
			},
			ChildInfo::Blob(info) => self.clear_blob_storage(&info.name),
			ChildInfo::OrderedMap(info) => self.clear_ordered_map_storage(&info.name),
		}
	}

	fn clear_blob_storage(&mut self, name: &[u8]) -> u32 {
		let context = &self.context;
		let Some(entry) = self.blobs.get_mut(name) else { return 0 };
		entry.clear_movable_storage(&|| Arc::new(context.spawn_blob()), &self.context)
	}

	fn clear_ordered_map_storage(&mut self, name: &[u8]) -> u32 {
		let context = &self.context;
		let Some(entry) = self.ordered_maps.get_mut(name) else { return 0 };
		entry.clear_movable_storage(&|| Arc::new(context.spawn_child()), &self.context)
	}

	/// Removes all key-value pairs which keys share the given prefix.
	///
	/// Can be rolled back or committed when called inside a transaction.
	pub(crate) fn clear_prefix(&mut self, prefix: &[u8]) -> u32 {
		self.mark_dirty();
		self.top.clear_where(|key, _| key.starts_with(prefix))
	}

	/// Removes all key-value pairs which keys share the given prefix.
	///
	/// Can be rolled back or committed when called inside a transaction
	pub(crate) fn clear_child_prefix(&mut self, child_info: &ChildInfo, prefix: &[u8]) -> u32 {
		self.mark_dirty();
		let context = &self.context;
		match child_info {
			ChildInfo::Default(info) => {
				let child = self.children.entry(info.name.clone()).or_insert_with(|| {
					ChildChanges { changes: context.spawn_child(), infos: info.clone() }
				});
				let updatable = child.infos.try_update(&info);
				debug_assert!(updatable);
				child.changes.clear_where(|key, _| key.starts_with(prefix))
			},
			ChildInfo::OrderedMap(info) => {
				let Some(OrdMapChanges { changes, infos }) = self.ordered_maps.get_mut(&info.name)
				else {
					return 0
				};
				if infos.value_ref().removed {
					return 0
				}

				unsafe { rc_mut_unchecked(changes) }.clear_where(|key, _| key.starts_with(prefix))
			},
			ChildInfo::Blob(_info) => 0,
		}
	}

	/// A value of zero means that no transaction is open and changes are committed on write.
	pub fn transaction_depth(&self) -> usize {
		self.context.transaction_depth()
	}

	/// Start a new nested transaction.
	///
	/// This allows to either commit or roll back all changes that where made while this
	/// transaction was open. Any transaction must be closed by either `rollback_transaction` or
	/// `commit_transaction` before this overlay can be converted into storage changes.
	///
	/// Changes made without any open transaction are committed immediately.
	pub fn start_transaction(&mut self) {
		self.context.start_transaction();
		self.top.start_transaction();
		for (_, child) in self.children.iter_mut() {
			child.changes.start_transaction();
		}
		for (_, ordmap) in self.ordered_maps.iter_mut() {
			// TODO could lazy start as infos
			unsafe { rc_mut_unchecked(&mut ordmap.changes) }.start_transaction();
		}
		for (_, blob) in self.blobs.iter_mut() {
			unsafe { rc_mut_unchecked(&mut blob.changes) }.start_transaction();
		}
		self.offchain.overlay_mut().start_transaction();
	}

	/// Rollback the last transaction started by `start_transaction`.
	///
	/// Any changes made during that transaction are discarded. Returns an error if
	/// there is no open transaction that can be rolled back.
	pub fn rollback_transaction(&mut self) -> Result<(), NoOpenTransaction> {
		self.mark_dirty();

		let start_depth = self.context.transaction_depth();
		self.context.rollback_transaction()?;

		self.top.rollback_transaction(start_depth)?;
		retain_map(&mut self.children, |_, child| {
			child
				.changes
				.rollback_transaction(start_depth)
				.expect("Top and children changesets are started in lockstep; qed");
			!child.changes.is_empty()
		});

		retain_map(&mut self.ordered_maps, |_, OrdMapChanges { changes, infos }| {
			match infos.take_last_origin(start_depth) {
				Some(OriginEntry::Empty) => (),
				None | Some(OriginEntry::Current) => {
					unsafe { rc_mut_unchecked(changes) }
						.rollback_transaction(start_depth)
						.expect("Top and children changesets are started in lockstep; qed");
				},
				Some(OriginEntry::Removed(mut last_removed)) => {
					let depth = last_removed.transaction_depth();
					unsafe { rc_mut_unchecked(&mut last_removed) }
						.stored_to_depth(depth, start_depth - 1)
						.expect("Top and children changesets are started in lockstep; qed");
					*changes = last_removed;
				},
			}
			let empty = infos
				.rollback_transaction(start_depth)
				.expect("Top and children changesets are started in lockstep; qed");
			!empty
		});
		retain_map(&mut self.blobs, |_, BlobChanges { changes, infos }| {
			match infos.take_last_origin(start_depth) {
				Some(OriginEntry::Empty) => (),
				None | Some(OriginEntry::Current) => {
					unsafe { rc_mut_unchecked(changes) }
						.rollback_transaction(start_depth)
						.expect("Top and children changesets are started in lockstep; qed");
				},
				Some(OriginEntry::Removed(mut last_removed)) => {
					let depth = last_removed.transaction_depth();
					unsafe { rc_mut_unchecked(&mut last_removed) }
						.stored_to_depth(depth, start_depth - 1)
						.expect("Top and children changesets are started in lockstep; qed");
					*changes = last_removed;
				},
			}
			let empty = infos
				.rollback_transaction(start_depth)
				.expect("Top and children changesets are started in lockstep; qed");
			!empty
		});

		self.offchain
			.overlay_mut()
			.rollback_transaction(start_depth)
			.expect("Top and offchain changesets are started in lockstep; qed");
		Ok(())
	}

	/// Commit the last transaction started by `start_transaction`.
	///
	/// Any changes made during that transaction are committed. Returns an error if there
	/// is no open transaction that can be committed.
	pub fn commit_transaction(&mut self) -> Result<(), NoOpenTransaction> {
		let start_depth = self.context.transaction_depth();
		self.context.commit_transaction()?;
		self.top.commit_transaction(start_depth)?;
		for (_, child) in self.children.iter_mut() {
			child
				.changes
				.commit_transaction(start_depth)
				.expect("Top and children changesets are started in lockstep; qed");
		}

		for (_, ordmap) in self.ordered_maps.iter_mut() {
			ordmap
				.infos
				.commit_transaction(start_depth)
				.expect("Top and children changesets are started in lockstep; qed");
			unsafe { rc_mut_unchecked(&mut ordmap.changes) }
				.commit_transaction(start_depth)
				.expect("Top and children changesets are started in lockstep; qed");
		}

		for (_, blob) in self.blobs.iter_mut() {
			blob.infos
				.commit_transaction(start_depth)
				.expect("Top and children changesets are started in lockstep; qed");
			unsafe { rc_mut_unchecked(&mut blob.changes) }
				.commit_transaction(start_depth)
				.expect("Top and children changesets are started in lockstep; qed");
		}

		self.offchain
			.overlay_mut()
			.commit_transaction(start_depth)
			.expect("Top and offchain changesets are started in lockstep; qed");
		Ok(())
	}

	/// Call this before transfering control to the runtime.
	///
	/// This protects all existing transactions from being removed by the runtime.
	/// Calling this while already inside the runtime will return an error.
	pub fn enter_runtime(&mut self) -> Result<(), AlreadyInRuntime> {
		self.context.enter_runtime()?;
		Ok(())
	}

	/// Call this when control returns from the runtime.
	///
	/// If `commit`, comits all dangling transaction left open by the runtime,
	/// else rollback them.
	/// Calling this while outside the runtime will return an error.
	pub fn exit_runtime(&mut self, commit: bool) -> Result<(), NotInRuntime> {
		let nb_open = self.context.exit_runtime()?;
		if nb_open > 0 {
			warn!(
				"{} storage transactions are left open by the runtime. Those will be rolled back.",
				nb_open,
			);
		}
		for _ in 0..nb_open {
			if commit {
				self.commit_transaction().expect("counted above");
			} else {
				self.rollback_transaction().expect("counted above");
			}
		}
		Ok(())
	}

	/// Consume all changes (top + children) and return them.
	///
	/// After calling this function no more changes are contained in this changeset.
	///
	/// Panics:
	/// Panics if `transaction_depth() > 0`
	pub(crate) fn drain_committed(
		&mut self,
	) -> (
		impl Iterator<Item = (StorageKey, Option<StorageValue>)>,
		impl Iterator<
			Item = (
				StorageKey,
				(impl Iterator<Item = (StorageKey, Option<StorageValue>)>, DefaultChild),
			),
		>,
		impl Iterator<Item = (OrdMapMeta, impl Iterator<Item = (StorageKey, Option<StorageValue>)>)>,
		impl Iterator<Item = (BlobMeta, impl Iterator<Item = [u8; BLOB_CHUNK_SIZE]>)>,
	) {
		self.context.guard_drain_committed();
		use sp_std::mem::take;
		self.context = Default::default(); // Return to client (legacy behavior).
		(
			take(&mut self.top).drain_committed(),
			take(&mut self.children)
				.into_iter()
				.map(|(key, child)| (key, (child.changes.drain_committed(), child.infos))),
			take(&mut self.ordered_maps).into_iter().filter_map(|(_key, mut ordmap)| {
				let info = ordmap.infos.drain_committed();
				(!info.removed).then(|| {
					(
						info,
						sp_std::mem::take(unsafe { rc_mut_unchecked(&mut ordmap.changes) })
							.drain_committed(),
					)
				})
			}),
			take(&mut self.blobs).into_iter().filter_map(|(_key, blob)| {
				if let Some((info, iter)) =
					Self::blob_chunks_into_committed(blob.changes, blob.infos)
				{
					(!info.removed).then(|| (info, iter))
				} else {
					None
				}
			}),
		)
	}

	/// Consume all changes (top + children) and return them.
	///
	/// After calling this function no more changes are contained in this changeset.
	///
	/// Panics:
	/// Panics if `transaction_depth() > 0`
	pub fn offchain_drain_committed(
		&mut self,
	) -> impl Iterator<Item = ((StorageKey, StorageKey), OffchainOverlayedChange)> {
		self.context.guard_drain_committed();
		self.offchain.drain()
	}

	/// Get an iterator over all child changes as seen by the current transaction.
	pub fn children(
		&self,
	) -> impl Iterator<Item = (impl Iterator<Item = (&StorageKey, &OverlayedValue)>, &DefaultChild)>
	{
		self.children.values().map(|v| (v.changes.changes(), &v.infos))
	}

	/// Get an iterator over all child changes as seen by the current transaction.
	pub fn blob_storages(&self) -> impl Iterator<Item = (impl Iterator<Item = &[u8]>, &BlobMeta)> {
		self.blobs.iter().filter_map(|(_name, blob)| blob.chunks())
	}

	/// Get an iterator over all top changes as been by the current transaction.
	pub fn changes(&self) -> impl Iterator<Item = (&StorageKey, &OverlayedValue)> {
		self.top.changes()
	}

	/// Get an optional iterator over all child changes stored under the supplied key.
	pub fn child_changes(
		&self,
		key: &[u8],
	) -> Option<(impl Iterator<Item = (&StorageKey, &OverlayedValue)>, &DefaultChild)> {
		self.children.get(key).map(|child| (child.changes.changes(), &child.infos))
	}

	/// Get an optional iterator over all ordered map changes stored under the supplied key.
	pub fn ordered_map_changes(
		&self,
		name: &[u8],
	) -> Option<(impl Iterator<Item = (&StorageKey, &OverlayedValue)>, &OrdMapMeta)> {
		self.ordered_maps.get(name).and_then(|ordmap| {
			let info = ordmap.infos.value_ref();
			(!info.removed).then(|| (ordmap.changes.changes(), info))
		})
	}

	/// Get an list of all index operations.
	pub fn transaction_index_ops(&self) -> &[IndexOperation] {
		&self.transaction_index_ops
	}

	/// Convert this instance with all changes into a [`StorageChanges`] instance.
	/// TODO remove if unused.
	pub fn into_storage_changes<B: Backend<H>>(
		mut self,
		backend: &B,
		state_version: StateVersion,
	) -> Result<StorageChanges<H>, DefaultError>
	where
		H::Out: Ord + Encode + 'static,
	{
		self.drain_storage_changes(backend, state_version)
	}

	/// Drain all changes into a [`StorageChanges`] instance. Leave empty overlay in place.
	pub fn drain_storage_changes<B: Backend<H>>(
		&mut self,
		backend: &B,
		state_version: StateVersion,
	) -> Result<StorageChanges<H>, DefaultError>
	where
		H::Out: Ord + Encode + 'static,
	{
		let (transaction, transaction_storage_root) = match self.storage_transaction_cache.take() {
			Some(cache) => cache.into_inner(),
			// If the transaction does not exist, we generate it.
			None => {
				self.storage_root(backend, state_version);
				self.storage_transaction_cache
					.take()
					.expect("`storage_transaction_cache` was just initialized; qed")
					.into_inner()
			},
		};

		let (main_storage_changes, child_storage_changes, ordmaps_changes, blobs_changes) =
			self.drain_committed();
		let offchain_storage_changes = self.offchain_drain_committed().collect();

		#[cfg(feature = "std")]
		let transaction_index_changes = std::mem::take(&mut self.transaction_index_ops);

		Ok(StorageChanges {
			main_storage_changes: main_storage_changes.collect(),
			child_storage_changes: child_storage_changes
				.map(|(sk, it)| (sk, it.0.collect()))
				.collect(),
			ordered_maps_changes: ordmaps_changes.map(|(info, it)| (info, it.collect())).collect(),
			blobs_changes: blobs_changes
				.map(|(info, blob)| {
					let size = info.size;
					(info, blob_from_chunks(blob, size))
				})
				.collect(),
			offchain_storage_changes,
			transaction,
			transaction_storage_root,
			#[cfg(feature = "std")]
			transaction_index_changes,
		})
	}

	/// Generate the storage root using `backend` and all changes
	/// as seen by the current transaction.
	///
	/// Returns the storage root and whether it was already cached.
	pub fn storage_root<B: Backend<H>>(
		&mut self,
		backend: &B,
		state_version: StateVersion,
	) -> (H::Out, bool)
	where
		H::Out: Ord + Encode,
	{
		if let Some(cache) = &self.storage_transaction_cache {
			return (cache.transaction_storage_root, true)
		}

		let delta = self.changes().map(|(k, v)| (&k[..], v.value().map(|v| &v[..])));
		let child_delta = self.children().map(|(changes, info)| {
			(info, changes.map(|(k, v)| (&k[..], v.value().map(|v| &v[..]))))
		});

		let (root, transaction) = backend.full_storage_root(delta, child_delta, state_version);

		self.storage_transaction_cache =
			Some(StorageTransactionCache { transaction, transaction_storage_root: root });

		(root, false)
	}

	/// Generate the child storage root using `backend` and all child changes
	/// as seen by the current transaction.
	///
	/// Returns the child storage root and whether it was already cached.
	pub fn child_storage_root<B: Backend<H>>(
		&mut self,
		child_info: &ChildInfo,
		backend: &B,
		state_version: StateVersion,
	) -> Result<(H::Out, bool), B::Error>
	where
		H::Out: Ord + Encode + Decode,
	{
		let storage_key = child_info.storage_key();
		let prefixed_storage_key = child_info.prefixed_storage_key();

		if self.storage_transaction_cache.is_some() {
			let root = self
				.storage(prefixed_storage_key.as_slice())
				.map(|v| Ok(v.map(|v| v.to_vec())))
				.or_else(|| backend.storage(prefixed_storage_key.as_slice()).map(Some).transpose())
				.transpose()?
				.flatten()
				.and_then(|k| Decode::decode(&mut &k[..]).ok())
				// V1 is equivalent to V0 on empty root.
				.unwrap_or_else(empty_child_trie_root::<LayoutV1<H>>);

			return Ok((root, true))
		}

		let root = if let Some((changes, _info)) = self.child_changes(storage_key) {
			let delta = changes.map(|(k, v)| (k.as_ref(), v.value().map(AsRef::as_ref)));
			Some(backend.child_storage_root(&child_info, delta, state_version))
		} else {
			None
		};

		let root = if let Some((root, is_empty, _)) = root {
			// We store update in the overlay in order to be able to use
			// 'self.storage_transaction' cache. This is brittle as it rely on Ext only querying
			// the trie backend for storage root.
			// A better design would be to manage 'child_storage_transaction' in a
			// similar way as 'storage_transaction' but for each child trie.
			self.set_storage(prefixed_storage_key.into_inner(), (!is_empty).then(|| root.encode()));

			self.mark_dirty();

			root
		} else {
			// empty overlay
			let root = backend
				.storage(prefixed_storage_key.as_slice())?
				.and_then(|k| Decode::decode(&mut &k[..]).ok())
				// V1 is equivalent to V0 on empty root.
				.unwrap_or_else(empty_child_trie_root::<LayoutV1<H>>);

			root
		};

		Ok((root, false))
	}

	/// Returns an iterator over the keys (in lexicographic order) following `key` (excluding `key`)
	/// alongside its value.
	pub fn iter_after(&self, key: &[u8]) -> impl Iterator<Item = (&[u8], &OverlayedValue)> {
		self.top.changes_after(key)
	}

	/// Returns an iterator over the keys (in lexicographic order) following `key` (excluding `key`)
	/// alongside its value for the given `storage_key` child.
	pub fn child_iter_after(
		&self,
		child_info: &ChildInfo,
		key: &[u8],
	) -> Option<impl Iterator<Item = (&[u8], &OverlayedValue)>> {
		match child_info {
			ChildInfo::Default(_) => Some(
				self.children
					.get(child_info.storage_key())
					.map(|child| child.changes.changes_after(key))
					.into_iter()
					.flatten(),
			),
			ChildInfo::OrderedMap(_infos) => None,
			ChildInfo::Blob(_infos) => None,
		}
	}

	/// Read only access ot offchain overlay.
	pub fn offchain(&self) -> &OffchainChanges {
		&self.offchain
	}

	/// Write a key value pair to the offchain storage overlay.
	pub fn set_offchain_storage(&mut self, key: &[u8], value: Option<&[u8]>) {
		use sp_core::offchain::STORAGE_PREFIX;
		match value {
			Some(value) => self.offchain.set(STORAGE_PREFIX, key, value),
			None => self.offchain.remove(STORAGE_PREFIX, key),
		}
	}

	/// Add transaction index operation.
	pub fn add_transaction_index(&mut self, op: IndexOperation) {
		self.transaction_index_ops.push(op)
	}

	/// Check if a storage was initialized.
	pub fn storage_exists(&self, info: &ChildInfo) -> bool {
		match info {
			// default child storage are viewed as always existing
			// with empty root.
			ChildInfo::Default(_) => true,
			ChildInfo::OrderedMap(info) => self
				.ordered_maps
				.get(info.name.as_slice())
				.map(|ordmap| !ordmap.infos.value_ref().removed)
				.unwrap_or(false),
			ChildInfo::Blob(info) => self
				.blobs
				.get(info.name.as_slice())
				.map(|blob| !blob.infos.value_ref().removed)
				.unwrap_or(false),
		}
	}

	/// Change info for a storage, reset storage data if `clear_existing` is set to `true`.
	/// Return true if update happen (either the storage already exist or was created).
	pub fn update_storage_info(&mut self, info: ChildInfo, clear_existing: bool) -> bool {
		match info {
			// No update info for default child storage,
			// its existence is only related to its content.
			ChildInfo::Default(_) => false,
			ChildInfo::OrderedMap(info) => {
				if clear_existing {
					self.clear_ordered_map_storage(&info.name);
				}
				let context = &self.context;
				let entry =
					self.ordered_maps.entry(info.name.clone()).or_insert_with(|| OrdMapChanges {
						changes: Arc::new(context.spawn_child()),
						infos: context.spawn_info(OrdMapMeta::from(info.clone())),
					});
				// even if same content we register and
				// update.
				let stored = entry.infos.modify_value(&self.context);
				if stored.infos.algorithm != info.algorithm {
					stored.cached_hash = None;
				}
				// TODO put in in a and_modify?? so only when existing entry?
				// TODO try update function is rather unclear: just explicitely
				// update algo and error on different name or different mode (if not None).
				let success = if stored.removed {
					stored.removed = false;
					stored.infos = info;
					true
				} else {
					stored.infos.try_update(&info)
				};
				if !success {
					crate::warn!(target: "runtime", "Try update failure should not happen.");
				}
				success
			},
			ChildInfo::Blob(info) => {
				if clear_existing {
					self.clear_blob_storage(&info.name);
				}
				let context = &self.context;
				let entry = self.blobs.entry(info.name.clone()).or_insert_with(|| BlobChanges {
					changes: Arc::new(context.spawn_blob()),
					infos: context.spawn_info(BlobMeta::from(info.clone())),
				});

				// even if same content we register and
				// update.
				let stored = entry.infos.modify_value(&self.context);
				if clear_existing {
					// TODO redundant with first call to clear remove??
					stored.size = 0;
					stored.cached_hash = None;
				}
				if stored.infos.algorithm != info.algorithm {
					stored.cached_hash = None;
				}

				let success = if stored.removed {
					stored.removed = false;
					stored.infos = info;
					true
				} else {
					stored.infos.try_update(&info)
				};
				if !success {
					crate::warn!(target: "runtime", "Try update failure should not happen.");
				}
				success
			},
		}
	}

	/// Cache root.
	/// Do nothing on failure.
	pub fn cache_ordered_map_root(&mut self, name: &[u8], root: Vec<u8>) {
		let Some(entry) = self.ordered_maps.get_mut(name) else { return };
		let entry = entry.infos.modify_value(&self.context);
		debug_assert!(!entry.removed);
		entry.cached_hash = Some(root);
	}

	/// Cache hash.
	/// Do nothing on failure.
	pub fn cache_blob_hash(&mut self, name: &[u8], hash: Vec<u8>) {
		let Some(entry) = self.blobs.get_mut(name) else { return };
		let entry = entry.infos.modify_value(&self.context);
		debug_assert!(!entry.removed);
		entry.cached_hash = Some(hash);
	}

	/// Copy current content of a storage to another one.
	/// If target exists it is replaced by this new content.
	pub fn storage_copy(&mut self, info: &ChildInfo, target_name: &[u8]) -> bool {
		let context = &self.context;
		match info {
			// Copy not supported.
			ChildInfo::Default(_) => false,
			ChildInfo::OrderedMap(info) => OrdMapChanges::copy_movable_storage(
				&mut self.ordered_maps,
				&info,
				target_name,
				&|| Arc::new(context.spawn_child()),
				&|| context.spawn_info(OrdMapMeta::from(info.clone())),
				&self.context,
			),
			ChildInfo::Blob(info) => BlobChanges::copy_movable_storage(
				&mut self.blobs,
				&info,
				target_name,
				&|| Arc::new(context.spawn_blob()),
				&|| context.spawn_info(BlobMeta::from(info.clone())),
				&self.context,
			),
		}
	}

	/// Move a storage to a different name.
	/// If target exists it is replaced by this new content.
	pub fn storage_move(&mut self, info: &ChildInfo, target_name: &[u8]) -> bool {
		let context = &self.context;
		match info {
			// Move not supported.
			ChildInfo::Default(_) => false,
			ChildInfo::OrderedMap(info) => OrdMapChanges::move_movable_storage(
				&mut self.ordered_maps,
				&info,
				target_name,
				&|| Arc::new(context.spawn_child()),
				&|| context.spawn_info(OrdMapMeta::from(info.clone())),
				&self.context,
			),
			ChildInfo::Blob(info) => BlobChanges::move_movable_storage(
				&mut self.blobs,
				&info,
				target_name,
				&|| Arc::new(context.spawn_blob()),
				&|| context.spawn_info(BlobMeta::from(info.clone())),
				&self.context,
			),
		}
	}
}

/// Common behavior between transient storage contents, technical trait to factor code.
pub(crate) trait TransientContentCommon<M>: Sized {
	// TODO can just call on use (no need for trait in this case)
	fn rollback_moved_state(&mut self, depth: usize) -> Result<(), NoOpenTransaction>;

	fn copy_on_cleared_from(&mut self, from: &MovableStorage<Self, M>);
}

impl TransientContentCommon<OrdMapInfo> for OverlayedChangeSet {
	fn rollback_moved_state(&mut self, depth: usize) -> Result<(), NoOpenTransaction> {
		let _ = self.rollback_transaction(depth)?;
		Ok(())
	}

	fn copy_on_cleared_from(&mut self, from: &MovableStorage<Self, OrdMapInfo>) {
		for (key, value) in from.changes.changes() {
			if let Some(value) = value.value_ref() {
				let dest = self.modify(key.clone(), Default::default);
				*dest = Some(value.clone());
			}
		}
	}
}

impl TransientContentCommon<BlobInfo> for OverlayedChangeSetBlob {
	fn rollback_moved_state(&mut self, depth: usize) -> Result<(), NoOpenTransaction> {
		let _ = self.rollback_transaction(depth)?;
		Ok(())
	}

	fn copy_on_cleared_from(&mut self, from: &MovableStorage<Self, BlobInfo>) {
		if let Some(chunks) = from.chunks() {
			for (i, value) in chunks.0.enumerate() {
				let chunk = self.modify_chunk(i as u32);
				chunk[..value.len()].copy_from_slice(value);
			}
		}
	}
}

impl<C, A> MovableStorage<C, TransientInfo<A>>
where
	A: Clone,
	C: TransientContentCommon<TransientInfo<A>>,
{
	fn move_storage(
		&mut self,
		spawn_changes: &impl Fn() -> Arc<C>,
		context: &OverlayedContext,
	) -> Option<(u32, Arc<C>)> {
		if !self.infos.value_ref().removed {
			let info = self.infos.modify_value(context);
			let result = info.size as u32;
			info.removed = true;
			info.size = 0;
			info.cached_hash = None;
			let last = sp_std::mem::replace(&mut self.changes, spawn_changes());
			if self.infos.need_keep_origin(context.transaction_depth()) {
				self.infos.set_last_removed(last.clone(), context);
			}
			Some((result, last))
		} else {
			None
		}
	}

	fn clear_movable_storage(
		&mut self,
		spawn_changes: &impl Fn() -> Arc<C>,
		context: &OverlayedContext,
	) -> u32 {
		let depth = context.transaction_depth();
		let info = self.infos.modify_value(context);
		let result = info.size as u32;
		info.removed = true;
		info.size = 0;
		info.cached_hash = None;
		let last = sp_std::mem::replace(&mut self.changes, spawn_changes());
		if self.infos.need_keep_origin(depth) {
			self.infos.set_last_removed(last, context);
		}
		result
	}

	fn copy_movable_storage(
		map: &mut Map<Name, Self>,
		info: &TransientInfo<A>,
		target_name: &[u8],
		spawn_changes: &impl Fn() -> Arc<C>,
		spawn_infos: &impl Fn() -> OverlayedInfos<MovableMeta<TransientInfo<A>>, Arc<C>>,
		context: &OverlayedContext,
	) -> bool {
		if &info.name == target_name {
			return false
		}
		let info_dest = if let Some(origin) = map.get(&info.name) {
			let mut info_dest = origin.infos.value_ref().clone();
			if info_dest.removed {
				return false
			};
			info_dest.infos.name = target_name.to_vec();
			info_dest
		} else {
			return false
		};

		if let Some(entry) = map.get_mut(target_name) {
			entry.clear_movable_storage(spawn_changes, context);
		}

		let entry = map
			.entry(target_name.to_vec())
			.or_insert_with(|| Self { changes: spawn_changes(), infos: spawn_infos() })
			as *mut MovableStorage<C, TransientInfo<A>>;

		let Some(origin) = map.get(&info.name) else { return false };

		// Access pointer to new val as we know ordered map.
		// implementation do not change on origin access.
		let entry: &mut _ = unsafe { &mut *entry };

		// even if same content we register and
		// update.
		let dest = entry.infos.modify_value(context);
		*dest = info_dest;

		unsafe { rc_mut_unchecked(&mut entry.changes) }.copy_on_cleared_from(origin);
		true
	}

	fn move_movable_storage(
		map: &mut Map<Name, Self>,
		info: &TransientInfo<A>,
		target_name: &[u8],
		spawn_changes: &impl Fn() -> Arc<C>,
		spawn_infos: &impl Fn() -> OverlayedInfos<MovableMeta<TransientInfo<A>>, Arc<C>>,
		context: &OverlayedContext,
	) -> bool {
		if &info.name == target_name {
			return false
		}
		let info_new = if let Some(origin) = map.get(&info.name) {
			let mut info_ori = origin.infos.value_ref().clone();
			if info_ori.removed {
				return false
			};
			info_ori.infos.name = target_name.to_vec();
			info_ori
		} else {
			return false
		};

		let Some((_size, state)) = map
			.get_mut(&info.name)
			.and_then(|entry| entry.move_storage(spawn_changes, context))
		else {
			return false
		};

		if let Some(entry) = map.get_mut(target_name) {
			entry.clear_movable_storage(spawn_changes, context);
		}

		let entry = map
			.entry(target_name.to_vec())
			.or_insert_with(|| Self { changes: spawn_changes(), infos: spawn_infos() });

		// even if same content we register and
		// update.
		let dest = entry.infos.modify_value(context);
		*dest = info_new;

		entry.changes = state;
		true
	}
}

/// Storage transaction layers support.
pub trait Transactional {
	/// Should start transaction be call.
	const REQUIRE_START_TRANSACTION: bool;

	/// Start a new nested transaction.
	///
	/// This allows to either commit or roll back all changes that were made while this
	/// transaction was open. Any transaction must be closed by either `commit_transaction`
	/// or `rollback_transaction` before this overlay can be converted into storage changes.
	///
	/// Changes made without any open transaction are committed immediately.
	fn start_transaction(&mut self);

	/// Commit the last transaction started by `start_transaction`.
	///
	/// Any changes made during that transaction are committed. Returns an error if
	/// there is no open transaction that can be committed.
	fn commit_transaction(&mut self, transaction_depth: usize) -> Result<(), NoOpenTransaction>;

	/// Rollback the last transaction started by `start_transaction`.
	///
	/// Any changes made during that transaction are discarded. Returns an error if
	/// there is no open transaction that can be rolled back.
	/// Returns `true` if no remaining content (no overlay and content same as initial one).
	#[must_use = "When empty returned, the object need to be acted upon."]
	fn rollback_transaction(&mut self, transaction_depth: usize)
		-> Result<bool, NoOpenTransaction>;

	/// Set a transactional object set a a given depth ready for restore.
	/// TODO should be useless now (always -1 if correct).
	fn stored_to_depth(
		&mut self,
		mut set_at: usize,
		restore_at: usize,
	) -> Result<(), NoOpenTransaction> {
		debug_assert!(restore_at <= set_at);
		self.rollback_transaction(set_at)?;
		loop {
			while set_at > 0 {
				set_at -= 1;
				if set_at > restore_at {
					self.rollback_transaction(set_at)?;
					continue
				}
			}
			return Ok(())
		}
	}
}

#[cfg(feature = "std")]
impl<H: Hasher> From<sp_core::storage::Storage> for Changes<H> {
	fn from(storage: sp_core::storage::Storage) -> Self {
		let context = OverlayedContext::default();
		let top: OverlayedChangeSet = storage.top.into();
		let ordered_maps: Map<Name, OrdMapChanges> = storage
			.ordered_map_storages
			.into_iter()
			.map(|(k, v)| {
				(
					k,
					OrdMapChanges {
						changes: Arc::new(v.data.into()),
						infos: context.spawn_info(OrdMapMeta::from(v.info)),
					},
				)
			})
			.collect();
		let blobs: Map<Name, BlobChanges> = storage
			.blob_storages
			.into_iter()
			.map(|(k, v)| {
				(
					k,
					BlobChanges {
						changes: Arc::new(v.data.into()),
						infos: context.spawn_info(BlobMeta::from(v.info)),
					},
				)
			})
			.collect();
		Self {
			context,
			top,
			children: storage
				.children_default
				.into_iter()
				.map(|(k, v)| (k, ChildChanges { changes: v.data.into(), infos: v.info }))
				.collect(),
			ordered_maps,
			blobs,
			..Default::default()
		}
	}
}

impl BlobChanges {
	pub(crate) fn chunks<'a>(&'a self) -> Option<(impl Iterator<Item = &'a [u8]>, &'a BlobMeta)> {
		let BlobChanges { changes: blob, infos } = self;
		let infos = infos.value_ref();
		if infos.removed {
			return None
		}

		let (chunk_end, chunk_end_offset) = blob_chunk_end_index(infos.size);

		let nb_chunk = if chunk_end == 0 && chunk_end_offset == 0 { 0 } else { chunk_end + 1 };
		let iter = (0..nb_chunk).into_iter().map(move |at| {
			let end_chunk = if at == chunk_end { chunk_end_offset } else { BLOB_CHUNK_SIZE };
			let chunk = &blob.get(at).value_ref().as_ref()[..end_chunk];
			chunk
		});

		Some((iter, infos))
	}
}

#[cfg(feature = "std")]
fn retain_map<K, V, F>(map: &mut Map<K, V>, f: F)
where
	K: std::cmp::Eq + std::hash::Hash,
	F: FnMut(&K, &mut V) -> bool,
{
	map.retain(f);
}

#[cfg(not(feature = "std"))]
fn retain_map<K, V, F>(map: &mut Map<K, V>, mut f: F)
where
	K: Ord,
	F: FnMut(&K, &mut V) -> bool,
{
	let old = sp_std::mem::replace(map, Map::default());
	for (k, mut v) in old.into_iter() {
		if f(&k, &mut v) {
			map.insert(k, v);
		}
	}
}

/// An overlayed extension is either a mutable reference
/// or an owned extension.
#[cfg(feature = "std")]
pub enum OverlayedExtension<'a> {
	MutRef(&'a mut Box<dyn Extension>),
	Owned(Box<dyn Extension>),
}

/// Overlayed extensions which are sourced from [`Extensions`].
///
/// The sourced extensions will be stored as mutable references,
/// while extensions that are registered while execution are stored
/// as owned references. After the execution of a runtime function, we
/// can safely drop this object while not having modified the original
/// list.
#[cfg(feature = "std")]
pub struct OverlayedExtensions<'a> {
	extensions: Map<TypeId, OverlayedExtension<'a>>,
}

#[cfg(feature = "std")]
impl<'a> OverlayedExtensions<'a> {
	/// Create a new instance of overalyed extensions from the given extensions.
	pub fn new(extensions: &'a mut Extensions) -> Self {
		Self {
			extensions: extensions
				.iter_mut()
				.map(|(k, v)| (*k, OverlayedExtension::MutRef(v)))
				.collect(),
		}
	}

	/// Return a mutable reference to the requested extension.
	pub fn get_mut(&mut self, ext_type_id: TypeId) -> Option<&mut dyn Any> {
		self.extensions.get_mut(&ext_type_id).map(|ext| match ext {
			OverlayedExtension::MutRef(ext) => ext.as_mut_any(),
			OverlayedExtension::Owned(ext) => ext.as_mut_any(),
		})
	}

	/// Register extension `extension` with the given `type_id`.
	pub fn register(
		&mut self,
		type_id: TypeId,
		extension: Box<dyn Extension>,
	) -> Result<(), sp_externalities::Error> {
		match self.extensions.entry(type_id) {
			MapEntry::Vacant(vacant) => {
				vacant.insert(OverlayedExtension::Owned(extension));
				Ok(())
			},
			MapEntry::Occupied(_) => Err(sp_externalities::Error::ExtensionAlreadyRegistered),
		}
	}

	/// Deregister extension with the given `type_id`.
	///
	/// Returns `true` when there was an extension registered for the given `type_id`.
	pub fn deregister(&mut self, type_id: TypeId) -> bool {
		self.extensions.remove(&type_id).is_some()
	}
}

fn blob_chunk_start_index(start: usize) -> (u32, usize) {
	((start / BLOB_CHUNK_SIZE) as u32, start % BLOB_CHUNK_SIZE)
}
fn blob_chunk_end_index(end: usize) -> (u32, usize) {
	if end == 0 {
		return (0, 0)
	}
	let chunk_end = end / BLOB_CHUNK_SIZE;
	let chunk_end_offset = end % BLOB_CHUNK_SIZE;
	if chunk_end_offset == 0 {
		(chunk_end as u32 - 1, BLOB_CHUNK_SIZE)
	} else {
		(chunk_end as u32, chunk_end_offset)
	}
}

pub(crate) fn blob_from_chunks<B: AsRef<[u8]>>(
	mut iter: impl Iterator<Item = B>,
	size: usize,
) -> Vec<u8> {
	let mut result = Vec::with_capacity(size);
	while let Some(chunk) = iter.next() {
		if (size - result.len()) < BLOB_CHUNK_SIZE {
			result.extend_from_slice(&chunk.as_ref()[..size - result.len()]);
			break
		} else {
			result.extend_from_slice(&chunk.as_ref()[..]);
		}
	}
	debug_assert!(iter.next().is_none());
	result
}

// This function is used to access movable storage content.
// To avoid keeping moving location reference on revert and
// some additional transactional complexity, we just keep
// a reference count to the content.
//
// When moving reference (on copy in source origin and a
// current state in destination at most), we keep source and destination content
// in oringin only if not `Empty` origin or `Removed` origin.
// Since first move put both state in this states we are sure
// the next move origin will not put an rc copy in a `Removed`.
//
// When doing rollback we consume all `Removed` origin and ends
// with single step assertion.
//
// When commiting, `Removed` origin overwrites the existing origin
// if it is not already `Removed` or `Empty`.
// We still don't have more than 2 copy in this case as current copy
// get overwrite by the child one.
//
// Some assumption could be add: the rc count is limited to 2
// per layer. This function is only ever call on the latest
// copy.
// TODO both assertion could be use in checked in debug mode by
// storing strong count and depth along the Arc.
unsafe fn rc_mut_unchecked<T>(rc: &mut Arc<T>) -> &mut T {
	let rc: *const T = Arc::as_ptr(rc);
	let rc: *mut T = rc as *mut _;
	&mut *rc
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{ext::Ext, new_in_mem, InMemoryBackend};
	use array_bytes::bytes2hex;
	use sp_core::{traits::Externalities, Blake2Hasher};
	use std::collections::BTreeMap;

	#[test]
	fn overlayed_storage_works() {
		let mut overlayed = Changes::<Blake2Hasher>::default();

		let key = vec![42, 69, 169, 142];

		assert!(overlayed.storage(&key).is_none());

		overlayed.start_transaction();

		overlayed.set_storage(key.clone(), Some(vec![1, 2, 3]));
		assert_eq!(overlayed.storage(&key).unwrap(), Some(&[1, 2, 3][..]));

		overlayed.commit_transaction().unwrap();

		assert_eq!(overlayed.storage(&key).unwrap(), Some(&[1, 2, 3][..]));

		overlayed.start_transaction();

		overlayed.set_storage(key.clone(), Some(vec![]));
		assert_eq!(overlayed.storage(&key).unwrap(), Some(&[][..]));

		overlayed.set_storage(key.clone(), None);
		assert!(overlayed.storage(&key).unwrap().is_none());

		overlayed.rollback_transaction().unwrap();

		assert_eq!(overlayed.storage(&key).unwrap(), Some(&[1, 2, 3][..]));

		overlayed.set_storage(key.clone(), None);
		assert!(overlayed.storage(&key).unwrap().is_none());
	}

	#[test]
	fn offchain_overlayed_storage_transactions_works() {
		use sp_core::offchain::STORAGE_PREFIX;
		fn check_offchain_content(
			state: &Changes<Blake2Hasher>,
			nb_commit: usize,
			expected: Vec<(Vec<u8>, Option<Vec<u8>>)>,
		) {
			let mut state = state.clone();
			for _ in 0..nb_commit {
				state.commit_transaction().unwrap();
			}
			let offchain_data: Vec<_> = state.offchain_drain_committed().collect();
			let expected: Vec<_> = expected
				.into_iter()
				.map(|(key, value)| {
					let change = match value {
						Some(value) => OffchainOverlayedChange::SetValue(value),
						None => OffchainOverlayedChange::Remove,
					};
					((STORAGE_PREFIX.to_vec(), key), change)
				})
				.collect();
			assert_eq!(offchain_data, expected);
		}

		let mut overlayed = Changes::default();

		let key = vec![42, 69, 169, 142];

		check_offchain_content(&overlayed, 0, vec![]);

		overlayed.start_transaction();

		overlayed.set_offchain_storage(key.as_slice(), Some(&[1, 2, 3][..]));
		check_offchain_content(&overlayed, 1, vec![(key.clone(), Some(vec![1, 2, 3]))]);

		overlayed.commit_transaction().unwrap();

		check_offchain_content(&overlayed, 0, vec![(key.clone(), Some(vec![1, 2, 3]))]);

		overlayed.start_transaction();

		overlayed.set_offchain_storage(key.as_slice(), Some(&[][..]));
		check_offchain_content(&overlayed, 1, vec![(key.clone(), Some(vec![]))]);

		overlayed.set_offchain_storage(key.as_slice(), None);
		check_offchain_content(&overlayed, 1, vec![(key.clone(), None)]);

		overlayed.rollback_transaction().unwrap();

		check_offchain_content(&overlayed, 0, vec![(key.clone(), Some(vec![1, 2, 3]))]);

		overlayed.set_offchain_storage(key.as_slice(), None);
		check_offchain_content(&overlayed, 0, vec![(key.clone(), None)]);
	}

	#[test]
	fn overlayed_storage_root_works() {
		let state_version = StateVersion::default();
		let initial: BTreeMap<_, _> = vec![
			(b"doe".to_vec(), b"reindeer".to_vec()),
			(b"dog".to_vec(), b"puppyXXX".to_vec()),
			(b"dogglesworth".to_vec(), b"catXXX".to_vec()),
			(b"doug".to_vec(), b"notadog".to_vec()),
		]
		.into_iter()
		.collect();
		let backend = InMemoryBackend::<Blake2Hasher>::from((initial, state_version));
		let mut overlay = Changes::default();

		overlay.start_transaction();
		overlay.set_storage(b"dog".to_vec(), Some(b"puppy".to_vec()));
		overlay.set_storage(b"dogglesworth".to_vec(), Some(b"catYYY".to_vec()));
		overlay.set_storage(b"doug".to_vec(), Some(vec![]));
		overlay.commit_transaction().unwrap();

		overlay.start_transaction();
		overlay.set_storage(b"dogglesworth".to_vec(), Some(b"cat".to_vec()));
		overlay.set_storage(b"doug".to_vec(), None);

		{
			let mut ext = Ext::new(&mut overlay, &backend, None);
			let root = "39245109cef3758c2eed2ccba8d9b370a917850af3824bc8348d505df2c298fa";

			assert_eq!(bytes2hex("", &ext.storage_root(state_version)), root);
			// Calling a second time should use it from the cache
			assert_eq!(bytes2hex("", &ext.storage_root(state_version)), root);
		}

		// Check that the storage root is recalculated
		overlay.set_storage(b"doug2".to_vec(), Some(b"yes".to_vec()));

		let mut ext = Ext::new(&mut overlay, &backend, None);
		let root = "5c0a4e35cb967de785e1cb8743e6f24b6ff6d45155317f2078f6eb3fc4ff3e3d";
		assert_eq!(bytes2hex("", &ext.storage_root(state_version)), root);
	}

	#[test]
	fn overlayed_child_storage_root_works() {
		let state_version = StateVersion::default();
		let child_info = ChildInfo::new_default(b"Child1");
		let child_info = &child_info;
		let backend = new_in_mem::<Blake2Hasher>();
		let mut overlay = Changes::<Blake2Hasher>::default();
		overlay.start_transaction();
		overlay.set_child_storage(child_info, &[20], Some(&[20]));
		overlay.set_child_storage(child_info, &[30], Some(&[30]));
		overlay.set_child_storage(child_info, &[40], Some(&[40]));
		overlay.commit_transaction().unwrap();
		overlay.set_child_storage(child_info, &[10], Some(&[10]));
		overlay.set_child_storage(child_info, &[30], None);

		{
			let mut ext = Ext::new(&mut overlay, &backend, None);
			let child_root = "c02965e1df4dc5baf6977390ce67dab1d7a9b27a87c1afe27b50d29cc990e0f5";
			let root = "eafb765909c3ed5afd92a0c564acf4620d0234b31702e8e8e9b48da72a748838";

			assert_eq!(
				bytes2hex("", &ext.child_storage_root(child_info, state_version).unwrap()),
				child_root,
			);

			assert_eq!(bytes2hex("", &ext.storage_root(state_version)), root);

			// Calling a second time should use it from the cache
			assert_eq!(
				bytes2hex("", &ext.child_storage_root(child_info, state_version).unwrap()),
				child_root,
			);
		}
	}

	#[test]
	fn next_storage_key_change_works() {
		let mut overlay = Changes::<Blake2Hasher>::default();
		overlay.start_transaction();
		overlay.set_storage(vec![20], Some(vec![20]));
		overlay.set_storage(vec![30], Some(vec![30]));
		overlay.set_storage(vec![40], Some(vec![40]));
		overlay.commit_transaction().unwrap();
		overlay.set_storage(vec![10], Some(vec![10]));
		overlay.set_storage(vec![30], None);

		// next_prospective < next_committed
		let next_to_5 = overlay.iter_after(&[5]).next().unwrap();
		assert_eq!(next_to_5.0.to_vec(), vec![10]);
		assert_eq!(next_to_5.1.value(), Some(&vec![10]));

		// next_committed < next_prospective
		let next_to_10 = overlay.iter_after(&[10]).next().unwrap();
		assert_eq!(next_to_10.0.to_vec(), vec![20]);
		assert_eq!(next_to_10.1.value(), Some(&vec![20]));

		// next_committed == next_prospective
		let next_to_20 = overlay.iter_after(&[20]).next().unwrap();
		assert_eq!(next_to_20.0.to_vec(), vec![30]);
		assert_eq!(next_to_20.1.value(), None);

		// next_committed, no next_prospective
		let next_to_30 = overlay.iter_after(&[30]).next().unwrap();
		assert_eq!(next_to_30.0.to_vec(), vec![40]);
		assert_eq!(next_to_30.1.value(), Some(&vec![40]));

		overlay.set_storage(vec![50], Some(vec![50]));
		// next_prospective, no next_committed
		let next_to_40 = overlay.iter_after(&[40]).next().unwrap();
		assert_eq!(next_to_40.0.to_vec(), vec![50]);
		assert_eq!(next_to_40.1.value(), Some(&vec![50]));
	}

	#[test]
	fn next_child_storage_key_change_works() {
		let child_info = ChildInfo::new_default(b"Child1");
		let child_info = &child_info;
		let mut overlay = Changes::<Blake2Hasher>::default();
		overlay.start_transaction();
		overlay.set_child_storage(child_info, &[20], Some(&[20]));
		overlay.set_child_storage(child_info, &[30], Some(&[30]));
		overlay.set_child_storage(child_info, &[40], Some(&[40]));
		overlay.commit_transaction().unwrap();
		overlay.set_child_storage(child_info, &[10], Some(&[10]));
		overlay.set_child_storage(child_info, &[30], None);

		// next_prospective < next_committed
		let next_to_5 = overlay.child_iter_after(child_info, &[5]).unwrap().next().unwrap();
		assert_eq!(next_to_5.0.to_vec(), vec![10]);
		assert_eq!(next_to_5.1.value(), Some(&vec![10]));

		// next_committed < next_prospective
		let next_to_10 = overlay.child_iter_after(child_info, &[10]).unwrap().next().unwrap();
		assert_eq!(next_to_10.0.to_vec(), vec![20]);
		assert_eq!(next_to_10.1.value(), Some(&vec![20]));

		// next_committed == next_prospective
		let next_to_20 = overlay.child_iter_after(child_info, &[20]).unwrap().next().unwrap();
		assert_eq!(next_to_20.0.to_vec(), vec![30]);
		assert_eq!(next_to_20.1.value(), None);

		// next_committed, no next_prospective
		let next_to_30 = overlay.child_iter_after(child_info, &[30]).unwrap().next().unwrap();
		assert_eq!(next_to_30.0.to_vec(), vec![40]);
		assert_eq!(next_to_30.1.value(), Some(&vec![40]));

		overlay.set_child_storage(child_info, &[50], Some(&[50]));
		// next_prospective, no next_committed
		let next_to_40 = overlay.child_iter_after(child_info, &[40]).unwrap().next().unwrap();
		assert_eq!(next_to_40.0.to_vec(), vec![50]);
		assert_eq!(next_to_40.1.value(), Some(&vec![50]));
	}

	#[test]
	#[should_panic]
	fn drain_with_open_transaction_panics() {
		let mut overlay = Changes::<Blake2Hasher>::default();
		overlay.start_transaction();
		let _ = overlay.drain_committed();
	}
}
