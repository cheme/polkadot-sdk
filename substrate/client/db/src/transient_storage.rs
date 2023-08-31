// This file is part of Substrate.

// Copyright (C) 2022-2022 Parity Technologies (UK) Ltd.
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

//! Client db storage to handle transient storage info.
//!
//! This provides a default option storage backend and a way to
//! plug external code to handle this information.
//!
//! Note plugins only target rust library, for other language
//! ffi should be added to a rust plugin.

use crate::{columns, Database, DbHash, PruningMode};
use codec::{Decode, Encode};
use core::ffi::c_void;
use libloading::{Library, Symbol};
use log::{debug, error, warn};
use sp_blockchain::Result as ClientResult;
use sp_database::Transaction;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use sp_state_machine::{BlobsCollection, OrdMapsCollection};
use std::{collections::HashMap, path::PathBuf, sync::Arc};

/// Plugin interface version.
pub const PLUGIN_VERSION: u32 = 1;

/// Plugin error code.
pub type ErrorCode = u8;

pub fn should_error(code: ErrorCode) -> bool {
	code == 1
}

pub fn did_succeed(code: ErrorCode) -> bool {
	code == 0
}
/// A ffi function that takes a rust struct pointer as input and return a
/// error code.
/// For the `add_transient_changes` callback.
pub type AddChangeFn = unsafe extern "C" fn(
	hash: *const c_void,
	parent_hash: *const c_void,
	number: *const c_void,
	btrees: *const c_void,
	blobs: *const c_void,
) -> ErrorCode;

/// A ffi function for the `canonicalize` callback.
pub type CanonicalizeFn = unsafe extern "C" fn(
	hash: *const c_void,

	parent_hash: *const c_void,
	number: *const c_void,
) -> ErrorCode;

/// A ffi function for the `drop_or_prune` callback.
pub type DropOrPruneFn = unsafe extern "C" fn(
	hash: *const c_void,

	parent_hash: *const c_void,
	number: *const c_void,
) -> ErrorCode;

/// A ffi function for the `commited_transient_changes` callback.
pub type CommitedFn = unsafe extern "C" fn(
	hash: *const c_void,
	parent_hash: *const c_void,
	number: *const c_void,
) -> ErrorCode;

/// A ffi function for the `rollbacked_transient_changes` callback.
pub type RollbackedFn = unsafe extern "C" fn(
	hash: *const c_void,
	parent_hash: *const c_void,
	number: *const c_void,
) -> ErrorCode;

/// Callback to different backends for transient storage
/// when this can be added statically during client build.
pub trait TransientStorageHook<Block: BlockT> {
	/// Transient changes added to the client db transaction.
	fn add_transient_changes(
		&mut self,
		hash: &Block::Hash,
		parent_hash: &Block::Hash,
		number: &NumberFor<Block>,
		btrees_changes: &OrdMapsCollection,
		blobs_changes: &BlobsCollection,
	) -> ClientResult<()>;

	/// Callback on canonicalize block.
	fn canonicalize(
		&mut self,
		hash: &Block::Hash,
		parent_hash: &Block::Hash,
		number: &NumberFor<Block>,
	) -> ClientResult<()>;

	/// Callback on pruning
	fn drop_or_prune(
		&mut self,
		hash: &Block::Hash,
		parent_hash: &Block::Hash,
		number: &NumberFor<Block>,
	) -> ClientResult<()>;

	/// Callback when transient changes are commited.
	fn commited_transient_changes(
		&mut self,
		hash: &Block::Hash,
		parent_hash: &Block::Hash,
		number: &NumberFor<Block>,
	) -> ClientResult<()>;

	/// Callback when transient changes are rollbacked.
	fn rollbacked_transient_changes(
		&mut self,
		hash: &Block::Hash,
		parent_hash: &Block::Hash,
		number: &NumberFor<Block>,
	) -> ClientResult<()>;
}

/// A simple implementation of transient data indexing.
/// This is meant to be use by default when no better implementation
/// is attached, but do not try to be performant.
pub(super) struct TransientArchive<'a, Block: BlockT> {
	pub db: Arc<dyn Database<DbHash>>,
	pub hash: &'a Block::Hash,
	pub parent_hash: &'a Block::Hash,
	pub number: NumberFor<Block>,
	pub in_mem: &'a mut TransientArchiveInMemory<Block>,
}

/// In memory storage of transient data.
/// This is memory buffer before storing.
/// Keep non-canonical infos.
pub(super) struct TransientArchiveInMemory<Block: BlockT> {
	infos: HashMap<Block::Hash, TransientBlockInfo>,
	conf: TransientArchiveConfig,
	hooks: Vec<Box<dyn TransientStorageHook<Block>>>,
	plugins: Vec<(Library, PathBuf)>,
}

// not send transient ptr should not leak.
unsafe impl<Block: BlockT + Send> Send for TransientArchiveInMemory<Block> {}

// not sync transient ptr should not leak.
unsafe impl<Block: BlockT + Sync> Sync for TransientArchiveInMemory<Block> {}

/// Configuration for transient storages.
pub struct TransientArchiveConfig {
	/// Path to the directory containing the plugins dynlibs.
	pub plugin_path: PathBuf,
	/// If defined only start if there is the right number of expected plugins.
	pub assert_nb_plugins: Option<usize>,
	/// Should default storage be use.
	pub use_default_storage: bool,
	/// Pruning to apply on the default storage (if used).
	pub pruning: PruningMode,
}

impl<Block: BlockT> TransientArchiveInMemory<Block> {
	/// New in memory archive storage.
	pub fn new(
		conf: TransientArchiveConfig,
		hooks: Vec<Box<dyn TransientStorageHook<Block>>>,
	) -> ClientResult<Self> {
		let mut result =
			TransientArchiveInMemory { infos: HashMap::new(), conf, plugins: Vec::new(), hooks };
		result.load_plugins(None)?;
		Ok(result)
	}

	pub(crate) fn load_plugins(
		&mut self,
		test_conf: Option<(&PathBuf, Option<usize>)>,
	) -> ClientResult<()> {
		let (path, expected) = if let Some(test) = test_conf {
			test
		} else {
			(&self.conf.plugin_path, self.conf.assert_nb_plugins)
		};
		if path.is_dir() {
			for path in std::fs::read_dir(path).map_err(|err| {
				sp_blockchain::Error::Storage(format!("Error opening storage plugin dir: {}", err))
			})? {
				let path = path.map_err(|err| {
					sp_blockchain::Error::Storage(format!("Error entry storage plugin: {}", err))
				})?;
				let path = path.path();
				let lib = unsafe {
					libloading::Library::new(&path).map_err(|err| {
						sp_blockchain::Error::Storage(format!("Error opening plugin file: {}", err))
					})?
				};
				unsafe {
					let plugin_version: Symbol<*const u32> = lib.get(b"PLUGIN_VERSION\0").unwrap();
					if **plugin_version != PLUGIN_VERSION {
						return Err(sp_blockchain::Error::Storage(format!(
							"Plugin at {:?} with incompatible version, have {:?} expected {:?}",
							path, **plugin_version, PLUGIN_VERSION
						)))
					}
					let call: Result<Symbol<AddChangeFn>, _> = lib.get(b"add_transient_changes\0");
					if let Err(err) = call {
						return Err(sp_blockchain::Error::Storage(format!(
							"Plugin at {:?} could not load add_transient_changes {:?}",
							path, err,
						)))
					}

					let call: Result<Symbol<CanonicalizeFn>, _> = lib.get(b"canonicalize\0");
					if let Err(err) = call {
						return Err(sp_blockchain::Error::Storage(format!(
							"Plugin at {:?} could not load canonicalize {:?}",
							path, err,
						)))
					}

					let call: Result<Symbol<DropOrPruneFn>, _> = lib.get(b"drop_or_prune\0");
					if let Err(err) = call {
						return Err(sp_blockchain::Error::Storage(format!(
							"Plugin at {:?} could not load drop_or_prune {:?}",
							path, err,
						)))
					}

					let call: Result<Symbol<RollbackedFn>, _> =
						lib.get(b"rollbacked_transient_changes\0");
					if let Err(err) = call {
						return Err(sp_blockchain::Error::Storage(format!(
							"Plugin at {:?} could not load rollbacked_transient_changes {:?}",
							path, err,
						)))
					}

					let call: Result<Symbol<RollbackedFn>, _> =
						lib.get(b"commited_transient_changes\0");
					if let Err(err) = call {
						return Err(sp_blockchain::Error::Storage(format!(
							"Plugin at {:?} could not load commited_transient_changes {:?}",
							path, err,
						)))
					}
				};
				self.plugins.push((lib, path));
			}
		}
		if let Some(nb) = expected {
			if self.plugins.len() != nb {
				return Err(sp_blockchain::Error::Storage(format!(
					"Expected {:?} plugins for this client, incorrect number present {:?}.",
					nb,
					self.plugins.len()
				)))
			}
		}
		Ok(())
	}
}

struct TransientBlockInfo {
	// TODO consider map if query needed (currently we only query for test)
	btrees_changes: OrdMapsCollection,
	// TODO consider map if query needed (currently we only query for test)
	blobs_changes: BlobsCollection,
}

#[derive(Encode, Decode)]
enum JournalEntry {
	NewName(Vec<u8>),
	NewKey(Vec<u8>),
}

impl<'a, Block: BlockT> TransientArchive<'a, Block> {
	#[cfg(test)]
	/// Access btree content.
	pub fn get_btree(&self, name: &[u8], key: &[u8]) -> Option<Vec<u8>> {
		if let Some(infos) = self.in_mem.infos.get(&self.hash) {
			for (info, btree) in infos.btrees_changes.iter() {
				debug_assert!(!info.removed);
				if info.infos.name.as_slice() == name {
					for (k, value) in btree.iter() {
						if k == key {
							return value.clone()
						}
					}
				}
			}
			return None
		}

		let name = name.encode();
		let btree_key = Self::btree_key(self.hash, name.as_slice(), key);
		self.db.get(columns::AUX, &btree_key)
	}

	#[cfg(test)]
	/// Access blob content.
	pub fn get_blob(&self, name: &[u8]) -> Option<Vec<u8>> {
		if let Some(infos) = self.in_mem.infos.get(&self.hash) {
			for (info, blob) in infos.blobs_changes.iter() {
				debug_assert!(!info.removed);
				if info.infos.name.as_slice() == name {
					return Some(blob.clone())
				}
			}
			return None
		}

		let blob_key = Self::blob_key(self.hash, name);
		self.db.get(columns::AUX, &blob_key)
	}

	/// Write btrees and blobs changes.
	pub fn add_transient_changes(
		&mut self,
		btrees_changes: OrdMapsCollection,
		blobs_changes: BlobsCollection,
		tx: &mut Transaction<DbHash>,
	) -> ClientResult<()> {
		for hook in self.in_mem.hooks.iter_mut() {
			hook.add_transient_changes(
				&self.hash,
				&self.parent_hash,
				&self.number,
				&btrees_changes,
				&blobs_changes,
			)?;
		}
		for lib in self.in_mem.plugins.iter_mut() {
			unsafe {
				let call: Symbol<AddChangeFn> =
					lib.0.get(b"add_transient_changes\0").expect("Checked on load");
				let r = call(
					(self.hash as *const Block::Hash).cast(),
					(self.parent_hash as *const Block::Hash).cast(),
					(&self.number as *const NumberFor<Block>).cast(),
					(&btrees_changes as *const OrdMapsCollection).cast(),
					(&blobs_changes as *const BlobsCollection).cast(),
				);
				if !did_succeed(r) {
					error!("Error in plugin {:?} for add transient call", lib.1);
				}
				if should_error(r) {
					return Err(sp_blockchain::Error::Storage(format!(
						"Error in plugin {:?} for add transient call",
						lib.1
					)))
				}
			}
		}
		if !self.in_mem.conf.use_default_storage {
			return Ok(())
		}
		if self.in_mem.conf.pruning.is_archive() {
			// just write, no checks TODO same if range is long (see latest change), but then need
			// to journal for removal of other on canonicalization
			let mut journal = vec![0u8]; // version 0
			self.write_btrees(btrees_changes, tx, &mut journal);
			self.write_blobs(blobs_changes, tx, &mut journal);
			// TODO skip writing journal
			tx.set_from_vec(columns::AUX, &Self::journal_key(self.hash), journal);
			return Ok(())
		}
		let info = TransientBlockInfo { btrees_changes, blobs_changes };

		if self.in_mem.infos.insert(self.hash.clone(), info).is_some() {
			warn!(
				"Adding transient info twice for a same block at {:?}: {:?}",
				self.hash, self.number
			);
		}
		Ok(())
	}

	/// Block canonicalization call.
	pub fn canonicalize(&mut self, tx: &mut Transaction<DbHash>) -> ClientResult<()> {
		for hook in self.in_mem.hooks.iter_mut() {
			hook.canonicalize(&self.hash, &self.parent_hash, &self.number)?;
		}
		for lib in self.in_mem.plugins.iter_mut() {
			unsafe {
				let call: Symbol<CanonicalizeFn> =
					lib.0.get(b"canonicalize\0").expect("Checked on load");
				let r = call(
					(self.hash as *const Block::Hash).cast(),
					(self.parent_hash as *const Block::Hash).cast(),
					(&self.number as *const NumberFor<Block>).cast(),
				);
				if !did_succeed(r) {
					error!("Error in plugin {:?} for canonicalize call", lib.1);
				}
				if should_error(r) {
					return Err(sp_blockchain::Error::Storage(format!(
						"Error in plugin {:?} for canonicalize call",
						lib.1
					)))
				}
			}
		}

		if !self.in_mem.conf.use_default_storage {
			return Ok(())
		}

		if self.in_mem.conf.pruning.is_archive() {
			// done in `add_transient_changes`. TODO for long history read from db and prune.
			return Ok(())
		}
		if let Some(info) = self.in_mem.infos.remove(&self.hash) {
			let mut journal = vec![0u8]; // version 0
			self.write_btrees(info.btrees_changes, tx, &mut journal);
			self.write_blobs(info.blobs_changes, tx, &mut journal);
			tx.set_from_vec(columns::AUX, &Self::journal_key(self.hash), journal);
		} else {
			debug!("Canonicalize, no transient info at {:?}: {:?}", self.hash, self.number);
		}
		Ok(())
	}

	// TODO consider calling drop and prune from canonicalize instead, but
	// would require checking if cannonical for ArchiveCanonical.
	// And then have custom pruning duration here?
	/// Out of state pruning range.
	pub fn drop_or_prune(&mut self, tx: &mut Transaction<DbHash>) -> ClientResult<()> {
		for hook in self.in_mem.hooks.iter_mut() {
			hook.drop_or_prune(&self.hash, &self.parent_hash, &self.number)?;
		}
		for lib in self.in_mem.plugins.iter_mut() {
			unsafe {
				let call: Symbol<DropOrPruneFn> =
					lib.0.get(b"drop_or_prune\0").expect("checked on loading");
				let r = call(
					(self.hash as *const Block::Hash).cast(),
					(self.parent_hash as *const Block::Hash).cast(),
					(&self.number as *const NumberFor<Block>).cast(),
				);
				if !did_succeed(r) {
					error!("Error in plugin {:?} for drop_or_prune call", lib.1);
				}
				if should_error(r) {
					return Err(sp_blockchain::Error::Storage(format!(
						"Error in plugin {:?} for drop_or_prune call",
						lib.1
					)))
				}
			}
		}

		if !self.in_mem.conf.use_default_storage {
			return Ok(())
		}
		match self.in_mem.conf.pruning {
			PruningMode::ArchiveAll => return Ok(()),
			_ => (),
		}
		let journal_key = Self::journal_key(self.hash);
		let Some(journal) = self.db.get(columns::AUX, &journal_key) else {
			debug!("Missing journal, skipping pruning {:?}", self.hash);
			return Ok(())
		};
		tx.remove(columns::AUX, &journal_key);
		let mut read_journal = journal.as_slice();
		let mut current_btree: Option<Vec<u8>> = None;
		let Some(version) = read_journal.get(0) else {
			warn!("Invalid journal encoding, skipping pruning {:?}", self.hash);
			return Ok(())
		};
		read_journal = &read_journal[1..];
		if *version != 0 {
			warn!("Unexepected journal version {:?}, skipping pruning {:?}", version, self.hash);
			return Ok(())
		}
		while let Some(type_item) = read_journal.get(0) {
			read_journal = &read_journal[1..];
			match type_item {
				0u8 => {
					let Ok(name) = Vec::<u8>::decode(&mut read_journal) else {
						warn!("Invalid journal encoding, skipping pruning {:?}", self.hash);
						return Ok(())
					};
					current_btree = Some(name);
				},
				1u8 => {
					// Note all decode here could be replace by just decoding size
					// to avoid instantiating a vec.
					let Ok(name) = Vec::<u8>::decode(&mut read_journal) else {
						warn!("Invalid journal encoding, skipping pruning {:?}", self.hash);
						return Ok(())
					};
					current_btree = None;
					let key = Self::blob_key(self.hash, name.as_slice());
					tx.remove(columns::AUX, &key);
				},
				2u8 => {
					let Ok(key) = Vec::<u8>::decode(&mut read_journal) else {
						warn!("Invalid journal encoding, skipping pruning {:?}", self.hash);
						return Ok(())
					};
					let Some(name) = current_btree.as_ref() else {
						warn!("Invalid journal encoding, skipping pruning {:?}", self.hash);
						return Ok(())
					};
					let name = name.encode();
					let key = Self::btree_key(self.hash, name.as_slice(), &key);
					tx.remove(columns::AUX, &key);
				},
				_ => {
					warn!("Invalid journal encoding, skipping pruning {:?}", self.hash);
					return Ok(())
				},
			}
		}
		Ok(())
	}

	/// Changes where commited in db.
	pub fn commited_transient_changes(&mut self) -> ClientResult<()> {
		for hook in self.in_mem.hooks.iter_mut() {
			hook.commited_transient_changes(&self.hash, &self.parent_hash, &self.number)?;
		}
		for lib in self.in_mem.plugins.iter_mut() {
			unsafe {
				let call: Symbol<CommitedFn> =
					lib.0.get(b"commited_transient_changes\0").expect("checked on loading");
				let r = call(
					(self.hash as *const Block::Hash).cast(),
					(self.parent_hash as *const Block::Hash).cast(),
					(&self.number as *const NumberFor<Block>).cast(),
				);
				if !did_succeed(r) {
					error!("Error in plugin {:?} for commited_transient_changes call", lib.1);
				}
				if should_error(r) {
					return Err(sp_blockchain::Error::Storage(format!(
						"Error in plugin {:?} for commited_transient_changes call",
						lib.1
					)))
				}
			}
		}
		Ok(())
	}

	/// Changes where rollbacked in db.
	pub fn rollbacked_transient_changes(&mut self) -> ClientResult<()> {
		for hook in self.in_mem.hooks.iter_mut() {
			hook.rollbacked_transient_changes(&self.hash, &self.parent_hash, &self.number)?;
		}
		for lib in self.in_mem.plugins.iter_mut() {
			unsafe {
				let call: Symbol<RollbackedFn> =
					lib.0.get(b"rollbacked_transient_changes\0").expect("checked on loading");
				let r = call(
					(self.hash as *const Block::Hash).cast(),
					(self.parent_hash as *const Block::Hash).cast(),
					(&self.number as *const NumberFor<Block>).cast(),
				);
				if !did_succeed(r) {
					error!("Error in plugin {:?} for rollbacked_transient_changes call", lib.1);
				}
				if should_error(r) {
					return Err(sp_blockchain::Error::Storage(format!(
						"Error in plugin {:?} for rollbacked_transient_changes call",
						lib.1
					)))
				}
			}
		}
		Ok(())
	}

	fn write_btrees(
		&mut self,
		btrees_changes: OrdMapsCollection,
		tx: &mut Transaction<DbHash>,
		journal: &mut Vec<u8>,
	) {
		for (info, changes) in btrees_changes {
			match info.infos.mode {
				Some(sp_core::storage::transient::Mode::Archive) => (),
				Some(sp_core::storage::transient::Mode::Drop) | None => continue,
			}
			if info.removed {
				// Note that there is currently no sense to have removed
				// info, but will be needed in case of a non transient mode.
				continue
			}
			let name = info.infos.name.encode();
			journal.push(0u8);
			journal.extend_from_slice(name.as_slice());
			let mut values = std::collections::BTreeSet::new();
			for (key, change) in changes {
				if let Some(change) = change {
					tx.set_from_vec(
						columns::AUX,
						&Self::btree_key(self.hash, name.as_slice(), key.as_slice()),
						change,
					);
					values.insert(key);
				} else {
					// transient, this is not needed at this point.
				}
			}
			// Note that empty btrees are only lookable through journal
			for key in values.iter() {
				journal.push(2u8);
				key.encode_to(journal);
			}
		}
	}

	fn write_blobs(
		&mut self,
		blobs_changes: BlobsCollection,
		tx: &mut Transaction<DbHash>,
		journal: &mut Vec<u8>,
	) {
		for (info, blob) in blobs_changes {
			match info.infos.mode {
				Some(sp_core::storage::transient::Mode::Archive) => (),
				Some(sp_core::storage::transient::Mode::Drop) | None => continue,
			}
			if info.removed {
				// Note that there is currently no sense to have removed
				// info, but will be needed in case of a non transient mode.
				continue
			}
			let name = &info.infos.name;
			journal.push(1u8);
			name.encode_to(journal);
			tx.set_from_vec(columns::AUX, &Self::blob_key(self.hash, name.as_slice()), blob);
		}
	}

	fn journal_key(hash: &Block::Hash) -> Vec<u8> {
		let mut key = Vec::with_capacity(32 + 16);
		key.extend_from_slice(b"TransientJournal");
		key.extend_from_slice(hash.as_ref());
		key
	}

	// TODO also consider a key to indicate btree exists (keep info of empty btree)?
	fn btree_key(hash: &Block::Hash, encoded_name: &[u8], btree_key: &[u8]) -> Vec<u8> {
		let mut key = Vec::with_capacity(32 + 19 + encoded_name.len() + btree_key.len());
		key.extend_from_slice(b"TransientOrdMapsItem");
		key.extend_from_slice(hash.as_ref());
		key.extend_from_slice(encoded_name);
		key.extend_from_slice(btree_key);
		key
	}

	fn blob_key(hash: &Block::Hash, blob_key: &[u8]) -> Vec<u8> {
		let mut key = Vec::with_capacity(32 + 18 + blob_key.len());
		key.extend_from_slice(b"TransientBlobsItem");
		key.extend_from_slice(hash.as_ref());
		key.extend_from_slice(blob_key);
		key
	}
}
