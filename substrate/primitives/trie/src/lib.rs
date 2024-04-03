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

//! Utility functions to interact with Substrate's Base-16 Modified Merkle Patricia tree ("trie").

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "std")]
pub mod cache;
mod error;
mod node_codec;
mod node_header;
#[cfg(feature = "std")]
pub mod recorder;
mod storage_proof;
mod trie_codec;
mod trie_stream;

#[cfg(feature = "std")]
pub mod proof_size_extension;

/// Our `NodeCodec`-specific error.
pub use error::Error;
/// The Substrate format implementation of `NodeCodec`.
pub use node_codec::NodeCodec;
use sp_std::{borrow::Borrow, boxed::Box, marker::PhantomData, vec::Vec};
pub use storage_proof::{CompactProof, StorageProof};
/// Trie codec reexport, mainly child trie support
/// for trie compact proof.
pub use trie_codec::{decode_compact, encode_compact, Error as CompactProofError};
/// Various re-exports from the `memory_db` module of `trie-db` crate.
pub use trie_db::memory_db::{prefixed_key, HashKey, KeyFunction, PrefixedKey};
/// Various re-exports from the `node_db` module of `trie-db` crate.
pub use trie_db::node_db::{NodeDB as NodeDBT, EMPTY_PREFIX};
use trie_db::proof::{generate_proof, verify_proof};
/// Various re-exports from the `trie-db` crate.
pub use trie_db::{
	nibble_ops,
	node::{NodePlan, ValuePlan},
	CError, Changeset, DBValue, ExistingChangesetNode, Location, NewChangesetNode, Query, Recorder,
	Trie, TrieCache, TrieConfiguration, TrieDBIterator, TrieDBKeyIterator, TrieDBRawIterator,
	TrieLayout, TrieRecorder,
};
pub use trie_db::{
	node_db::{Hasher, Prefix},
	proof::VerifyError,
	MerkleValue,
};
/// The Substrate format implementation of `TrieStream`.
pub use trie_stream::TrieStream;

/// substrate trie layout
pub struct LayoutV0<H, DL>(PhantomData<(H, DL)>);

/// substrate trie layout, with external value nodes.
pub struct LayoutV1<H, DL>(PhantomData<(H, DL)>);

impl<H, DL> TrieLayout for LayoutV0<H, DL>
where
	H: Hasher,
	DL: Location,
{
	const USE_EXTENSION: bool = false;
	const ALLOW_EMPTY: bool = true;
	const MAX_INLINE_VALUE: Option<u32> = None;

	type Hash = H;
	type Codec = NodeCodec<Self::Hash>;
	type Location = DL;
}

impl<H, DL> TrieConfiguration for LayoutV0<H, DL>
where
	H: Hasher,
	DL: Location,
{
	fn trie_root<I, A, B>(input: I) -> <Self::Hash as Hasher>::Out
	where
		I: IntoIterator<Item = (A, B)>,
		A: AsRef<[u8]> + Ord,
		B: AsRef<[u8]>,
	{
		trie_db::trie_root::trie_root_no_extension::<H, TrieStream, _, _, _>(
			input,
			Self::MAX_INLINE_VALUE,
		)
	}

	fn trie_root_unhashed<I, A, B>(input: I) -> Vec<u8>
	where
		I: IntoIterator<Item = (A, B)>,
		A: AsRef<[u8]> + Ord,
		B: AsRef<[u8]>,
	{
		trie_db::trie_root::unhashed_trie_no_extension::<H, TrieStream, _, _, _>(
			input,
			Self::MAX_INLINE_VALUE,
		)
	}

	fn encode_index(input: u32) -> Vec<u8> {
		codec::Encode::encode(&codec::Compact(input))
	}
}

impl<H, DL> TrieLayout for LayoutV1<H, DL>
where
	H: Hasher,
	DL: Location,
{
	const USE_EXTENSION: bool = false;
	const ALLOW_EMPTY: bool = true;
	const MAX_INLINE_VALUE: Option<u32> = Some(sp_core::storage::TRIE_VALUE_NODE_THRESHOLD);

	type Hash = H;
	type Codec = NodeCodec<Self::Hash>;
	type Location = DL;
}

impl<H, DL> TrieConfiguration for LayoutV1<H, DL>
where
	H: Hasher,
	DL: Location,
{
	fn trie_root<I, A, B>(input: I) -> <Self::Hash as Hasher>::Out
	where
		I: IntoIterator<Item = (A, B)>,
		A: AsRef<[u8]> + Ord,
		B: AsRef<[u8]>,
	{
		trie_db::trie_root::trie_root_no_extension::<H, TrieStream, _, _, _>(
			input,
			Self::MAX_INLINE_VALUE,
		)
	}

	fn trie_root_unhashed<I, A, B>(input: I) -> Vec<u8>
	where
		I: IntoIterator<Item = (A, B)>,
		A: AsRef<[u8]> + Ord,
		B: AsRef<[u8]>,
	{
		trie_db::trie_root::unhashed_trie_no_extension::<H, TrieStream, _, _, _>(
			input,
			Self::MAX_INLINE_VALUE,
		)
	}

	fn encode_index(input: u32) -> Vec<u8> {
		codec::Encode::encode(&codec::Compact(input))
	}
}

/// DB location hint for a trie node.
#[cfg(feature = "std")]
pub type DBLocation = u64;

#[cfg(not(feature = "std"))]
pub type DBLocation = ();

/// Type that is able to provide a [`trie_db::TrieRecorder`].
///
/// Types implementing this trait can be used to maintain recorded state
/// across operations on different [`trie_db::TrieDB`] instances.
pub trait TrieRecorderProvider<H: Hasher, L: Location> {
	/// Recorder type that is going to be returned by implementors of this trait.
	type Recorder<'a>: trie_db::TrieRecorder<H::Out, L> + 'a
	where
		Self: 'a;

	/// Create a [`StorageProof`] derived from the internal state.
	fn drain_storage_proof(&self) -> Option<StorageProof>;

	/// Provide a recorder implementing [`trie_db::TrieRecorder`].
	fn as_trie_recorder(&self, storage_root: H::Out) -> Self::Recorder<'_>;
}

/// Type that is able to provide a proof size estimation.
pub trait ProofSizeProvider {
	/// Returns the storage proof size.
	fn estimate_encoded_size(&self) -> usize;
}

/// TrieDB error over `TrieConfiguration` trait.
pub type TrieError<L> = trie_db::TrieError<TrieHash<L>, CError<L>>;
/// Reexport from `trie_db`, with genericity set for `Hasher` trait.
pub type NodeDB<'a, H, L> = dyn trie_db::node_db::NodeDB<H, trie_db::DBValue, L> + 'a;
/// Reexport from `trie_db`, with genericity set for `Hasher` trait.
/// This uses a noops `KeyFunction` (key addressing must be hashed or using
/// an encoding scheme that avoid key conflict).
pub type MemoryDB<H> =
	trie_db::memory_db::MemoryDB<H, trie_db::memory_db::HashKey<H>, trie_db::DBValue>;
/// Reexport from `trie_db`, with genericity set for `Hasher` trait.
/// This uses a prefixed `KeyFunction`
pub type PrefixedMemoryDB<H> =
	trie_db::memory_db::MemoryDB<H, trie_db::memory_db::PrefixedKey<H>, trie_db::DBValue>;
/// Reexport from `trie_db`, with genericity set for `Hasher` trait.
pub type GenericMemoryDB<H, KF> = trie_db::memory_db::MemoryDB<H, KF, trie_db::DBValue>;

/// Persistent trie database read-access interface for the a given hasher.
pub type TrieDB<'a, 'cache, L> = trie_db::TrieDB<'a, 'cache, L>;
/// Builder for creating a [`TrieDB`].
pub type TrieDBBuilder<'a, 'cache, L> = trie_db::TrieDBBuilder<'a, 'cache, L>;
/// Persistent trie database write-access interface for the a given hasher.
pub type TrieDBMut<'a, L> = trie_db::TrieDBMut<'a, L>;
/// Builder for creating a [`TrieDBMut`].
pub type TrieDBMutBuilder<'a, L> = trie_db::TrieDBMutBuilder<'a, L>;
/// Querying interface, as in `trie_db` but less generic.
pub type Lookup<'a, 'cache, L, Q> = trie_db::Lookup<'a, 'cache, L, Q>;
/// Hash type for a trie layout.
pub type TrieHash<L> = <<L as TrieLayout>::Hash as Hasher>::Out;
/// Change set for child trie.
pub type ChildChangeset<H> = Box<trie_db::triedbmut::Changeset<H, DBLocation>>;

/// This module is for non generic definition of trie type.
/// Only the `Hasher` trait is generic in this case.
pub mod trie_types {
	use super::*;

	/// Persistent trie database read-access interface for the a given hasher.
	///
	/// Read only V1 and V0 are compatible, thus we always use V1.
	pub type TrieDB<'a, 'cache, H> = super::TrieDB<'a, 'cache, LayoutV1<H, DBLocation>>;
	/// Builder for creating a [`TrieDB`].
	pub type TrieDBBuilder<'a, 'cache, H> =
		super::TrieDBBuilder<'a, 'cache, LayoutV1<H, DBLocation>>;
	/// Builder for creating a [`TrieDB`] for state V0.
	pub type TrieDBBuilderV0<'a, 'cache, H, L> = super::TrieDBBuilder<'a, 'cache, LayoutV0<H, L>>;
	/// Builder for creating a [`TrieDB`] for state V1.
	pub type TrieDBBuilderV1<'a, 'cache, H, L> = super::TrieDBBuilder<'a, 'cache, LayoutV1<H, L>>;
	/// Persistent trie database write-access interface for the a given hasher.
	pub type TrieDBMutV0<'a, H> = super::TrieDBMut<'a, LayoutV0<H, DBLocation>>;
	/// Builder for creating a [`TrieDBMutV0`].
	pub type TrieDBMutBuilderV0<'a, H> = super::TrieDBMutBuilder<'a, LayoutV0<H, DBLocation>>;
	/// Persistent trie database write-access interface for the a given hasher.
	pub type TrieDBMutV1<'a, H> = super::TrieDBMut<'a, LayoutV1<H, DBLocation>>;
	/// Builder for creating a [`TrieDBMutV1`].
	pub type TrieDBMutBuilderV1<'a, H> = super::TrieDBMutBuilder<'a, LayoutV1<H, DBLocation>>;
	/// Querying interface, as in `trie_db` but less generic.
	pub type Lookup<'a, 'cache, H, Q> = trie_db::Lookup<'a, 'cache, LayoutV1<H, DBLocation>, Q>;
	/// As in `trie_db`, but less generic, error type for the crate.
	pub type TrieError<H> = trie_db::TrieError<H, super::Error<H>>;
}

/// Alias to root hash and db location.
pub type Root<L> = (TrieHash<L>, <L as TrieLayout>::Location);

/// Create a proof for a subset of keys in a trie.
///
/// The `keys` may contain any set of keys regardless of each one of them is included
/// in the `db`.
///
/// For a key `K` that is included in the `db` a proof of inclusion is generated.
/// For a key `K` that is not included in the `db` a proof of non-inclusion is generated.
/// These can be later checked in `verify_trie_proof`.
pub fn generate_trie_proof<'a, L, I, K, DB>(
	db: &DB,
	root: TrieHash<L>,
	keys: I,
) -> Result<Vec<Vec<u8>>, Box<TrieError<L>>>
where
	L: TrieConfiguration,
	I: IntoIterator<Item = &'a K>,
	K: 'a + AsRef<[u8]>,
	DB: trie_db::node_db::NodeDB<L::Hash, trie_db::DBValue, L::Location>,
{
	generate_proof::<_, L, _, _>(db, &root, keys)
}

/// Verify a set of key-value pairs against a trie root and a proof.
///
/// Checks a set of keys with optional values for inclusion in the proof that was generated by
/// `generate_trie_proof`.
/// If the value in the pair is supplied (`(key, Some(value))`), this key-value pair will be
/// checked for inclusion in the proof.
/// If the value is omitted (`(key, None)`), this key will be checked for non-inclusion in the
/// proof.
pub fn verify_trie_proof<'a, L, I, K, V>(
	root: &TrieHash<L>,
	proof: &[Vec<u8>],
	items: I,
) -> Result<(), VerifyError<TrieHash<L>, CError<L>>>
where
	L: TrieConfiguration,
	I: IntoIterator<Item = &'a (K, Option<V>)>,
	K: 'a + AsRef<[u8]>,
	V: 'a + AsRef<[u8]>,
{
	verify_proof::<L, _, _, _>(root, proof, items)
}

/// Determine a trie root given a hash DB and delta values.
pub fn delta_trie_root<L: TrieConfiguration, I, A, B, V>(
	db: &dyn trie_db::node_db::NodeDB<L::Hash, trie_db::DBValue, L::Location>,
	root: Root<L>,
	delta: I,
	recorder: Option<&mut dyn trie_db::TrieRecorder<TrieHash<L>, L::Location>>,
	cache: Option<&mut dyn TrieCache<L::Codec, L::Location>>,
	keyspace: Option<&[u8]>,
) -> Result<trie_db::Changeset<TrieHash<L>, L::Location>, Box<TrieError<L>>>
where
	I: IntoIterator<Item = (A, B, Option<trie_db::triedbmut::TreeRefChangeset<L>>)>,
	A: Borrow<[u8]>,
	B: Borrow<Option<V>>,
	V: Borrow<[u8]>,
{
	let mut trie = TrieDBMutBuilder::<L>::from_existing_with_db_location(db, root.0, root.1)
		.with_optional_cache(cache)
		.with_optional_recorder(recorder)
		.build();

	let mut delta = delta.into_iter().collect::<Vec<_>>();
	delta.sort_by(|l, r| l.0.borrow().cmp(r.0.borrow()));

	for (key, change, set) in delta {
		match change.borrow() {
			Some(val) => trie.insert_with_tree_ref(key.borrow(), val.borrow(), set)?,
			None => trie.remove_with_tree_ref(key.borrow(), set)?,
		};
	}
	if let Some(ks) = keyspace {
		Ok(trie.commit_with_keyspace(ks))
	} else {
		Ok(trie.commit())
	}
}

/// Read a value from the trie.
pub fn read_trie_value<
	L: TrieLayout,
	DB: trie_db::node_db::NodeDB<L::Hash, trie_db::DBValue, L::Location>,
>(
	db: &DB,
	root: &TrieHash<L>,
	key: &[u8],
	recorder: Option<&mut dyn TrieRecorder<TrieHash<L>, L::Location>>,
	cache: Option<&mut dyn TrieCache<L::Codec, L::Location>>,
) -> Result<Option<Vec<u8>>, Box<TrieError<L>>> {
	TrieDBBuilder::<L>::new(db, root)
		.with_optional_cache(cache)
		.with_optional_recorder(recorder)
		.build()
		.get(key)
}

/// Read a value from the trie, get db location if db uses it.
pub fn read_trie_value_with_location<
	L: TrieLayout,
	DB: trie_db::node_db::NodeDB<L::Hash, trie_db::DBValue, L::Location>,
>(
	db: &DB,
	root: &TrieHash<L>,
	root_key: &[u8],
	recorder: Option<&mut dyn TrieRecorder<TrieHash<L>, L::Location>>,
	cache: Option<&mut dyn TrieCache<L::Codec, L::Location>>,
) -> Result<Option<(Vec<u8>, L::Location)>, Box<TrieError<L>>> {
	let trie = TrieDBBuilder::<L>::new(db, root)
		.with_optional_cache(cache)
		.with_optional_recorder(recorder)
		.build();

	let mut iter = trie_db::TrieDBNodeIterator::new(&trie)?;
	use trie_db::TrieIterator;
	iter.seek(root_key)?;
	let Some(item) = iter.next() else { return Ok(None) };
	let item = item?;
	let node = &item.2;
	let location = node.node_plan().additional_ref_location(node.locations());
	let Some(root) = iter.item_from_raw(&item) else { return Ok(None) };
	let (root_key2, root) = root?;
	// TODO should be a debug_assert
	if root_key2.as_slice() != root_key {
		return Ok(None);
	}
	Ok(Some((root, location.unwrap_or_default())))
}

/// Read the [`trie_db::MerkleValue`] of the node that is the closest descendant for
/// the provided key.
pub fn read_trie_first_descendant_value<L: TrieLayout, DB>(
	db: &DB,
	root: &TrieHash<L>,
	key: &[u8],
	recorder: Option<&mut dyn TrieRecorder<TrieHash<L>, L::Location>>,
	cache: Option<&mut dyn TrieCache<L::Codec, L::Location>>,
) -> Result<Option<MerkleValue<TrieHash<L>>>, Box<TrieError<L>>>
where
	DB: trie_db::node_db::NodeDB<L::Hash, trie_db::DBValue, L::Location>,
{
	TrieDBBuilder::<L>::new(db, root)
		.with_optional_cache(cache)
		.with_optional_recorder(recorder)
		.build()
		.lookup_first_descendant(key)
}

/// Read a value from the trie with given Query.
pub fn read_trie_value_with<
	L: TrieLayout,
	Q: Query<L::Hash, Item = Vec<u8>>,
	DB: trie_db::node_db::NodeDB<L::Hash, trie_db::DBValue, L::Location>,
>(
	db: &DB,
	root: &TrieHash<L>,
	key: &[u8],
	query: Q,
) -> Result<Option<Vec<u8>>, Box<TrieError<L>>> {
	TrieDBBuilder::<L>::new(db, root).build().get_with(key, query)
}

/// Determine the empty trie root.
pub fn empty_trie_root<L: TrieConfiguration>() -> <L::Hash as Hasher>::Out {
	L::trie_root::<_, Vec<u8>, Vec<u8>>(core::iter::empty())
}

/// Determine the empty child trie root.
pub fn empty_child_trie_root<L: TrieConfiguration>() -> <L::Hash as Hasher>::Out {
	L::trie_root::<_, Vec<u8>, Vec<u8>>(core::iter::empty())
}

/// Determine a child trie root given its ordered contents, closed form. H is the default hasher,
/// but a generic implementation may ignore this type parameter and use other hashers.
pub fn child_trie_root<L: TrieConfiguration, I, A, B>(input: I) -> <L::Hash as Hasher>::Out
where
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord,
	B: AsRef<[u8]>,
{
	L::trie_root(input)
}

/// Determine a child trie root given a hash DB and delta values. H is the default hasher,
/// but a generic implementation may ignore this type parameter and use other hashers.
pub fn child_delta_trie_root<L: TrieConfiguration, I, A, B, RD, V>(
	keyspace: &[u8],
	db: &dyn trie_db::node_db::NodeDB<L::Hash, trie_db::DBValue, L::Location>,
	root_data: RD,
	root_location: L::Location,
	delta: I,
	recorder: Option<&mut dyn TrieRecorder<TrieHash<L>, L::Location>>,
	cache: Option<&mut dyn TrieCache<L::Codec, L::Location>>,
) -> Result<trie_db::Changeset<TrieHash<L>, L::Location>, Box<TrieError<L>>>
where
	I: IntoIterator<Item = (A, B)>,
	A: Borrow<[u8]>,
	B: Borrow<Option<V>>,
	V: Borrow<[u8]>,
	RD: AsRef<[u8]>,
	L::Location: Send + Sync,
{
	let mut root = TrieHash::<L>::default();
	// root is fetched from DB, not writable by runtime, so it's always valid.
	root.as_mut().copy_from_slice(root_data.as_ref());

	let db = KeySpacedDB::new(db, keyspace);
	delta_trie_root::<L, _, _, _, _>(
		&db,
		(root, root_location),
		delta.into_iter().map(|(k, v)| (k, v, None)),
		recorder,
		cache,
		Some(keyspace),
	)
}

/// Read a value from the child trie.
pub fn read_child_trie_value<L: TrieConfiguration>(
	keyspace: &[u8],
	db: &dyn trie_db::node_db::NodeDB<L::Hash, trie_db::DBValue, L::Location>,
	root: &Root<L>,
	key: &[u8],
	recorder: Option<&mut dyn TrieRecorder<TrieHash<L>, L::Location>>,
	cache: Option<&mut dyn TrieCache<L::Codec, L::Location>>,
) -> Result<Option<Vec<u8>>, Box<TrieError<L>>> {
	let db = KeySpacedDB::new(db, keyspace);
	TrieDBBuilder::<L>::new_with_db_location(&db, &root.0, root.1)
		.with_optional_recorder(recorder)
		.with_optional_cache(cache)
		.build()
		.get(key)
		.map(|x| x.map(|val| val.to_vec()))
}

/// Read a hash from the child trie.
pub fn read_child_trie_hash<L: TrieConfiguration>(
	keyspace: &[u8],
	db: &dyn trie_db::node_db::NodeDB<L::Hash, trie_db::DBValue, L::Location>,
	root: &Root<L>,
	key: &[u8],
	recorder: Option<&mut dyn TrieRecorder<TrieHash<L>, L::Location>>,
	cache: Option<&mut dyn TrieCache<L::Codec, L::Location>>,
) -> Result<Option<TrieHash<L>>, Box<TrieError<L>>> {
	let db = KeySpacedDB::new(db, keyspace);
	TrieDBBuilder::<L>::new_with_db_location(&db, &root.0, root.1)
		.with_optional_recorder(recorder)
		.with_optional_cache(cache)
		.build()
		.get_hash(key)
}

/// Read the [`trie_db::MerkleValue`] of the node that is the closest descendant for
/// the provided child key.
pub fn read_child_trie_first_descendant_value<L: TrieConfiguration, DB>(
	keyspace: &[u8],
	db: &DB,
	root: &Root<L>,
	key: &[u8],
	recorder: Option<&mut dyn TrieRecorder<TrieHash<L>, L::Location>>,
	cache: Option<&mut dyn TrieCache<L::Codec, L::Location>>,
) -> Result<Option<MerkleValue<TrieHash<L>>>, Box<TrieError<L>>>
where
	DB: trie_db::node_db::NodeDB<L::Hash, trie_db::DBValue, L::Location>,
{
	let db = KeySpacedDB::new(db, keyspace);
	TrieDBBuilder::<L>::new_with_db_location(&db, &root.0, root.1)
		.with_optional_recorder(recorder)
		.with_optional_cache(cache)
		.build()
		.lookup_first_descendant(key)
}

/// Read a value from the child trie with given query.
pub fn read_child_trie_value_with<L, Q, DB>(
	keyspace: &[u8],
	db: &dyn trie_db::node_db::NodeDB<L::Hash, trie_db::DBValue, L::Location>,
	root_slice: &[u8],
	root_location: L::Location,
	key: &[u8],
	query: Q,
) -> Result<Option<Vec<u8>>, Box<TrieError<L>>>
where
	L: TrieConfiguration,
	Q: Query<L::Hash, Item = DBValue>,
	DB: trie_db::node_db::NodeDB<L::Hash, trie_db::DBValue, L::Location>,
{
	let mut root = TrieHash::<L>::default();
	// root is fetched from DB, not writable by runtime, so it's always valid.
	root.as_mut().copy_from_slice(root_slice);

	let db = KeySpacedDB::new(db, keyspace);
	TrieDBBuilder::<L>::new_with_db_location(&db, &root, root_location)
		.build()
		.get_with(key, query)
		.map(|x| x.map(|val| val.to_vec()))
}

/// `NodeDB` implementation that append a encoded prefix (unique id bytes) in addition to the
/// prefix of every key value.
pub struct KeySpacedDB<'a, H, T, DL>(&'a dyn trie_db::node_db::NodeDB<H, T, DL>, &'a [u8]);

/// Utility function used to merge some byte data (keyspace) and `prefix` data
/// before calling key value database primitives.
fn keyspace_as_prefix_alloc(ks: &[u8], prefix: Prefix) -> (Vec<u8>, Option<u8>) {
	let mut result = sp_std::vec![0; ks.len() + prefix.0.len()];
	result[..ks.len()].copy_from_slice(ks);
	result[ks.len()..].copy_from_slice(prefix.0);
	(result, prefix.1)
}

impl<'a, H, T, DL> KeySpacedDB<'a, H, T, DL> {
	/// instantiate new keyspaced db
	#[inline]
	pub fn new(db: &'a dyn trie_db::node_db::NodeDB<H, T, DL>, ks: &'a [u8]) -> Self {
		KeySpacedDB(db, ks)
	}
}

impl<'a, H, T, L> trie_db::node_db::NodeDB<H, T, L> for KeySpacedDB<'a, H, T, L>
where
	H: Hasher,
	T: From<&'static [u8]>,
{
	fn get(&self, key: &H::Out, prefix: Prefix, location: L) -> Option<(T, Vec<L>)> {
		let derived_prefix = keyspace_as_prefix_alloc(self.1, prefix);
		self.0.get(key, (&derived_prefix.0, derived_prefix.1), location)
	}

	fn contains(&self, key: &H::Out, prefix: Prefix, location: L) -> bool {
		let derived_prefix = keyspace_as_prefix_alloc(self.1, prefix);
		self.0.contains(key, (&derived_prefix.0, derived_prefix.1), location)
	}
}

/// Constants used into trie simplification codec.
mod trie_constants {
	const FIRST_PREFIX: u8 = 0b_00 << 6;
	pub const LEAF_PREFIX_MASK: u8 = 0b_01 << 6;
	pub const BRANCH_WITHOUT_MASK: u8 = 0b_10 << 6;
	pub const BRANCH_WITH_MASK: u8 = 0b_11 << 6;
	pub const EMPTY_TRIE: u8 = FIRST_PREFIX | (0b_00 << 4);
	pub const ALT_HASHING_LEAF_PREFIX_MASK: u8 = FIRST_PREFIX | (0b_1 << 5);
	pub const ALT_HASHING_BRANCH_WITH_MASK: u8 = FIRST_PREFIX | (0b_01 << 4);
	pub const ESCAPE_COMPACT_HEADER: u8 = EMPTY_TRIE | 0b_00_01;
}

#[cfg(test)]
mod tests {
	use super::*;
	use codec::{Compact, Decode, Encode};
	use sp_core::Blake2Hasher;
	use trie_db::{
		node_db::{Hasher, NodeDB, NodeDBMut},
		test_utils::{Alphabet, StandardMap, ValueMode},
		DBValue, NodeCodec as NodeCodecT, Trie,
	};

	type LayoutV0 = super::LayoutV0<Blake2Hasher, ()>;
	type LayoutV1 = super::LayoutV1<Blake2Hasher, ()>;
	type LayoutV0T = super::LayoutV0<Blake2Hasher, Option<usize>>;
	type LayoutV1T = super::LayoutV1<Blake2Hasher, Option<usize>>;

	type MemoryDBMeta = trie_db::memory_db::MemoryDB<
		Blake2Hasher,
		trie_db::memory_db::HashKey<Blake2Hasher>,
		trie_db::DBValue,
	>;

	type MemTreeDBMeta = trie_db::mem_tree_db::MemTreeDB<Blake2Hasher>;

	fn hashed_null_node<T: TrieConfiguration>() -> TrieHash<T> {
		<T::Codec as NodeCodecT>::hashed_null_node()
	}

	fn check_equivalent<T, D>(input: &Vec<(&[u8], &[u8])>)
	where
		T: TrieConfiguration,
		D: NodeDBMut<T::Hash, DBValue, T::Location> + Default,
	{
		let closed_form = T::trie_root(input.clone());
		let d = T::trie_root_unhashed(input.clone());
		println!("Data: {:#x?}, {:#x?}", d, Blake2Hasher::hash(&d[..]));
		let persistent = {
			let mut memdb = D::default();
			let mut t = TrieDBMutBuilder::<T>::new(&mut memdb).build();
			for (x, y) in input.iter().rev() {
				t.insert(x, y).unwrap();
			}
			t.commit().root_hash()
		};
		assert_eq!(closed_form, persistent);
	}

	fn check_iteration<T, D>(input: &Vec<(&[u8], &[u8])>)
	where
		T: TrieConfiguration,
		D: NodeDBMut<T::Hash, DBValue, T::Location> + Default,
	{
		let mut memdb = D::default();
		let mut t = TrieDBMutBuilder::<T>::new(&mut memdb).build();
		for (x, y) in input.clone() {
			t.insert(x, y).unwrap();
		}
		let changes = t.commit();
		let root = memdb.apply_changeset(changes);
		let t = TrieDBBuilder::<T>::new(&memdb, &root).build();
		assert_eq!(
			input.iter().map(|(i, j)| (i.to_vec(), j.to_vec())).collect::<Vec<_>>(),
			t.iter()
				.unwrap()
				.map(|x| x.map(|y| (y.0, y.1.to_vec())).unwrap())
				.collect::<Vec<_>>()
		);
	}

	fn check_input(input: &Vec<(&[u8], &[u8])>) {
		check_equivalent::<LayoutV0, MemoryDBMeta>(input);
		check_iteration::<LayoutV0, MemoryDBMeta>(input);
		check_equivalent::<LayoutV1, MemoryDBMeta>(input);
		check_iteration::<LayoutV1, MemoryDBMeta>(input);
		check_equivalent::<LayoutV0T, MemTreeDBMeta>(input);
		check_iteration::<LayoutV0T, MemTreeDBMeta>(input);
		check_equivalent::<LayoutV1T, MemTreeDBMeta>(input);
		check_iteration::<LayoutV1T, MemTreeDBMeta>(input);
	}

	#[test]
	fn default_trie_root() {
		let mut db = MemoryDB::default();
		let empty = TrieDBMutBuilder::<LayoutV1>::new(&mut db).build();
		let root1 = empty.commit().root_hash().as_ref().to_vec();
		let root2: Vec<u8> = LayoutV1::trie_root::<_, Vec<u8>, Vec<u8>>(std::iter::empty())
			.as_ref()
			.iter()
			.cloned()
			.collect();

		assert_eq!(root1, root2);
	}

	#[test]
	fn empty_is_equivalent() {
		let input: Vec<(&[u8], &[u8])> = vec![];
		check_input(&input);
	}

	#[test]
	fn leaf_is_equivalent() {
		let input: Vec<(&[u8], &[u8])> = vec![(&[0xaa][..], &[0xbb][..])];
		check_input(&input);
	}

	#[test]
	fn branch_is_equivalent() {
		let input: Vec<(&[u8], &[u8])> =
			vec![(&[0xaa][..], &[0x10][..]), (&[0xba][..], &[0x11][..])];
		check_input(&input);
	}

	#[test]
	fn extension_and_branch_is_equivalent() {
		let input: Vec<(&[u8], &[u8])> =
			vec![(&[0xaa][..], &[0x10][..]), (&[0xab][..], &[0x11][..])];
		check_input(&input);
	}

	#[test]
	fn standard_is_equivalent() {
		let st = StandardMap {
			alphabet: Alphabet::All,
			min_key: 32,
			journal_key: 0,
			value_mode: ValueMode::Random,
			count: 1000,
		};
		let mut d = st.make();
		d.sort_by(|(a, _), (b, _)| a.cmp(b));
		let dr = d.iter().map(|v| (&v.0[..], &v.1[..])).collect();
		check_input(&dr);
	}

	#[test]
	fn extension_and_branch_with_value_is_equivalent() {
		let input: Vec<(&[u8], &[u8])> = vec![
			(&[0xaa][..], &[0xa0][..]),
			(&[0xaa, 0xaa][..], &[0xaa][..]),
			(&[0xaa, 0xbb][..], &[0xab][..]),
		];
		check_input(&input);
	}

	#[test]
	fn bigger_extension_and_branch_with_value_is_equivalent() {
		let input: Vec<(&[u8], &[u8])> = vec![
			(&[0xaa][..], &[0xa0][..]),
			(&[0xaa, 0xaa][..], &[0xaa][..]),
			(&[0xaa, 0xbb][..], &[0xab][..]),
			(&[0xbb][..], &[0xb0][..]),
			(&[0xbb, 0xbb][..], &[0xbb][..]),
			(&[0xbb, 0xcc][..], &[0xbc][..]),
		];
		check_input(&input);
	}

	#[test]
	fn single_long_leaf_is_equivalent() {
		let input: Vec<(&[u8], &[u8])> = vec![
			(
				&[0xaa][..],
				&b"ABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABC"[..],
			),
			(&[0xba][..], &[0x11][..]),
		];
		check_input(&input);
	}

	#[test]
	fn two_long_leaves_is_equivalent() {
		let input: Vec<(&[u8], &[u8])> = vec![
			(
				&[0xaa][..],
				&b"ABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABC"[..],
			),
			(
				&[0xba][..],
				&b"ABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABC"[..],
			),
		];
		check_input(&input);
	}

	fn populate_trie<'db, T: TrieConfiguration>(
		db: &'db dyn NodeDB<T::Hash, DBValue, T::Location>,
		v: &[(Vec<u8>, Vec<u8>)],
	) -> TrieDBMut<'db, T> {
		let mut t = TrieDBMutBuilder::<T>::new(db).build();
		for i in 0..v.len() {
			let key: &[u8] = &v[i].0;
			let val: &[u8] = &v[i].1;
			t.insert(key, val).unwrap();
		}
		t
	}

	fn unpopulate_trie<T: TrieConfiguration>(t: &mut TrieDBMut<'_, T>, v: &[(Vec<u8>, Vec<u8>)]) {
		for i in v {
			let key: &[u8] = &i.0;
			t.remove(key).unwrap();
		}
	}

	#[test]
	fn random_should_work() {
		random_should_work_inner::<LayoutV1T, MemTreeDBMeta>();
		random_should_work_inner::<LayoutV1, MemoryDBMeta>();
		random_should_work_inner::<LayoutV0, MemoryDBMeta>();
	}
	fn random_should_work_inner<L, D>()
	where
		L: TrieConfiguration,
		D: NodeDBMut<L::Hash, DBValue, L::Location> + Default,
	{
		let mut seed = <Blake2Hasher as Hasher>::Out::zero();
		for test_i in 0..10_000 {
			if test_i % 50 == 0 {
				println!("{:?} of 10000 stress tests done", test_i);
			}
			let x = StandardMap {
				alphabet: Alphabet::Custom(b"@QWERTYUIOPASDFGHJKLZXCVBNM[/]^_".to_vec()),
				min_key: 5,
				journal_key: 0,
				value_mode: ValueMode::Index,
				count: 100,
			}
			.make_with(seed.as_fixed_bytes_mut());

			let real = L::trie_root(x.clone());
			let mut memdb = D::default();

			let memtrie = populate_trie::<L>(&mut memdb, &x);
			let commit = memtrie.commit();
			let root = memdb.apply_changeset(commit);

			if root != real {
				println!("TRIE MISMATCH");
				println!();
				println!("{:?} vs {:?}", root, real);
				for i in &x {
					println!("{:#x?} -> {:#x?}", i.0, i.1);
				}
			}
			assert_eq!(root, real);
			let mut memtrie = TrieDBMutBuilder::<L>::from_existing(&memdb, root).build();
			unpopulate_trie::<L>(&mut memtrie, &x);
			let commit = memtrie.commit();
			let root = memdb.apply_changeset(commit);
			let hashed_null_node = hashed_null_node::<L>();
			if root != hashed_null_node {
				println!("- TRIE MISMATCH");
				println!();
				println!("{:?} vs {:?}", root, hashed_null_node);
				for i in &x {
					println!("{:#x?} -> {:#x?}", i.0, i.1);
				}
			}
			assert_eq!(root, hashed_null_node);
		}
	}

	fn to_compact(n: u8) -> u8 {
		Compact(n).encode()[0]
	}

	#[test]
	fn codec_trie_empty() {
		let input: Vec<(&[u8], &[u8])> = vec![];
		let trie = LayoutV1::trie_root_unhashed(input);
		println!("trie: {:#x?}", trie);
		assert_eq!(trie, vec![0x0]);
	}

	#[test]
	fn codec_trie_single_tuple() {
		let input = vec![(vec![0xaa], vec![0xbb])];
		let trie = LayoutV1::trie_root_unhashed(input);
		println!("trie: {:#x?}", trie);
		assert_eq!(
			trie,
			vec![
				0x42,          // leaf 0x40 (2^6) with (+) key of 2 nibbles (0x02)
				0xaa,          // key data
				to_compact(1), // length of value in bytes as Compact
				0xbb           // value data
			]
		);
	}

	#[test]
	fn codec_trie_two_tuples_disjoint_keys() {
		let input = vec![(&[0x48, 0x19], &[0xfe]), (&[0x13, 0x14], &[0xff])];
		let trie = LayoutV1::trie_root_unhashed(input);
		println!("trie: {:#x?}", trie);
		let mut ex = Vec::<u8>::new();
		ex.push(0x80); // branch, no value (0b_10..) no nibble
		ex.push(0x12); // slots 1 & 4 are taken from 0-7
		ex.push(0x00); // no slots from 8-15
		ex.push(to_compact(0x05)); // first slot: LEAF, 5 bytes long.
		ex.push(0x43); // leaf 0x40 with 3 nibbles
		ex.push(0x03); // first nibble
		ex.push(0x14); // second & third nibble
		ex.push(to_compact(0x01)); // 1 byte data
		ex.push(0xff); // value data
		ex.push(to_compact(0x05)); // second slot: LEAF, 5 bytes long.
		ex.push(0x43); // leaf with 3 nibbles
		ex.push(0x08); // first nibble
		ex.push(0x19); // second & third nibble
		ex.push(to_compact(0x01)); // 1 byte data
		ex.push(0xfe); // value data

		assert_eq!(trie, ex);
	}

	#[test]
	fn iterator_works() {
		iterator_works_inner::<LayoutV1T, MemTreeDBMeta>();
		iterator_works_inner::<LayoutV1, MemoryDBMeta>();
		iterator_works_inner::<LayoutV0, MemoryDBMeta>();
	}
	fn iterator_works_inner<L, D>()
	where
		L: TrieConfiguration,
		D: NodeDBMut<L::Hash, DBValue, L::Location> + Default,
	{
		let pairs = vec![
			(
				array_bytes::hex2bytes_unchecked("0103000000000000000464"),
				array_bytes::hex2bytes_unchecked("0400000000"),
			),
			(
				array_bytes::hex2bytes_unchecked("0103000000000000000469"),
				array_bytes::hex2bytes_unchecked("0401000000"),
			),
		];

		let mut mdb = D::default();
		let t = populate_trie::<L>(&mut mdb, &pairs);
		let changes = t.commit();
		let root = mdb.apply_changeset(changes);

		let trie = TrieDBBuilder::<L>::new(&mdb, &root).build();

		let iter = trie.iter().unwrap();
		let mut iter_pairs = Vec::new();
		for pair in iter {
			let (key, value) = pair.unwrap();
			iter_pairs.push((key, value));
		}

		assert_eq!(pairs, iter_pairs);
	}

	#[test]
	fn proof_non_inclusion_works() {
		let pairs = vec![
			(array_bytes::hex2bytes_unchecked("0102"), array_bytes::hex2bytes_unchecked("01")),
			(array_bytes::hex2bytes_unchecked("0203"), array_bytes::hex2bytes_unchecked("0405")),
		];

		let mut memdb = MemoryDB::default();
		let t = populate_trie::<LayoutV1>(&mut memdb, &pairs);
		let root = t.commit().apply_to(&mut memdb);

		let non_included_key: Vec<u8> = array_bytes::hex2bytes_unchecked("0909");
		let proof =
			generate_trie_proof::<LayoutV1, _, _, _>(&memdb, root, &[non_included_key.clone()])
				.unwrap();

		// Verifying that the K was not included into the trie should work.
		assert!(verify_trie_proof::<LayoutV1, _, _, Vec<u8>>(
			&root,
			&proof,
			&[(non_included_key.clone(), None)],
		)
		.is_ok());

		// Verifying that the K was included into the trie should fail.
		assert!(verify_trie_proof::<LayoutV1, _, _, Vec<u8>>(
			&root,
			&proof,
			&[(non_included_key, Some(array_bytes::hex2bytes_unchecked("1010")))],
		)
		.is_err());
	}

	#[test]
	fn proof_inclusion_works() {
		let pairs = vec![
			(array_bytes::hex2bytes_unchecked("0102"), array_bytes::hex2bytes_unchecked("01")),
			(array_bytes::hex2bytes_unchecked("0203"), array_bytes::hex2bytes_unchecked("0405")),
		];

		let mut memdb = MemoryDB::default();
		let t = populate_trie::<LayoutV1>(&mut memdb, &pairs);
		let root = t.commit().apply_to(&mut memdb);

		let proof =
			generate_trie_proof::<LayoutV1, _, _, _>(&memdb, root, &[pairs[0].0.clone()]).unwrap();

		// Check that a K, V included into the proof are verified.
		assert!(verify_trie_proof::<LayoutV1, _, _, _>(
			&root,
			&proof,
			&[(pairs[0].0.clone(), Some(pairs[0].1.clone()))]
		)
		.is_ok());

		// Absence of the V is not verified with the proof that has K, V included.
		assert!(verify_trie_proof::<LayoutV1, _, _, Vec<u8>>(
			&root,
			&proof,
			&[(pairs[0].0.clone(), None)]
		)
		.is_err());

		// K not included into the trie is not verified.
		assert!(verify_trie_proof::<LayoutV1, _, _, _>(
			&root,
			&proof,
			&[(array_bytes::hex2bytes_unchecked("4242"), Some(pairs[0].1.clone()))]
		)
		.is_err());

		// K included into the trie but not included into the proof is not verified.
		assert!(verify_trie_proof::<LayoutV1, _, _, _>(
			&root,
			&proof,
			&[(pairs[1].0.clone(), Some(pairs[1].1.clone()))]
		)
		.is_err());
	}

	#[test]
	fn generate_storage_root_with_proof_works_independently_from_the_delta_order() {
		let proof = StorageProof::decode(&mut &include_bytes!("../test-res/proof")[..]).unwrap();
		let storage_root =
			sp_core::H256::decode(&mut &include_bytes!("../test-res/storage_root")[..]).unwrap();
		// Delta order that is "invalid" so that it would require a different proof.
		let invalid_delta = Vec::<(Vec<u8>, Option<Vec<u8>>)>::decode(
			&mut &include_bytes!("../test-res/invalid-delta-order")[..],
		)
		.unwrap();
		// Delta order that is "valid"
		let valid_delta = Vec::<(Vec<u8>, Option<Vec<u8>>)>::decode(
			&mut &include_bytes!("../test-res/valid-delta-order")[..],
		)
		.unwrap();

		let proof_db = proof.into_memory_db::<Blake2Hasher>();
		let first_storage_root = delta_trie_root::<LayoutV0, _, _, _, _>(
			&mut proof_db.clone(),
			(storage_root, Default::default()),
			valid_delta
				.iter()
				.map(|(k, v)| (k.as_slice(), v.as_ref().map(Vec::as_slice), None)),
			None,
			None,
			None,
		)
		.unwrap()
		.root_hash();
		let second_storage_root = delta_trie_root::<LayoutV0, _, _, _, _>(
			&mut proof_db.clone(),
			(storage_root, Default::default()),
			invalid_delta
				.iter()
				.map(|(k, v)| (k.as_slice(), v.as_ref().map(Vec::as_slice), None)),
			None,
			None,
			None,
		)
		.unwrap()
		.root_hash();

		assert_eq!(first_storage_root, second_storage_root);
	}

	#[test]
	fn big_key() {
		let check = |keysize: usize| {
			let mut memdb = MemoryDB::<Blake2Hasher>::default();
			let mut t = TrieDBMutBuilder::<LayoutV1>::new(&mut memdb).build();
			t.insert(&vec![0x01u8; keysize][..], &[0x01u8, 0x23]).unwrap();
			let root = t.commit().apply_to(&mut memdb);
			let t = TrieDBBuilder::<LayoutV1>::new(&memdb, &root).build();
			assert_eq!(t.get(&vec![0x01u8; keysize][..]).unwrap(), Some(vec![0x01u8, 0x23]));
		};
		check(u16::MAX as usize / 2); // old limit
		check(u16::MAX as usize / 2 + 1); // value over old limit still works
	}

	#[test]
	fn node_with_no_children_fail_decoding() {
		let branch = NodeCodec::<Blake2Hasher>::branch_node_nibbled(
			b"some_partial".iter().copied(),
			24,
			vec![None; 16].into_iter(),
			Some(trie_db::node::Value::<()>::Inline(b"value"[..].into())),
		);
		assert!(NodeCodec::<Blake2Hasher>::decode(branch.as_slice(), &[()]).is_err());
	}
}
