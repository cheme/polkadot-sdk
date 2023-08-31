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

//! Shareable Substrate types.

#![warn(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

/// Initialize a key-value collection from array.
///
/// Creates a vector of given pairs and calls `collect` on the iterator from it.
/// Can be used to create a `HashMap`.
#[macro_export]
macro_rules! map {
	($( $name:expr => $value:expr ),* $(,)? ) => (
		vec![ $( ( $name, $value ) ),* ].into_iter().collect()
	);
}

#[doc(hidden)]
pub use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
#[cfg(feature = "serde")]
pub use serde;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use sp_runtime_interface::pass_by::{PassByEnum, PassByInner};
use sp_std::{ops::Deref, prelude::*};

pub use sp_debug_derive::RuntimeDebug;

#[cfg(feature = "serde")]
pub use impl_serde::serialize as bytes;

#[cfg(feature = "full_crypto")]
pub mod hashing;

#[cfg(feature = "full_crypto")]
pub use hashing::{blake2_128, blake2_256, keccak_256, twox_128, twox_256, twox_64};
pub mod crypto;
pub mod hexdisplay;
pub use paste;

#[cfg(feature = "bandersnatch-experimental")]
pub mod bandersnatch;
#[cfg(feature = "bls-experimental")]
pub mod bls;
pub mod defer;
pub mod ecdsa;
pub mod ed25519;
pub mod hash;
#[cfg(feature = "std")]
mod hasher;
pub mod offchain;
pub mod sr25519;
pub mod testing;
#[cfg(feature = "std")]
pub mod traits;
pub mod uint;

#[cfg(feature = "bls-experimental")]
pub use bls::{bls377, bls381};

pub use self::{
	hash::{convert_hash, H160, H256, H512},
	uint::{U256, U512},
};
#[cfg(feature = "full_crypto")]
pub use crypto::{ByteArray, DeriveJunction, Pair, Public};

#[cfg(feature = "std")]
pub use self::hasher::blake2::Blake2Hasher;
#[cfg(feature = "std")]
pub use self::hasher::keccak::KeccakHasher;
pub use hash_db::Hasher;

pub use bounded_collections as bounded;
#[cfg(feature = "std")]
pub use bounded_collections::{bounded_btree_map, bounded_vec};
pub use bounded_collections::{
	parameter_types, ConstBool, ConstI128, ConstI16, ConstI32, ConstI64, ConstI8, ConstU128,
	ConstU16, ConstU32, ConstU64, ConstU8, Get, GetDefault, TryCollect, TypedGet,
};
pub use sp_storage as storage;

#[doc(hidden)]
pub use sp_std;

/// Hex-serialized shim for `Vec<u8>`.
#[derive(PartialEq, Eq, Clone, RuntimeDebug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize, Hash, PartialOrd, Ord))]
pub struct Bytes(#[cfg_attr(feature = "serde", serde(with = "bytes"))] pub Vec<u8>);

impl From<Vec<u8>> for Bytes {
	fn from(s: Vec<u8>) -> Self {
		Bytes(s)
	}
}

impl From<OpaqueMetadata> for Bytes {
	fn from(s: OpaqueMetadata) -> Self {
		Bytes(s.0)
	}
}

impl Deref for Bytes {
	type Target = [u8];
	fn deref(&self) -> &[u8] {
		&self.0[..]
	}
}

impl codec::WrapperTypeEncode for Bytes {}

impl codec::WrapperTypeDecode for Bytes {
	type Wrapped = Vec<u8>;
}

#[cfg(feature = "std")]
impl sp_std::str::FromStr for Bytes {
	type Err = bytes::FromHexError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		bytes::from_hex(s).map(Bytes)
	}
}

/// Stores the encoded `RuntimeMetadata` for the native side as opaque type.
#[derive(Encode, Decode, PartialEq, TypeInfo)]
pub struct OpaqueMetadata(Vec<u8>);

impl OpaqueMetadata {
	/// Creates a new instance with the given metadata blob.
	pub fn new(metadata: Vec<u8>) -> Self {
		OpaqueMetadata(metadata)
	}
}

impl sp_std::ops::Deref for OpaqueMetadata {
	type Target = Vec<u8>;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

/// Simple blob to hold a `PeerId` without committing to its format.
#[derive(
	Default,
	Clone,
	Eq,
	PartialEq,
	Ord,
	PartialOrd,
	Encode,
	Decode,
	RuntimeDebug,
	PassByInner,
	TypeInfo,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OpaquePeerId(pub Vec<u8>);

impl OpaquePeerId {
	/// Create new `OpaquePeerId`
	pub fn new(vec: Vec<u8>) -> Self {
		OpaquePeerId(vec)
	}
}

/// Provide a simple 4 byte identifier for a type.
pub trait TypeId {
	/// Simple 4 byte identifier.
	const TYPE_ID: [u8; 4];
}

/// A log level matching the one from `log` crate.
///
/// Used internally by `sp_io::logging::log` method.
#[derive(Encode, Decode, PassByEnum, Copy, Clone)]
pub enum LogLevel {
	/// `Error` log level.
	Error = 1_isize,
	/// `Warn` log level.
	Warn = 2_isize,
	/// `Info` log level.
	Info = 3_isize,
	/// `Debug` log level.
	Debug = 4_isize,
	/// `Trace` log level.
	Trace = 5_isize,
}

impl From<u32> for LogLevel {
	fn from(val: u32) -> Self {
		match val {
			x if x == LogLevel::Warn as u32 => LogLevel::Warn,
			x if x == LogLevel::Info as u32 => LogLevel::Info,
			x if x == LogLevel::Debug as u32 => LogLevel::Debug,
			x if x == LogLevel::Trace as u32 => LogLevel::Trace,
			_ => LogLevel::Error,
		}
	}
}

impl From<log::Level> for LogLevel {
	fn from(l: log::Level) -> Self {
		use log::Level::*;
		match l {
			Error => Self::Error,
			Warn => Self::Warn,
			Info => Self::Info,
			Debug => Self::Debug,
			Trace => Self::Trace,
		}
	}
}

impl From<LogLevel> for log::Level {
	fn from(l: LogLevel) -> Self {
		use self::LogLevel::*;
		match l {
			Error => Self::Error,
			Warn => Self::Warn,
			Info => Self::Info,
			Debug => Self::Debug,
			Trace => Self::Trace,
		}
	}
}

/// Log level filter that expresses which log levels should be filtered.
///
/// This enum matches the [`log::LevelFilter`] enum.
#[derive(Encode, Decode, PassByEnum, Copy, Clone)]
pub enum LogLevelFilter {
	/// `Off` log level filter.
	Off = 0_isize,
	/// `Error` log level filter.
	Error = 1_isize,
	/// `Warn` log level filter.
	Warn = 2_isize,
	/// `Info` log level filter.
	Info = 3_isize,
	/// `Debug` log level filter.
	Debug = 4_isize,
	/// `Trace` log level filter.
	Trace = 5_isize,
}

impl From<LogLevelFilter> for log::LevelFilter {
	fn from(l: LogLevelFilter) -> Self {
		use self::LogLevelFilter::*;
		match l {
			Off => Self::Off,
			Error => Self::Error,
			Warn => Self::Warn,
			Info => Self::Info,
			Debug => Self::Debug,
			Trace => Self::Trace,
		}
	}
}

impl From<log::LevelFilter> for LogLevelFilter {
	fn from(l: log::LevelFilter) -> Self {
		use log::LevelFilter::*;
		match l {
			Off => Self::Off,
			Error => Self::Error,
			Warn => Self::Warn,
			Info => Self::Info,
			Debug => Self::Debug,
			Trace => Self::Trace,
		}
	}
}

/// Encodes the given value into a buffer and returns the pointer and the length as a single `u64`.
///
/// When Substrate calls into Wasm it expects a fixed signature for functions exported
/// from the Wasm blob. The return value of this signature is always a `u64`.
/// This `u64` stores the pointer to the encoded return value and the length of this encoded value.
/// The low `32bits` are reserved for the pointer, followed by `32bit` for the length.
#[cfg(not(feature = "std"))]
pub fn to_substrate_wasm_fn_return_value(value: &impl Encode) -> u64 {
	let encoded = value.encode();

	let ptr = encoded.as_ptr() as u64;
	let length = encoded.len() as u64;
	let res = ptr | (length << 32);

	// Leak the output vector to avoid it being freed.
	// This is fine in a WASM context since the heap
	// will be discarded after the call.
	sp_std::mem::forget(encoded);

	res
}

/// The void type - it cannot exist.
// Oh rust, you crack me up...
#[derive(Clone, Decode, Encode, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub enum Void {}

/// Macro for creating `Maybe*` marker traits.
///
/// Such a maybe-marker trait requires the given bound when `feature = std` and doesn't require
/// the bound on `no_std`. This is useful for situations where you require that a type implements
/// a certain trait with `feature = std`, but not on `no_std`.
///
/// # Example
///
/// ```
/// sp_core::impl_maybe_marker! {
///     /// A marker for a type that implements `Debug` when `feature = std`.
///     trait MaybeDebug: std::fmt::Debug;
///     /// A marker for a type that implements `Debug + Display` when `feature = std`.
///     trait MaybeDebugDisplay: std::fmt::Debug, std::fmt::Display;
/// }
/// ```
#[macro_export]
macro_rules! impl_maybe_marker {
	(
		$(
			$(#[$doc:meta] )+
			trait $trait_name:ident: $( $trait_bound:path ),+;
		)+
	) => {
		$(
			$(#[$doc])+
			#[cfg(feature = "std")]
			pub trait $trait_name: $( $trait_bound + )+ {}
			#[cfg(feature = "std")]
			impl<T: $( $trait_bound + )+> $trait_name for T {}

			$(#[$doc])+
			#[cfg(not(feature = "std"))]
			pub trait $trait_name {}
			#[cfg(not(feature = "std"))]
			impl<T> $trait_name for T {}
		)+
	}
}

/// Macro for creating `Maybe*` marker traits.
///
/// Such a maybe-marker trait requires the given bound when either `feature = std` or `feature =
/// serde` is activated.
///
/// # Example
///
/// ```
/// sp_core::impl_maybe_marker_std_or_serde! {
///     /// A marker for a type that implements `Debug` when `feature = serde` or `feature = std`.
///     trait MaybeDebug: std::fmt::Debug;
///     /// A marker for a type that implements `Debug + Display` when `feature = serde` or `feature = std`.
///     trait MaybeDebugDisplay: std::fmt::Debug, std::fmt::Display;
/// }
/// ```
#[macro_export]
macro_rules! impl_maybe_marker_std_or_serde {
	(
		$(
			$(#[$doc:meta] )+
			trait $trait_name:ident: $( $trait_bound:path ),+;
		)+
	) => {
		$(
			$(#[$doc])+
			#[cfg(any(feature = "serde", feature = "std"))]
			pub trait $trait_name: $( $trait_bound + )+ {}
			#[cfg(any(feature = "serde", feature = "std"))]
			impl<T: $( $trait_bound + )+> $trait_name for T {}

			$(#[$doc])+
			#[cfg(not(any(feature = "serde", feature = "std")))]
			pub trait $trait_name {}
			#[cfg(not(any(feature = "serde", feature = "std")))]
			impl<T> $trait_name for T {}
		)+
	}
}

/// The maximum number of bytes that can be allocated at one time.
// The maximum possible allocation size was chosen rather arbitrary, 32 MiB should be enough for
// everybody.
pub const MAX_POSSIBLE_ALLOCATION: u32 = 33554432; // 2^25 bytes, 32 MiB

pub use sp_storage::transient::{Hash32Algorithm, HasherHandle, Hashers};

/// Utility function to easilly implement `Hashers` from
/// the default `Hasher`.
/// TODO consider moving Hashers trait here and simply make it default method.
#[cfg(feature = "full_crypto")]
pub fn hash32_with_algorithm_inline(data: &[u8], algo: Hash32Algorithm) -> [u8; 32] {
	match algo {
		Hash32Algorithm::Blake2b256 => crate::hashing::blake2_256(data).into(),
	}
}

/// Hasher state (when processing in multiple steps).
#[cfg(feature = "full_crypto")]
#[derive(Clone)]
pub enum Hash32State {
	/// Blake2b hasher, 256 bits version.
	Blake2b256(crate::hashing::Blake2b256State),
}

#[cfg(feature = "full_crypto")]
impl Hash32State {
	/// Instantiate a new stat.
	pub fn new(algo: sp_storage::transient::Hash32Algorithm) -> Self {
		match algo {
			sp_storage::transient::Hash32Algorithm::Blake2b256 =>
				Hash32State::Blake2b256(crate::hashing::Blake2b256State::new()),
		}
	}

	/// Hash more content.
	pub fn update(&mut self, data: &[u8]) {
		match self {
			Hash32State::Blake2b256(blake) => blake.update(data),
		}
	}

	/// Obtain hash.
	pub fn finalize(self) -> [u8; 32] {
		match self {
			Hash32State::Blake2b256(blake) => blake.finalize(),
		}
	}
}

/// Base implementation for hashers externalities.
#[cfg(feature = "full_crypto")]
#[derive(Default, Clone)]
pub struct HashersExternalities(Vec<Option<Hash32State>>);

#[cfg(feature = "std")]
impl std::fmt::Debug for HashersExternalities {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_tuple("HashersExternalies").finish()
	}
}
// TODO u32 in opaque non copyiable clonable type: similar to the property
// of Hash32State.
#[cfg(feature = "full_crypto")]
impl HashersExternalities {
	/// Get hasher state handle initiated with given data.
	/// See sp_io::hashing::get_hasher.
	pub fn get_hasher(&mut self, algorithm: Hash32Algorithm) -> Option<HasherHandle> {
		if self.0.len() == u32::MAX as usize {
			return None
		}
		self.0.push(Some(Hash32State::new(algorithm)));
		// No safe constructor here, trying to keep type opaque as possible.
		Some(unsafe { sp_std::mem::transmute(self.0.len() as u32 - 1) })
	}

	/// Drop a given hasher instance.
	/// If hasher handle is undefined, all hashers instance
	/// will be drop.
	pub fn drop_hasher(&mut self, hasher: Option<HasherHandle>) {
		if let Some(ix) = hasher {
			let ix: u32 = unsafe { sp_std::mem::transmute(ix) };
			if let Some(hasher) = self.0.get_mut(ix as usize) {
				*hasher = None;
				for i in (0..self.0.len()).rev() {
					if self.0[i].is_none() {
						let _ = self.0.pop();
					}
				}
			}
		} else {
			self.0.clear();
		}
	}

	/// Update hashing with given data.
	/// Return true if successful.
	/// Return false if missing hasher.
	pub fn hasher_update(&mut self, handle: HasherHandle, data: &[u8]) -> bool {
		let handle: u32 = unsafe { sp_std::mem::transmute(handle) };
		if let Some(Some(hasher)) = self.0.get_mut(handle as usize) {
			hasher.update(data);
			true
		} else {
			false
		}
	}

	/// Finalize hashing, dropping the stored hasher and returning
	/// the resulting hash if successful.
	/// Return None if missing hasher.
	pub fn hasher_finalize(&mut self, handle: HasherHandle) -> Option<[u8; 32]> {
		let handle: u32 = unsafe { sp_std::mem::transmute(handle) };
		if let Some(hasher) = self.0.get_mut(handle as usize).and_then(Option::take) {
			let hash = hasher.finalize();
			for i in (0..self.0.len()).rev() {
				if self.0[i].is_none() {
					let _ = self.0.pop();
				}
			}
			Some(hash)
		} else {
			None
		}
	}
}

/// Generates a macro for checking if a certain feature is enabled.
///
/// These feature checking macros can be used to conditionally enable/disable code in a dependent
/// crate based on a feature in the crate where the macro is called.
///
/// # Example
///```
/// sp_core::generate_feature_enabled_macro!(check_std_is_enabled, feature = "std", $);
/// sp_core::generate_feature_enabled_macro!(check_std_or_serde_is_enabled, any(feature = "std", feature = "serde"), $);
///
/// // All the code passed to the macro will then conditionally compiled based on the features
/// // activated for the crate where the macro was generated.
/// check_std_is_enabled! {
///     struct StdEnabled;
/// }
///```
#[macro_export]
// We need to skip formatting this macro because of this bug:
// https://github.com/rust-lang/rustfmt/issues/5283
#[rustfmt::skip]
macro_rules! generate_feature_enabled_macro {
	( $macro_name:ident, $feature_name:meta, $d:tt ) => {
		$crate::paste::paste!{
			/// Enable/disable the given code depending on
			#[doc = concat!("`", stringify!($feature_name), "`")]
			/// being enabled for the crate or not.
			///
			/// # Example
			///
			/// ```nocompile
			/// // Will add the code depending on the feature being enabled or not.
			#[doc = concat!(stringify!($macro_name), "!( println!(\"Hello\") )")]
			/// ```
			#[cfg($feature_name)]
			#[macro_export]
			macro_rules! [<_ $macro_name>] {
				( $d ( $d input:tt )* ) => {
					$d ( $d input )*
				}
			}

			/// Enable/disable the given code depending on
			#[doc = concat!("`", stringify!($feature_name), "`")]
			/// being enabled for the crate or not.
			///
			/// # Example
			///
			/// ```nocompile
			/// // Will add the code depending on the feature being enabled or not.
			#[doc = concat!(stringify!($macro_name), "!( println!(\"Hello\") )")]
			/// ```
			#[cfg(not($feature_name))]
			#[macro_export]
			macro_rules! [<_ $macro_name>] {
				( $d ( $d input:tt )* ) => {};
			}

			// Work around for: <https://github.com/rust-lang/rust/pull/52234>
			#[doc(hidden)]
			pub use [<_ $macro_name>] as $macro_name;
		}
	};
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	#[should_panic]
	fn generate_feature_enabled_macro_panics() {
		generate_feature_enabled_macro!(if_test, test, $);
		if_test!(panic!("This should panic"));
	}

	#[test]
	fn generate_feature_enabled_macro_works() {
		generate_feature_enabled_macro!(if_not_test, not(test), $);
		if_not_test!(panic!("This should not panic"));
	}
}
