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

//! # Remote Externalities
//!
//! An equivalent of `sp_io::TestExternalities` that can load its state from a remote substrate
//! based chain, or a local state snapshot file.

use codec::{Compact, Decode, Encode};
use indicatif::{ProgressBar, ProgressStyle};
use jsonrpsee::{
	core::params::ArrayParams,
	http_client::{HttpClient, HttpClientBuilder},
};
use log::*;
use serde::de::DeserializeOwned;
use sp_core::{
	hexdisplay::HexDisplay,
	storage::{
		well_known_keys::{is_default_child_storage_key, DEFAULT_CHILD_STORAGE_KEY_PREFIX},
		ChildInfo, ChildType, PrefixedStorageKey, StorageData, StorageKey,
	},
};
use sp_runtime::{
	traits::{Block as BlockT, Hash, HashingFor},
	StateVersion,
};
use sp_state_machine::TestExternalities;
use spinners::{Spinner, Spinners};
use std::{
	cmp::{max, min},
	fs,
	ops::{Deref, DerefMut},
	path::{Path, PathBuf},
	sync::Arc,
	time::{Duration, Instant},
};
use substrate_rpc_client::{rpc_params, BatchRequestBuilder, ChainApi, ClientT, StateApi};
use tokio_retry::{strategy::FixedInterval, Retry};

type KeyValue = (StorageKey, StorageData);
type TopKeyValues = Vec<KeyValue>;
type ChildKeyValues = Vec<(ChildInfo, Vec<KeyValue>)>;
type SnapshotVersion = Compact<u16>;

const LOG_TARGET: &str = "remote-ext";
const DEFAULT_HTTP_ENDPOINT: &str = "https://rpc.polkadot.io:443";
const SNAPSHOT_VERSION: SnapshotVersion = Compact(3);

/// The snapshot that we store on disk.
#[derive(Decode, Encode)]
struct Snapshot<H> {
	snapshot_version: SnapshotVersion,
	state_version: StateVersion,
	block_hash: H,
	// <Vec<Key, (Value, MemoryDbRefCount)>>
	raw_storage: Vec<(Vec<u8>, (Vec<u8>, i32))>,
	storage_root: H,
}

impl<H: Decode> Snapshot<H> {
	pub fn new(
		state_version: StateVersion,
		block_hash: H,
		raw_storage: Vec<(Vec<u8>, (Vec<u8>, i32))>,
		storage_root: H,
	) -> Self {
		Self {
			snapshot_version: SNAPSHOT_VERSION,
			state_version,
			block_hash,
			raw_storage,
			storage_root,
		}
	}

	fn load(path: &PathBuf) -> Result<Snapshot<H>, &'static str> {
		let bytes = fs::read(path).map_err(|_| "fs::read failed.")?;
		// The first item in the SCALE encoded struct bytes is the snapshot version. We decode and
		// check that first, before proceeding to decode the rest of the snapshot.
		let snapshot_version = SnapshotVersion::decode(&mut &*bytes)
			.map_err(|_| "Failed to decode snapshot version")?;

		if snapshot_version != SNAPSHOT_VERSION {
			return Err("Unsupported snapshot version detected. Please create a new snapshot.")
		}

		Decode::decode(&mut &*bytes).map_err(|_| "Decode failed")
	}
}

/// An externalities that acts exactly the same as [`sp_io::TestExternalities`] but has a few extra
/// bits and pieces to it, and can be loaded remotely.
pub struct RemoteExternalities<H: Hash> {
	/// The inner externalities.
	pub inner_ext: TestExternalities<H>,
	/// The block hash with which we created this externality env.
	pub block_hash: H::Out,
}

impl<H: Hash> Deref for RemoteExternalities<H> {
	type Target = TestExternalities<H>;
	fn deref(&self) -> &Self::Target {
		&self.inner_ext
	}
}

impl<H: Hash> DerefMut for RemoteExternalities<H> {
	fn deref_mut(&mut self) -> &mut Self::Target {
		&mut self.inner_ext
	}
}

/// The execution mode.
#[derive(Clone)]
pub enum Mode<H> {
	/// Online. Potentially writes to a snapshot file.
	Online(OnlineConfig<H>),
	/// Offline. Uses a state snapshot file and needs not any client config.
	Offline(OfflineConfig),
	/// Prefer using a snapshot file if it exists, else use a remote server.
	OfflineOrElseOnline(OfflineConfig, OnlineConfig<H>),
}

impl<H> Default for Mode<H> {
	fn default() -> Self {
		Mode::Online(OnlineConfig::default())
	}
}

/// Configuration of the offline execution.
///
/// A state snapshot config must be present.
#[derive(Clone)]
pub struct OfflineConfig {
	/// The configuration of the state snapshot file to use. It must be present.
	pub state_snapshot: SnapshotConfig,
}

/// Description of the transport protocol (for online execution).
#[derive(Debug, Clone)]
pub enum Transport {
	/// Use the `URI` to open a new WebSocket connection.
	Uri(String),
	/// Use HTTP connection.
	RemoteClient(HttpClient),
}

impl Transport {
	fn as_client(&self) -> Option<&HttpClient> {
		match self {
			Self::RemoteClient(client) => Some(client),
			_ => None,
		}
	}

	// Build an HttpClient from a URI.
	async fn init(&mut self) -> Result<(), &'static str> {
		if let Self::Uri(uri) = self {
			log::debug!(target: LOG_TARGET, "initializing remote client to {:?}", uri);

			// If we have a ws uri, try to convert it to an http uri.
			// We use an HTTP client rather than WS because WS starts to choke with "accumulated
			// message length exceeds maximum" errors after processing ~10k keys when fetching
			// from a node running a default configuration.
			let uri = if uri.starts_with("ws://") {
				let uri = uri.replace("ws://", "http://");
				log::info!(target: LOG_TARGET, "replacing ws:// in uri with http://: {:?} (ws is currently unstable for fetching remote storage, for more see https://github.com/paritytech/jsonrpsee/issues/1086)", uri);
				uri
			} else if uri.starts_with("wss://") {
				let uri = uri.replace("wss://", "https://");
				log::info!(target: LOG_TARGET, "replacing wss:// in uri with https://: {:?} (ws is currently unstable for fetching remote storage, for more see https://github.com/paritytech/jsonrpsee/issues/1086)", uri);
				uri
			} else {
				uri.clone()
			};
			let http_client = HttpClientBuilder::default()
				.max_request_size(u32::MAX)
				.max_response_size(u32::MAX)
				.request_timeout(std::time::Duration::from_secs(60 * 5))
				.build(uri)
				.map_err(|e| {
					log::error!(target: LOG_TARGET, "error: {:?}", e);
					"failed to build http client"
				})?;

			*self = Self::RemoteClient(http_client)
		}

		Ok(())
	}
}

impl From<String> for Transport {
	fn from(uri: String) -> Self {
		Transport::Uri(uri)
	}
}

impl From<HttpClient> for Transport {
	fn from(client: HttpClient) -> Self {
		Transport::RemoteClient(client)
	}
}

/// Configuration of the online execution.
///
/// A state snapshot config may be present and will be written to in that case.
#[derive(Clone)]
pub struct OnlineConfig<H> {
	/// The block hash at which to get the runtime state. Will be latest finalized head if not
	/// provided.
	pub at: Option<H>,
	/// An optional state snapshot file to WRITE to, not for reading. Not written if set to `None`.
	pub state_snapshot: Option<SnapshotConfig>,
	/// The pallets to scrape. These values are hashed and added to `hashed_prefix`.
	pub pallets: Vec<String>,
	/// Transport config.
	pub transport: Transport,
	/// Lookout for child-keys, and scrape them as well if set to true.
	pub child_trie: bool,
	/// Storage entry key prefixes to be injected into the externalities. The *hashed* prefix must
	/// be given.
	pub hashed_prefixes: Vec<Vec<u8>>,
	/// Storage entry keys to be injected into the externalities. The *hashed* key must be given.
	pub hashed_keys: Vec<Vec<u8>>,
}

impl<H: Clone> OnlineConfig<H> {
	/// Return rpc (http) client reference.
	fn rpc_client(&self) -> &HttpClient {
		self.transport
			.as_client()
			.expect("http client must have been initialized by now; qed.")
	}

	fn at_expected(&self) -> H {
		self.at.clone().expect("block at must be initialized; qed")
	}
}

impl<H> Default for OnlineConfig<H> {
	fn default() -> Self {
		Self {
			transport: Transport::from(DEFAULT_HTTP_ENDPOINT.to_owned()),
			child_trie: true,
			at: None,
			state_snapshot: None,
			pallets: Default::default(),
			hashed_keys: Default::default(),
			hashed_prefixes: Default::default(),
		}
	}
}

impl<H> From<String> for OnlineConfig<H> {
	fn from(t: String) -> Self {
		Self { transport: t.into(), ..Default::default() }
	}
}

/// Configuration of the state snapshot.
#[derive(Clone)]
pub struct SnapshotConfig {
	/// The path to the snapshot file.
	pub path: PathBuf,
}

impl SnapshotConfig {
	pub fn new<P: Into<PathBuf>>(path: P) -> Self {
		Self { path: path.into() }
	}
}

impl From<String> for SnapshotConfig {
	fn from(s: String) -> Self {
		Self::new(s)
	}
}

impl Default for SnapshotConfig {
	fn default() -> Self {
		Self { path: Path::new("SNAPSHOT").into() }
	}
}

/// Builder for remote-externalities.
#[derive(Clone)]
pub struct Builder<B: BlockT> {
	/// Custom key-pairs to be injected into the final externalities. The *hashed* keys and values
	/// must be given.
	hashed_key_values: Vec<KeyValue>,
	/// The keys that will be excluded from the final externality. The *hashed* key must be given.
	hashed_blacklist: Vec<Vec<u8>>,
	/// Connectivity mode, online or offline.
	mode: Mode<B::Hash>,
	/// If provided, overwrite the state version with this. Otherwise, the state_version of the
	/// remote node is used. All cache files also store their state version.
	///
	/// Overwrite only with care.
	overwrite_state_version: Option<StateVersion>,
}

impl<B: BlockT> Default for Builder<B> {
	fn default() -> Self {
		Self {
			mode: Default::default(),
			hashed_key_values: Default::default(),
			hashed_blacklist: Default::default(),
			overwrite_state_version: None,
		}
	}
}

// Mode methods
impl<B: BlockT> Builder<B> {
	fn as_online(&self) -> &OnlineConfig<B::Hash> {
		match &self.mode {
			Mode::Online(config) => config,
			Mode::OfflineOrElseOnline(_, config) => config,
			_ => panic!("Unexpected mode: Online"),
		}
	}

	fn as_online_mut(&mut self) -> &mut OnlineConfig<B::Hash> {
		match &mut self.mode {
			Mode::Online(config) => config,
			Mode::OfflineOrElseOnline(_, config) => config,
			_ => panic!("Unexpected mode: Online"),
		}
	}
}

// RPC methods
impl<B: BlockT> Builder<B>
where
	B::Hash: DeserializeOwned,
	B::Header: DeserializeOwned,
{
	const PARALLEL_REQUESTS: usize = 4;
	const BATCH_SIZE_INCREASE_FACTOR: f32 = 1.10;
	const BATCH_SIZE_DECREASE_FACTOR: f32 = 0.50;
	const REQUEST_DURATION_TARGET: Duration = Duration::from_secs(15);
	const INITIAL_BATCH_SIZE: usize = 10;
	// nodes by default will not return more than 1000 keys per request
	const DEFAULT_KEY_DOWNLOAD_PAGE: u32 = 1000;
	const MAX_RETRIES: usize = 12;
	const KEYS_PAGE_RETRY_INTERVAL: Duration = Duration::from_secs(5);

	async fn rpc_get_storage(
		&self,
		key: StorageKey,
		maybe_at: Option<B::Hash>,
	) -> Result<Option<StorageData>, &'static str> {
		trace!(target: LOG_TARGET, "rpc: get_storage");
		self.as_online().rpc_client().storage(key, maybe_at).await.map_err(|e| {
			error!(target: LOG_TARGET, "Error = {:?}", e);
			"rpc get_storage failed."
		})
	}

	/// Get the latest finalized head.
	async fn rpc_get_head(&self) -> Result<B::Hash, &'static str> {
		trace!(target: LOG_TARGET, "rpc: finalized_head");

		// sadly this pretty much unreadable...
		ChainApi::<(), _, B::Header, ()>::finalized_head(self.as_online().rpc_client())
			.await
			.map_err(|e| {
				error!(target: LOG_TARGET, "Error = {:?}", e);
				"rpc finalized_head failed."
			})
	}

	async fn get_keys_single_page(
		&self,
		prefix: Option<StorageKey>,
		start_key: Option<StorageKey>,
		at: B::Hash,
	) -> Result<Vec<StorageKey>, &'static str> {
		self.as_online()
			.rpc_client()
			.storage_keys_paged(prefix, Self::DEFAULT_KEY_DOWNLOAD_PAGE, start_key, Some(at))
			.await
			.map_err(|e| {
				error!(target: LOG_TARGET, "Error = {:?}", e);
				"rpc get_keys failed"
			})
	}

	/// Get keys with `prefix` at `block` in a parallel manner.
	async fn rpc_get_keys_parallel(
		&self,
		prefix: &StorageKey,
		block: B::Hash,
		parallel: usize,
	) -> Result<Vec<StorageKey>, &'static str> {
		/// Divide the workload and return the start key of each chunks. Guaranteed to return a
		/// non-empty list.
		fn gen_start_keys(prefix: &StorageKey) -> Vec<StorageKey> {
			let mut prefix = prefix.as_ref().to_vec();
			let scale = 32usize.saturating_sub(prefix.len());

			// no need to divide workload
			if scale < 9 {
				prefix.extend(vec![0; scale]);
				return vec![StorageKey(prefix)]
			}

			let chunks = 16;
			let step = 0x10000 / chunks;
			let ext = scale - 2;

			(0..chunks)
				.map(|i| {
					let mut key = prefix.clone();
					let start = i * step;
					key.extend(vec![(start >> 8) as u8, (start & 0xff) as u8]);
					key.extend(vec![0; ext]);
					StorageKey(key)
				})
				.collect()
		}

		let start_keys = gen_start_keys(&prefix);
		let start_keys: Vec<Option<&StorageKey>> = start_keys.iter().map(Some).collect();
		let mut end_keys: Vec<Option<&StorageKey>> = start_keys[1..].to_vec();
		end_keys.push(None);

		// use a semaphore to limit max scraping tasks
		let parallel = Arc::new(tokio::sync::Semaphore::new(parallel));
		let builder = Arc::new(self.clone());
		let mut handles = vec![];

		for (start_key, end_key) in start_keys.into_iter().zip(end_keys) {
			let permit = parallel
				.clone()
				.acquire_owned()
				.await
				.expect("semaphore is not closed until the end of loop");

			let builder = builder.clone();
			let prefix = prefix.clone();
			let start_key = start_key.cloned();
			let end_key = end_key.cloned();

			let handle = tokio::spawn(async move {
				let res = builder
					.rpc_get_keys_in_range(&prefix, block, start_key.as_ref(), end_key.as_ref())
					.await;
				drop(permit);
				res
			});

			handles.push(handle);
		}

		parallel.close();

		let keys = futures::future::join_all(handles)
			.await
			.into_iter()
			.filter_map(|res| match res {
				Ok(Ok(keys)) => Some(keys),
				_ => None,
			})
			.flatten()
			.collect::<Vec<StorageKey>>();

		Ok(keys)
	}

	/// Get all keys with `prefix` within the given range at `block`.
	/// Both `start_key` and `end_key` are optional if you want an open-ended range.
	async fn rpc_get_keys_in_range(
		&self,
		prefix: &StorageKey,
		block: B::Hash,
		start_key: Option<&StorageKey>,
		end_key: Option<&StorageKey>,
	) -> Result<Vec<StorageKey>, &'static str> {
		let mut last_key: Option<&StorageKey> = start_key;
		let mut keys: Vec<StorageKey> = vec![];

		loop {
			// This loop can hit the node with very rapid requests, occasionally causing it to
			// error out in CI (https://github.com/paritytech/substrate/issues/14129), so we retry.
			let retry_strategy =
				FixedInterval::new(Self::KEYS_PAGE_RETRY_INTERVAL).take(Self::MAX_RETRIES);
			let get_page_closure =
				|| self.get_keys_single_page(Some(prefix.clone()), last_key.cloned(), block);
			let mut page = Retry::spawn(retry_strategy, get_page_closure).await?;

			// avoid duplicated keys across workloads
			if let (Some(last), Some(end)) = (page.last(), end_key) {
				if last >= end {
					page.retain(|key| key < end);
				}
			}

			let page_len = page.len();
			keys.extend(page);
			last_key = keys.last();

			// scraping out of range or no more matches,
			// we are done either way
			if page_len < Self::DEFAULT_KEY_DOWNLOAD_PAGE as usize {
				log::debug!(target: LOG_TARGET, "last page received: {}", page_len);
				break
			}

			log::debug!(
				target: LOG_TARGET,
				"new total = {}, full page received: {}",
				keys.len(),
				HexDisplay::from(last_key.expect("full page received, cannot be None"))
			);
		}

		Ok(keys)
	}

	/// Fetches storage data from a node using a dynamic batch size.
	///
	/// This function adjusts the batch size on the fly to help prevent overwhelming the node with
	/// large batch requests, and stay within request size limits enforced by the node.
	///
	/// # Arguments
	///
	/// * `client` - An `Arc` wrapped `HttpClient` used for making the requests.
	/// * `payloads` - A vector of tuples containing a JSONRPC method name and `ArrayParams`
	///
	/// # Returns
	///
	/// Returns a `Result` with a vector of `Option<StorageData>`, where each element corresponds to
	/// the storage data for the given method and parameters. The result will be an `Err` with a
	/// `String` error message if the request fails.
	///
	/// # Errors
	///
	/// This function will return an error if:
	/// * The batch request fails and the batch size is less than 2.
	/// * There are invalid batch params.
	/// * There is an error in the batch response.
	///
	/// # Example
	///
	/// ```ignore
	/// use your_crate::{get_storage_data_dynamic_batch_size, HttpClient, ArrayParams};
	/// use std::sync::Arc;
	///
	/// async fn example() {
	///     let client = HttpClient::new();
	///     let payloads = vec![
	///         ("some_method".to_string(), ArrayParams::new(vec![])),
	///         ("another_method".to_string(), ArrayParams::new(vec![])),
	///     ];
	///     let initial_batch_size = 10;
	///
	///     let storage_data = get_storage_data_dynamic_batch_size(client, payloads, batch_size).await;
	///     match storage_data {
	///         Ok(data) => println!("Storage data: {:?}", data),
	///         Err(e) => eprintln!("Error fetching storage data: {}", e),
	///     }
	/// }
	/// ```
	async fn get_storage_data_dynamic_batch_size(
		client: &HttpClient,
		payloads: Vec<(String, ArrayParams)>,
		bar: &ProgressBar,
	) -> Result<Vec<Option<StorageData>>, String> {
		let mut all_data: Vec<Option<StorageData>> = vec![];
		let mut start_index = 0;
		let mut retries = 0usize;
		let mut batch_size = Self::INITIAL_BATCH_SIZE;
		let total_payloads = payloads.len();

		while start_index < total_payloads {
			log::debug!(
				target: LOG_TARGET,
				"Remaining payloads: {} Batch request size: {}",
				total_payloads - start_index,
				batch_size,
			);

			let end_index = usize::min(start_index + batch_size, total_payloads);
			let page = &payloads[start_index..end_index];

			// Build the batch request
			let mut batch = BatchRequestBuilder::new();
			for (method, params) in page.iter() {
				batch
					.insert(method, params.clone())
					.map_err(|_| "Invalid batch method and/or params")?;
			}

			let request_started = Instant::now();
			let batch_response = match client.batch_request::<Option<StorageData>>(batch).await {
				Ok(batch_response) => {
					retries = 0;
					batch_response
				},
				Err(e) => {
					if retries > Self::MAX_RETRIES {
						return Err(e.to_string())
					}

					retries += 1;
					let failure_log = format!(
						"Batch request failed ({}/{} retries). Error: {}",
						retries,
						Self::MAX_RETRIES,
						e
					);
					// after 2 subsequent failures something very wrong is happening. log a warning
					// and reset the batch size down to 1.
					if retries >= 2 {
						log::warn!("{}", failure_log);
						batch_size = 1;
					} else {
						log::debug!("{}", failure_log);
						// Decrease batch size by DECREASE_FACTOR
						batch_size =
							(batch_size as f32 * Self::BATCH_SIZE_DECREASE_FACTOR) as usize;
					}
					continue
				},
			};

			let request_duration = request_started.elapsed();
			batch_size = if request_duration > Self::REQUEST_DURATION_TARGET {
				// Decrease batch size
				max(1, (batch_size as f32 * Self::BATCH_SIZE_DECREASE_FACTOR) as usize)
			} else {
				// Increase batch size, but not more than the remaining total payloads to process
				min(
					total_payloads - start_index,
					max(
						batch_size + 1,
						(batch_size as f32 * Self::BATCH_SIZE_INCREASE_FACTOR) as usize,
					),
				)
			};

			log::debug!(
				target: LOG_TARGET,
				"Request duration: {:?} Target duration: {:?} Last batch size: {} Next batch size: {}",
				request_duration,
				Self::REQUEST_DURATION_TARGET,
				end_index - start_index,
				batch_size
			);

			let batch_response_len = batch_response.len();
			for item in batch_response.into_iter() {
				match item {
					Ok(x) => all_data.push(x),
					Err(e) => return Err(e.message().to_string()),
				}
			}
			bar.inc(batch_response_len as u64);

			// Update the start index for the next iteration
			start_index = end_index;
		}

		Ok(all_data)
	}

	/// Synonym of `getPairs` that uses paged queries to first get the keys, and then
	/// map them to values one by one.
	///
	/// This can work with public nodes. But, expect it to be darn slow.
	pub(crate) async fn rpc_get_pairs(
		&self,
		prefix: StorageKey,
		at: B::Hash,
		pending_ext: &mut TestExternalities<HashingFor<B>>,
	) -> Result<Vec<KeyValue>, &'static str> {
		let start = Instant::now();
		let mut sp = Spinner::with_timer(Spinners::Dots, "Scraping keys...".into());
		// TODO We could start downloading when having collected the first batch of keys
		// https://github.com/paritytech/polkadot-sdk/issues/2494
		let keys = self
			.rpc_get_keys_parallel(&prefix, at, Self::PARALLEL_REQUESTS)
			.await?
			.into_iter()
			.collect::<Vec<_>>();
		sp.stop_with_message(format!(
			"✅ Found {} keys ({:.2}s)",
			keys.len(),
			start.elapsed().as_secs_f32()
		));
		if keys.is_empty() {
			return Ok(Default::default())
		}

		let client = self.as_online().rpc_client();
		let payloads = keys
			.iter()
			.map(|key| ("state_getStorage".to_string(), rpc_params!(key, at)))
			.collect::<Vec<_>>();

		let bar = ProgressBar::new(payloads.len() as u64);
		bar.enable_steady_tick(Duration::from_secs(1));
		bar.set_message("Downloading key values".to_string());
		bar.set_style(
			ProgressStyle::with_template(
				"[{elapsed_precise}] {msg} {per_sec} [{wide_bar}] {pos}/{len} ({eta})",
			)
			.unwrap()
			.progress_chars("=>-"),
		);
		let payloads_chunked = payloads.chunks((payloads.len() / Self::PARALLEL_REQUESTS).max(1));
		let requests = payloads_chunked.map(|payload_chunk| {
			Self::get_storage_data_dynamic_batch_size(client, payload_chunk.to_vec(), &bar)
		});
		// Execute the requests and move the Result outside.
		let storage_data_result: Result<Vec<_>, _> =
			futures::future::join_all(requests).await.into_iter().collect();
		// Handle the Result.
		let storage_data = match storage_data_result {
			Ok(storage_data) => storage_data.into_iter().flatten().collect::<Vec<_>>(),
			Err(e) => {
				log::error!(target: LOG_TARGET, "Error while getting storage data: {}", e);
				return Err("Error while getting storage data")
			},
		};
		bar.finish_with_message("✅ Downloaded key values");
		println!();

		// Check if we got responses for all submitted requests.
		assert_eq!(keys.len(), storage_data.len());

		let key_values = keys
			.iter()
			.zip(storage_data)
			.map(|(key, maybe_value)| match maybe_value {
				Some(data) => (key.clone(), data),
				None => {
					log::warn!(target: LOG_TARGET, "key {:?} had none corresponding value.", &key);
					let data = StorageData(vec![]);
					(key.clone(), data)
				},
			})
			.collect::<Vec<_>>();

		let mut sp = Spinner::with_timer(Spinners::Dots, "Inserting keys into DB...".into());
		let start = Instant::now();
		pending_ext.batch_insert(key_values.clone().into_iter().filter_map(|(k, v)| {
			// Don't insert the child keys here, they need to be inserted separately with all their
			// data in the load_child_remote function.
			match is_default_child_storage_key(&k.0) {
				true => None,
				false => Some((k.0, v.0)),
			}
		}));
		sp.stop_with_message(format!(
			"✅ Inserted keys into DB ({:.2}s)",
			start.elapsed().as_secs_f32()
		));
		Ok(key_values)
	}

	/// Get the values corresponding to `child_keys` at the given `prefixed_top_key`.
	pub(crate) async fn rpc_child_get_storage_paged(
		client: &HttpClient,
		prefixed_top_key: &StorageKey,
		child_keys: Vec<StorageKey>,
		at: B::Hash,
	) -> Result<Vec<KeyValue>, &'static str> {
		let child_keys_len = child_keys.len();

		let payloads = child_keys
			.iter()
			.map(|key| {
				(
					"childstate_getStorage".to_string(),
					rpc_params![
						PrefixedStorageKey::new(prefixed_top_key.as_ref().to_vec()),
						key,
						at
					],
				)
			})
			.collect::<Vec<_>>();

		let bar = ProgressBar::new(payloads.len() as u64);
		let storage_data =
			match Self::get_storage_data_dynamic_batch_size(client, payloads, &bar).await {
				Ok(storage_data) => storage_data,
				Err(e) => {
					log::error!(target: LOG_TARGET, "batch processing failed: {:?}", e);
					return Err("batch processing failed")
				},
			};

		assert_eq!(child_keys_len, storage_data.len());

		Ok(child_keys
			.iter()
			.zip(storage_data)
			.map(|(key, maybe_value)| match maybe_value {
				Some(v) => (key.clone(), v),
				None => {
					log::warn!(target: LOG_TARGET, "key {:?} had no corresponding value.", &key);
					(key.clone(), StorageData(vec![]))
				},
			})
			.collect::<Vec<_>>())
	}

	pub(crate) async fn rpc_child_get_keys(
		client: &HttpClient,
		prefixed_top_key: &StorageKey,
		child_prefix: StorageKey,
		at: B::Hash,
	) -> Result<Vec<StorageKey>, &'static str> {
		let retry_strategy =
			FixedInterval::new(Self::KEYS_PAGE_RETRY_INTERVAL).take(Self::MAX_RETRIES);
		let get_child_keys_closure = || {
			#[allow(deprecated)]
			substrate_rpc_client::ChildStateApi::storage_keys(
				client,
				PrefixedStorageKey::new(prefixed_top_key.as_ref().to_vec()),
				child_prefix.clone(),
				Some(at),
			)
		};
		let child_keys =
			Retry::spawn(retry_strategy, get_child_keys_closure).await.map_err(|e| {
				error!(target: LOG_TARGET, "Error = {:?}", e);
				"rpc child_get_keys failed."
			})?;

		debug!(
			target: LOG_TARGET,
			"[thread = {:?}] scraped {} child-keys of the child-bearing top key: {}",
			std::thread::current().id(),
			child_keys.len(),
			HexDisplay::from(prefixed_top_key)
		);

		Ok(child_keys)
	}
}

impl<B: BlockT + DeserializeOwned> Builder<B>
where
	B::Hash: DeserializeOwned,
	B::Header: DeserializeOwned,
{
	/// Load all of the child keys from the remote config, given the already scraped list of top key
	/// pairs.
	///
	/// `top_kv` need not be only child-bearing top keys. It should be all of the top keys that are
	/// included thus far.
	///
	/// This function concurrently populates `pending_ext`. the return value is only for writing to
	/// cache, we can also optimize further.
	async fn load_child_remote(
		&self,
		top_kv: &[KeyValue],
		pending_ext: &mut TestExternalities<HashingFor<B>>,
	) -> Result<ChildKeyValues, &'static str> {
		let child_roots = top_kv
			.iter()
			.filter(|(k, _)| is_default_child_storage_key(k.as_ref()))
			.map(|(k, _)| k.clone())
			.collect::<Vec<_>>();

		if child_roots.is_empty() {
			info!(target: LOG_TARGET, "👩‍👦 no child roots found to scrape",);
			return Ok(Default::default())
		}

		info!(
			target: LOG_TARGET,
			"👩‍👦 scraping child-tree data from {} top keys",
			child_roots.len(),
		);

		let at = self.as_online().at_expected();

		let client = self.as_online().rpc_client();
		let mut child_kv = vec![];
		for prefixed_top_key in child_roots {
			let child_keys =
				Self::rpc_child_get_keys(client, &prefixed_top_key, StorageKey(vec![]), at).await?;

			let child_kv_inner =
				Self::rpc_child_get_storage_paged(client, &prefixed_top_key, child_keys, at)
					.await?;

			let prefixed_top_key = PrefixedStorageKey::new(prefixed_top_key.clone().0);
			let un_prefixed = match ChildType::from_prefixed_key(&prefixed_top_key) {
				Some((ChildType::ParentKeyId, storage_key)) => storage_key,
				None => {
					log::error!(target: LOG_TARGET, "invalid key: {:?}", prefixed_top_key);
					return Err("Invalid child key")
				},
			};

			let info = ChildInfo::new_default(un_prefixed);
			let key_values =
				child_kv_inner.iter().cloned().map(|(k, v)| (k.0, v.0)).collect::<Vec<_>>();
			child_kv.push((info.clone(), child_kv_inner));
			for (k, v) in key_values {
				pending_ext.insert_child(info.clone(), k, v);
			}
		}

		Ok(child_kv)
	}

	/// Build `Self` from a network node denoted by `uri`.
	///
	/// This function concurrently populates `pending_ext`. the return value is only for writing to
	/// cache, we can also optimize further.
	async fn load_top_remote(
		&self,
		pending_ext: &mut TestExternalities<HashingFor<B>>,
	) -> Result<TopKeyValues, &'static str> {
		let config = self.as_online();
		let at = self
			.as_online()
			.at
			.expect("online config must be initialized by this point; qed.");
		log::info!(target: LOG_TARGET, "scraping key-pairs from remote at block height {:?}", at);

		let mut keys_and_values = Vec::new();
		for prefix in &config.hashed_prefixes {
			let now = std::time::Instant::now();
			let additional_key_values =
				self.rpc_get_pairs(StorageKey(prefix.to_vec()), at, pending_ext).await?;
			let elapsed = now.elapsed();
			log::info!(
				target: LOG_TARGET,
				"adding data for hashed prefix: {:?}, took {:.2}s",
				HexDisplay::from(prefix),
				elapsed.as_secs_f32()
			);
			keys_and_values.extend(additional_key_values);
		}

		for key in &config.hashed_keys {
			let key = StorageKey(key.to_vec());
			log::info!(
				target: LOG_TARGET,
				"adding data for hashed key: {:?}",
				HexDisplay::from(&key)
			);
			match self.rpc_get_storage(key.clone(), Some(at)).await? {
				Some(value) => {
					pending_ext.insert(key.clone().0, value.clone().0);
					keys_and_values.push((key, value));
				},
				None => {
					log::warn!(
						target: LOG_TARGET,
						"no data found for hashed key: {:?}",
						HexDisplay::from(&key)
					);
				},
			}
		}

		Ok(keys_and_values)
	}

	/// The entry point of execution, if `mode` is online.
	///
	/// initializes the remote client in `transport`, and sets the `at` field, if not specified.
	async fn init_remote_client(&mut self) -> Result<(), &'static str> {
		// First, initialize the http client.
		self.as_online_mut().transport.init().await?;

		// Then, if `at` is not set, set it.
		if self.as_online().at.is_none() {
			let at = self.rpc_get_head().await?;
			log::info!(
				target: LOG_TARGET,
				"since no at is provided, setting it to latest finalized head, {:?}",
				at
			);
			self.as_online_mut().at = Some(at);
		}

		// Then, a few transformation that we want to perform in the online config:
		let online_config = self.as_online_mut();
		online_config.pallets.iter().for_each(|p| {
			online_config
				.hashed_prefixes
				.push(sp_crypto_hashing::twox_128(p.as_bytes()).to_vec())
		});

		if online_config.child_trie {
			online_config.hashed_prefixes.push(DEFAULT_CHILD_STORAGE_KEY_PREFIX.to_vec());
		}

		// Finally, if by now, we have put any limitations on prefixes that we are interested in, we
		// download everything.
		if online_config
			.hashed_prefixes
			.iter()
			.filter(|p| *p != DEFAULT_CHILD_STORAGE_KEY_PREFIX)
			.count() == 0
		{
			log::info!(
				target: LOG_TARGET,
				"since no prefix is filtered, the data for all pallets will be downloaded"
			);
			online_config.hashed_prefixes.push(vec![]);
		}

		Ok(())
	}

	/// Load the data from a remote server. The main code path is calling into `load_top_remote` and
	/// `load_child_remote`.
	///
	/// Must be called after `init_remote_client`.
	async fn load_remote_and_maybe_save(
		&mut self,
	) -> Result<TestExternalities<HashingFor<B>>, &'static str> {
		let state_version =
			StateApi::<B::Hash>::runtime_version(self.as_online().rpc_client(), None)
				.await
				.map_err(|e| {
					error!(target: LOG_TARGET, "Error = {:?}", e);
					"rpc runtime_version failed."
				})
				.map(|v| v.state_version())?;
		let mut pending_ext = TestExternalities::new_with_code_and_state(
			Default::default(),
			Default::default(),
			self.overwrite_state_version.unwrap_or(state_version),
		);

		// Load data from the remote into `pending_ext`.
		let top_kv = self.load_top_remote(&mut pending_ext).await?;
		self.load_child_remote(&top_kv, &mut pending_ext).await?;

		// If we need to save a snapshot, save the raw storage and root hash to the snapshot.
		if let Some(path) = self.as_online().state_snapshot.clone().map(|c| c.path) {
			let (raw_storage, storage_root) = pending_ext.into_raw_snapshot();
			let snapshot = Snapshot::<B::Hash>::new(
				state_version,
				self.as_online()
					.at
					.expect("set to `Some` in `init_remote_client`; must be called before; qed"),
				raw_storage.clone(),
				storage_root,
			);
			let encoded = snapshot.encode();
			log::info!(
				target: LOG_TARGET,
				"writing snapshot of {} bytes to {:?}",
				encoded.len(),
				path
			);
			std::fs::write(path, encoded).map_err(|_| "fs::write failed")?;

			// pending_ext was consumed when creating the snapshot, need to reinitailize it
			return Ok(TestExternalities::from_raw_snapshot(
				raw_storage,
				storage_root,
				self.overwrite_state_version.unwrap_or(state_version),
			))
		}

		Ok(pending_ext)
	}

	async fn do_load_remote(&mut self) -> Result<RemoteExternalities<HashingFor<B>>, &'static str> {
		self.init_remote_client().await?;
		let block_hash = self.as_online().at_expected();
		let inner_ext = self.load_remote_and_maybe_save().await?;
		Ok(RemoteExternalities { block_hash, inner_ext })
	}

	fn do_load_offline(
		&mut self,
		config: OfflineConfig,
	) -> Result<RemoteExternalities<HashingFor<B>>, &'static str> {
		let mut sp = Spinner::with_timer(Spinners::Dots, "Loading snapshot...".into());
		let start = Instant::now();
		info!(target: LOG_TARGET, "Loading snapshot from {:?}", &config.state_snapshot.path);
		let Snapshot { snapshot_version: _, block_hash, state_version, raw_storage, storage_root } =
			Snapshot::<B::Hash>::load(&config.state_snapshot.path)?;

		let inner_ext = TestExternalities::from_raw_snapshot(
			raw_storage,
			storage_root,
			self.overwrite_state_version.unwrap_or(state_version),
		);
		sp.stop_with_message(format!("✅ Loaded snapshot ({:.2}s)", start.elapsed().as_secs_f32()));

		Ok(RemoteExternalities { inner_ext, block_hash })
	}

	pub(crate) async fn pre_build(
		mut self,
	) -> Result<RemoteExternalities<HashingFor<B>>, &'static str> {
		let mut ext = match self.mode.clone() {
			Mode::Offline(config) => self.do_load_offline(config)?,
			Mode::Online(_) => self.do_load_remote().await?,
			Mode::OfflineOrElseOnline(offline_config, _) => {
				match self.do_load_offline(offline_config) {
					Ok(x) => x,
					Err(_) => self.do_load_remote().await?,
				}
			},
		};

		// inject manual key values.
		if !self.hashed_key_values.is_empty() {
			log::info!(
				target: LOG_TARGET,
				"extending externalities with {} manually injected key-values",
				self.hashed_key_values.len()
			);
			ext.batch_insert(self.hashed_key_values.into_iter().map(|(k, v)| (k.0, v.0)));
		}

		// exclude manual key values.
		if !self.hashed_blacklist.is_empty() {
			log::info!(
				target: LOG_TARGET,
				"excluding externalities from {} keys",
				self.hashed_blacklist.len()
			);
			for k in self.hashed_blacklist {
				ext.execute_with(|| sp_io::storage::clear(&k));
			}
		}

		Ok(ext)
	}
}

// Public methods
impl<B: BlockT + DeserializeOwned> Builder<B>
where
	B::Hash: DeserializeOwned,
	B::Header: DeserializeOwned,
{
	/// Create a new builder.
	pub fn new() -> Self {
		Default::default()
	}

	/// Inject a manual list of key and values to the storage.
	pub fn inject_hashed_key_value(mut self, injections: Vec<KeyValue>) -> Self {
		for i in injections {
			self.hashed_key_values.push(i.clone());
		}
		self
	}

	/// Blacklist this hashed key from the final externalities. This is treated as-is, and should be
	/// pre-hashed.
	pub fn blacklist_hashed_key(mut self, hashed: &[u8]) -> Self {
		self.hashed_blacklist.push(hashed.to_vec());
		self
	}

	/// Configure a state snapshot to be used.
	pub fn mode(mut self, mode: Mode<B::Hash>) -> Self {
		self.mode = mode;
		self
	}

	/// The state version to use.
	pub fn overwrite_state_version(mut self, version: StateVersion) -> Self {
		self.overwrite_state_version = Some(version);
		self
	}

	pub async fn build(self) -> Result<RemoteExternalities<HashingFor<B>>, &'static str> {
		let mut ext = self.pre_build().await?;
		ext.commit_all().unwrap();

		info!(
			target: LOG_TARGET,
			"initialized state externalities with storage root {:?} and state_version {:?}",
			ext.as_backend().map(|b| *b.root()),
			ext.state_version
		);

		Ok(ext)
	}
}

#[cfg(test)]
mod test_prelude {
	pub(crate) use super::*;
	pub(crate) use sp_runtime::testing::{Block as RawBlock, ExtrinsicWrapper, H256 as Hash};
	pub(crate) type Block = RawBlock<ExtrinsicWrapper<Hash>>;

	pub(crate) fn init_logger() {
		sp_tracing::try_init_simple();
	}
}

#[cfg(test)]
mod tests {
	use super::test_prelude::*;

	#[tokio::test]
	async fn can_load_state_snapshot() {
		init_logger();
		Builder::<Block>::new()
			.mode(Mode::Offline(OfflineConfig {
				state_snapshot: SnapshotConfig::new("test_data/proxy_test"),
			}))
			.build()
			.await
			.unwrap()
			.execute_with(|| {});
	}

	#[tokio::test]
	async fn can_exclude_from_snapshot() {
		init_logger();

		// get the first key from the snapshot file.
		let some_key = Builder::<Block>::new()
			.mode(Mode::Offline(OfflineConfig {
				state_snapshot: SnapshotConfig::new("test_data/proxy_test"),
			}))
			.build()
			.await
			.expect("Can't read state snapshot file")
			.execute_with(|| {
				let key =
					sp_io::storage::next_key(&[]).expect("some key must exist in the snapshot");
				assert!(sp_io::storage::get(&key).is_some());
				key
			});

		Builder::<Block>::new()
			.mode(Mode::Offline(OfflineConfig {
				state_snapshot: SnapshotConfig::new("test_data/proxy_test"),
			}))
			.blacklist_hashed_key(&some_key)
			.build()
			.await
			.expect("Can't read state snapshot file")
			.execute_with(|| assert!(sp_io::storage::get(&some_key).is_none()));
	}
}

#[cfg(all(test, feature = "remote-test"))]
mod remote_tests {
	use super::test_prelude::*;
	use std::{env, os::unix::fs::MetadataExt};

	fn endpoint() -> String {
		env::var("TEST_WS").unwrap_or_else(|_| DEFAULT_HTTP_ENDPOINT.to_string())
	}

	#[tokio::test]
	async fn state_version_is_kept_and_can_be_altered() {
		const CACHE: &'static str = "state_version_is_kept_and_can_be_altered";
		init_logger();

		// first, build a snapshot.
		let ext = Builder::<Block>::new()
			.mode(Mode::Online(OnlineConfig {
				transport: endpoint().clone().into(),
				pallets: vec!["Proxy".to_owned()],
				child_trie: false,
				state_snapshot: Some(SnapshotConfig::new(CACHE)),
				..Default::default()
			}))
			.build()
			.await
			.unwrap();

		// now re-create the same snapshot.
		let cached_ext = Builder::<Block>::new()
			.mode(Mode::Offline(OfflineConfig { state_snapshot: SnapshotConfig::new(CACHE) }))
			.build()
			.await
			.unwrap();

		assert_eq!(ext.state_version, cached_ext.state_version);

		// now overwrite it
		let other = match ext.state_version {
			StateVersion::V0 => StateVersion::V1,
			StateVersion::V1 => StateVersion::V0,
		};
		let cached_ext = Builder::<Block>::new()
			.mode(Mode::Offline(OfflineConfig { state_snapshot: SnapshotConfig::new(CACHE) }))
			.overwrite_state_version(other)
			.build()
			.await
			.unwrap();

		assert_eq!(cached_ext.state_version, other);
	}

	#[tokio::test]
	async fn snapshot_block_hash_works() {
		const CACHE: &'static str = "snapshot_block_hash_works";
		init_logger();

		// first, build a snapshot.
		let ext = Builder::<Block>::new()
			.mode(Mode::Online(OnlineConfig {
				transport: endpoint().clone().into(),
				pallets: vec!["Proxy".to_owned()],
				child_trie: false,
				state_snapshot: Some(SnapshotConfig::new(CACHE)),
				..Default::default()
			}))
			.build()
			.await
			.unwrap();

		// now re-create the same snapshot.
		let cached_ext = Builder::<Block>::new()
			.mode(Mode::Offline(OfflineConfig { state_snapshot: SnapshotConfig::new(CACHE) }))
			.build()
			.await
			.unwrap();

		assert_eq!(ext.block_hash, cached_ext.block_hash);
	}

	#[tokio::test]
	async fn child_keys_are_loaded() {
		const CACHE: &'static str = "snapshot_retains_storage";
		init_logger();

		// create an ext with children keys
		let child_ext = Builder::<Block>::new()
			.mode(Mode::Online(OnlineConfig {
				transport: endpoint().clone().into(),
				pallets: vec!["Proxy".to_owned()],
				child_trie: true,
				state_snapshot: Some(SnapshotConfig::new(CACHE)),
				..Default::default()
			}))
			.build()
			.await
			.unwrap();

		// create an ext without children keys
		let ext = Builder::<Block>::new()
			.mode(Mode::Online(OnlineConfig {
				transport: endpoint().clone().into(),
				pallets: vec!["Proxy".to_owned()],
				child_trie: false,
				state_snapshot: Some(SnapshotConfig::new(CACHE)),
				..Default::default()
			}))
			.build()
			.await
			.unwrap();

		// there should be more keys in the child ext.
		assert!(
			child_ext
				.as_backend()
				.unwrap()
				.backend_storage()
				.as_prefixed_mem_db()
				.unwrap()
				.keys()
				.len() > ext
				.as_backend()
				.unwrap()
				.backend_storage()
				.as_prefixed_mem_db()
				.unwrap()
				.keys()
				.len()
		);
	}

	#[tokio::test]
	async fn offline_else_online_works() {
		const CACHE: &'static str = "offline_else_online_works_data";
		init_logger();
		// this shows that in the second run, we use the remote and create a snapshot.
		Builder::<Block>::new()
			.mode(Mode::OfflineOrElseOnline(
				OfflineConfig { state_snapshot: SnapshotConfig::new(CACHE) },
				OnlineConfig {
					transport: endpoint().clone().into(),
					pallets: vec!["Proxy".to_owned()],
					child_trie: false,
					state_snapshot: Some(SnapshotConfig::new(CACHE)),
					..Default::default()
				},
			))
			.build()
			.await
			.unwrap()
			.execute_with(|| {});

		// this shows that in the second run, we are not using the remote
		Builder::<Block>::new()
			.mode(Mode::OfflineOrElseOnline(
				OfflineConfig { state_snapshot: SnapshotConfig::new(CACHE) },
				OnlineConfig {
					transport: "ws://non-existent:666".to_owned().into(),
					..Default::default()
				},
			))
			.build()
			.await
			.unwrap()
			.execute_with(|| {});

		let to_delete = std::fs::read_dir(Path::new("."))
			.unwrap()
			.into_iter()
			.map(|d| d.unwrap())
			.filter(|p| p.path().file_name().unwrap_or_default() == CACHE)
			.collect::<Vec<_>>();

		assert!(to_delete.len() == 1);
		std::fs::remove_file(to_delete[0].path()).unwrap();
	}

	#[tokio::test]
	async fn can_build_one_small_pallet() {
		init_logger();
		Builder::<Block>::new()
			.mode(Mode::Online(OnlineConfig {
				transport: endpoint().clone().into(),
				pallets: vec!["Proxy".to_owned()],
				child_trie: false,
				..Default::default()
			}))
			.build()
			.await
			.unwrap()
			.execute_with(|| {});
	}

	#[tokio::test]
	async fn can_build_few_pallet() {
		init_logger();
		Builder::<Block>::new()
			.mode(Mode::Online(OnlineConfig {
				transport: endpoint().clone().into(),
				pallets: vec!["Proxy".to_owned(), "Multisig".to_owned()],
				child_trie: false,
				..Default::default()
			}))
			.build()
			.await
			.unwrap()
			.execute_with(|| {});
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn can_create_snapshot() {
		const CACHE: &'static str = "can_create_snapshot";
		init_logger();

		Builder::<Block>::new()
			.mode(Mode::Online(OnlineConfig {
				transport: endpoint().clone().into(),
				state_snapshot: Some(SnapshotConfig::new(CACHE)),
				pallets: vec!["Proxy".to_owned()],
				child_trie: false,
				..Default::default()
			}))
			.build()
			.await
			.unwrap()
			.execute_with(|| {});

		let to_delete = std::fs::read_dir(Path::new("."))
			.unwrap()
			.into_iter()
			.map(|d| d.unwrap())
			.filter(|p| p.path().file_name().unwrap_or_default() == CACHE)
			.collect::<Vec<_>>();

		assert!(to_delete.len() == 1);
		let to_delete = to_delete.first().unwrap();
		assert!(std::fs::metadata(to_delete.path()).unwrap().size() > 1);
		std::fs::remove_file(to_delete.path()).unwrap();
	}

	#[tokio::test]
	async fn can_create_child_snapshot() {
		const CACHE: &'static str = "can_create_child_snapshot";
		init_logger();
		Builder::<Block>::new()
			.mode(Mode::Online(OnlineConfig {
				transport: endpoint().clone().into(),
				state_snapshot: Some(SnapshotConfig::new(CACHE)),
				pallets: vec!["Crowdloan".to_owned()],
				child_trie: true,
				..Default::default()
			}))
			.build()
			.await
			.unwrap()
			.execute_with(|| {});

		let to_delete = std::fs::read_dir(Path::new("."))
			.unwrap()
			.into_iter()
			.map(|d| d.unwrap())
			.filter(|p| p.path().file_name().unwrap_or_default() == CACHE)
			.collect::<Vec<_>>();

		assert!(to_delete.len() == 1);
		let to_delete = to_delete.first().unwrap();
		assert!(std::fs::metadata(to_delete.path()).unwrap().size() > 1);
		std::fs::remove_file(to_delete.path()).unwrap();
	}

	#[tokio::test]
	async fn can_build_big_pallet() {
		if std::option_env!("TEST_WS").is_none() {
			return
		}
		init_logger();
		Builder::<Block>::new()
			.mode(Mode::Online(OnlineConfig {
				transport: endpoint().clone().into(),
				pallets: vec!["Staking".to_owned()],
				child_trie: false,
				..Default::default()
			}))
			.build()
			.await
			.unwrap()
			.execute_with(|| {});
	}

	#[tokio::test]
	async fn can_fetch_all() {
		if std::option_env!("TEST_WS").is_none() {
			return
		}
		init_logger();
		Builder::<Block>::new()
			.mode(Mode::Online(OnlineConfig {
				transport: endpoint().clone().into(),
				..Default::default()
			}))
			.build()
			.await
			.unwrap()
			.execute_with(|| {});
	}

	#[tokio::test]
	async fn can_fetch_in_parallel() {
		init_logger();

		let mut builder = Builder::<Block>::new().mode(Mode::Online(OnlineConfig {
			transport: endpoint().clone().into(),
			..Default::default()
		}));
		builder.init_remote_client().await.unwrap();

		let at = builder.as_online().at.unwrap();

		let prefix = StorageKey(vec![13]);
		let paged = builder.rpc_get_keys_in_range(&prefix, at, None, None).await.unwrap();
		let para = builder.rpc_get_keys_parallel(&prefix, at, 4).await.unwrap();
		assert_eq!(paged, para);

		let prefix = StorageKey(vec![]);
		let paged = builder.rpc_get_keys_in_range(&prefix, at, None, None).await.unwrap();
		let para = builder.rpc_get_keys_parallel(&prefix, at, 8).await.unwrap();
		assert_eq!(paged, para);
	}
}
