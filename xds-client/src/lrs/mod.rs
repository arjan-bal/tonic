/*
 *
 * Copyright 2026 gRPC authors.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 */

//! [Load Reporting Service](https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/load_stats/v3/lrs.proto)
//! client.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::sync::Weak;

use bytes::Bytes;

use crate::client::config::ServerConfig;
use crate::client::retry::RetryPolicy;
use crate::error::Result;
use crate::lrs::load_store::LoadStoreInner;
use crate::lrs::message::LoadStatsRequest;
use crate::lrs::message::LoadStatsResponse;
use crate::lrs::worker::WorkerConfig;
use crate::lrs::worker::spawn_worker;
use crate::message::Node;
use crate::runtime::Runtime;
use crate::transport::TransportBuilder;

mod backend_metrics;
mod load_store;
pub mod message;
mod worker;

pub use backend_metrics::BackendMetricPropagation;
pub use backend_metrics::BackendMetrics;
pub use load_store::CallOutcome;
pub use load_store::CallTracker;
pub use load_store::ClusterLevelStats;
pub use load_store::ClusterLocalityStats;
pub use load_store::LoadStore;

/// Trait for encoding/decoding LRS (Load Reporting Service) messages.
///
/// Implementations convert between the crate-owned message types
/// and their serialized wire format.
pub trait LrsCodec: Send + Sync + 'static {
    /// Encode a [`LoadStatsRequest`] to bytes.
    fn encode_load_stats_request(&self, request: &LoadStatsRequest<'_>) -> Result<Bytes>;

    /// Decode bytes into a [`LoadStatsResponse`].
    fn decode_load_stats_response(&self, bytes: Bytes) -> Result<LoadStatsResponse>;
}

/// Builder for [`LrsClient`].
#[derive(Debug)]
pub struct LrsClientBuilder<TB, C, R> {
    /// Identity of the client application reporting load to the LRS server.
    node: Node,

    /// Used to connect to the LRS server.
    transport_builder: TB,

    /// Used to encode/decode LRS messages.
    codec: C,

    /// Used to spawn background tasks, and measure time.
    runtime: R,

    /// Used to reconnect to LRS servers after stream failures.
    retry_policy: RetryPolicy,
}

impl<TB, C, R> LrsClientBuilder<TB, C, R>
where
    TB: TransportBuilder,
    C: LrsCodec,
    R: Runtime,
{
    /// Create a new builder with the given node, transport builder, codec, and runtime.
    pub fn new(node: Node, transport_builder: TB, codec: C, runtime: R) -> Self {
        Self {
            node,
            transport_builder,
            codec,
            runtime,
            retry_policy: RetryPolicy::default(),
        }
    }

    /// Set the retry policy for reconnecting to LRS servers after stream
    /// failures.
    ///
    /// Defaults to [`RetryPolicy::default`] (gRFC A6).
    pub fn with_retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }

    /// Build the client.
    ///
    /// No background task is started until
    /// [`load_store`](LrsClient::load_store) is called.
    pub fn build(self) -> LrsClient {
        let Self {
            node,
            transport_builder,
            codec,
            runtime,
            retry_policy,
        } = self;
        let transport_builder = Arc::new(transport_builder);
        let codec = Arc::new(codec);
        let spawn = move |server: &ServerConfig| {
            spawn_worker(WorkerConfig {
                server: server.clone(),
                node: node.clone(),
                transport_builder: transport_builder.clone(),
                codec: codec.clone(),
                runtime: runtime.clone(),
                retry_policy: retry_policy.clone(),
            })
        };
        LrsClient {
            inner: Arc::new(LrsClientInner {
                workers: Mutex::new(HashMap::new()),
                spawn: Box::new(spawn),
            }),
        }
    }
}

/// The LRS client.
///
/// Reports load to LRS servers on behalf of the client application. Cloning
/// this handle creates a new reference to the same client.
#[derive(Clone)]
pub struct LrsClient {
    inner: Arc<LrsClientInner>,
}

struct LrsClientInner {
    /// The `LoadStore`s of the servers with running workers, by server URI.
    workers: Mutex<HashMap<String, Weak<LoadStoreInner>>>,

    /// Spawns the worker for a server, and returns its first `LoadStore`.
    spawn: Box<dyn Fn(&ServerConfig) -> LoadStore + Send + Sync>,
}

impl fmt::Debug for LrsClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let workers = self
            .inner
            .workers
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        f.debug_struct("LrsClient")
            .field("servers", &workers.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl LrsClient {
    /// Create a new builder with the given node, transport builder, codec, and runtime.
    pub fn builder<TB, C, R>(
        node: Node,
        transport_builder: TB,
        codec: C,
        runtime: R,
    ) -> LrsClientBuilder<TB, C, R>
    where
        TB: TransportBuilder,
        C: LrsCodec,
        R: Runtime,
    {
        LrsClientBuilder::new(node, transport_builder, codec, runtime)
    }

    /// Returns a handle for recording loads reported to `server`.
    ///
    /// The first call for a server starts reporting to it, in a background
    /// task. Reporting stops after a final report once every [`LoadStore`]
    /// for the server, and every recorder and call tracker created from them,
    /// has been dropped.
    pub fn load_store(&self, server: &ServerConfig) -> LoadStore {
        let mut workers = self
            .inner
            .workers
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(load_store) = workers.get(server.uri()).and_then(LoadStore::upgrade) {
            return load_store;
        }
        workers.retain(|_, load_store| load_store.strong_count() > 0);
        let load_store = (self.inner.spawn)(server);
        workers.insert(server.uri().to_owned(), load_store.downgrade());
        load_store
    }
}
