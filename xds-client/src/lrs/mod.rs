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

use bytes::Bytes;

use crate::error::Result;
use crate::lrs::message::LoadStatsRequest;
use crate::lrs::message::LoadStatsResponse;
use crate::message::Node;
use crate::runtime::Runtime;
use crate::transport::TransportBuilder;

pub mod backend_metrics;
pub mod load_store;
pub mod message;

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

    /// Used to spawn background tasks.
    runtime: R,
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
        }
    }

    /// Build the client.
    pub fn build(self) -> LrsClient<TB, C, R> {
        LrsClient {
            node: self.node,
            transport_builder: self.transport_builder,
            codec: self.codec,
            runtime: self.runtime,
        }
    }
}

/// The LRS client.
///
/// Reports load to LRS servers on behalf of the client application.
// TODO: once a background worker exists, hand `transport_builder`, `codec`
// and `runtime` to it (as `XdsClient` does) so this type no longer needs to be
// generic.
#[derive(Debug)]
pub struct LrsClient<TB, C, R> {
    /// Identity of the client application reporting load to the LRS server.
    node: Node,

    /// Used to connect to the LRS server.
    transport_builder: TB,

    /// Used to encode/decode LRS messages.
    codec: C,

    /// Used to spawn background tasks.
    runtime: R,
}

impl<TB, C, R> LrsClient<TB, C, R>
where
    TB: TransportBuilder,
    C: LrsCodec,
    R: Runtime,
{
    /// Create a new builder with the given node, transport builder, codec, and runtime.
    pub fn builder(
        node: Node,
        transport_builder: TB,
        codec: C,
        runtime: R,
    ) -> LrsClientBuilder<TB, C, R> {
        LrsClientBuilder::new(node, transport_builder, codec, runtime)
    }
}
