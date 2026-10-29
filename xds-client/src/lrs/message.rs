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

//! Crate-owned LRS message types.
//!
//! These types are codegen-agnostic and serve as the interface between
//! the LRS client logic and the codec layer. The codec converts these
//! to/from the wire format (e.g., prost/envoy-types or google-protobuf).

use std::time::Duration;

use crate::message::Node;

/// A load stats request to send to the LRS server.
///
/// This struct borrows data to avoid unnecessary allocations when encoding.
/// The data only needs to live long enough for the codec to encode it.
// TODO: add `cluster_stats` once load reporting is implemented.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LoadStatsRequest<'a> {
    /// The node reporting load.
    pub node: &'a Node,
}

impl<'a> LoadStatsRequest<'a> {
    /// Create a new load stats request for the given node.
    pub fn new(node: &'a Node) -> Self {
        Self { node }
    }
}

/// A load stats response from the LRS server.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct LoadStatsResponse {
    /// Clusters to report stats for. Ignored if `send_all_clusters` is true.
    pub clusters: Vec<String>,
    /// If true, the client should send stats for all clusters it knows about.
    pub send_all_clusters: bool,
    /// The minimum interval of time to collect stats over.
    pub load_reporting_interval: Duration,
    /// Whether endpoint-level load reports should be sent, in addition to
    /// cluster-level ones.
    pub report_endpoint_granularity: bool,
}

impl LoadStatsResponse {
    /// Create a new load stats response with the given reporting interval.
    ///
    /// Other fields default to empty/false and can be set using builder
    /// methods.
    pub fn new(load_reporting_interval: Duration) -> Self {
        Self {
            load_reporting_interval,
            ..Default::default()
        }
    }

    /// Set the clusters to report stats for.
    pub fn with_clusters(mut self, clusters: Vec<String>) -> Self {
        self.clusters = clusters;
        self
    }

    /// Set whether stats should be sent for all clusters.
    pub fn with_send_all_clusters(mut self, send_all_clusters: bool) -> Self {
        self.send_all_clusters = send_all_clusters;
        self
    }

    /// Set whether endpoint-level load reports should be sent.
    pub fn with_report_endpoint_granularity(mut self, report_endpoint_granularity: bool) -> Self {
        self.report_endpoint_granularity = report_endpoint_granularity;
        self
    }
}
