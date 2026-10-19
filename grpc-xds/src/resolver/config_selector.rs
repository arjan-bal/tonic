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

use std::sync::Arc;

use grpc::__unstable::client::name_resolution::config_selector::ConfigSelector;
use grpc::__unstable::client::name_resolution::config_selector::RpcConfig;
use grpc::__unstable::client::name_resolution::config_selector::SelectConfigOptions;

use super::ClusterRef;

/// Routes each RPC to a cluster.
#[derive(Debug)]
pub struct XdsConfigSelector {
    cluster_refs: Vec<Arc<ClusterRef>>,
}

impl XdsConfigSelector {
    pub(super) fn new(cluster_refs: Vec<Arc<ClusterRef>>) -> Self {
        Self { cluster_refs }
    }

    /// Returns the names of the clusters this selector holds refs to.
    #[cfg(test)]
    pub(super) fn cluster_names(&self) -> Vec<&str> {
        self.cluster_refs.iter().map(|c| c.name()).collect()
    }
}

impl ConfigSelector for XdsConfigSelector {
    fn select_config(&self, options: SelectConfigOptions) -> Result<RpcConfig, grpc::StatusError> {
        // TODO: pick a cluster and attach its ClusterRef to the RPC via
        // `options.call_options.set_option(..)`, so the cluster stays in the
        // service config until the RPC is done.
        todo!()
    }
}
