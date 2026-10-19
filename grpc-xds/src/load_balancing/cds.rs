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

//! Mock of the `cds_experimental` LB policy (gRFC A74).
//!
//! Only the policy's name and config are implemented, so that the cluster
//! manager can parse the xDS resolver's service config, which names this
//! policy as the child policy of every cluster.
//!
//! TODO: replace with the real CDS policy.

use std::sync::Once;

use grpc::__unstable::client::load_balancing::ChannelController;
use grpc::__unstable::client::load_balancing::LbConfigJson;
use grpc::__unstable::client::load_balancing::LbPolicy;
use grpc::__unstable::client::load_balancing::LbPolicyBuilder;
use grpc::__unstable::client::load_balancing::LbPolicyOptions;
use grpc::__unstable::client::load_balancing::WorkData;
use grpc::__unstable::client::load_balancing::registry::GLOBAL_LB_REGISTRY;
use grpc::__unstable::client::name_resolution::ResolverUpdate;
use serde::Deserialize;
use serde::Serialize;

pub(crate) const POLICY_NAME: &str = "cds_experimental";
static START: Once = Once::new();

/// Config of the `cds_experimental` policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CdsConfig {
    /// Name of the cluster to load balance across.
    pub(crate) cluster: String,
}

#[derive(Debug)]
struct CdsBuilder;

impl LbPolicyBuilder for CdsBuilder {
    type LbPolicy = CdsPolicy;

    fn build(&self, _options: LbPolicyOptions) -> Self::LbPolicy {
        CdsPolicy
    }

    fn name(&self) -> &'static str {
        POLICY_NAME
    }

    fn parse_config(&self, config: &LbConfigJson) -> Result<CdsConfig, String> {
        config
            .convert_to()
            .map_err(|e| format!("failed to deserialize cds_experimental config: {e}"))
    }
}

#[derive(Debug)]
struct CdsPolicy;

impl LbPolicy for CdsPolicy {
    type LbConfig = CdsConfig;

    fn resolver_update(
        &mut self,
        _update: ResolverUpdate,
        _config: &Self::LbConfig,
        _channel_controller: &mut dyn ChannelController,
    ) -> Result<(), String> {
        todo!()
    }

    fn work(&mut self, _data: Option<WorkData>, _channel_controller: &mut dyn ChannelController) {
        todo!()
    }

    fn exit_idle(&mut self, _channel_controller: &mut dyn ChannelController) {
        todo!()
    }
}

/// Registers the mock CDS policy as an LbPolicy.
pub(crate) fn reg() {
    START.call_once(|| {
        GLOBAL_LB_REGISTRY.add_builder(CdsBuilder);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_config_reads_cluster() {
        let config = CdsBuilder
            .parse_config(&LbConfigJson::new(r#"{"cluster": "a"}"#).unwrap())
            .unwrap();
        assert_eq!(
            config,
            CdsConfig {
                cluster: "a".to_string()
            }
        );
    }

    #[test]
    fn parse_config_requires_cluster() {
        let err = CdsBuilder
            .parse_config(&LbConfigJson::new("{}").unwrap())
            .unwrap_err();
        assert!(err.contains("cluster"), "unexpected error: {err}");
    }
}
