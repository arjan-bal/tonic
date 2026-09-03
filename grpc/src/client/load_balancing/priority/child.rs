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

//! Child policy wrapper for the `priority_experimental` load balancing policy.
//!
//! Each priority in the priority policy is represented by an instance of
//! [`ChildPolicy`], constructed via [`ChildBuilder`].
//!
//! [`ChildPolicy`] wraps a [`GracefulSwitchPolicy`] to support dynamic
//! switching between child LB policies (e.g., transitioning from `round_robin`
//! to `pick_first`) without dropping in-flight RPCs or abruptly terminating
//! connections.
//!
//! It also implements re-resolution filtering as specified in [gRFC A37] and
//! [gRFC A56]: if `ignore_reresolution_requests` is set to `true` in
//! [`ChildConfig`], re-resolution requests triggered by this child (e.g., when
//! it enters `TRANSIENT_FAILURE`) are intercepted and suppressed via
//! [`WrappedController`], preventing redundant name resolution churn.
//!
//! [gRFC A37]:
//!   https://github.com/grpc/proposal/blob/master/A37-xds-aggregate-and-logical-dns-clusters.md
//! [gRFC A56]:
//!   https://github.com/grpc/proposal/blob/master/A56-priority-lb-policy.md

use std::sync::Arc;

use crate::client::load_balancing::ChannelController;
use crate::client::load_balancing::LbPolicy;
use crate::client::load_balancing::LbPolicyBuilder;
use crate::client::load_balancing::LbPolicyOptions;
use crate::client::load_balancing::LbState;
use crate::client::load_balancing::ParsedJsonLbConfig;
use crate::client::load_balancing::WorkData;
use crate::client::load_balancing::graceful_switch::GracefulSwitchLbConfig;
use crate::client::load_balancing::graceful_switch::GracefulSwitchPolicy;
use crate::client::load_balancing::subchannel::Subchannel;
use crate::client::load_balancing::subchannel::SubchannelState;
use crate::client::name_resolution::ResolverUpdate;
use crate::client::service_config::serde_bindings::LbConfigSerde;
use crate::core::Address;

/// Configuration for an individual child under the `priority_experimental`
/// LB policy.
///
/// Corresponds to the protobuf message
/// `PriorityLoadBalancingPolicyConfig.Child` defined in
/// [gRFC A56 §LB Policy Configuration]:
///
/// ```proto
/// message Child {
///   repeated LoadBalancingConfig config = 1;
///   bool ignore_reresolution_requests = 2;
/// }
/// ```
///
/// [gRFC A56 §LB Policy Configuration]:
///   https://github.com/grpc/proposal/blob/master/A56-priority-lb-policy.md#lb-policy-configuration
#[derive(Debug, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub(super) struct ChildConfig {
    /// If `true`, re-resolution requests from this child policy will be ignored
    /// and not forwarded to the channel controller.
    ///
    /// This prevents lower-priority or failover children from triggering
    /// unnecessary name resolution when they enter `TRANSIENT_FAILURE`.
    /// See [gRFC A37] and [gRFC A56] for details.
    ///
    /// [gRFC A37]:
    ///   https://github.com/grpc/proposal/blob/master/A37-xds-aggregate-and-logical-dns-clusters.md
    /// [gRFC A56]:
    ///   https://github.com/grpc/proposal/blob/master/A56-priority-lb-policy.md
    #[serde(default)]
    pub(super) ignore_reresolution_requests: bool,

    /// The child load balancing policy configuration, specifying the policy
    /// to instantiate (e.g., `round_robin`, `pick_first`, `weighted_target`)
    /// and its policy-specific configuration.
    pub(super) config: LbConfigSerde,
}

/// Builder for [`ChildPolicy`].
///
/// Produces wrapped LB policy instances that wrap a [`GracefulSwitchPolicy`]
/// and filter re-resolution requests if
/// [`ChildConfig::ignore_reresolution_requests`] is set to `true`.
///
/// This builder is used internally by the priority policy to instantiate
/// children managed by [`ChildManager`], and is not registered in
/// [`GLOBAL_LB_REGISTRY`].
///
/// [`ChildManager`]: crate::client::load_balancing::child_manager::ChildManager
/// [`GLOBAL_LB_REGISTRY`]: crate::client::load_balancing::GLOBAL_LB_REGISTRY
#[derive(Debug)]
pub(super) struct ChildBuilder {}

impl LbPolicyBuilder for ChildBuilder {
    type LbPolicy = ChildPolicy;

    fn build(&self, options: LbPolicyOptions) -> Self::LbPolicy {
        let graceful_switch = GracefulSwitchPolicy::new(options.runtime, options.work_scheduler);
        ChildPolicy {
            graceful_switch,
            ignore_reresolution_requests: false,
        }
    }

    fn name(&self) -> &'static str {
        "priority_child_lb"
    }

    /// Config parsing is a no-op here because child configurations are
    /// deserialized and validated as part of `PriorityConfig` in the parent
    /// priority policy.
    fn parse_config(
        &self,
        _config: &ParsedJsonLbConfig,
    ) -> Result<Option<<Self::LbPolicy as LbPolicy>::LbConfig>, String> {
        Ok(None)
    }
}

/// A child load balancing policy wrapper for the priority balancer.
///
/// It delegates load balancing duties to an inner [`GracefulSwitchPolicy`]
/// while intercepting control operations from the child to the channel
/// controller. Specifically, if `ignore_reresolution_requests` is enabled in
/// the active [`ChildConfig`], re-resolution requests from the child are
/// filtered out to prevent unnecessary DNS/resolver queries during priority
/// failovers.
#[derive(Debug)]
pub(super) struct ChildPolicy {
    graceful_switch: GracefulSwitchPolicy,
    ignore_reresolution_requests: bool,
}

impl LbPolicy for ChildPolicy {
    type LbConfig = ChildConfig;

    fn resolver_update(
        &mut self,
        update: ResolverUpdate,
        config: Option<&Self::LbConfig>,
        channel_controller: &mut dyn ChannelController,
    ) -> Result<(), String> {
        let Some(config) = config else {
            return Err(
                "priority child balancer received update with missing LB config".to_owned(),
            );
        };
        self.ignore_reresolution_requests = config.ignore_reresolution_requests;
        let mut wrapped_controller =
            WrappedController::new(channel_controller, self.ignore_reresolution_requests);
        let gs_cfg = GracefulSwitchLbConfig::new(
            config.config.builder.clone(),
            config.config.config.clone(),
        );
        self.graceful_switch
            .resolver_update(update, Some(&gs_cfg), &mut wrapped_controller)
    }

    fn subchannel_update(
        &mut self,
        subchannel: Arc<dyn Subchannel>,
        state: &SubchannelState,
        channel_controller: &mut dyn ChannelController,
    ) {
        let mut wrapped_controller =
            WrappedController::new(channel_controller, self.ignore_reresolution_requests);
        self.graceful_switch
            .subchannel_update(subchannel, state, &mut wrapped_controller)
    }

    fn work(&mut self, data: Option<WorkData>, channel_controller: &mut dyn ChannelController) {
        let mut wrapped_controller =
            WrappedController::new(channel_controller, self.ignore_reresolution_requests);
        self.graceful_switch.work(data, &mut wrapped_controller)
    }

    fn exit_idle(&mut self, channel_controller: &mut dyn ChannelController) {
        let mut wrapped_controller =
            WrappedController::new(channel_controller, self.ignore_reresolution_requests);
        self.graceful_switch.exit_idle(&mut wrapped_controller)
    }
}

/// A [`ChannelController`] proxy that conditionally filters re-resolution
/// requests.
struct WrappedController<'a> {
    channel_controller: &'a mut dyn ChannelController,
    ignore_reresolution_requests: bool,
}

impl<'a> WrappedController<'a> {
    fn new(
        channel_controller: &'a mut dyn ChannelController,
        ignore_reresolution_requests: bool,
    ) -> Self {
        Self {
            ignore_reresolution_requests,
            channel_controller,
        }
    }
}

impl ChannelController for WrappedController<'_> {
    fn new_subchannel(&mut self, address: &Address) -> (Arc<dyn Subchannel>, SubchannelState) {
        self.channel_controller.new_subchannel(address)
    }

    fn update_picker(&mut self, update: LbState) {
        self.channel_controller.update_picker(update)
    }

    fn request_resolution(&mut self) {
        if !self.ignore_reresolution_requests {
            self.channel_controller.request_resolution();
        }
    }
}
