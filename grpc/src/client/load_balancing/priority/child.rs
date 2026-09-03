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

// Child is a child of priority balancer.
#[derive(Debug, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub(super) struct ChildConfig {
    #[serde(default)]
    pub(super) ignore_reresolution_requests: bool,
    pub(super) config: LbConfigSerde,
}

/// Produces wrapped LB policies that can block re-resolution requests from the
/// wrapped policy if the ignore_reresolution_requests is set in the LbConfig.
/// It is not registered in the global registry.
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

    fn parse_config(
        &self,
        _config: &ParsedJsonLbConfig,
    ) -> Result<Option<<Self::LbPolicy as LbPolicy>::LbConfig>, String> {
        Ok(None)
    }
}

/// A policy that can block re-resolution requests from its children. It's child
/// is a graceful-switch balancer.
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
        let channe_controller =
            WrappedController::new(channel_controller, self.ignore_reresolution_requests);
        let gs_cfg = GracefulSwitchLbConfig::new(
            config.config.builder.clone(),
            config.config.config.clone(),
        );
        self.graceful_switch
            .resolver_update(update, Some(&gs_cfg), channel_controller)
    }

    fn subchannel_update(
        &mut self,
        subchannel: Arc<dyn Subchannel>,
        state: &SubchannelState,
        channel_controller: &mut dyn ChannelController,
    ) {
        let channe_controller =
            WrappedController::new(channel_controller, self.ignore_reresolution_requests);
        self.graceful_switch
            .subchannel_update(subchannel, state, channel_controller)
    }

    fn work(&mut self, data: Option<WorkData>, channel_controller: &mut dyn ChannelController) {
        let channe_controller =
            WrappedController::new(channel_controller, self.ignore_reresolution_requests);
        self.graceful_switch.work(data, channel_controller)
    }

    fn exit_idle(&mut self, channel_controller: &mut dyn ChannelController) {
        let channe_controller =
            WrappedController::new(channel_controller, self.ignore_reresolution_requests);
        self.graceful_switch.exit_idle(channel_controller)
    }
}

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
