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

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::mem;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use crate::client::ConnectivityState;
use crate::client::load_balancing::ChannelController;
use crate::client::load_balancing::DynLbPolicyBuilder;
use crate::client::load_balancing::FailingPicker;
use crate::client::load_balancing::GLOBAL_LB_REGISTRY;
use crate::client::load_balancing::LbPolicy;
use crate::client::load_balancing::LbPolicyBuilder;
use crate::client::load_balancing::LbPolicyOptions;
use crate::client::load_balancing::LbState;
use crate::client::load_balancing::ParsedJsonLbConfig;
use crate::client::load_balancing::WorkData;
use crate::client::load_balancing::WorkScheduler;
use crate::client::load_balancing::child_manager::ChildManager;
use crate::client::load_balancing::child_manager::ChildUpdate;
use crate::client::load_balancing::hierarchy;
use crate::client::load_balancing::priority::child::ChildBuilder;
use crate::client::load_balancing::priority::child::ChildData;
use crate::client::load_balancing::priority::child::ChildState;
use crate::client::load_balancing::priority::child::ChildState::Deactivated;
use crate::client::load_balancing::priority::child::Timer;
use crate::client::load_balancing::priority::config::PriorityConfig;
use crate::client::load_balancing::subchannel::Subchannel;
use crate::client::load_balancing::subchannel::SubchannelState;
use crate::client::name_resolution::ResolverUpdate;
use crate::rt::GrpcRuntime;

mod child;
mod config;

pub static POLICY_NAME: &str = "priority_experimental";
const CONNECTING_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) fn reg() {
    GLOBAL_LB_REGISTRY.add_builder(Builder {})
}

#[derive(Debug)]
struct Builder {}

impl LbPolicyBuilder for Builder {
    type LbPolicy = PriorityPolicy;

    fn build(&self, options: LbPolicyOptions) -> Self::LbPolicy {
        let rt = options.runtime;
        PriorityPolicy {
            child_mgr: ChildManager::new(rt.clone(), options.work_scheduler.clone()),
            child_data: HashMap::default(),
            priorities: Vec::default(),
            rt,
            work_scheduler: options.work_scheduler,
        }
    }

    fn name(&self) -> &'static str {
        POLICY_NAME
    }

    fn parse_config(&self, config: &ParsedJsonLbConfig) -> Result<Option<PriorityConfig>, String> {
        let cfg: PriorityConfig = config.convert_to().map_err(|e| e.to_string())?;
        cfg.validate()?;
        Ok(Some(cfg))
    }
}

#[derive(Debug)]
struct PriorityPolicy {
    child_mgr: ChildManager<String>,
    child_data: HashMap<String, ChildData>,
    priorities: Vec<String>,
    rt: GrpcRuntime,
    work_scheduler: Arc<dyn WorkScheduler>,
}

impl LbPolicy for PriorityPolicy {
    type LbConfig = PriorityConfig;

    fn resolver_update(
        &mut self,
        update: ResolverUpdate,
        config: Option<&Self::LbConfig>,
        channel_controller: &mut dyn ChannelController,
    ) -> Result<(), String> {
        let Some(config) = config else {
            return Err("priority balancer received update with missing LB config".to_owned());
        };
        // Shard by hierarchy.
        let mut sharded_endpoints = update.endpoints.map(hierarchy::group);

        // Remove children no-longer present in any priority.
        self.child_data
            .retain(|k, v| config.children.contains_key(k));

        // Update resolver state for all children, adding missing ones as
        // uninitialized.
        for (k, child_cfg) in &config.children {
            let endpoints = match &mut sharded_endpoints {
                Ok(grouped) => Ok(grouped.remove(k).unwrap_or_default()),
                Err(status) => Err(status.clone()),
            };

            let resolver_update = ResolverUpdate {
                attributes: update.attributes.clone(),
                endpoints,
                service_config: update.service_config.clone(),
                resolution_note: update.resolution_note.clone(),
            };

            match self.child_data.entry(k.clone()) {
                Entry::Occupied(mut entry) => {
                    entry.get_mut().resolver_update = resolver_update;
                }
                Entry::Vacant(entry) => {
                    entry.insert(ChildData {
                        state: ChildState::Uninitialized,
                        child_config: child_cfg.clone(),
                        resolver_update,
                    });
                }
            }
        }

        // Update children.
        let res = self.push_child_resolver_updates(channel_controller);
        self.reconcile(channel_controller);
        res
    }

    fn subchannel_update(
        &mut self,
        subchannel: std::sync::Arc<dyn Subchannel>,
        state: &SubchannelState,
        channel_controller: &mut dyn ChannelController,
    ) {
        self.child_mgr
            .subchannel_update(subchannel, state, channel_controller);
        self.reconcile(channel_controller);
    }

    fn work(&mut self, data: Option<WorkData>, channel_controller: &mut dyn ChannelController) {
        self.child_mgr.work(data, channel_controller);
        self.reconcile(channel_controller);
    }

    fn exit_idle(&mut self, channel_controller: &mut dyn ChannelController) {
        self.child_mgr.exit_idle(channel_controller);
        self.reconcile(channel_controller);
    }
}

impl PriorityPolicy {
    fn push_child_resolver_updates(
        &mut self,
        channel_controller: &mut dyn ChannelController,
    ) -> Result<(), String> {
        let child_updates = self
            .child_data
            .iter()
            .filter(|(_, data)| {
                if let ChildState::Uninitialized = data.state {
                    false
                } else {
                    true
                }
            })
            .map(|(k, v)| ChildUpdate {
                child_identifier: k.clone(),
                child_policy_builder: Arc::new(ChildBuilder {}),
                child_update: Some(),
            });
        let res = self.child_mgr.update(child_updates, channel_controller);

        todo!()
    }

    fn reconcile(&mut self, channel_controller: &mut dyn ChannelController) {
        self.handle_deactivation_timer();
        self.handle_connectivity_timer();
        self.update_child_data();
        self.choose_priority(channel_controller);
    }

    fn update_child_data(&mut self) {
        for child in self.child_mgr.children() {
            let child_data = self
                .child_data
                .get_mut(&child.identifier)
                .expect("missing priority child entry");
            // Take ownership of the current state and replace it with a temporary
            // value.
            let old_state = mem::replace(&mut child_data.state, ChildState::Retrying);
            child_data.state = match child.state.connectivity_state {
                ConnectivityState::Idle => ChildState::Steady,
                ConnectivityState::Connecting => match old_state {
                    ChildState::Uninitialized => ChildState::Uninitialized,
                    ChildState::Connecting(timer) => ChildState::Connecting(timer),
                    ChildState::Retrying => ChildState::Retrying,
                    ChildState::Steady => ChildState::Connecting(Timer::new(
                        CONNECTING_TIMEOUT,
                        self.work_scheduler.clone(),
                        self.rt.clone(),
                    )),
                    ChildState::Deactivated(timer) => Deactivated(timer),
                },
                ConnectivityState::Ready => ChildState::Steady,
                ConnectivityState::TransientFailure => ChildState::Retrying,
            };
        }
    }

    fn choose_priority(&mut self, channel_controller: &mut dyn ChannelController) {
        // If priority list is empty, report TRANSIENT_FAILURE.
        if self.priorities.is_empty() {
            channel_controller.update_picker(LbState {
                connectivity_state: ConnectivityState::TransientFailure,
                picker: Arc::new(FailingPicker {
                    error: "priority policy has empty priority list".to_owned(),
                }),
            });
            return;
        }

        let initialized_child_states: HashMap<&String, &LbState> = self
            .child_mgr
            .children()
            .map(|child| (&child.identifier, &child.state))
            .collect();

        for (idx, child_id) in self.priorities.iter().enumerate() {
            let child_data = self
                .child_data
                .get_mut(child_id)
                .expect("missing entry for child priority");
            // Re-activate child if necessary.
            if let ChildState::Deactivated(_) = child_data.state {
                let cur_state = initialized_child_states
                    .get(child_id)
                    .expect("missing child manager entry for priority child");
                let new_state = match cur_state.connectivity_state {
                    ConnectivityState::Idle | ConnectivityState::Ready => ChildState::Steady,
                    ConnectivityState::Connecting => ChildState::Connecting(Timer::new(
                        CONNECTING_TIMEOUT,
                        self.work_scheduler.clone(),
                        self.rt.clone(),
                    )),
                    ConnectivityState::TransientFailure => ChildState::Retrying,
                };
                child_data.state = new_state;
            }
            match &child_data.state {
                ChildState::Uninitialized => {
                    // Move to connecting.
                    child_data.state = ChildState::Connecting(Timer::new(
                        CONNECTING_TIMEOUT,
                        self.work_scheduler.clone(),
                        self.rt.clone(),
                    ));
                    // Call Child manager.
                    self.set_current_priority(channel_controller, idx, false);
                    return;
                }
                ChildState::Connecting(timer) => {
                    self.set_current_priority(channel_controller, idx, false);
                    return;
                }
                ChildState::Retrying => {}
                ChildState::Steady => {
                    self.set_current_priority(channel_controller, idx, true);
                    return;
                }
                ChildState::Deactivated(timer) => {
                    unreachable!("child re-activate previously")
                }
            };
        }

        // We did not find a priority in READY or IDLE or whose failover timer
        // was pending, so check for one in CONNECTING.

        // We didn't find a child in CONNECTING, so delegate to the last child.
        todo!()
    }

    fn set_current_priority(
        &mut self,
        channel_controller: &mut dyn ChannelController,
        index: usize,
        deactivate_lower_priorities: bool,
    ) {
        todo!()
    }

    fn handle_connectivity_timer(&mut self) {
        for (_, child_data) in self.child_data.iter_mut() {
            if let ChildState::Connecting(connecting_state) = &child_data.state
                && connecting_state.deadline >= Instant::now()
            {
                child_data.state = ChildState::Retrying;
            }
        }
    }

    fn handle_deactivation_timer(&mut self) {
        self.child_data.retain(|id, s| match &s.state {
            ChildState::Deactivated(timer) => timer.deadline >= Instant::now(),
            _ => true,
        });

        let iter = self.child_data.keys().map(|id| {
            (
                id.clone(),
                Arc::new(ChildBuilder {}) as Arc<DynLbPolicyBuilder>,
            )
        });

        self.child_mgr.retain_children(iter);
    }
}
