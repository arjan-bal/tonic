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

use super::GLOBAL_LB_REGISTRY;
use crate::client::load_balancing::LbPolicy;
use crate::client::load_balancing::LbPolicyBuilder;
use crate::client::load_balancing::LbPolicyOptions;
use crate::client::load_balancing::ParsedJsonLbConfig;
use crate::client::service_config::serde_bindings::LbConfigSerde;

pub static POLICY_NAME: &str = "priority_experimental";

#[derive(Debug, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct PriorityConfig {
    // priorities is a list of child balancer names. They are sorted from
    // highest priority to low. The type/config for each child can be found in
    // field Children, with the balancer name as the key.
    #[serde(default)]
    pub priorities: Vec<String>,

    // Children is a map from the child balancer names to their configs. Child
    // names can be found in field Priorities.
    #[serde(default)]
    pub children: HashMap<String, Child>,
}

impl PriorityConfig {
    pub(crate) fn validate(&self) -> Result<(), String> {
        for name in &self.priorities {
            if !self.children.contains_key(name) {
                return Err(format!(
                    "LB policy name \"{name}\" found in Priorities field ({:?}) is not found in Children field ({:?})",
                    self.priorities, self.children
                ));
            }
        }
        for name in self.children.keys() {
            if !self.priorities.contains(name) {
                return Err(format!(
                    "LB policy name \"{name}\" found in Children field ({:?}) is not found in Priorities field ({:?})",
                    self.children, self.priorities
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
struct Builder {}

impl LbPolicyBuilder for Builder {
    type LbPolicy = PiorityPolicy;

    fn build(&self, options: LbPolicyOptions) -> Self::LbPolicy {
        PiorityPolicy {}
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

pub(crate) fn reg() {
    GLOBAL_LB_REGISTRY.add_builder(Builder {})
}

#[derive(Debug)]
struct PiorityPolicy {}

impl LbPolicy for PiorityPolicy {
    type LbConfig = PriorityConfig;

    fn resolver_update(
        &mut self,
        update: crate::client::name_resolution::ResolverUpdate,
        config: Option<&Self::LbConfig>,
        channel_controller: &mut dyn super::ChannelController,
    ) -> Result<(), String> {
        todo!()
    }

    fn subchannel_update(
        &mut self,
        subchannel: std::sync::Arc<dyn super::subchannel::Subchannel>,
        state: &super::subchannel::SubchannelState,
        channel_controller: &mut dyn super::ChannelController,
    ) {
        todo!()
    }

    fn work(
        &mut self,
        data: Option<super::WorkData>,
        channel_controller: &mut dyn super::ChannelController,
    ) {
        todo!()
    }

    fn exit_idle(&mut self, channel_controller: &mut dyn super::ChannelController) {
        todo!()
    }
}

// Child is a child of priority balancer.
#[derive(Debug, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Child {
    #[serde(default)]
    pub ignore_reresolution_requests: bool,
    pub config: LbConfigSerde,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_config_child_not_found() {
        let js = r#"{
  "priorities": ["child-1", "child-2", "child-3"],
  "children": {
    "child-1": {"config": [{"round_robin":{}}]},
    "child-3": {"config": [{"round_robin":{}}]}
  }
}"#;
        let builder = Builder {};
        let got = ParsedJsonLbConfig::new(js).and_then(|cfg| builder.parse_config(&cfg));
        assert!(got.is_err());
    }

    #[test]
    fn parse_config_child_not_used() {
        let js = r#"{
  "priorities": ["child-1", "child-2"],
  "children": {
    "child-1": {"config": [{"round_robin":{}}]},
    "child-2": {"config": [{"round_robin":{}}]},
    "child-3": {"config": [{"round_robin":{}}]}
  }
}"#;
        let builder = Builder {};
        let got = ParsedJsonLbConfig::new(js).and_then(|cfg| builder.parse_config(&cfg));
        assert!(got.is_err());
    }

    #[test]
    fn parse_config_success() {
        let js = r#"{
  "priorities": ["child-1", "child-2", "child-3"],
  "children": {
    "child-1": {"config": [{"round_robin":{}}], "ignoreReresolutionRequests": true},
    "child-2": {"config": [{"pick_first": {"shuffleAddressList": true}}]},
    "child-3": {"config": [{"round_robin":{}}]}
  }
}"#;
        let builder = Builder {};
        let got = ParsedJsonLbConfig::new(js)
            .and_then(|cfg| builder.parse_config(&cfg))
            .unwrap()
            .unwrap();

        assert_eq!(got.priorities, vec!["child-1", "child-2", "child-3"]);
        assert_eq!(got.children.len(), 3);

        let child1 = got.children.get("child-1").unwrap();
        assert!(child1.ignore_reresolution_requests);
        assert_eq!(child1.config.builder.name(), "round_robin");
        assert!(child1.config.config.is_none());

        let child2 = got.children.get("child-2").unwrap();
        assert!(!child2.ignore_reresolution_requests);
        assert_eq!(child2.config.builder.name(), "pick_first");
        let pf_cfg = child2
            .config
            .config
            .as_ref()
            .unwrap()
            .downcast_ref::<crate::client::load_balancing::pick_first::PickFirstConfig>()
            .unwrap();
        assert!(pf_cfg.shuffle_address_list);

        let child3 = got.children.get("child-3").unwrap();
        assert!(!child3.ignore_reresolution_requests);
        assert_eq!(child3.config.builder.name(), "round_robin");
        assert!(child3.config.config.is_none());
    }
}
