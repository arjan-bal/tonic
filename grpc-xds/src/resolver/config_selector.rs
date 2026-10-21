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
use grpc::StatusCodeError;
use grpc::StatusError;
use grpc::client::CallOptions;

use super::ClusterRef;
use crate::resource::RouteMatch;
use crate::wrr::RandomWrr;
use crate::wrr::Wrr;

/// The cluster an RPC was routed to. The config selector stores an
/// `Arc<PickedCluster>` in the RPC's `CallOptions`, where it tells the cluster
/// manager picker which child to pick from, and keeps the cluster subscribed
/// until the channel drops the call options, i.e. until the RPC is committed.
#[derive(Debug)]
pub(super) struct PickedCluster {
    /// Name of the cluster manager child for the cluster ("cluster:<name>").
    child_name: String,
    /// Keeps the cluster subscribed and in the service config while this pick
    /// is alive.
    _cluster_ref: Arc<ClusterRef>,
}

impl PickedCluster {
    pub(super) fn new(child_name: String, cluster_ref: Arc<ClusterRef>) -> Self {
        Self {
            child_name,
            _cluster_ref: cluster_ref,
        }
    }
}

/// Returns the name of the cluster manager child picked for the RPC with
/// `call_options`, or `None` if the config selector didn't pick one.
pub(crate) fn picked_child_name(call_options: &CallOptions) -> Option<&str> {
    call_options
        .get_option::<Arc<PickedCluster>>()
        .map(|picked| picked.child_name.as_str())
}

/// Stores a pick of child `child_name` in `call_options`, as the config
/// selector would. The pick's `ClusterRef` isn't tracked by any resolver.
#[cfg(test)]
pub(crate) fn set_picked_cluster_for_testing(call_options: &mut CallOptions, child_name: &str) {
    let picked = PickedCluster::new(
        child_name.to_owned(),
        Arc::new(test_utils::untracked_cluster_ref(child_name)),
    );
    call_options.set_option(Arc::new(picked));
}

/// Routes each RPC to a cluster using the virtual host's routes (gRFC A28).
#[derive(Debug)]
pub(super) struct XdsConfigSelector {
    /// In the virtual host's order; the first matching route wins.
    routes: Vec<SelectorRoute>,
}

/// A route of an [`XdsConfigSelector`].
#[derive(Debug)]
pub(super) struct SelectorRoute {
    pub(super) route_match: RouteMatch,
    pub(super) target: RouteTarget,
}

/// Where a route sends the RPCs that match it.
#[derive(Debug)]
pub(super) enum RouteTarget {
    Cluster(Arc<PickedCluster>),
    WeightedClusters(RandomWrr<Arc<PickedCluster>>),
    /// RPCs matching the route fail instead of falling through to a later
    /// route.
    Unsupported,
}

impl XdsConfigSelector {
    pub(super) fn new(routes: Vec<SelectorRoute>) -> Self {
        Self { routes }
    }

    /// Returns this selector's routes.
    #[cfg(test)]
    pub(super) fn routes(&self) -> &[SelectorRoute] {
        &self.routes
    }
}

impl ConfigSelector for XdsConfigSelector {
    fn select_config(&self, options: SelectConfigOptions<'_>) -> Result<RpcConfig, StatusError> {
        let headers = options.request_headers;
        let route = self
            .routes
            .iter()
            .find(|route| {
                route
                    .route_match
                    .is_match(headers.method_name(), headers.metadata())
            })
            .ok_or_else(|| {
                StatusError::new(StatusCodeError::Unavailable, "no matching route found")
            })?;
        let picked = match &route.target {
            RouteTarget::Cluster(picked) => picked,
            RouteTarget::WeightedClusters(clusters) => clusters.next().ok_or_else(|| {
                StatusError::new(
                    StatusCodeError::Internal,
                    "route has no cluster with a non-zero weight",
                )
            })?,
            RouteTarget::Unsupported => {
                return Err(StatusError::new(
                    StatusCodeError::Unavailable,
                    "matched route does not have a supported route action",
                ));
            }
        };
        options.call_options.set_option(picked.clone());
        Ok(RpcConfig::default())
    }
}

#[cfg(test)]
pub(super) mod test_utils {
    use grpc::__unstable::client::name_resolution::WorkScheduler;

    use super::*;
    use crate::resolver::mocks::DependencyManager;

    /// A work scheduler that ignores requests.
    struct NopWorkScheduler;

    impl WorkScheduler for NopWorkScheduler {
        fn schedule_work(&self) {}
    }

    /// Returns a ref to cluster `name` that no resolver tracks. Its
    /// subscription is to a throwaway mock dependency manager.
    pub(in crate::resolver) fn untracked_cluster_ref(name: &str) -> ClusterRef {
        let (dependency_manager, _updates_tx) = DependencyManager::new();
        ClusterRef {
            name: name.to_owned(),
            _subscription: dependency_manager.subscribe_to_cluster(name),
            work_scheduler: Arc::new(NopWorkScheduler),
        }
    }
}

#[cfg(test)]
mod tests {
    use grpc::client::RequestHeaders;
    use grpc::metadata::MetadataMap;

    use super::test_utils::untracked_cluster_ref;
    use super::*;
    use crate::resolver::service_config::cluster_child_name;
    use crate::resource::HeaderMatchSpecifier;
    use crate::resource::HeaderMatcher;
    use crate::resource::PathSpecifier;
    use crate::resource::StringMatcher;
    use crate::wrr::WrrBuilder;
    use crate::wrr::test_utils::wrr_builder;

    const METHOD: &str = "/pkg.Service/Method";

    /// Returns a pick of cluster `name`, as the resolver would create it.
    fn picked(name: &str) -> Arc<PickedCluster> {
        Arc::new(PickedCluster::new(
            cluster_child_name(name),
            Arc::new(untracked_cluster_ref(name)),
        ))
    }

    /// Returns a route match for paths starting with `prefix`.
    fn prefix_match(prefix: &str) -> RouteMatch {
        RouteMatch {
            path_specifier: PathSpecifier::Prefix(prefix.to_string()),
            headers: Vec::new(),
            case_sensitive: true,
            match_fraction: None,
        }
    }

    fn route(route_match: RouteMatch, target: RouteTarget) -> SelectorRoute {
        SelectorRoute {
            route_match,
            target,
        }
    }

    /// Runs `selector` for an RPC to `METHOD` with `metadata`. Returns the
    /// result and the RPC's call options.
    fn select(
        selector: &XdsConfigSelector,
        metadata: MetadataMap,
    ) -> (Result<RpcConfig, StatusError>, CallOptions) {
        let headers = RequestHeaders::new()
            .with_method_name(METHOD)
            .with_metadata(metadata);
        let mut call_options = CallOptions::new();
        let result = selector.select_config(SelectConfigOptions::new(&headers, &mut call_options));
        (result, call_options)
    }

    /// Returns the child picked for an RPC to `METHOD` without metadata.
    /// Panics if the selector fails the RPC.
    fn picked_child(selector: &XdsConfigSelector) -> String {
        let (result, call_options) = select(selector, MetadataMap::new());
        result.expect("selector should pick a cluster");
        picked_child_name(&call_options)
            .expect("selector should set a picked cluster")
            .to_string()
    }

    #[test]
    fn first_matching_route_wins() {
        let selector = XdsConfigSelector::new(vec![
            route(prefix_match("/other."), RouteTarget::Cluster(picked("x"))),
            route(prefix_match("/pkg."), RouteTarget::Cluster(picked("a"))),
            route(prefix_match(""), RouteTarget::Cluster(picked("b"))),
        ]);

        assert_eq!(picked_child(&selector), "cluster:a");
    }

    #[test]
    fn route_matches_on_headers() {
        let mut canary_match = prefix_match("");
        canary_match.headers.push(HeaderMatcher {
            name: "x-env".to_string(),
            match_specifier: HeaderMatchSpecifier::String(StringMatcher::exact("canary", false)),
            invert_match: false,
        });
        let selector = XdsConfigSelector::new(vec![
            route(canary_match, RouteTarget::Cluster(picked("canary"))),
            route(prefix_match(""), RouteTarget::Cluster(picked("prod"))),
        ]);

        let mut metadata = MetadataMap::new();
        metadata.insert("x-env", "canary".parse().unwrap());
        let (result, call_options) = select(&selector, metadata);
        assert!(result.is_ok());
        assert_eq!(picked_child_name(&call_options), Some("cluster:canary"));

        assert_eq!(picked_child(&selector), "cluster:prod");
    }

    #[test]
    fn no_matching_route_fails_unavailable() {
        let selector = XdsConfigSelector::new(vec![route(
            prefix_match("/other."),
            RouteTarget::Cluster(picked("a")),
        )]);

        let (result, call_options) = select(&selector, MetadataMap::new());

        let status = result.unwrap_err();
        assert_eq!(status.code(), StatusCodeError::Unavailable);
        assert_eq!(status.message(), "no matching route found");
        assert_eq!(picked_child_name(&call_options), None);
    }

    #[test]
    fn unsupported_action_fails_unavailable() {
        let selector = XdsConfigSelector::new(vec![
            route(prefix_match("/pkg."), RouteTarget::Unsupported),
            route(prefix_match(""), RouteTarget::Cluster(picked("a"))),
        ]);

        let (result, call_options) = select(&selector, MetadataMap::new());

        let status = result.unwrap_err();
        assert_eq!(status.code(), StatusCodeError::Unavailable);
        assert_eq!(
            status.message(),
            "matched route does not have a supported route action"
        );
        assert_eq!(picked_child_name(&call_options), None);
    }

    #[test]
    fn weighted_clusters_follow_wrr() {
        let clusters = wrr_builder(&[0, 2, 4]).build([(picked("a"), 2), (picked("b"), 3)]);
        let selector = XdsConfigSelector::new(vec![route(
            prefix_match(""),
            RouteTarget::WeightedClusters(clusters),
        )]);

        let picks: Vec<String> = (0..3).map(|_| picked_child(&selector)).collect();

        assert_eq!(picks, ["cluster:a", "cluster:b", "cluster:b"]);
    }

    #[test]
    fn rpc_holds_picked_cluster_until_options_dropped() {
        let a = picked("a");
        let selector = XdsConfigSelector::new(vec![route(
            prefix_match(""),
            RouteTarget::Cluster(a.clone()),
        )]);
        // Held by `a` and the selector.
        assert_eq!(Arc::strong_count(&a), 2);

        let (_, rpc1) = select(&selector, MetadataMap::new());
        let (_, rpc2) = select(&selector, MetadataMap::new());
        assert_eq!(Arc::strong_count(&a), 4);

        drop(rpc1);
        assert_eq!(Arc::strong_count(&a), 3);
        drop(selector);
        drop(rpc2);
        assert_eq!(Arc::strong_count(&a), 1);
    }

    #[test]
    fn picked_child_name_is_none_without_pick() {
        assert_eq!(picked_child_name(&CallOptions::new()), None);
    }

    #[test]
    fn set_picked_cluster_for_testing_sets_child_name() {
        let mut call_options = CallOptions::new();
        set_picked_cluster_for_testing(&mut call_options, "cluster:a");
        assert_eq!(picked_child_name(&call_options), Some("cluster:a"));
    }
}
