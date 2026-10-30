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
use grpc::__unstable::client::name_resolution::config_selector::DynIntercept;
use grpc::__unstable::client::name_resolution::config_selector::RpcConfig;
use grpc::__unstable::client::name_resolution::config_selector::SelectConfigOptions;
use grpc::StatusCodeError;
use grpc::StatusError;
use grpc::async_trait;
use grpc::client::CallOptions;
use grpc::client::DynInvoke;
use grpc::client::DynRecvStream;
use grpc::client::DynSendStream;
use grpc::client::RequestHeaders;

use super::ClusterRef;
use crate::resource::RouteMatch;
use crate::wrr::RandomWrr;
use crate::wrr::Wrr;

/// The cluster an RPC was routed to. The cluster's [`ClusterInterceptor`]
/// stores an `Arc<PickedCluster>` in the RPC's `CallOptions`, where it tells
/// the cluster manager picker which child to pick from.
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

/// Stores a pick of child `child_name` in `call_options`, as a cluster
/// interceptor would. The pick's `ClusterRef` isn't tracked by any resolver.
#[cfg(test)]
pub(crate) fn set_picked_cluster_for_testing(call_options: &mut CallOptions, child_name: &str) {
    let picked = PickedCluster::new(
        child_name.to_owned(),
        Arc::new(test_utils::untracked_cluster_ref(child_name)),
    );
    call_options.set_option(Arc::new(picked));
}

/// The interceptor for the RPCs routed to a cluster. Stores the cluster's
/// [`PickedCluster`] in each RPC's `CallOptions`.
///
/// A config selector has one per cluster, shared by every route that names
/// the cluster, so the selector holds a ref to each cluster its routes can
/// send RPCs to. Each RPC holds the interceptor of the cluster it was routed
/// to, through its `RpcConfig`, until the channel's `invoke` for the RPC
/// returns, i.e. until the RPC is committed. So an RPC keeps only its own
/// cluster subscribed.
#[derive(Debug)]
pub(super) struct ClusterInterceptor {
    picked: Arc<PickedCluster>,
}

impl ClusterInterceptor {
    pub(super) fn new(child_name: String, cluster_ref: Arc<ClusterRef>) -> Self {
        Self {
            picked: Arc::new(PickedCluster::new(child_name, cluster_ref)),
        }
    }
}

#[async_trait]
impl DynIntercept for ClusterInterceptor {
    async fn dyn_intercept(
        &self,
        headers: RequestHeaders,
        mut options: CallOptions,
        next: Arc<dyn DynInvoke>,
    ) -> (Box<dyn DynSendStream>, Box<dyn DynRecvStream>) {
        options.set_option(self.picked.clone());
        next.dyn_invoke(headers, options).await
    }
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
    Cluster(Arc<ClusterInterceptor>),
    WeightedClusters(RandomWrr<Arc<ClusterInterceptor>>),
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
        let cluster = match &route.target {
            RouteTarget::Cluster(cluster) => cluster,
            RouteTarget::WeightedClusters(clusters) => clusters.next().ok_or_else(|| {
                StatusError::new(
                    StatusCodeError::Internal,
                    "route has no cluster with a non-zero weight",
                )
            })?,
        };
        Ok(RpcConfig::default().with_interceptor(cluster.clone()))
    }
}

#[cfg(test)]
pub(super) mod test_utils {
    use std::sync::Mutex;

    use grpc::__unstable::client::name_resolution::WorkScheduler;
    use grpc::client::RecvStream;
    use grpc::client::ResponseStreamItem;
    use grpc::client::SendOptions;
    use grpc::client::SendStream;
    use grpc::core::RecvMessage;
    use grpc::core::SendMessage;
    use grpc::core::StreamEnded;

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

    /// The streams of an RPC that ended without a response.
    struct ClosedStream;

    impl SendStream for ClosedStream {
        async fn send(
            &mut self,
            _msg: &dyn SendMessage,
            _options: SendOptions,
        ) -> Result<(), StreamEnded> {
            Err(StreamEnded)
        }
    }

    impl RecvStream for ClosedStream {
        async fn recv(&mut self, _msg: &mut dyn RecvMessage) -> ResponseStreamItem {
            ResponseStreamItem::StreamClosed
        }
    }

    /// The end of an interceptor chain. Records the child picked for each RPC
    /// that reaches it.
    #[derive(Default)]
    struct RecordingInvoker {
        /// The child picked for each RPC, or `None` if no pick was stored in
        /// the RPC's call options.
        picked_children: Mutex<Vec<Option<String>>>,
    }

    #[async_trait]
    impl DynInvoke for RecordingInvoker {
        async fn dyn_invoke(
            &self,
            _headers: RequestHeaders,
            options: CallOptions,
        ) -> (Box<dyn DynSendStream>, Box<dyn DynRecvStream>) {
            self.picked_children
                .lock()
                .unwrap()
                .push(picked_child_name(&options).map(str::to_owned));
            (Box::new(ClosedStream), Box::new(ClosedStream))
        }
    }

    /// Starts an RPC with `headers` as a channel would: selects its config
    /// with `selector` and runs it through the config's interceptor. Returns
    /// the cluster manager child the RPC was routed to, or the status the
    /// selector failed the RPC with.
    pub(in crate::resolver) async fn route_rpc(
        selector: &XdsConfigSelector,
        headers: RequestHeaders,
    ) -> Result<String, StatusError> {
        let config = selector.select_config(SelectConfigOptions::new(&headers))?;
        let interceptor = config
            .interceptor
            .expect("selector should set an interceptor");
        let invoker = Arc::new(RecordingInvoker::default());
        interceptor
            .dyn_intercept(headers, CallOptions::new(), invoker.clone())
            .await;
        let picked_children = invoker.picked_children.lock().unwrap().clone();
        match picked_children.as_slice() {
            [Some(child)] => Ok(child.clone()),
            other => panic!("expected the RPC to reach the invoker with a pick, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use grpc::metadata::MetadataMap;

    use super::test_utils::route_rpc;
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

    /// Returns the interceptor for cluster `name`, as the resolver would
    /// create it.
    fn cluster(name: &str) -> Arc<ClusterInterceptor> {
        Arc::new(ClusterInterceptor::new(
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

    /// Returns the headers of an RPC to `METHOD` with `metadata`.
    fn headers(metadata: MetadataMap) -> RequestHeaders {
        RequestHeaders::new()
            .with_method_name(METHOD)
            .with_metadata(metadata)
    }

    /// Selects the config for an RPC to `METHOD` without metadata.
    fn select(selector: &XdsConfigSelector) -> Result<RpcConfig, StatusError> {
        selector.select_config(SelectConfigOptions::new(&headers(MetadataMap::new())))
    }

    /// Returns the child picked for an RPC to `METHOD` without metadata.
    /// Panics if the selector fails the RPC.
    async fn picked_child(selector: &XdsConfigSelector) -> String {
        route_rpc(selector, headers(MetadataMap::new()))
            .await
            .expect("selector should pick a cluster")
    }

    #[tokio::test]
    async fn first_matching_route_wins() {
        let selector = XdsConfigSelector::new(vec![
            route(prefix_match("/other."), RouteTarget::Cluster(cluster("x"))),
            route(prefix_match("/pkg."), RouteTarget::Cluster(cluster("a"))),
            route(prefix_match(""), RouteTarget::Cluster(cluster("b"))),
        ]);

        assert_eq!(picked_child(&selector).await, "cluster:a");
    }

    #[tokio::test]
    async fn route_matches_on_headers() {
        let mut canary_match = prefix_match("");
        canary_match.headers.push(HeaderMatcher {
            name: "x-env".to_string(),
            match_specifier: HeaderMatchSpecifier::String(StringMatcher::exact("canary", false)),
            invert_match: false,
        });
        let selector = XdsConfigSelector::new(vec![
            route(canary_match, RouteTarget::Cluster(cluster("canary"))),
            route(prefix_match(""), RouteTarget::Cluster(cluster("prod"))),
        ]);

        let mut metadata = MetadataMap::new();
        metadata.insert("x-env", "canary".parse().unwrap());
        assert_eq!(
            route_rpc(&selector, headers(metadata)).await.unwrap(),
            "cluster:canary"
        );

        assert_eq!(picked_child(&selector).await, "cluster:prod");
    }

    #[test]
    fn no_matching_route_fails_unavailable() {
        let selector = XdsConfigSelector::new(vec![route(
            prefix_match("/other."),
            RouteTarget::Cluster(cluster("a")),
        )]);

        let Err(status) = select(&selector) else {
            panic!("selector should fail the RPC");
        };

        assert_eq!(status.code(), StatusCodeError::Unavailable);
        assert_eq!(status.message(), "no matching route found");
    }

    #[tokio::test]
    async fn weighted_clusters_follow_wrr() {
        let clusters = wrr_builder(&[0, 2, 4]).build([(cluster("a"), 2), (cluster("b"), 3)]);
        let selector = XdsConfigSelector::new(vec![route(
            prefix_match(""),
            RouteTarget::WeightedClusters(clusters),
        )]);

        let mut picks = Vec::new();
        for _ in 0..3 {
            picks.push(picked_child(&selector).await);
        }

        assert_eq!(picks, ["cluster:a", "cluster:b", "cluster:b"]);
    }

    #[test]
    fn rpc_holds_only_picked_cluster() {
        let a = cluster("a");
        let b = cluster("b");
        let selector = XdsConfigSelector::new(vec![
            route(prefix_match("/pkg."), RouteTarget::Cluster(a.clone())),
            route(prefix_match(""), RouteTarget::Cluster(b.clone())),
        ]);
        // Each is held by the test and the selector.
        assert_eq!(Arc::strong_count(&a), 2);
        assert_eq!(Arc::strong_count(&b), 2);

        // The channel holds an RPC's config until the RPC's `invoke` returns.
        let rpc1 = select(&selector).unwrap();
        let rpc2 = select(&selector).unwrap();
        assert_eq!(Arc::strong_count(&a), 4);
        assert_eq!(Arc::strong_count(&b), 2);

        drop(selector);
        assert_eq!(Arc::strong_count(&a), 3);
        assert_eq!(Arc::strong_count(&b), 1);
        drop(rpc1);
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
