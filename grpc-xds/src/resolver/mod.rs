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
use std::fmt;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::Weak;

use grpc::__unstable::client::name_resolution::ChannelController;
use grpc::__unstable::client::name_resolution::Resolver;
use grpc::__unstable::client::name_resolution::ResolverBuilder;
use grpc::__unstable::client::name_resolution::ResolverOptions;
use grpc::__unstable::client::name_resolution::ResolverUpdate;
use grpc::__unstable::client::name_resolution::Target;
use grpc::__unstable::client::name_resolution::WorkScheduler;
use grpc::__unstable::client::name_resolution::config_selector::set_in_resolver_update;
use grpc::__unstable::rt::BoxedTaskHandle;

use crate::resolver::config_selector::PickedCluster;
use crate::resolver::config_selector::RouteTarget;
use crate::resolver::config_selector::SelectorRoute;
use crate::resolver::config_selector::XdsConfigSelector;
use crate::resolver::mocks::ClusterSubscription;
use crate::resolver::mocks::DependencyManager;
use crate::resolver::mocks::XdsClientProvider;
use crate::resolver::mocks::XdsClientWrapper;
use crate::resolver::mocks::XdsConfigResult;
use crate::resolver::mocks::XdsConfigWatcher;
use crate::resolver::nop_resolver::NopResolver;
use crate::resolver::service_config::cds_cluster_manager_service_config;
use crate::resolver::service_config::cluster_child_name;
use crate::resource::RouteAction;
use crate::wrr::RandomWrrBuilder;
use crate::wrr::WrrBuilder;
use crate::xds_config::XdsConfig;

mod config_selector;
mod mocks;
mod nop_resolver;
mod service_config;

pub(crate) use config_selector::picked_child_name;
#[cfg(test)]
pub(crate) use config_selector::set_picked_cluster_for_testing;

// TODO: register this builder in the global resolver registry, in the same
// place that calls `load_balancing::register()` for the LB policies named in
// the resolver's service config.
struct Builder {
    xds_client_provider: Arc<dyn XdsClientProvider>,
}

impl ResolverBuilder for Builder {
    fn build(&self, target: &Target, options: ResolverOptions) -> Box<dyn Resolver> {
        let lds_resource_name = match listener_resource_name(target) {
            Ok(name) => name.to_owned(),
            Err(err) => return NopResolver::new_with_err(err, options),
        };
        let xds_client = match self.xds_client_provider.get_or_create(&target.to_string()) {
            Ok(client) => client,
            Err(err) => {
                return NopResolver::new_with_err(
                    format!("xds: failed to create xds-client: {err}"),
                    options,
                );
            }
        };
        // TODO: create the DependencyManager and XdsResolver using
        // `xds_client` and `lds_resource_name`.
        let _ = (xds_client, lds_resource_name);
        todo!()
    }

    fn scheme(&self) -> &str {
        "xds"
    }

    fn is_valid_uri(&self, uri: &Target) -> bool {
        match listener_resource_name(uri) {
            Ok(_) => true,
            Err(err) => {
                eprintln!("{err}");
                false
            }
        }
    }
}

/// Returns the name of the Listener resource to watch for `target`: the
/// target path without its leading "/" (gRFC A27). The target's authority is
/// ignored.
fn listener_resource_name(target: &Target) -> Result<&str, String> {
    let path = target.path();
    let name = path.strip_prefix('/').unwrap_or(path);
    if name.is_empty() || name.ends_with('/') {
        return Err(format!(
            "xds: target {target} path does not contain a valid data plane authority"
        ));
    }
    Ok(name)
}

struct XdsResolver {
    xds_client: Arc<XdsClientWrapper>,
    dependency_manager: DependencyManager,
    /// Clusters that must stay in the LB policy config, keyed by cluster name.
    /// Weak, so the map doesn't keep clusters in use. An entry lives until its
    /// last `ClusterRef` is dropped and `work()` prunes it.
    active_clusters: HashMap<String, Weak<ClusterRef>>,
    lds_resource_name: String,
    /// The dependency manager's latest update that `work()` hasn't applied
    /// yet. Written by `update_task`; `work()` takes it.
    xds_config: Arc<Mutex<Option<XdsConfigResult>>>,
    /// The config selector for the latest `XdsConfig`. `None` before the
    /// first one arrives and after an error.
    current_config_selector: Option<Arc<XdsConfigSelector>>,
    /// Builds the weighted cluster pickers of new config selectors.
    wrr_builder: RandomWrrBuilder,
    /// Given to each `ClusterRef`, so that dropping the last ref for a cluster
    /// schedules a call to `work()`.
    work_scheduler: Arc<dyn WorkScheduler>,
    /// Task that polls the dependency manager for `XdsConfig` updates.
    /// Aborted when the resolver is dropped.
    update_task: BoxedTaskHandle,
}

impl XdsResolver {
    /// Creates the resolver and starts watching `dependency_manager` for
    /// `XdsConfig` updates.
    ///
    /// TODO: call from `Builder::build`.
    fn new(
        xds_client: Arc<XdsClientWrapper>,
        mut dependency_manager: DependencyManager,
        lds_resource_name: String,
        options: ResolverOptions,
    ) -> Self {
        let xds_config = Arc::new(Mutex::new(None));
        let update_task = options.runtime.spawn(Box::pin(watch_xds_config(
            dependency_manager.watch(),
            xds_config.clone(),
            options.work_scheduler.clone(),
        )));
        Self {
            xds_client,
            dependency_manager,
            active_clusters: HashMap::new(),
            lds_resource_name,
            xds_config,
            current_config_selector: None,
            wrr_builder: RandomWrrBuilder::default(),
            work_scheduler: options.work_scheduler,
            update_task,
        }
    }

    /// Returns a ref to cluster `name`, subscribing to the cluster if no live
    /// ref exists.
    fn get_or_create_cluster_ref(&mut self, name: &str) -> Arc<ClusterRef> {
        if let Some(cluster_ref) = self.active_clusters.get(name).and_then(Weak::upgrade) {
            return cluster_ref;
        }
        // Either the cluster is new, or its last ref was dropped (which
        // unsubscribed) and `work()` hasn't pruned it yet. Start a new ref,
        // replacing any dead entry.
        let cluster_ref = Arc::new(ClusterRef {
            name: name.to_owned(),
            _subscription: self.dependency_manager.subscribe_to_cluster(name),
            work_scheduler: self.work_scheduler.clone(),
        });
        self.active_clusters
            .insert(name.to_owned(), Arc::downgrade(&cluster_ref));
        cluster_ref
    }

    /// Returns a config selector for `xds_config`'s routes. It holds one ref
    /// to each cluster the routes can send RPCs to.
    fn new_config_selector(&mut self, xds_config: &XdsConfig) -> Arc<XdsConfigSelector> {
        // One pick per cluster, shared by every route that names it.
        let mut picks = HashMap::new();
        let mut routes = Vec::new();
        for route in &xds_config.virtual_host().routes {
            let target = match &route.action {
                RouteAction::Cluster(name) => {
                    RouteTarget::Cluster(self.picked_cluster(&mut picks, name))
                }
                RouteAction::WeightedClusters(clusters) => {
                    let clusters: Vec<_> = clusters
                        .iter()
                        .map(|c| (self.picked_cluster(&mut picks, &c.name), c.weight))
                        .collect();
                    RouteTarget::WeightedClusters(self.wrr_builder.build(clusters))
                }
            };
            routes.push(SelectorRoute {
                route_match: route.route_match.clone(),
                target,
            });
        }
        Arc::new(XdsConfigSelector::new(routes))
    }

    /// Returns the pick of cluster `name` from `picks`, creating it, and
    /// subscribing to the cluster if needed, if it isn't there yet.
    fn picked_cluster<'a>(
        &mut self,
        picks: &mut HashMap<&'a str, Arc<PickedCluster>>,
        name: &'a str,
    ) -> Arc<PickedCluster> {
        if let Some(picked) = picks.get(name) {
            return picked.clone();
        }
        let picked = Arc::new(PickedCluster::new(
            cluster_child_name(name),
            self.get_or_create_cluster_ref(name),
        ));
        picks.insert(name, picked.clone());
        picked
    }

    /// Removes the clusters whose last `ClusterRef` was dropped. Returns
    /// whether any cluster was removed.
    fn remove_unused_clusters(&mut self) -> bool {
        let num_clusters = self.active_clusters.len();
        // Dropping a dead `Weak` never runs `ClusterRef::drop`; that already
        // happened when its last ref was dropped.
        self.active_clusters
            .retain(|_, cluster_ref| cluster_ref.strong_count() > 0);
        self.active_clusters.len() != num_clusters
    }

    /// Sends the channel a service config for the active clusters, along with
    /// the current config selector. Does nothing without a current config
    /// selector, i.e. before the first `XdsConfig` and after an error.
    fn update_channel(&self, channel_controller: &mut dyn ChannelController) {
        let Some(config_selector) = &self.current_config_selector else {
            return;
        };
        let mut update = ResolverUpdate::default();
        update.service_config = channel_controller
            .parse_service_config(&self.service_config_json())
            .map(Some);
        // The channel falls back to its default config selector for updates
        // without one, so every update must carry the current selector.
        let update = set_in_resolver_update(config_selector.clone(), update);
        // The result is ignored: the channel applies the update, including its
        // config selector, even if the LB policy rejects it, and LB policies
        // request re-resolution themselves, which calls `resolve_now`.
        let _ = channel_controller.update(update);
    }

    /// Makes the channel stop using the previous xDS resources: the empty
    /// service config selects the default LB policy, which fails RPCs because
    /// there are no endpoints, adding `error` (the resolution note) to their
    /// status. The update carries no config selector, so the channel goes back
    /// to its default one and drops the previous selector, which releases its
    /// clusters.
    fn report_error(&self, channel_controller: &mut dyn ChannelController, error: String) {
        let mut update = ResolverUpdate::default();
        update.service_config = channel_controller.parse_service_config("{}").map(Some);
        update.resolution_note = Some(error);
        // See `update_channel` for why the result is ignored.
        let _ = channel_controller.update(update);
    }

    /// Returns the service config for the active clusters. See
    /// [`cds_cluster_manager_service_config`].
    fn service_config_json(&self) -> String {
        cds_cluster_manager_service_config(self.active_clusters.keys().map(String::as_str))
    }
}

/// Stores every update from `watcher` in `xds_config` and asks the channel to
/// call the resolver's `work()` method. Returns when the dependency manager
/// shuts down.
async fn watch_xds_config(
    mut watcher: XdsConfigWatcher,
    xds_config: Arc<Mutex<Option<XdsConfigResult>>>,
    work_scheduler: Arc<dyn WorkScheduler>,
) {
    while let Some(update) = watcher.next().await {
        // The guard is dropped at the end of this statement, so the lock isn't
        // held while scheduling work or across an await.
        *xds_config.lock().unwrap() = Some(update);
        work_scheduler.schedule_work();
    }
}

impl Resolver for XdsResolver {
    fn resolve_now(&mut self) {
        self.dependency_manager.request_reresolution();
    }

    fn work(&mut self, channel_controller: &mut dyn ChannelController) {
        let pending = self.xds_config.lock().unwrap().take();
        let new_config = match pending {
            Some(Ok(xds_config)) => {
                // Build the new selector before dropping the old one, so that
                // clusters used by both keep their refs instead of being
                // unsubscribed and subscribed again.
                self.current_config_selector = Some(self.new_config_selector(&xds_config));
                true
            }
            Some(Err(error)) => {
                // Stop using the previous resources (gRFC A74).
                self.current_config_selector = None;
                self.remove_unused_clusters();
                self.report_error(channel_controller, error);
                return;
            }
            None => false,
        };
        // Prune after replacing the selector and before building the update,
        // so that the update doesn't name a cluster the dependency manager may
        // have stopped watching. The channel still holds the previous
        // selector, so its clusters stay in the service config until the
        // channel drops it (gRFC A31).
        let removed = self.remove_unused_clusters();
        if new_config || removed {
            self.update_channel(channel_controller);
        }
    }
}

impl Drop for XdsResolver {
    fn drop(&mut self) {
        self.update_task.abort();
    }
}

/// A reference to a cluster that a config selector or an RPC may route to.
/// While any `ClusterRef` for a cluster is alive, the cluster stays in the
/// resolver's service config and the dependency manager stays subscribed to
/// it. Config selectors hold refs through their routes' `PickedCluster`s, and
/// each RPC holds one through the `PickedCluster` the selector stores in its
/// `CallOptions`, until the RPC is committed.
struct ClusterRef {
    name: String,
    /// Keeps the dependency manager subscribed to the cluster. Dropped, which
    /// unsubscribes, together with the last ref.
    _subscription: ClusterSubscription,
    work_scheduler: Arc<dyn WorkScheduler>,
}

impl fmt::Debug for ClusterRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClusterRef")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl Drop for ClusterRef {
    fn drop(&mut self) {
        // This can run on any thread, e.g. when an RPC finishes, so it must not
        // touch the resolver. Ask the channel to call `work()`, which removes
        // the cluster from the service config. The subscription is dropped
        // right after this returns.
        self.work_scheduler.schedule_work();
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::collections::HashMap;
    use std::sync::Arc;

    use grpc::__unstable::client::load_balancing::LbPolicyBuilder;
    use grpc::__unstable::client::load_balancing::ParsedLbConfig;
    use grpc::__unstable::client::name_resolution::ResolverBuilder;
    use grpc::__unstable::client::name_resolution::Target;
    use grpc::__unstable::client::name_resolution::config_selector::ConfigSelector;
    use grpc::__unstable::client::name_resolution::config_selector::SelectConfigOptions;
    use grpc::__unstable::client::service_config::ParseResult;
    use grpc::__unstable::rt::TaskHandle;
    use grpc::attributes::Attributes;
    use grpc::client::CallOptions;
    use grpc::client::RequestHeaders;
    use serde_json::json;
    use tokio::sync::mpsc;

    use super::*;
    use crate::resource::DomainMatcher;
    use crate::resource::ListenerResource;
    use crate::resource::PathSpecifier;
    use crate::resource::Route;
    use crate::resource::RouteConfigResource;
    use crate::resource::RouteMatch;
    use crate::resource::RouteSource;
    use crate::resource::VirtualHost;
    use crate::resource::WeightedCluster;
    use crate::wrr::test_utils::wrr_builder;
    use crate::xds_config::XdsConfig;

    /// Fails every attempt to create an xDS client.
    struct FailingXdsClientProvider;

    impl XdsClientProvider for FailingXdsClientProvider {
        fn get_or_create(&self, _name: &str) -> Result<Arc<XdsClientWrapper>, String> {
            Err("xds client must not be created".to_string())
        }
    }

    fn target(s: &str) -> Target {
        s.parse().unwrap()
    }

    fn builder() -> Builder {
        Builder {
            xds_client_provider: Arc::new(FailingXdsClientProvider),
        }
    }

    #[test]
    fn is_valid_uri_accepts_valid_targets() {
        let builder = builder();
        // No xDS client is needed, so the provider's error is never seen.
        assert!(builder.is_valid_uri(&target("xds:///foo")));
        assert!(builder.is_valid_uri(&target("xds://auth/foo")));
        assert!(builder.is_valid_uri(&target("xds:///foo/bar")));
    }

    #[test]
    fn is_valid_uri_rejects_empty_endpoint() {
        assert!(!builder().is_valid_uri(&target("xds:///")));
    }

    #[test]
    fn is_valid_uri_rejects_trailing_slash() {
        assert!(!builder().is_valid_uri(&target("xds:///foo/")));
    }

    #[test]
    fn listener_resource_name_is_target_path() {
        let cases = [
            // (target, want)
            ("xds:///foo.example.com", "foo.example.com"),
            ("xds:///foo.example.com:8080", "foo.example.com:8080"),
            ("xds:///foo/bar", "foo/bar"),
            // The authority is ignored.
            ("xds://auth.com/svc", "svc"),
        ];
        for (target_str, want) in cases {
            assert_eq!(
                listener_resource_name(&target(target_str)),
                Ok(want),
                "target: {target_str}"
            );
        }
    }

    #[test]
    fn listener_resource_name_rejects_empty_path() {
        assert!(listener_resource_name(&target("xds:///")).is_err());
    }

    /// Notifies `tx` each time work is scheduled.
    struct TestWorkScheduler {
        tx: mpsc::UnboundedSender<()>,
    }

    impl WorkScheduler for TestWorkScheduler {
        fn schedule_work(&self) {
            let _ = self.tx.send(());
        }
    }

    /// Returns a minimal valid `XdsConfig` for a Listener named "listener".
    fn test_xds_config() -> XdsConfig {
        xds_config_with_routes(Vec::new())
    }

    /// Returns a valid `XdsConfig` whose virtual host has one route per
    /// action, each matching every path.
    fn xds_config_with_routes(actions: Vec<RouteAction>) -> XdsConfig {
        let routes = actions
            .into_iter()
            .map(|action| Route {
                route_match: RouteMatch {
                    path_specifier: PathSpecifier::Prefix(String::new()),
                    headers: Vec::new(),
                    case_sensitive: true,
                    match_fraction: None,
                },
                action,
            })
            .collect();
        let route_config = Arc::new(RouteConfigResource {
            name: "routes".to_string(),
            virtual_hosts: vec![VirtualHost {
                name: "vhost".to_string(),
                domains: vec![DomainMatcher::Universal],
                routes,
            }],
        });
        let listener = Arc::new(ListenerResource {
            name: "listener".to_string(),
            route_source: RouteSource::Inline(route_config.clone()),
        });
        XdsConfig::try_new(listener, route_config, 0, HashMap::new()).expect("valid XdsConfig")
    }

    /// Handles for driving and observing a running `watch_xds_config` task.
    struct WatchHarness {
        /// Pushes updates to the mock dependency manager's watcher.
        updates_tx: mpsc::UnboundedSender<XdsConfigResult>,
        /// The state the task writes updates into.
        xds_config: Arc<Mutex<Option<XdsConfigResult>>>,
        /// Receives one message per `schedule_work()` call.
        work_rx: mpsc::UnboundedReceiver<()>,
        task: tokio::task::JoinHandle<()>,
    }

    impl WatchHarness {
        /// Waits until the task calls `schedule_work()`.
        async fn wait_for_work(&mut self) {
            self.work_rx.recv().await.expect("work was not scheduled");
        }
    }

    /// Spawns `watch_xds_config` on the test runtime, watching a new mock
    /// dependency manager.
    fn start_watch() -> WatchHarness {
        let (mut dependency_manager, updates_tx) = DependencyManager::new();
        let (work_tx, work_rx) = mpsc::unbounded_channel();
        let xds_config = Arc::new(Mutex::new(None));
        let task = tokio::spawn(watch_xds_config(
            dependency_manager.watch(),
            xds_config.clone(),
            Arc::new(TestWorkScheduler { tx: work_tx }),
        ));
        WatchHarness {
            updates_tx,
            xds_config,
            work_rx,
            task,
        }
    }

    #[tokio::test]
    async fn xds_config_update_is_stored_and_schedules_work() {
        let mut harness = start_watch();
        harness.updates_tx.send(Ok(test_xds_config())).unwrap();
        harness.wait_for_work().await;

        let stored = harness.xds_config.lock().unwrap();
        match &*stored {
            Some(Ok(config)) => assert_eq!(config.listener.name, "listener"),
            other => panic!("expected a stored Ok config, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn xds_config_error_is_stored_and_schedules_work() {
        let mut harness = start_watch();
        harness.updates_tx.send(Err("boom".to_string())).unwrap();
        harness.wait_for_work().await;

        let stored = harness.xds_config.lock().unwrap();
        assert!(
            matches!(&*stored, Some(Err(err)) if err == "boom"),
            "expected a stored error, got {stored:?}"
        );
    }

    #[tokio::test]
    async fn later_update_replaces_earlier_one() {
        let mut harness = start_watch();
        harness.updates_tx.send(Ok(test_xds_config())).unwrap();
        harness.updates_tx.send(Err("second".to_string())).unwrap();
        harness.wait_for_work().await;
        harness.wait_for_work().await;

        let stored = harness.xds_config.lock().unwrap();
        assert!(
            matches!(&*stored, Some(Err(err)) if err == "second"),
            "expected the later update, got {stored:?}"
        );
    }

    #[tokio::test]
    async fn watch_task_exits_when_dependency_manager_shuts_down() {
        let WatchHarness {
            updates_tx,
            xds_config,
            mut work_rx,
            task,
        } = start_watch();
        drop(updates_tx);
        task.await.expect("task should exit cleanly");

        assert!(xds_config.lock().unwrap().is_none());
        assert!(work_rx.try_recv().is_err(), "no work should be scheduled");
    }

    #[test]
    #[should_panic(expected = "called more than once")]
    fn dependency_manager_watch_twice_panics() {
        let (mut dependency_manager, _updates_tx) = DependencyManager::new();
        let _watcher = dependency_manager.watch();
        let _ = dependency_manager.watch();
    }

    /// A task handle for resolvers built without an update task.
    struct NoopTaskHandle;

    impl TaskHandle for NoopTaskHandle {
        fn abort(&self) {}
    }

    /// Records the service configs the resolver asks it to parse, and counts
    /// the updates it receives.
    #[derive(Default)]
    struct FakeChannelController {
        service_configs: Mutex<Vec<String>>,
        updates: usize,
        /// The most recent update. Like a channel, this keeps the update's
        /// config selector, and so its clusters, alive until the next update
        /// replaces it.
        last_update: Option<ResolverUpdate>,
    }

    impl FakeChannelController {
        /// Returns the service configs passed to `parse_service_config`, as
        /// JSON values.
        fn service_configs(&self) -> Vec<serde_json::Value> {
            self.service_configs
                .lock()
                .unwrap()
                .iter()
                .map(|config| serde_json::from_str(config).unwrap())
                .collect()
        }
    }

    impl ChannelController for FakeChannelController {
        fn update(&mut self, update: ResolverUpdate) -> Result<(), String> {
            self.updates += 1;
            self.last_update = Some(update);
            Ok(())
        }

        fn parse_service_config(&self, config: &str) -> ParseResult {
            self.service_configs
                .lock()
                .unwrap()
                .push(config.to_string());
            // `ServiceConfig` can't be constructed outside of grpc.
            Err("not supported by FakeChannelController".to_string())
        }
    }

    /// Returns a resolver without an update task, and a receiver that gets a
    /// message each time the resolver's work is scheduled.
    ///
    /// Builds the struct directly, since `XdsResolver::new` needs a
    /// `ResolverOptions`, which tests can't create.
    fn test_resolver() -> (XdsResolver, mpsc::UnboundedReceiver<()>) {
        let (dependency_manager, _updates_tx) = DependencyManager::new();
        let (work_tx, work_rx) = mpsc::unbounded_channel();
        let resolver = XdsResolver {
            xds_client: Arc::new(XdsClientWrapper),
            dependency_manager,
            active_clusters: HashMap::new(),
            lds_resource_name: "listener".to_string(),
            xds_config: Arc::new(Mutex::new(None)),
            current_config_selector: None,
            wrr_builder: RandomWrrBuilder::default(),
            work_scheduler: Arc::new(TestWorkScheduler { tx: work_tx }),
            update_task: Box::new(NoopTaskHandle),
        };
        (resolver, work_rx)
    }

    /// Returns an `XdsConfig` with one route per cluster in `clusters`, in
    /// order, each matching every path. RPCs therefore go to the first
    /// cluster.
    fn config_for_clusters(clusters: &[&str]) -> XdsConfig {
        let actions = clusters
            .iter()
            .map(|name| RouteAction::Cluster(name.to_string()))
            .collect();
        xds_config_with_routes(actions)
    }

    /// Returns a config selector from `resolver` for
    /// [`config_for_clusters`]`(clusters)`.
    fn selector_for_clusters(
        resolver: &mut XdsResolver,
        clusters: &[&str],
    ) -> Arc<XdsConfigSelector> {
        resolver.new_config_selector(&config_for_clusters(clusters))
    }

    /// Delivers `result` to `resolver` as the update task would, and runs
    /// `work()`.
    fn apply_result(
        resolver: &mut XdsResolver,
        controller: &mut FakeChannelController,
        result: XdsConfigResult,
    ) {
        *resolver.xds_config.lock().unwrap() = Some(result);
        resolver.work(controller);
    }

    /// Returns the resolver's current config selector. Panics if it has none.
    fn current_selector(resolver: &XdsResolver) -> &XdsConfigSelector {
        resolver
            .current_config_selector
            .as_deref()
            .expect("resolver should have a config selector")
    }

    /// Runs `selector` for an RPC and returns the RPC's call options. Panics
    /// if the selector fails the RPC.
    fn select(selector: &XdsConfigSelector) -> CallOptions {
        let headers = RequestHeaders::new().with_method_name("/pkg.Service/Method");
        let mut call_options = CallOptions::new();
        selector
            .select_config(SelectConfigOptions::new(&headers, &mut call_options))
            .expect("selector should pick a cluster");
        call_options
    }

    /// Returns how many times work was scheduled since the last call.
    fn scheduled_work(work_rx: &mut mpsc::UnboundedReceiver<()>) -> usize {
        let mut count = 0;
        while work_rx.try_recv().is_ok() {
            count += 1;
        }
        count
    }

    /// Returns the names of the resolver's active clusters, sorted.
    fn active_clusters(resolver: &XdsResolver) -> Vec<&str> {
        let mut names: Vec<&str> = resolver
            .active_clusters
            .keys()
            .map(String::as_str)
            .collect();
        names.sort();
        names
    }

    /// Returns the resolver's live dependency manager subscriptions per
    /// cluster.
    fn subscriptions(resolver: &XdsResolver) -> BTreeMap<String, usize> {
        resolver.dependency_manager.cluster_subscription_counts()
    }

    /// Returns a subscription count map with the given entries.
    fn counts(entries: &[(&str, usize)]) -> BTreeMap<String, usize> {
        entries
            .iter()
            .map(|(name, count)| (name.to_string(), *count))
            .collect()
    }

    /// Returns the service config the resolver should generate for
    /// `clusters`.
    fn expected_service_config(clusters: &[&str]) -> serde_json::Value {
        let children: serde_json::Map<String, serde_json::Value> = clusters
            .iter()
            .map(|name| {
                let child = json!({ "childPolicy": [{ "cds_experimental": { "cluster": name } }] });
                (format!("cluster:{name}"), child)
            })
            .collect();
        json!({
            "loadBalancingConfig": [
                { "xds_cluster_manager_experimental": { "children": children } }
            ]
        })
    }

    #[test]
    fn cluster_ref_is_shared_and_subscribes_once() {
        let (mut resolver, _work_rx) = test_resolver();
        let first = resolver.get_or_create_cluster_ref("a");
        let second = resolver.get_or_create_cluster_ref("a");

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(subscriptions(&resolver), counts(&[("a", 1)]));
    }

    #[test]
    fn dropping_last_cluster_ref_unsubscribes_and_schedules_work() {
        let (mut resolver, mut work_rx) = test_resolver();
        let first = resolver.get_or_create_cluster_ref("a");
        let second = first.clone();

        drop(first);
        assert_eq!(scheduled_work(&mut work_rx), 0);
        assert_eq!(subscriptions(&resolver), counts(&[("a", 1)]));

        drop(second);
        assert_eq!(scheduled_work(&mut work_rx), 1);
        assert_eq!(subscriptions(&resolver), counts(&[]));
    }

    #[test]
    fn work_prunes_unused_clusters() {
        let (mut resolver, mut work_rx) = test_resolver();
        let old_selector = selector_for_clusters(&mut resolver, &["a", "b"]);
        resolver.current_config_selector = Some(selector_for_clusters(&mut resolver, &["a"]));

        drop(old_selector);
        assert_eq!(scheduled_work(&mut work_rx), 1);
        let mut controller = FakeChannelController::default();
        resolver.work(&mut controller);

        assert_eq!(active_clusters(&resolver), ["a"]);
        assert_eq!(subscriptions(&resolver), counts(&[("a", 1)]));
        assert_eq!(controller.updates, 1);
        assert_eq!(
            controller.service_configs(),
            [expected_service_config(&["a"])]
        );
    }

    #[test]
    fn rpc_keeps_cluster_until_committed() {
        let (mut resolver, mut work_rx) = test_resolver();
        let old_selector = selector_for_clusters(&mut resolver, &["b"]);
        resolver.current_config_selector = Some(selector_for_clusters(&mut resolver, &["a"]));
        // An RPC routed to "b" by the old selector that isn't committed yet.
        let rpc_options = select(&old_selector);
        assert_eq!(picked_child_name(&rpc_options), Some("cluster:b"));

        drop(old_selector);
        assert_eq!(scheduled_work(&mut work_rx), 0);
        let mut controller = FakeChannelController::default();
        resolver.work(&mut controller);
        assert_eq!(active_clusters(&resolver), ["a", "b"]);
        assert_eq!(subscriptions(&resolver), counts(&[("a", 1), ("b", 1)]));
        assert_eq!(controller.updates, 0);

        // The channel drops the RPC's call options once it's committed.
        drop(rpc_options);
        assert_eq!(scheduled_work(&mut work_rx), 1);
        assert_eq!(subscriptions(&resolver), counts(&[("a", 1)]));
        resolver.work(&mut controller);
        assert_eq!(active_clusters(&resolver), ["a"]);
        assert_eq!(controller.updates, 1);
        assert_eq!(
            controller.service_configs(),
            [expected_service_config(&["a"])]
        );
    }

    #[test]
    fn work_without_unused_clusters_sends_no_update() {
        let (mut resolver, _work_rx) = test_resolver();
        resolver.current_config_selector = Some(selector_for_clusters(&mut resolver, &["a"]));

        let mut controller = FakeChannelController::default();
        resolver.work(&mut controller);

        assert_eq!(active_clusters(&resolver), ["a"]);
        assert_eq!(controller.updates, 0);
        assert!(controller.service_configs().is_empty());
    }

    #[test]
    fn work_without_config_selector_sends_no_update() {
        let (mut resolver, _work_rx) = test_resolver();
        drop(resolver.get_or_create_cluster_ref("a"));

        let mut controller = FakeChannelController::default();
        resolver.work(&mut controller);

        assert!(active_clusters(&resolver).is_empty());
        assert_eq!(controller.updates, 0);
        assert!(controller.service_configs().is_empty());
    }

    #[test]
    fn cluster_ref_recreated_before_prune_resubscribes() {
        let (mut resolver, mut work_rx) = test_resolver();
        // A current selector, so that removing a cluster would send an update.
        resolver.current_config_selector = Some(Arc::new(XdsConfigSelector::new(Vec::new())));
        drop(resolver.get_or_create_cluster_ref("a"));
        assert_eq!(subscriptions(&resolver), counts(&[]));

        // Reuse "a" before `work()` prunes its dead entry.
        let _cluster_ref = resolver.get_or_create_cluster_ref("a");
        assert_eq!(subscriptions(&resolver), counts(&[("a", 1)]));
        assert_eq!(scheduled_work(&mut work_rx), 1);
        let mut controller = FakeChannelController::default();
        resolver.work(&mut controller);

        assert_eq!(active_clusters(&resolver), ["a"]);
        assert_eq!(controller.updates, 0);
    }

    #[test]
    fn new_config_selector_refs_each_route_cluster_once() {
        let (mut resolver, _work_rx) = test_resolver();
        let config = xds_config_with_routes(vec![
            RouteAction::Cluster("a".to_string()),
            RouteAction::WeightedClusters(vec![
                WeightedCluster {
                    name: "b".to_string(),
                    weight: 1,
                },
                WeightedCluster {
                    name: "c".to_string(),
                    weight: 1,
                },
            ]),
            RouteAction::Cluster("a".to_string()),
        ]);

        let selector = resolver.new_config_selector(&config);

        // Both routes naming "a" share one pick.
        let routes = selector.routes();
        match (&routes[0].target, &routes[2].target) {
            (RouteTarget::Cluster(first), RouteTarget::Cluster(second)) => {
                assert!(Arc::ptr_eq(first, second));
            }
            other => panic!("expected two single-cluster routes, got {other:?}"),
        }
        assert_eq!(
            subscriptions(&resolver),
            counts(&[("a", 1), ("b", 1), ("c", 1)])
        );
    }

    #[test]
    fn new_config_selector_uses_cluster_weights() {
        let (mut resolver, _work_rx) = test_resolver();
        resolver.wrr_builder = wrr_builder(&[0, 1, 3]);
        let config = xds_config_with_routes(vec![RouteAction::WeightedClusters(vec![
            WeightedCluster {
                name: "b".to_string(),
                weight: 1,
            },
            WeightedCluster {
                name: "c".to_string(),
                weight: 3,
            },
        ])]);
        let selector = resolver.new_config_selector(&config);

        let picks: Vec<String> = (0..3)
            .map(|_| picked_child_name(&select(&selector)).unwrap().to_string())
            .collect();

        assert_eq!(picks, ["cluster:b", "cluster:c", "cluster:c"]);
    }

    #[test]
    fn xds_config_sends_selector_and_service_config() {
        let (mut resolver, _work_rx) = test_resolver();
        let mut controller = FakeChannelController::default();
        let config = xds_config_with_routes(vec![
            RouteAction::Cluster("a".to_string()),
            RouteAction::WeightedClusters(vec![
                WeightedCluster {
                    name: "b".to_string(),
                    weight: 1,
                },
                WeightedCluster {
                    name: "c".to_string(),
                    weight: 1,
                },
            ]),
        ]);

        apply_result(&mut resolver, &mut controller, Ok(config));

        assert_eq!(controller.updates, 1);
        assert_eq!(
            controller.service_configs(),
            [expected_service_config(&["a", "b", "c"])]
        );
        let update = controller.last_update.as_ref().unwrap();
        assert_ne!(
            update.attributes,
            Attributes::new(),
            "update should carry the config selector"
        );
        assert_eq!(update.endpoints, Ok(Vec::new()));
        assert_eq!(update.resolution_note, None);
        // The first route matches every RPC.
        let rpc = select(current_selector(&resolver));
        assert_eq!(picked_child_name(&rpc), Some("cluster:a"));
    }

    #[test]
    fn xds_config_is_applied_once() {
        let (mut resolver, _work_rx) = test_resolver();
        let mut controller = FakeChannelController::default();
        apply_result(
            &mut resolver,
            &mut controller,
            Ok(config_for_clusters(&["a"])),
        );

        resolver.work(&mut controller);

        assert_eq!(controller.updates, 1);
    }

    #[test]
    fn new_config_keeps_shared_cluster_ref() {
        let (mut resolver, mut work_rx) = test_resolver();
        let mut controller = FakeChannelController::default();
        apply_result(
            &mut resolver,
            &mut controller,
            Ok(config_for_clusters(&["a", "b"])),
        );
        let a_ref = resolver.active_clusters["a"].clone();

        apply_result(
            &mut resolver,
            &mut controller,
            Ok(config_for_clusters(&["a", "c"])),
        );

        // "a" kept its ref, so its subscription was never dropped.
        assert!(Weak::ptr_eq(&a_ref, &resolver.active_clusters["a"]));
        // The channel held the old selector until this update replaced it, so
        // "b" is still in the update.
        assert_eq!(
            controller.service_configs().last(),
            Some(&expected_service_config(&["a", "b", "c"]))
        );
        // Replacing the old selector released "b".
        assert_eq!(scheduled_work(&mut work_rx), 1);
        resolver.work(&mut controller);
        assert_eq!(controller.updates, 3);
        assert_eq!(
            controller.service_configs().last(),
            Some(&expected_service_config(&["a", "c"]))
        );
        assert_eq!(subscriptions(&resolver), counts(&[("a", 1), ("c", 1)]));
    }

    #[test]
    fn rpc_keeps_old_cluster_across_config_update() {
        let (mut resolver, mut work_rx) = test_resolver();
        let mut controller = FakeChannelController::default();
        apply_result(
            &mut resolver,
            &mut controller,
            Ok(config_for_clusters(&["a"])),
        );
        let rpc = select(current_selector(&resolver));

        apply_result(
            &mut resolver,
            &mut controller,
            Ok(config_for_clusters(&["b"])),
        );

        assert_eq!(
            controller.service_configs().last(),
            Some(&expected_service_config(&["a", "b"]))
        );
        // The channel dropped the old selector, but the RPC still holds "a".
        assert_eq!(scheduled_work(&mut work_rx), 0);
        resolver.work(&mut controller);
        assert_eq!(controller.updates, 2);

        // The channel drops the RPC's call options once it's committed.
        drop(rpc);
        assert_eq!(scheduled_work(&mut work_rx), 1);
        resolver.work(&mut controller);
        assert_eq!(controller.updates, 3);
        assert_eq!(
            controller.service_configs().last(),
            Some(&expected_service_config(&["b"]))
        );
        assert_eq!(subscriptions(&resolver), counts(&[("b", 1)]));
    }

    #[test]
    fn xds_config_error_reports_resolution_note() {
        let (mut resolver, mut work_rx) = test_resolver();
        let mut controller = FakeChannelController::default();
        apply_result(
            &mut resolver,
            &mut controller,
            Ok(config_for_clusters(&["a"])),
        );

        apply_result(&mut resolver, &mut controller, Err("boom".to_string()));

        assert_eq!(controller.updates, 2);
        let update = controller.last_update.as_ref().unwrap();
        assert_eq!(update.endpoints, Ok(Vec::new()));
        assert_eq!(update.resolution_note.as_deref(), Some("boom"));
        assert_eq!(
            update.attributes,
            Attributes::new(),
            "update should not carry a config selector"
        );
        assert_eq!(controller.service_configs().last(), Some(&json!({})));
        assert!(resolver.current_config_selector.is_none());
        // Replacing the channel's selector released "a".
        assert_eq!(subscriptions(&resolver), counts(&[]));
        assert_eq!(scheduled_work(&mut work_rx), 1);
        resolver.work(&mut controller);
        assert!(active_clusters(&resolver).is_empty());
        assert_eq!(controller.updates, 2);
    }

    #[test]
    fn error_before_first_config_is_reported() {
        let (mut resolver, _work_rx) = test_resolver();
        let mut controller = FakeChannelController::default();

        apply_result(&mut resolver, &mut controller, Err("boom".to_string()));

        assert_eq!(controller.updates, 1);
        let update = controller.last_update.as_ref().unwrap();
        assert_eq!(update.endpoints, Ok(Vec::new()));
        assert_eq!(update.resolution_note.as_deref(), Some("boom"));
        assert_eq!(update.attributes, Attributes::new());
        assert_eq!(controller.service_configs(), [json!({})]);
    }

    #[test]
    fn no_update_when_clusters_released_after_error() {
        let (mut resolver, mut work_rx) = test_resolver();
        let mut controller = FakeChannelController::default();
        apply_result(
            &mut resolver,
            &mut controller,
            Ok(config_for_clusters(&["a"])),
        );
        let rpc = select(current_selector(&resolver));
        apply_result(&mut resolver, &mut controller, Err("boom".to_string()));
        assert_eq!(subscriptions(&resolver), counts(&[("a", 1)]));

        drop(rpc);

        assert_eq!(scheduled_work(&mut work_rx), 1);
        resolver.work(&mut controller);
        assert!(active_clusters(&resolver).is_empty());
        assert_eq!(subscriptions(&resolver), counts(&[]));
        assert_eq!(controller.updates, 2);
    }

    #[test]
    fn config_after_error_restores_routing() {
        let (mut resolver, _work_rx) = test_resolver();
        let mut controller = FakeChannelController::default();
        apply_result(
            &mut resolver,
            &mut controller,
            Ok(config_for_clusters(&["a"])),
        );
        apply_result(&mut resolver, &mut controller, Err("boom".to_string()));

        apply_result(
            &mut resolver,
            &mut controller,
            Ok(config_for_clusters(&["b"])),
        );

        assert_eq!(controller.updates, 3);
        assert_eq!(
            controller.service_configs().last(),
            Some(&expected_service_config(&["b"]))
        );
        let update = controller.last_update.as_ref().unwrap();
        assert_ne!(update.attributes, Attributes::new());
        assert_eq!(update.resolution_note, None);
        let rpc = select(current_selector(&resolver));
        assert_eq!(picked_child_name(&rpc), Some("cluster:b"));
    }

    #[test]
    fn service_config_json_has_child_per_cluster() {
        let (mut resolver, _work_rx) = test_resolver();
        // A name that needs escaping in JSON.
        let _refs = [
            resolver.get_or_create_cluster_ref("b"),
            resolver.get_or_create_cluster_ref("a\"x"),
        ];

        let service_config: serde_json::Value =
            serde_json::from_str(&resolver.service_config_json()).unwrap();

        assert_eq!(service_config, expected_service_config(&["a\"x", "b"]));
    }

    #[test]
    fn service_config_parses_with_cluster_manager() {
        crate::load_balancing::register();
        let (mut resolver, _work_rx) = test_resolver();
        let _refs = [
            resolver.get_or_create_cluster_ref("a"),
            resolver.get_or_create_cluster_ref("b"),
        ];

        let service_config: serde_json::Value =
            serde_json::from_str(&resolver.service_config_json()).unwrap();
        let parsed = ParsedLbConfig::parse(&service_config["loadBalancingConfig"].to_string())
            .expect("cluster manager should parse the generated config");

        assert_eq!(parsed.builder.name(), "xds_cluster_manager_experimental");
    }

    #[test]
    fn dependency_manager_counts_cluster_subscriptions() {
        let (dependency_manager, _updates_tx) = DependencyManager::new();
        let first = dependency_manager.subscribe_to_cluster("a");
        let second = dependency_manager.subscribe_to_cluster("a");
        assert_eq!(
            dependency_manager.cluster_subscription_counts(),
            counts(&[("a", 2)])
        );

        drop(first);
        assert_eq!(
            dependency_manager.cluster_subscription_counts(),
            counts(&[("a", 1)])
        );

        drop(second);
        assert!(dependency_manager.cluster_subscription_counts().is_empty());
    }
}
