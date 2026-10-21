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
use std::collections::BTreeSet;
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
use percent_encoding::AsciiSet;
use percent_encoding::NON_ALPHANUMERIC;
use percent_encoding::utf8_percent_encode;

use crate::resolver::config_selector::XdsConfigSelector;
use crate::resolver::mocks::BootstrapConfig;
use crate::resolver::mocks::ClusterSubscription;
use crate::resolver::mocks::DependencyManager;
use crate::resolver::mocks::XdsClientProvider;
use crate::resolver::mocks::XdsClientWrapper;
use crate::resolver::mocks::XdsConfigResult;
use crate::resolver::mocks::XdsConfigWatcher;
use crate::resolver::nop_resolver::NopResolver;
use crate::resolver::service_config::cds_cluster_manager_service_config;
use crate::resource::RouteAction;
use crate::xds_config::XdsConfig;

mod config_selector;
mod mocks;
mod nop_resolver;
mod service_config;

// TODO: register this builder in the global resolver registry, in the same
// place that calls `load_balancing::register()` for the LB policies named in
// the resolver's service config.
struct Builder {
    xds_client_provider: Arc<dyn XdsClientProvider>,
}

impl ResolverBuilder for Builder {
    fn build(&self, target: &Target, options: ResolverOptions) -> Box<dyn Resolver> {
        let xds_client = match self.xds_client_provider.get_or_create(&target.to_string()) {
            Ok(client) => client,
            Err(err) => {
                return NopResolver::new_with_err(
                    format!("xds: failed to create xds-client: {err}"),
                    options,
                );
            }
        };
        let parsed = match parse_target(target, xds_client.bootstrap()) {
            Ok(parsed) => parsed,
            Err(err) => return NopResolver::new_with_err(err, options),
        };
        // TODO: create the DependencyManager and XdsResolver using
        // `xds_client` and `parsed.lds_resource_name`.
        let _ = parsed;
        todo!()
    }

    fn scheme(&self) -> &str {
        "xds"
    }

    fn is_valid_uri(&self, uri: &Target) -> bool {
        match parse_endpoint(uri) {
            Ok(_) => true,
            Err(err) => {
                eprintln!("{err}");
                false
            }
        }
    }
}

/// Output of full target validation, used when building a resolver.
#[derive(Debug, PartialEq, Eq)]
struct ParsedTarget {
    /// Name of the Listener resource to watch.
    lds_resource_name: String,
}

/// Validates the parts of `target` that don't depend on the bootstrap config.
/// Returns the endpoint: the target path without its leading "/".
fn parse_endpoint(target: &Target) -> Result<&str, String> {
    let path = target.path();
    let endpoint = path.strip_prefix('/').unwrap_or(path);
    if endpoint.is_empty() || endpoint.ends_with('/') {
        return Err(format!(
            "xds: target {target} path does not contain a valid data plane authority"
        ));
    }
    Ok(endpoint)
}

/// Validates `target` against `bootstrap` and computes the name of the
/// Listener resource to watch. Fails if the target has an authority that is
/// not in the bootstrap config.
fn parse_target(target: &Target, bootstrap: &BootstrapConfig) -> Result<ParsedTarget, String> {
    let endpoint = parse_endpoint(target)?;

    // Use the top-level template, or the per-authority one if the target has
    // an authority.
    let mut template = bootstrap
        .client_default_listener_resource_name_template
        .as_str();
    let authority = target.authority_host_port();
    if !authority.is_empty() {
        let authority_config = bootstrap.authorities.get(&authority).ok_or_else(|| {
            format!(
                "xds: authority {authority:?} specified in dial target {target} is not found in \
                 the bootstrap file"
            )
        })?;
        if !authority_config
            .client_listener_resource_name_template
            .is_empty()
        {
            template = &authority_config.client_listener_resource_name_template;
        }
    }
    Ok(ParsedTarget {
        lds_resource_name: populate_resource_template(template, endpoint),
    })
}

/// Replaces every "%s" in `template` with `target`. If the template is an
/// "xdstp:" URI, `target` is percent-encoded first (with '/' kept as is).
fn populate_resource_template(template: &str, target: &str) -> String {
    // Characters to percent-encode when putting a target into an "xdstp:"
    // resource name. Only characters allowed in a URI path (RFC 3986
    // section 3.3) may appear unencoded, as gRFC A47 requires. This set keeps
    // alphanumerics, '-', '_', '.', '~', '$', '&', '+', '=', ':', '@' and '/',
    // and encodes everything else.
    static XDSTP_PATH_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'~')
        .remove(b'$')
        .remove(b'&')
        .remove(b'+')
        .remove(b'=')
        .remove(b':')
        .remove(b'@')
        .remove(b'/');

    if !template.contains("%s") {
        return template.to_owned();
    }
    if template.starts_with("xdstp:") {
        let encoded = utf8_percent_encode(target, XDSTP_PATH_ENCODE_SET).to_string();
        return template.replace("%s", &encoded);
    }
    template.replace("%s", target)
}

struct XdsResolver {
    xds_client: Arc<XdsClientWrapper>,
    dependency_manager: DependencyManager,
    /// Clusters that must stay in the LB policy config, keyed by cluster name.
    /// Weak, so the map doesn't keep clusters in use. An entry lives until its
    /// last `ClusterRef` is dropped and `work()` prunes it.
    active_clusters: HashMap<String, Weak<ClusterRef>>,
    lds_resource_name: String,
    /// Latest update from the dependency manager; `None` until the first one
    /// arrives. Written by `update_task`, read by `work()`.
    xds_config: Arc<Mutex<Option<XdsConfigResult>>>,
    current_config_selector: Option<Arc<XdsConfigSelector>>,
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

    /// Returns a config selector holding one ref to each cluster that
    /// `xds_config`'s routes can send RPCs to.
    fn new_config_selector(&mut self, xds_config: &XdsConfig) -> Arc<XdsConfigSelector> {
        // A BTreeSet dedupes clusters used by several routes, in a
        // deterministic order.
        let mut names = BTreeSet::new();
        for route in &xds_config.virtual_host().routes {
            match &route.action {
                RouteAction::Cluster(name) => {
                    names.insert(name.as_str());
                }
                RouteAction::WeightedClusters(clusters) => {
                    names.extend(clusters.iter().map(|c| c.name.as_str()));
                }
                RouteAction::Unsupported => {}
            }
        }
        let cluster_refs = names
            .into_iter()
            .map(|name| self.get_or_create_cluster_ref(name))
            .collect();
        Arc::new(XdsConfigSelector::new(cluster_refs))
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
    /// the current config selector. Does nothing before the first config
    /// selector is created.
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
        // TODO: handle errors returned by the channel.
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
        todo!()
    }

    fn work(&mut self, channel_controller: &mut dyn ChannelController) {
        // TODO: create a new config selector when the XdsConfig changes. Keep
        // pruning before building any update, so that no update names a
        // cluster the dependency manager may have stopped watching.
        if self.remove_unused_clusters() {
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
/// it.
struct ClusterRef {
    name: String,
    /// Keeps the dependency manager subscribed to the cluster. Dropped, which
    /// unsubscribes, together with the last ref.
    _subscription: ClusterSubscription,
    work_scheduler: Arc<dyn WorkScheduler>,
}

impl ClusterRef {
    /// Returns the cluster name.
    fn name(&self) -> &str {
        &self.name
    }
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
    use grpc::__unstable::client::service_config::ParseResult;
    use grpc::__unstable::rt::TaskHandle;
    use serde_json::json;
    use tokio::sync::mpsc;

    use super::*;
    use crate::resolver::mocks::Authority;
    use crate::resource::DomainMatcher;
    use crate::resource::ListenerResource;
    use crate::resource::PathSpecifier;
    use crate::resource::Route;
    use crate::resource::RouteConfigResource;
    use crate::resource::RouteMatch;
    use crate::resource::RouteSource;
    use crate::resource::VirtualHost;
    use crate::resource::WeightedCluster;
    use crate::xds_config::XdsConfig;

    /// Returns clients wrapping a fixed bootstrap config, or a fixed error.
    struct FakeXdsClientProvider {
        bootstrap: Result<BootstrapConfig, String>,
    }

    impl XdsClientProvider for FakeXdsClientProvider {
        fn get_or_create(&self, _name: &str) -> Result<Arc<XdsClientWrapper>, String> {
            self.bootstrap
                .clone()
                .map(|bootstrap| Arc::new(XdsClientWrapper { bootstrap }))
        }
    }

    fn target(s: &str) -> Target {
        s.parse().unwrap()
    }

    fn builder() -> Builder {
        Builder {
            xds_client_provider: Arc::new(FakeXdsClientProvider {
                bootstrap: Err("bootstrap must not be read".to_string()),
            }),
        }
    }

    /// Validates `target` against the bootstrap returned by a client from
    /// `FakeXdsClientProvider`, as the resolver does when it is built.
    fn parse_with_provider(
        target_str: &str,
        bootstrap: BootstrapConfig,
    ) -> Result<ParsedTarget, String> {
        let provider = FakeXdsClientProvider {
            bootstrap: Ok(bootstrap),
        };
        let target = target(target_str);
        let client = provider.get_or_create(&target.to_string())?;
        parse_target(&target, client.bootstrap())
    }

    fn bootstrap_with_authority(name: &str) -> BootstrapConfig {
        BootstrapConfig {
            authorities: HashMap::from([(
                name.to_string(),
                Authority::with_default_template(name),
            )]),
            ..Default::default()
        }
    }

    #[test]
    fn is_valid_uri_accepts_valid_targets() {
        let builder = builder();
        // No bootstrap is needed, so the provider's error is never seen.
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
    fn parse_target_default_template() {
        let parsed = parse_with_provider("xds:///foo.example.com", BootstrapConfig::default());
        assert_eq!(
            parsed,
            Ok(ParsedTarget {
                lds_resource_name: "foo.example.com".to_string()
            })
        );
    }

    #[test]
    fn parse_target_custom_top_level_template() {
        let bootstrap = BootstrapConfig {
            client_default_listener_resource_name_template: "/listeners/%s".to_string(),
            ..Default::default()
        };
        let parsed = parse_with_provider("xds:///foo", bootstrap).unwrap();
        assert_eq!(parsed.lds_resource_name, "/listeners/foo");
    }

    #[test]
    fn parse_target_top_level_xdstp_template_is_encoded() {
        let bootstrap = BootstrapConfig {
            client_default_listener_resource_name_template:
                "xdstp://auth/envoy.config.listener.v3.Listener/%s".to_string(),
            ..Default::default()
        };
        let parsed = parse_with_provider("xds:///[::1]:8080", bootstrap).unwrap();
        assert_eq!(
            parsed.lds_resource_name,
            "xdstp://auth/envoy.config.listener.v3.Listener/%5B::1%5D:8080"
        );
    }

    #[test]
    fn parse_target_known_authority_default_template() {
        let parsed =
            parse_with_provider("xds://auth.com/svc", bootstrap_with_authority("auth.com"))
                .unwrap();
        assert_eq!(
            parsed.lds_resource_name,
            "xdstp://auth.com/envoy.config.listener.v3.Listener/svc"
        );
    }

    #[test]
    fn parse_target_unknown_authority() {
        let parsed = parse_with_provider("xds://other/svc", bootstrap_with_authority("auth.com"));
        let err = parsed.unwrap_err();
        assert!(err.contains("\"other\""), "unexpected error: {err}");
    }

    #[test]
    fn parse_target_authority_without_authorities_in_bootstrap() {
        let parsed = parse_with_provider("xds://auth.com/svc", BootstrapConfig::default());
        assert!(parsed.is_err());
    }

    #[test]
    fn parse_target_rejects_empty_endpoint() {
        let parsed = parse_with_provider("xds:///", BootstrapConfig::default());
        assert!(parsed.is_err());
    }

    #[test]
    fn xds_client_provider_error_is_propagated() {
        let provider = FakeXdsClientProvider {
            bootstrap: Err("no bootstrap".to_string()),
        };
        assert_eq!(
            provider.get_or_create("xds:///foo").err(),
            Some("no bootstrap".to_string())
        );
    }

    #[test]
    fn populate_resource_template_cases() {
        let cases = [
            // (template, target, want)
            ("/name/template", "[::1]:8080", "/name/template"),
            (
                "/name/template/%s",
                "[::1]:8080",
                "/name/template/[::1]:8080",
            ),
            (
                "xdstp://authority.com/%s",
                "0.0.0.0:8080",
                "xdstp://authority.com/0.0.0.0:8080",
            ),
            (
                "xdstp://authority.com/%s",
                "[::1]:8080",
                "xdstp://authority.com/%5B::1%5D:8080",
            ),
        ];
        for (template, target, want) in cases {
            assert_eq!(
                populate_resource_template(template, target),
                want,
                "template: {template}, target: {target}"
            );
        }
    }

    #[test]
    fn xdstp_encoding_details() {
        let cases = [
            // (target, want)
            ("server.example.com", "server.example.com"),
            ("my/service/region", "my/service/region"),
            ("a b", "a%20b"),
            ("a,b;c", "a%2Cb%3Bc"),
            ("-_.~$&+=:@", "-_.~$&+=:@"),
        ];
        for (target, want) in cases {
            assert_eq!(
                populate_resource_template("xdstp://a/%s", target),
                format!("xdstp://a/{want}"),
                "target: {target}"
            );
        }
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
        fn update(&mut self, _update: ResolverUpdate) -> Result<(), String> {
            self.updates += 1;
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
            xds_client: Arc::new(XdsClientWrapper {
                bootstrap: BootstrapConfig::default(),
            }),
            dependency_manager,
            active_clusters: HashMap::new(),
            lds_resource_name: "listener".to_string(),
            xds_config: Arc::new(Mutex::new(None)),
            current_config_selector: None,
            work_scheduler: Arc::new(TestWorkScheduler { tx: work_tx }),
            update_task: Box::new(NoopTaskHandle),
        };
        (resolver, work_rx)
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
        let old_selector = XdsConfigSelector::new(vec![
            resolver.get_or_create_cluster_ref("a"),
            resolver.get_or_create_cluster_ref("b"),
        ]);
        let current_selector =
            XdsConfigSelector::new(vec![resolver.get_or_create_cluster_ref("a")]);
        resolver.current_config_selector = Some(Arc::new(current_selector));

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
    fn rpc_ref_keeps_cluster_until_dropped() {
        let (mut resolver, mut work_rx) = test_resolver();
        let old_selector = XdsConfigSelector::new(vec![resolver.get_or_create_cluster_ref("b")]);
        let current_selector =
            XdsConfigSelector::new(vec![resolver.get_or_create_cluster_ref("a")]);
        resolver.current_config_selector = Some(Arc::new(current_selector));
        // Stands in for the ref an RPC routed to "b" will hold.
        let rpc_ref = resolver.get_or_create_cluster_ref("b");

        drop(old_selector);
        assert_eq!(scheduled_work(&mut work_rx), 0);
        let mut controller = FakeChannelController::default();
        resolver.work(&mut controller);
        assert_eq!(active_clusters(&resolver), ["a", "b"]);
        assert_eq!(subscriptions(&resolver), counts(&[("a", 1), ("b", 1)]));
        assert_eq!(controller.updates, 0);

        drop(rpc_ref);
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
        let selector = XdsConfigSelector::new(vec![resolver.get_or_create_cluster_ref("a")]);
        resolver.current_config_selector = Some(Arc::new(selector));

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

        assert_eq!(selector.cluster_names(), ["a", "b", "c"]);
        assert_eq!(
            subscriptions(&resolver),
            counts(&[("a", 1), ("b", 1), ("c", 1)])
        );
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
