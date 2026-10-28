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

#[cfg(test)]
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use tokio::sync::mpsc;

use crate::xds_config::XdsConfig;

/// Mock xDS client.
///
/// TODO: replace with the real xDS client once it is integrated.
pub(super) struct XdsClientWrapper;

/// Creates or reuses xDS clients, keyed by name (gRFC A71).
///
/// TODO: replace with the real xDS client pool once it is implemented.
pub(super) trait XdsClientProvider: Send + Sync {
    /// Returns the xDS client for `name`, creating it if needed. Channels pass
    /// their target URI string as the name; servers use a fixed key. Fails if
    /// the client can't be created, e.g. because the bootstrap config is
    /// missing or invalid.
    fn get_or_create(&self, name: &str) -> Result<Arc<XdsClientWrapper>, String>;
}

/// An `XdsConfig` update from the dependency manager: a new snapshot, or an
/// error that prevents the channel from getting one (e.g. the Listener or
/// RouteConfiguration doesn't exist).
pub(super) type XdsConfigResult = Result<XdsConfig, String>;

/// Mock of the xDS dependency manager (gRFC A74).
///
/// TODO: replace with the real dependency manager once it is implemented.
pub(super) struct DependencyManager {
    watcher: Option<XdsConfigWatcher>,
    /// Number of live `ClusterSubscription`s per cluster name. Shared with the
    /// subscriptions, which may outlive the dependency manager.
    cluster_subscriptions: Arc<Mutex<HashMap<String, usize>>>,
}

impl DependencyManager {
    /// Returns a mock dependency manager, and the sender used to push
    /// `XdsConfig` updates to its watcher.
    pub(super) fn new() -> (Self, mpsc::UnboundedSender<XdsConfigResult>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let dependency_manager = Self {
            watcher: Some(XdsConfigWatcher { rx }),
            cluster_subscriptions: Arc::default(),
        };
        (dependency_manager, tx)
    }

    /// Returns the watcher that receives this dependency manager's
    /// `XdsConfig` updates.
    ///
    /// # Panics
    ///
    /// Panics if called more than once.
    pub(super) fn watch(&mut self) -> XdsConfigWatcher {
        self.watcher
            .take()
            .expect("DependencyManager::watch called more than once")
    }

    /// Subscribes to the Cluster resource `name`, so that the cluster stays in
    /// the `XdsConfig` even if the route config stops referencing it. The
    /// subscription lasts until the returned handle is dropped.
    pub(super) fn subscribe_to_cluster(&self, name: &str) -> ClusterSubscription {
        *self
            .cluster_subscriptions
            .lock()
            .unwrap()
            .entry(name.to_owned())
            .or_default() += 1;
        ClusterSubscription {
            name: name.to_owned(),
            cluster_subscriptions: self.cluster_subscriptions.clone(),
        }
    }

    /// Asks the dependency manager to re-resolve its DNS clusters.
    ///
    /// TODO: implement in the real dependency manager.
    pub(super) fn request_reresolution(&self) {}

    /// Returns the number of live subscriptions for each subscribed cluster.
    #[cfg(test)]
    pub(super) fn cluster_subscription_counts(&self) -> BTreeMap<String, usize> {
        self.cluster_subscriptions
            .lock()
            .unwrap()
            .iter()
            .map(|(name, count)| (name.clone(), *count))
            .collect()
    }
}

/// Keeps a [`DependencyManager`] subscribed to a cluster. Dropping it
/// unsubscribes.
///
/// May be dropped on any thread, e.g. when the last RPC routed to the cluster
/// finishes.
pub(super) struct ClusterSubscription {
    name: String,
    cluster_subscriptions: Arc<Mutex<HashMap<String, usize>>>,
}

impl Drop for ClusterSubscription {
    fn drop(&mut self) {
        let mut subscriptions = self.cluster_subscriptions.lock().unwrap();
        if let Some(count) = subscriptions.get_mut(&self.name) {
            *count -= 1;
            if *count == 0 {
                subscriptions.remove(&self.name);
            }
        }
    }
}

/// Receives `XdsConfig` updates from a [`DependencyManager`].
pub(super) struct XdsConfigWatcher {
    rx: mpsc::UnboundedReceiver<XdsConfigResult>,
}

impl XdsConfigWatcher {
    /// Returns the next update, or `None` once the dependency manager has
    /// shut down.
    pub(super) async fn next(&mut self) -> Option<XdsConfigResult> {
        self.rx.recv().await
    }
}
