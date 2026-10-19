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
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::xds_config::XdsConfig;

/// Mock xDS client.
///
/// TODO: replace with the real xDS client once it is integrated.
pub(super) struct XdsClientWrapper {
    pub(super) bootstrap: BootstrapConfig,
}

impl XdsClientWrapper {
    /// Returns the bootstrap config this client was created with.
    pub(super) fn bootstrap(&self) -> &BootstrapConfig {
        &self.bootstrap
    }
}

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
}

impl DependencyManager {
    /// Returns a mock dependency manager, and the sender used to push
    /// `XdsConfig` updates to its watcher.
    pub(super) fn new() -> (Self, mpsc::UnboundedSender<XdsConfigResult>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let dependency_manager = Self {
            watcher: Some(XdsConfigWatcher { rx }),
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

/// Mock of a single bootstrap authority entry.
#[derive(Debug, Clone)]
pub(super) struct Authority {
    /// Must start with "xdstp://<authority>/". Defaults to
    /// "xdstp://<authority>/envoy.config.listener.v3.Listener/%s".
    pub(super) client_listener_resource_name_template: String,
}

impl Authority {
    /// Returns an authority entry that uses the default listener resource name
    /// template for `authority_name`.
    pub(super) fn with_default_template(authority_name: &str) -> Self {
        Self {
            client_listener_resource_name_template: format!(
                "xdstp://{authority_name}/envoy.config.listener.v3.Listener/%s"
            ),
        }
    }
}

/// Mock of the client-side parts of the xDS bootstrap config used by the
/// resolver (gRFC A27 / A47).
///
/// TODO: replace with the real bootstrap once it is implemented.
#[derive(Debug, Clone)]
pub(crate) struct BootstrapConfig {
    /// Template for the Listener name when the target has no authority.
    /// Defaults to "%s".
    pub(super) client_default_listener_resource_name_template: String,
    /// Map from authority name to its config.
    pub(super) authorities: HashMap<String, Authority>,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            client_default_listener_resource_name_template: "%s".to_string(),
            authorities: HashMap::new(),
        }
    }
}
