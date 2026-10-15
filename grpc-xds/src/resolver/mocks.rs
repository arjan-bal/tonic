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

pub(super) struct DependencyManager {}

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
