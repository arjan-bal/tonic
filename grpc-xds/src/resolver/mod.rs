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

use grpc::__unstable::client::name_resolution::Resolver;
use grpc::__unstable::client::name_resolution::ResolverBuilder;
use grpc::__unstable::client::name_resolution::ResolverOptions;
use grpc::__unstable::client::name_resolution::Target;
use percent_encoding::AsciiSet;
use percent_encoding::NON_ALPHANUMERIC;
use percent_encoding::utf8_percent_encode;

use crate::resolver::config_selector::XdsConfigSelector;
use crate::resolver::mocks::BootstrapConfig;
use crate::resolver::mocks::DependencyManager;
use crate::resolver::mocks::XdsClientProvider;
use crate::resolver::mocks::XdsClientWrapper;
use crate::resolver::nop_resolver::NopResolver;
use crate::xds_config::XdsConfig;

mod config_selector;
mod mocks;
mod nop_resolver;

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
    active_clusters: Arc<ClusterRef>,
    lds_resource_name: String,
    xds_config: Option<XdsConfig>,
    current_config_selector: Option<Arc<XdsConfigSelector>>,
}

struct ClusterRef {}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use grpc::__unstable::client::name_resolution::ResolverBuilder;
    use grpc::__unstable::client::name_resolution::Target;

    use super::*;
    use crate::resolver::mocks::Authority;

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
}
