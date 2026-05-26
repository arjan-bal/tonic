/*
 *
 * Copyright 2025 gRPC authors.
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

use std::fmt::Debug;
use std::sync::Arc;
use std::sync::LazyLock;

use hyper_util::client::proxy::matcher::Matcher;

use super::ResolverOptions;
use super::Target;
use crate::client::name_resolution::Address;
use crate::client::name_resolution::ChannelController;
use crate::client::name_resolution::NopResolver;
use crate::client::name_resolution::Resolver;
use crate::client::name_resolution::ResolverBuilder;
use crate::client::name_resolution::ResolverUpdate;
use crate::client::name_resolution::TCP_IP_NETWORK_TYPE;
use crate::client::name_resolution::global_registry;
use crate::client::service_config::ServiceConfig;

static MATCHER: LazyLock<Matcher> = LazyLock::new(Matcher::from_env);

pub(crate) struct Builder {
    child_builder: Arc<dyn ResolverBuilder>,
}

impl ResolverBuilder for Builder {
    fn build(&self, target: &Target, options: ResolverOptions) -> Box<dyn Resolver> {
        match self.new_resolver(target, options) {
            Ok(resolver) => resolver,
            Err((err, options)) => NopResolver::new_with_err(err, options),
        }
    }

    fn scheme(&self) -> &str {
        self.child_builder.scheme()
    }

    fn is_valid_uri(&self, uri: &Target) -> bool {
        self.child_builder.is_valid_uri(uri)
    }

    fn default_authority(&self, target: &Target) -> String {
        self.child_builder.default_authority(target)
    }
}

impl Builder {
    pub(crate) fn new(child_builder: Arc<dyn ResolverBuilder>) -> Self {
        Self { child_builder }
    }

    fn new_resolver(
        &self,
        target: &Target,
        options: ResolverOptions,
    ) -> Result<Box<dyn Resolver>, (String, ResolverOptions)> {
        let path = target.path();
        let target_host = path.strip_prefix("/").unwrap_or(path);

        let Ok(uri) = http::Uri::builder()
            .scheme("https")
            .authority(target_host)
            .path_and_query("/")
            .build()
        else {
            // Target isn't a valid hostname, skip proxy.
            return Ok(self.child_builder.build(target, options));
        };

        let Some(intercept) = MATCHER.intercept(&uri) else {
            return Ok(self.child_builder.build(target, options));
        };

        let credentials = intercept.basic_auth().map(|hv| Credentials {
            header_value: hv.clone(),
        });

        let proxy_options = ProxyOptions {
            credentials,
            connect_addr: target_host.to_owned(),
        };

        let Some(proxy_host) = intercept.uri().authority() else {
            return Err((
                format!("Proxy URI missing authority: {}", intercept.uri()),
                options,
            ));
        };
        let target_str = format!("dns:///{}", proxy_host);
        let target: Target = match target_str.parse() {
            Ok(t) => t,
            Err(e) => {
                return Err((
                    format!("failed to parse proxy target {target_str}: {e}"),
                    options,
                ));
            }
        };

        let Some(dns_builder) = global_registry().get("dns") else {
            return Err((
                "DNS resolver not registered, failed to resolve proxy address".to_owned(),
                options,
            ));
        };

        let child = dns_builder.build(&target, options);
        Ok(Box::new(HttpsProxyResolver {
            child,
            proxy_options: Arc::new(proxy_options),
        }))
    }
}

struct HttpsProxyResolver {
    child: Box<dyn Resolver>,
    proxy_options: Arc<ProxyOptions>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Credentials {
    header_value: http::HeaderValue,
}

impl Credentials {
    pub(crate) fn header_value(&self) -> &http::HeaderValue {
        &self.header_value
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub(crate) struct ProxyOptions {
    credentials: Option<Credentials>,
    connect_addr: String,
}

impl ProxyOptions {
    pub(crate) fn credentials(&self) -> Option<&Credentials> {
        self.credentials.as_ref()
    }

    pub(crate) fn connect_addr(&self) -> &str {
        &self.connect_addr
    }
}

impl Resolver for HttpsProxyResolver {
    fn resolve_now(&mut self) {
        self.child.resolve_now();
    }

    fn work(&mut self, channel_controller: &mut dyn ChannelController) {
        let mut interceptor = InterceptingController {
            inner: channel_controller,
            proxy_options: &self.proxy_options,
        };
        self.child.work(&mut interceptor);
    }
}

struct InterceptingController<'a> {
    inner: &'a mut dyn ChannelController,
    proxy_options: &'a Arc<ProxyOptions>,
}

impl<'a> ChannelController for InterceptingController<'a> {
    fn update(&mut self, mut update: ResolverUpdate) -> Result<(), String> {
        if let Ok(endpoints) = &mut update.endpoints {
            for endpoint in endpoints {
                for address in &mut endpoint.addresses {
                    if address.network_type == TCP_IP_NETWORK_TYPE {
                        address.attributes = address.attributes.add(self.proxy_options.clone());
                    }
                }
            }
        }
        self.inner.update(update)
    }

    fn parse_service_config(&self, config: &str) -> Result<ServiceConfig, String> {
        self.inner.parse_service_config(config)
    }
}

pub(crate) fn proxy_options_for_addr(addr: &Address) -> Option<&ProxyOptions> {
    addr.attributes
        .get::<Arc<ProxyOptions>>()
        .map(AsRef::as_ref)
}
