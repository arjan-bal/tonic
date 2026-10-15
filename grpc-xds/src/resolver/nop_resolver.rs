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

use grpc::__unstable::client::name_resolution::ChannelController;
use grpc::__unstable::client::name_resolution::Resolver;
use grpc::__unstable::client::name_resolution::ResolverOptions;
use grpc::__unstable::client::name_resolution::ResolverUpdate;

/// A resolver that returns the same result every time its work method is
/// called. It is used to return an error to the channel when a resolver fails
/// to build.
///
/// Copied from grpc's private `NopResolver`.
/// TODO: remove once grpc exposes it.
pub(super) struct NopResolver {
    update: Option<ResolverUpdate>,
}

impl Resolver for NopResolver {
    fn resolve_now(&mut self) {}

    fn work(&mut self, channel_controller: &mut dyn ChannelController) {
        if let Some(update) = self.update.take() {
            let _ = channel_controller.update(update);
        }
    }
}

impl NopResolver {
    /// Returns a resolver that reports `err` to the channel once.
    pub(super) fn new_with_err(err: String, options: ResolverOptions) -> Box<dyn Resolver> {
        options.work_scheduler.schedule_work();
        Box::new(Self::with_err(err))
    }

    fn with_err(err: String) -> Self {
        let mut update = ResolverUpdate::default();
        update.endpoints = Err(err);
        NopResolver {
            update: Some(update),
        }
    }
}

#[cfg(test)]
mod tests {
    use grpc::__unstable::client::name_resolution::ChannelController;
    use grpc::__unstable::client::name_resolution::Resolver;
    use grpc::__unstable::client::name_resolution::ResolverUpdate;
    use grpc::__unstable::client::service_config::ParseResult;

    use super::NopResolver;

    #[derive(Default)]
    struct FakeChannelController {
        updates: Vec<ResolverUpdate>,
    }

    impl ChannelController for FakeChannelController {
        fn update(&mut self, update: ResolverUpdate) -> Result<(), String> {
            self.updates.push(update);
            Ok(())
        }

        fn parse_service_config(&self, _config: &str) -> ParseResult {
            unimplemented!("not used by NopResolver")
        }
    }

    #[test]
    fn work_reports_error_once() {
        let mut resolver = NopResolver::with_err("boom".to_string());
        let mut controller = FakeChannelController::default();

        resolver.work(&mut controller);
        assert_eq!(controller.updates.len(), 1);
        assert_eq!(controller.updates[0].endpoints, Err("boom".to_string()));

        // Subsequent calls must not send any more updates.
        resolver.resolve_now();
        resolver.work(&mut controller);
        assert_eq!(controller.updates.len(), 1);
    }
}
