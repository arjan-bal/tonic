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

use crate::server::DynHandle;
use crate::server::descriptor::ServiceDescriptor;

/// A gRPC service that can register its methods with a server router.
///
/// Implementations return their descriptor metadata via [`descriptor()`](Service::descriptor)
/// and produce their method handlers via [`register_methods()`](Service::register_methods).
pub trait Service: Send + 'static {
    /// Returns the service descriptor (pure metadata).
    ///
    /// This provides service and method metadata without registering handlers,
    /// enabling use cases like server reflection and service listing.
    fn descriptor(&self) -> ServiceDescriptor;

    /// Produces all method handlers for this service as type-erased dynamic handlers
    /// paired with their full method path (e.g. `"/mypackage.Echo/UnaryEcho"`).
    fn register_methods(self) -> Vec<(String, Arc<dyn DynHandle>)>;
}
