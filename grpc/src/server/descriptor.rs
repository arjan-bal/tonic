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

/// The type (cardinality) of a gRPC method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodType {
    /// One request message followed by one response message.
    Unary,
    /// Zero or more request messages with one response message.
    ClientStreaming,
    /// One request message followed by zero or more response messages.
    ServerStreaming,
    /// Zero or more request and response messages arbitrarily interleaved.
    BidiStreaming,
}

/// Pure metadata about a single gRPC method.
///
/// This is a data class — it carries no handler logic. It describes what a
/// method looks like (its path and cardinality) without specifying how it's
/// implemented.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct MethodDescriptor {
    /// Full method path, e.g., `"/helloworld.Greeter/SayHello"`.
    full_path: String,
    /// The method cardinality.
    method_type: MethodType,
}

impl MethodDescriptor {
    /// Creates a descriptor for the given method path and cardinality.
    pub fn new(full_path: impl Into<String>, method_type: MethodType) -> Self {
        Self {
            full_path: full_path.into(),
            method_type,
        }
    }

    /// Returns the full method path, e.g., `"/helloworld.Greeter/SayHello"`.
    pub fn full_path(&self) -> &str {
        &self.full_path
    }

    /// Consumes the descriptor, returning its owned full method path.
    pub fn into_full_path(self) -> String {
        self.full_path
    }

    /// Returns the method cardinality.
    pub fn method_type(&self) -> MethodType {
        self.method_type
    }
}

/// Pure metadata about a gRPC service.
///
/// This is a data class — it carries no handler logic. It describes what a
/// service looks like (its name and the methods it contains) without
/// specifying how they're implemented.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ServiceDescriptor {
    /// Fully qualified service name, e.g., `"helloworld.Greeter"`.
    name: String,
    /// Descriptors for all methods in this service.
    methods: Vec<MethodDescriptor>,
}

impl ServiceDescriptor {
    /// Creates a descriptor for the given service name and methods.
    pub fn new(name: impl Into<String>, methods: Vec<MethodDescriptor>) -> Self {
        Self {
            name: name.into(),
            methods,
        }
    }

    /// Returns the fully qualified service name, e.g., `"helloworld.Greeter"`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the descriptors for all methods in this service.
    pub fn methods(&self) -> &[MethodDescriptor] {
        &self.methods
    }
}
