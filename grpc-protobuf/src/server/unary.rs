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

use grpc::async_trait;
use grpc::server::CallOptions;
use grpc::server::DynHandle;
use grpc::server::DynRecvStream;
use grpc::server::DynSendStream;
use grpc::server::Handle;
use grpc::server::RecvStream;
use grpc::server::RequestHeaders;
use grpc::server::ResponseStreamItem;
use grpc::server::SendOptions;
use grpc::server::SendStream;
use grpc::server::Trailers;
use grpc::server::interceptor::Intercept;
use grpc::server::stream_util::RequestValidator;
use protobuf::AsMut;
use protobuf::AsView;
use protobuf::Message;
use protobuf::MutProxied;
use protobuf::Proxied;

use crate::ProtoRecvMessage;
use crate::ProtoSendMessage;
use crate::SendFuture;
use crate::ServerStatus;
use crate::ServerStatusError;
use crate::StatusCodeError;
use crate::trailers_conv::trailers_from_status;

/// A unary RPC method handler on the server.
///
/// Implementations receive a single request message and populate a single
/// response message.
#[trait_variant::make(Send)]
pub trait UnaryMethod: Sync + 'static {
    /// The protobuf request message type.
    type Request: Message;
    /// The protobuf response message type.
    type Response: Message;

    /// Handles a unary RPC call.
    ///
    /// Receives a view of the incoming `request` message and populates the
    /// `response` message, returning a [`ServerStatus`] to indicate success
    /// or failure.
    async fn call(
        &self,
        request: <Self::Request as Proxied>::View<'_>,
        response: <Self::Response as MutProxied>::Mut<'_>,
    ) -> ServerStatus;
}

/// An adapter that wraps a [`UnaryMethod`] to handle incoming unary RPCs.
pub struct UnaryAdapter<M> {
    handle: InnerHandler<M>,
}

impl<M> UnaryAdapter<M> {
    /// Creates a new [`UnaryAdapter`] wrapping the given `method`.
    pub fn new(method: M) -> Self {
        Self {
            handle: InnerHandler { method },
        }
    }
}

#[async_trait]
impl<M> DynHandle for UnaryAdapter<M>
where
    M: UnaryMethod,
{
    async fn dyn_handle(
        &self,
        headers: RequestHeaders,
        options: CallOptions,
        mut tx: &mut dyn DynSendStream,
        rx: Box<dyn DynRecvStream + 'static>,
    ) -> Trailers {
        RequestValidator::new(true)
            .intercept(headers, options, &mut tx, rx, &self.handle)
            .make_send()
            .await
    }
}

struct InnerHandler<M> {
    method: M,
}

impl<M> Handle for InnerHandler<M>
where
    M: UnaryMethod,
{
    async fn handle(
        &self,
        _headers: RequestHeaders,
        _options: CallOptions,
        tx: &mut impl SendStream,
        mut rx: impl RecvStream + 'static,
    ) -> Trailers {
        // TODO: Allocate both the request and response messages together in an
        // arena.
        let mut req = <M::Request as Default>::default();
        let mut resp = <M::Response as Default>::default();

        if rx
            .next(&mut ProtoRecvMessage::from_mut(&mut req))
            .await
            .expect("ResponseValidator allowed zero messages for unary stream")
            .is_err()
        {
            return trailers_from_status(Err(ServerStatusError::new(
                StatusCodeError::Internal,
                "stream failure",
            )));
        }

        let status = self.method.call(req.as_view(), resp.as_mut()).await;

        if status.is_ok() {
            let send = ProtoSendMessage::from_view(&resp);
            let mut options = SendOptions::default();
            options.final_msg = true;

            let _ = tx.send(ResponseStreamItem::Message(&send), options).await;
        }

        trailers_from_status(status)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;

    use grpc::core::Address;
    use grpc::core::ConnectionInfo;
    use grpc::core::RecvMessage;
    use grpc::credentials::SecurityInfo;
    use protobuf_well_known_types::Any;

    use super::*;

    struct TestUnaryMethod {
        called: Arc<AtomicBool>,
    }

    impl UnaryMethod for TestUnaryMethod {
        type Request = Any;
        type Response = Any;

        async fn call(
            &self,
            _request: <Self::Request as Proxied>::View<'_>,
            _response: <Self::Response as MutProxied>::Mut<'_>,
        ) -> ServerStatus {
            self.called.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    struct MockSendStream;

    impl SendStream for MockSendStream {
        async fn send<'a>(
            &mut self,
            _item: ResponseStreamItem<'a>,
            _options: SendOptions,
        ) -> Result<(), ()> {
            Ok(())
        }
    }

    struct EmptyRecvStream;

    impl RecvStream for EmptyRecvStream {
        async fn next(&mut self, _msg: &mut dyn RecvMessage) -> Option<Result<(), ()>> {
            None
        }
    }

    #[tokio::test]
    async fn test_unary_zero_messages_returns_error() {
        let called = Arc::new(AtomicBool::new(false));
        let adapter = UnaryAdapter::new(TestUnaryMethod {
            called: called.clone(),
        });

        let connection_info = ConnectionInfo::new(
            Address::default(),
            Address::default(),
            SecurityInfo::new(""),
        );
        let headers = RequestHeaders::new("/test.TestService/TestMethod", connection_info);

        let mut tx = MockSendStream;
        let rx: Box<dyn DynRecvStream> = Box::new(EmptyRecvStream);

        let trailers = adapter
            .dyn_handle(headers, CallOptions::default(), &mut tx, rx)
            .await;

        let status = trailers
            .status()
            .as_ref()
            .expect_err("expected error status in trailers when client sends 0 messages");
        assert_eq!(status.code(), grpc::StatusCodeError::Internal);
        assert_eq!(status.message(), "unary stream received zero messages");
        assert!(
            !called.load(Ordering::SeqCst),
            "method should not be called when request stream sends 0 messages"
        );
    }
}
