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

//! Interceptors providing server-side stream validation.

use tokio::sync::oneshot;

use crate::StatusCodeError;
use crate::StatusError;
use crate::core::RecvMessage;
use crate::server::CallOptions;
use crate::server::Handle;
use crate::server::RecvStream;
use crate::server::RequestHeaders;
use crate::server::SendStream;
use crate::server::Trailers;
use crate::server::interceptor::Intercept;

/// An interceptor that wraps the incoming request [`RecvStream`] in a
/// [`RecvStreamValidator`].
#[derive(Debug)]
pub struct RequestValidator {
    is_unary: bool,
}

impl RequestValidator {
    /// Creates an instance of a `RequestValidator` that wraps incoming
    /// [`RecvStream`]s in a [`RecvStreamValidator`].
    pub fn new(is_unary: bool) -> Self {
        RequestValidator { is_unary }
    }
}

impl Intercept for RequestValidator {
    async fn intercept(
        &self,
        headers: RequestHeaders,
        options: CallOptions,
        tx: &mut impl SendStream,
        rx: impl RecvStream + 'static,
        next: &impl Handle,
    ) -> Trailers {
        let (error_tx, mut error_rx) = oneshot::channel();
        let wrapped_rx = RecvStreamValidator::new(rx, self.is_unary, error_tx);

        let handler_trailers = next.handle(headers, options, tx, wrapped_rx).await;
        if let Ok(interceptor_trailers) = error_rx.try_recv() {
            return interceptor_trailers;
        }
        handler_trailers
    }
}

#[derive(Debug, Clone, Copy)]
enum RecvStreamState {
    AwaitingMessages,
    Done,
    Errored,
}

/// Wraps a server's [`RecvStream`] and performs protocol validation on it.
struct RecvStreamValidator<R> {
    recv_stream: R,
    state: RecvStreamState,
    is_unary: bool,
    error_tx: Option<oneshot::Sender<Trailers>>,
}

impl<R: RecvStream> RecvStreamValidator<R> {
    /// Wraps `recv_stream` and performs protocol validation when it is
    /// accessed.
    ///
    /// If `is_unary` is set, expects the client to send exactly one request
    /// message.
    fn new(recv_stream: R, is_unary: bool, error_tx: oneshot::Sender<Trailers>) -> Self {
        Self {
            recv_stream,
            state: RecvStreamState::AwaitingMessages,
            is_unary,
            error_tx: Some(error_tx),
        }
    }

    fn error(&mut self, s: impl Into<String>) -> Option<Result<(), ()>> {
        self.state = RecvStreamState::Errored;
        let status = StatusError::new(StatusCodeError::Internal, s);
        if let Some(tx) = self.error_tx.take() {
            let _ = tx.send(Trailers::new(Err(status)));
        }
        Some(Err(()))
    }
}

impl<R: RecvStream> RecvStream for RecvStreamValidator<R> {
    async fn next(&mut self, msg: &mut dyn RecvMessage) -> Option<Result<(), ()>> {
        match self.state {
            RecvStreamState::Done => return None,
            RecvStreamState::Errored => return Some(Err(())),
            RecvStreamState::AwaitingMessages => {}
        }

        if !self.is_unary {
            return match self.recv_stream.next(msg).await {
                Some(Ok(())) => Some(Ok(())),
                None => {
                    self.state = RecvStreamState::Done;
                    None
                }
                Some(Err(())) => {
                    self.state = RecvStreamState::Errored;
                    Some(Err(()))
                }
            };
        }

        // For unary calls, validate that the client sends exactly one message
        // and then terminates the stream. Since a unary server handler only
        // calls `next` once, both checks must happen during this single call.
        match self.recv_stream.next(msg).await {
            Some(Ok(())) => {
                // The first message was decoded into `msg`. Check that the
                // stream ends immediately after this message. If the stream has
                // ended (`None`), `msg` remains unmodified.
                match self.recv_stream.next(msg).await {
                    None => {
                        self.state = RecvStreamState::Done;
                        Some(Ok(()))
                    }
                    Some(Ok(())) => self.error("unary stream received multiple messages"),
                    Some(Err(())) => {
                        self.state = RecvStreamState::Errored;
                        Some(Err(()))
                    }
                }
            }
            None => self.error("unary stream received zero messages"),
            Some(Err(())) => {
                self.state = RecvStreamState::Errored;
                Some(Err(()))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;

    use bytes::Bytes;
    use tokio::sync::mpsc;

    use super::*;
    use crate::core::test_connection_info;
    use crate::server::ResponseStreamItem;
    use crate::server::SendOptions;
    use crate::server::interceptor::HandleExt as _;

    struct NopRecvMessage;

    impl RecvMessage for NopRecvMessage {
        fn decode(&mut self, _data: &mut dyn bytes::Buf) -> Result<(), String> {
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

    #[derive(Debug, Clone)]
    enum RequestStreamItem {
        Message,
        StreamClosed,
        Error,
    }

    struct MockRecvStream {
        rx: mpsc::UnboundedReceiver<RequestStreamItem>,
    }

    impl RecvStream for MockRecvStream {
        async fn next(&mut self, msg: &mut dyn RecvMessage) -> Option<Result<(), ()>> {
            match self.rx.recv().await {
                Some(RequestStreamItem::Message) => {
                    let mut dummy = Bytes::from_static(b"");
                    let _ = msg.decode(&mut dummy);
                    Some(Ok(()))
                }
                Some(RequestStreamItem::StreamClosed) => None,
                Some(RequestStreamItem::Error) => Some(Err(())),
                None => None,
            }
        }
    }

    fn mock_recv_stream() -> (mpsc::UnboundedSender<RequestStreamItem>, MockRecvStream) {
        let (tx, rx) = mpsc::unbounded_channel();
        (tx, MockRecvStream { rx })
    }

    #[derive(Debug)]
    enum ExpectedStatus {
        Ok,
        Error(StatusCodeError, &'static str),
    }

    struct UnaryHandler;

    impl Handle for UnaryHandler {
        async fn handle(
            &self,
            _headers: RequestHeaders,
            _options: CallOptions,
            _tx: &mut impl SendStream,
            mut rx: impl RecvStream + 'static,
        ) -> Trailers {
            // A unary handler calls next only once.
            match rx.next(&mut NopRecvMessage).await {
                Some(Ok(())) => Trailers::new(Ok(())),
                Some(Err(())) => Trailers::new(Err(StatusError::new(
                    StatusCodeError::Aborted,
                    "handler saw error",
                ))),
                None => unreachable!(),
            }
        }
    }

    struct EchoDrainHandler;

    impl Handle for EchoDrainHandler {
        async fn handle(
            &self,
            _headers: RequestHeaders,
            _options: CallOptions,
            _tx: &mut impl SendStream,
            mut rx: impl RecvStream + 'static,
        ) -> Trailers {
            while let Some(res) = rx.next(&mut NopRecvMessage).await {
                if res.is_err() {
                    return Trailers::new(Err(StatusError::new(
                        StatusCodeError::Aborted,
                        "handler saw error",
                    )));
                }
            }
            Trailers::new(Ok(()))
        }
    }

    async fn validate_unary_scenario(scenario: &[RequestStreamItem], expect: ExpectedStatus) {
        let (tx, rx) = mock_recv_stream();
        for item in scenario {
            tx.send(item.clone()).unwrap();
        }

        let handler = UnaryHandler.with_interceptor(RequestValidator::new(true));
        let mut mock_tx = MockSendStream;
        let trailers = handler
            .handle(
                RequestHeaders::new("", test_connection_info()),
                CallOptions::default(),
                &mut mock_tx,
                rx,
            )
            .await;

        match expect {
            ExpectedStatus::Ok => {
                assert!(trailers.status().is_ok());
            }
            ExpectedStatus::Error(expected_code, expected_msg) => {
                let status = trailers
                    .status()
                    .as_ref()
                    .expect_err("expected error status in trailer");
                assert_eq!(status.code(), expected_code);
                assert!(status.message().contains(expected_msg));
            }
        }
    }

    async fn validate_stream_scenario(scenario: &[RequestStreamItem], expect: ExpectedStatus) {
        let (tx, rx) = mock_recv_stream();
        for item in scenario {
            tx.send(item.clone()).unwrap();
        }

        let handler = EchoDrainHandler.with_interceptor(RequestValidator::new(false));
        let mut mock_tx = MockSendStream;
        let trailers = handler
            .handle(
                RequestHeaders::new("", test_connection_info()),
                CallOptions::default(),
                &mut mock_tx,
                rx,
            )
            .await;

        match expect {
            ExpectedStatus::Ok => {
                assert!(trailers.status().is_ok());
            }
            ExpectedStatus::Error(expected_code, expected_msg) => {
                let status = trailers
                    .status()
                    .as_ref()
                    .expect_err("expected error status in trailer");
                assert_eq!(status.code(), expected_code);
                assert!(status.message().contains(expected_msg));
            }
        }
    }

    #[tokio::test]
    async fn test_validator_unary_ok_without_message() {
        let scenarios = [vec![RequestStreamItem::StreamClosed]];

        for scenario in &scenarios {
            validate_unary_scenario(
                scenario,
                ExpectedStatus::Error(
                    StatusCodeError::Internal,
                    "unary stream received zero messages",
                ),
            )
            .await;
        }
    }

    #[tokio::test]
    async fn test_validator_unary_multiple_messages() {
        let scenarios = [vec![RequestStreamItem::Message, RequestStreamItem::Message]];

        for scenario in &scenarios {
            validate_unary_scenario(
                scenario,
                ExpectedStatus::Error(
                    StatusCodeError::Internal,
                    "unary stream received multiple messages",
                ),
            )
            .await;
        }
    }

    #[tokio::test]
    async fn test_validator_successful_unary() {
        let scenarios = [vec![
            RequestStreamItem::Message,
            RequestStreamItem::StreamClosed,
        ]];

        for scenario in &scenarios {
            validate_unary_scenario(scenario, ExpectedStatus::Ok).await;
        }
    }

    #[tokio::test]
    async fn test_validator_erroring_unary() {
        let scenarios = [
            vec![RequestStreamItem::Error],
            vec![RequestStreamItem::Message, RequestStreamItem::Error],
        ];

        for scenario in &scenarios {
            validate_unary_scenario(
                scenario,
                ExpectedStatus::Error(StatusCodeError::Aborted, "handler saw error"),
            )
            .await;
        }
    }

    #[tokio::test]
    async fn test_validator_successful_stream() {
        let scenarios = [vec![
            RequestStreamItem::Message,
            RequestStreamItem::Message,
            RequestStreamItem::Message,
            RequestStreamItem::StreamClosed,
        ]];

        for scenario in &scenarios {
            validate_stream_scenario(scenario, ExpectedStatus::Ok).await;
        }
    }

    #[tokio::test]
    async fn test_validator_erroring_stream() {
        let scenarios = [vec![
            RequestStreamItem::Message,
            RequestStreamItem::Message,
            RequestStreamItem::Error,
        ]];

        for scenario in &scenarios {
            validate_stream_scenario(
                scenario,
                ExpectedStatus::Error(StatusCodeError::Aborted, "handler saw error"),
            )
            .await;
        }
    }

    struct StepHandler {
        steps: Vec<Option<Result<(), ()>>>,
        executed: Arc<AtomicBool>,
    }

    impl Handle for StepHandler {
        async fn handle(
            &self,
            _headers: RequestHeaders,
            _options: CallOptions,
            _tx: &mut impl SendStream,
            mut rx: impl RecvStream + 'static,
        ) -> Trailers {
            for expected in &self.steps {
                assert_eq!(rx.next(&mut NopRecvMessage).await, *expected);
            }
            self.executed.store(true, Ordering::SeqCst);
            Trailers::new(Ok(()))
        }
    }

    async fn validate_terminal_steps(
        is_unary: bool,
        items: &[RequestStreamItem],
        expected_steps: &[Option<Result<(), ()>>],
    ) -> Trailers {
        let executed = Arc::new(AtomicBool::new(false));
        let handler = StepHandler {
            steps: expected_steps.to_vec(),
            executed: executed.clone(),
        }
        .with_interceptor(RequestValidator::new(is_unary));

        let (tx, rx) = mock_recv_stream();
        for item in items {
            tx.send(item.clone()).unwrap();
        }

        let mut mock_tx = MockSendStream;
        let trailers = handler
            .handle(
                RequestHeaders::new("", test_connection_info()),
                CallOptions::default(),
                &mut mock_tx,
                rx,
            )
            .await;

        assert!(executed.load(Ordering::SeqCst));
        trailers
    }

    async fn validate_unary_terminal_steps(
        items: &[RequestStreamItem],
        expected_steps: &[Option<Result<(), ()>>],
    ) -> Trailers {
        validate_terminal_steps(true, items, expected_steps).await
    }

    async fn validate_stream_terminal_steps(
        items: &[RequestStreamItem],
        expected_steps: &[Option<Result<(), ()>>],
    ) -> Trailers {
        validate_terminal_steps(false, items, expected_steps).await
    }

    #[tokio::test]
    async fn test_validator_terminal_state_streaming_done() {
        let trailers =
            validate_stream_terminal_steps(&[RequestStreamItem::StreamClosed], &[None, None]).await;
        assert!(trailers.status().is_ok());
    }

    #[tokio::test]
    async fn test_validator_terminal_state_streaming_error() {
        validate_stream_terminal_steps(
            &[RequestStreamItem::Error],
            &[Some(Err(())), Some(Err(()))],
        )
        .await;
    }

    #[tokio::test]
    async fn test_validator_terminal_state_unary_done() {
        let trailers = validate_unary_terminal_steps(
            &[RequestStreamItem::Message, RequestStreamItem::StreamClosed],
            &[Some(Ok(())), None, None],
        )
        .await;
        assert!(trailers.status().is_ok());
    }

    #[tokio::test]
    async fn test_validator_terminal_state_unary_zero_messages() {
        let trailers = validate_unary_terminal_steps(
            &[RequestStreamItem::StreamClosed],
            &[Some(Err(())), Some(Err(()))],
        )
        .await;
        let status = trailers.status().as_ref().unwrap_err();
        assert_eq!(status.code(), StatusCodeError::Internal);
        assert!(
            status
                .message()
                .contains("unary stream received zero messages")
        );
    }

    #[tokio::test]
    async fn test_validator_terminal_state_unary_multiple_messages() {
        let trailers = validate_unary_terminal_steps(
            &[RequestStreamItem::Message, RequestStreamItem::Message],
            &[Some(Err(())), Some(Err(()))],
        )
        .await;
        let status = trailers.status().as_ref().unwrap_err();
        assert_eq!(status.code(), StatusCodeError::Internal);
        assert!(
            status
                .message()
                .contains("unary stream received multiple messages")
        );
    }
}
