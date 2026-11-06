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

//! The LRS worker: one actor per LRS server, which reports the loads recorded
//! in its [`LoadReporter`] over a `StreamLoadStats` stream.
//!
//! A transport loop owns the connection, its retries and the stream I/O, and
//! sends lifecycle events to the actor through a FIFO queue. It also decodes
//! the responses, which depends on no reporting state, and it runs in the
//! actor's task rather than its own. The actor alone owns the reporting state,
//! and handles each event to completion without waiting on I/O. The only strong
//! sender of the queue is held by the [`WorkerHandle`] shared by all the
//! [`LoadStore`]s for the server, and the recorders and call trackers created
//! from them. When the last of them is dropped, the worker sends a final report
//! with the loads recorded since the previous one, and stops.

use std::future::Future;
use std::future::pending;
use std::pin::Pin;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

use crate::client::config::ServerConfig;
use crate::client::retry::Backoff;
use crate::client::retry::RetryPolicy;
use crate::error::Error;
use crate::error::Result;
use crate::lrs::LrsCodec;
use crate::lrs::load_store::ClusterSelection;
use crate::lrs::load_store::LoadReporter;
use crate::lrs::load_store::LoadStore;
use crate::lrs::message::LoadStatsRequest;
use crate::lrs::message::LoadStatsResponse;
use crate::message::Node;
use crate::runtime::Runtime;
use crate::transport::Transport;
use crate::transport::TransportBuilder;
use crate::transport::TransportReceiver;
use crate::transport::TransportSender;

/// The gRPC method of the LRS stream.
const LRS_METHOD: &str = "/envoy.service.load_stats.v3.LoadReportingService/StreamLoadStats";

/// The shortest load reporting interval. Shorter intervals requested by the
/// server are raised to this.
const MIN_LOAD_REPORTING_INTERVAL: Duration = Duration::from_secs(1);

/// Client feature that lets the server set `send_all_clusters`.
const SEND_ALL_CLUSTERS_FEATURE: &str = "envoy.lrs.supports_send_all_clusters";

/// How long to wait for the server to end the stream after the final report,
/// before cancelling the stream anyway.
const FINAL_REPORT_TIMEOUT: Duration = Duration::from_secs(5);

/// Keeps a worker running. Shared, through `LoadStoreInner`, by all the
/// `LoadStore`s for its server and the recorders created from them.
///
/// Holds the only strong sender of the worker's queue. When it's dropped,
/// along with the `LoadStoreInner`, the queue closes once any event being sent
/// has been queued, and the worker exits after handling the queued events and
/// sending a final report.
pub(super) struct WorkerHandle {
    _events: mpsc::UnboundedSender<TransportEvent>,
}

/// What a worker needs to run, from the [`LrsClient`](super::LrsClient).
pub(super) struct WorkerConfig<TB, C, R> {
    pub(super) server: ServerConfig,
    pub(super) node: Node,
    pub(super) transport_builder: Arc<TB>,
    pub(super) codec: Arc<C>,
    pub(super) runtime: R,
    pub(super) retry_policy: RetryPolicy,
}

/// Spawns the worker for `config.server`, and returns the first `LoadStore`
/// for it.
pub(super) fn spawn_worker<TB, C, R>(config: WorkerConfig<TB, C, R>) -> LoadStore
where
    TB: TransportBuilder,
    C: LrsCodec,
    R: Runtime,
{
    let (events_tx, events_rx) = mpsc::unbounded_channel();
    // `events_tx` is the only strong sender of the queue, and it's moved into
    // the `WorkerHandle` below, which ends up in the `LoadStoreInner` shared
    // by every `LoadStore`, recorder and call tracker for this server. The
    // transport loop only holds a weak sender, so it doesn't keep the queue
    // open itself.
    let weak_events = events_tx.downgrade();
    // Load report intervals are measured with the runtime's clock, like the
    // report timers.
    let runtime = config.runtime.clone();
    let (reporter, load_store) = LoadReporter::new(
        Arc::new(move || runtime.now()),
        WorkerHandle { _events: events_tx },
    );
    let transport = run_transport(
        config.runtime.clone(),
        config.transport_builder,
        config.codec.clone(),
        config.server,
        config.retry_policy,
        weak_events,
    );
    let worker = LrsWorker {
        codec: config.codec,
        runtime: config.runtime.clone(),
        node: config.node,
        reporter,
        events_rx,
        stream: None,
    };
    config.runtime.spawn(worker.run(transport));
    load_store
}

/// Inputs to the worker from the transport loop, processed in enqueue order.
///
/// Events of one stream come in Ready -> Response* -> Failed order. Failing to
/// connect sends Failed without Ready. The queue is FIFO, so events of
/// different streams don't interleave.
enum TransportEvent {
    Ready {
        writes: mpsc::UnboundedSender<Bytes>,
        cancel: oneshot::Sender<()>,
    },
    /// A decoded response. A response that can't be decoded ends the stream
    /// instead.
    Response(LoadStatsResponse),
    /// The stream ended, or couldn't be started.
    Failed,
}

/// A pending report timer.
type ReportTimer = Pin<Box<dyn Future<Output = ()> + Send>>;

/// The actor reporting loads to one LRS server.
struct LrsWorker<C, R> {
    codec: Arc<C>,
    runtime: R,
    node: Node,
    reporter: LoadReporter,
    events_rx: mpsc::UnboundedReceiver<TransportEvent>,
    /// The current stream, if any.
    stream: Option<LrsStream>,
}

/// State of one stream, reset on every reconnection. Dropped by the worker to
/// end the stream.
struct LrsStream {
    writes_tx: mpsc::UnboundedSender<Bytes>,
    /// Dropping it ends the stream.
    cancel: oneshot::Sender<()>,
    /// From the latest response, if any.
    config: Option<ReportConfig>,
    /// When the next report is due. Set only while there is a config.
    next_report_timer: Option<ReportTimer>,
    /// Whether the previous report had nothing in it.
    last_report_was_empty: bool,
}

/// What to report, and how often, from a `LoadStatsResponse`.
struct ReportConfig {
    clusters: ClusterSelection,
    interval: Duration,
}

impl ReportConfig {
    fn new(response: LoadStatsResponse) -> Self {
        let clusters = if response.send_all_clusters {
            ClusterSelection::All
        } else {
            ClusterSelection::Only(response.clusters.into_iter().collect())
        };
        Self {
            clusters,
            interval: response
                .load_reporting_interval
                .max(MIN_LOAD_REPORTING_INTERVAL),
        }
    }
}

impl<C: LrsCodec, R: Runtime> LrsWorker<C, R> {
    /// Runs the worker until the last `LoadStore` for its server is dropped.
    ///
    /// `transport` is polled in this task, alongside the queue: event handlers
    /// never await, so they never hold it up. Returning drops it, which ends
    /// its stream, if any.
    async fn run(mut self, transport: impl Future<Output = ()> + Send) {
        let mut transport = pin!(transport);
        loop {
            tokio::select! {
                event = self.events_rx.recv() => match event {
                    Some(event) => self.handle_transport_event(event),
                    // The `WorkerHandle`, and so the queue's only strong
                    // sender, was dropped with the last `LoadStoreInner`, and
                    // every queued event has been handled.
                    None => break,
                },
                () = wait_for(self.stream.as_mut().and_then(|s| s.next_report_timer.as_mut())) => {
                    self.send_report();
                }
                // The transport retries forever, so it only stops once the
                // `WorkerHandle` is gone and it has no stream. No report can
                // be sent then.
                () = &mut transport => return,
            }
        }
        // Every `LoadStore`, recorder and call tracker for the server is gone.
        self.send_final_report(transport).await;
    }

    fn handle_transport_event(&mut self, event: TransportEvent) {
        match event {
            TransportEvent::Ready { writes, cancel } => {
                let request = LoadStatsRequest::new(&self.node)
                    .with_client_features(&[SEND_ALL_CLUSTERS_FEATURE]);
                // If the initial request can't be sent, dropping the stream
                // ends it.
                if send_request(&*self.codec, &writes, &request).is_ok() {
                    self.stream = Some(LrsStream {
                        writes_tx: writes,
                        cancel,
                        config: None,
                        next_report_timer: None,
                        last_report_was_empty: false,
                    });
                }
            }
            TransportEvent::Response(response) => {
                // Ignore responses from a stream the worker ended.
                let Some(stream) = &mut self.stream else {
                    return;
                };
                let config = ReportConfig::new(response);
                // Restart the timer only if the interval changed. Other changes
                // apply from the next report.
                let restart_timer = stream
                    .config
                    .as_ref()
                    .is_none_or(|current| current.interval != config.interval);
                if restart_timer {
                    stream.next_report_timer = Some(report_timer(&self.runtime, config.interval));
                }
                stream.config = Some(config);
            }
            TransportEvent::Failed => self.stream = None,
        }
    }

    /// Sends a load report, when the stream's report timer fires, unless both
    /// this one and the previous one are empty, and schedules the next one.
    fn send_report(&mut self) {
        let Some(stream) = &mut self.stream else {
            return;
        };
        // The timer fired. It's set again once the report is queued.
        stream.next_report_timer = None;
        let Some(interval) = stream.config.as_ref().map(|config| config.interval) else {
            return;
        };
        if report(&mut self.reporter, &*self.codec, &self.node, stream).is_err() {
            // Dropping the stream ends it.
            self.stream = None;
            return;
        }
        stream.next_report_timer = Some(report_timer(&self.runtime, interval));
    }

    /// Sends the loads recorded since the previous report, if the stream has
    /// a config. Then half-closes the stream, and polls `transport` until the
    /// server ends the stream, for at most [`FINAL_REPORT_TIMEOUT`], before
    /// cancelling it.
    async fn send_final_report(&mut self, transport: Pin<&mut impl Future<Output = ()>>) {
        let Some(mut stream) = self.stream.take() else {
            return;
        };
        let Ok(true) = report(&mut self.reporter, &*self.codec, &self.node, &mut stream) else {
            return;
        };
        // Closing the write queue half-closes the stream once the queued
        // requests are written. The transport then reads until the server
        // ends the stream, and stops. Keep `cancel` until then, or until the
        // timeout: cancelling the stream earlier could discard the report.
        let LrsStream {
            writes_tx: writes,
            cancel,
            ..
        } = stream;
        drop(writes);
        tokio::select! {
            () = transport => {}
            () = self.runtime.sleep(FINAL_REPORT_TIMEOUT) => {}
        }
        drop(cancel);
    }
}

/// Sends a load report on `stream`, unless both it and the previous one are
/// empty, or the stream has no config. Returns whether a report was sent.
fn report<C: LrsCodec>(
    reporter: &mut LoadReporter,
    codec: &C,
    node: &Node,
    stream: &mut LrsStream,
) -> Result<bool> {
    let Some(config) = &stream.config else {
        return Ok(false);
    };
    let reports = reporter.snapshot(&config.clusters);
    let is_empty = reports.is_empty();
    let skip = is_empty && stream.last_report_was_empty;
    stream.last_report_was_empty = is_empty;
    if skip {
        return Ok(false);
    }
    let request = LoadStatsRequest::new(node).with_cluster_stats(&reports);
    send_request(codec, &stream.writes_tx, &request)?;
    Ok(true)
}

/// Waits for `timer`, or forever if there's none.
async fn wait_for(timer: Option<&mut ReportTimer>) {
    match timer {
        Some(timer) => timer.await,
        None => pending().await,
    }
}

fn report_timer<R: Runtime>(runtime: &R, interval: Duration) -> ReportTimer {
    let runtime = runtime.clone();
    Box::pin(async move { runtime.sleep(interval).await })
}

/// Encodes `request` and queues it on the stream.
fn send_request<C: LrsCodec>(
    codec: &C,
    writes: &mpsc::UnboundedSender<Bytes>,
    request: &LoadStatsRequest<'_>,
) -> Result<()> {
    let bytes = codec.encode_load_stats_request(request)?;
    writes.send(bytes).map_err(|_| Error::StreamClosed)
}

/// Sends `event` to the worker, unless it has stopped.
///
/// The upgraded sender is strong only for the duration of the send, so it
/// can delay closing the queue only briefly. Upgrading fails once the
/// `WorkerHandle` is gone.
fn send_event(
    events: &mpsc::WeakUnboundedSender<TransportEvent>,
    event: TransportEvent,
) -> Result<()> {
    events
        .upgrade()
        .ok_or(Error::StreamClosed)?
        .send(event)
        .map_err(|_| Error::StreamClosed)
}

/// Connects to the server and runs streams, reconnecting with backoff
/// forever, until the worker stops. Never reads or changes the reporting
/// state.
async fn run_transport<R: Runtime, TB: TransportBuilder, C: LrsCodec>(
    runtime: R,
    transport_builder: Arc<TB>,
    codec: Arc<C>,
    server: ServerConfig,
    retry_policy: RetryPolicy,
    events: mpsc::WeakUnboundedSender<TransportEvent>,
) {
    let mut backoff = Backoff::new(retry_policy);
    loop {
        let saw_response = if let Ok(transport) = transport_builder.build(&server).await
            && let Ok((tx, rx)) = transport.new_stream(LRS_METHOD).await
        {
            let (writes, write_rx) = mpsc::unbounded_channel();
            let (cancel, cancelled) = oneshot::channel();
            let ready = TransportEvent::Ready { writes, cancel };
            if send_event(&events, ready).is_err() {
                return;
            }
            run_stream::<TB::Transport, _>(tx, rx, write_rx, cancelled, &*codec, &events).await
        } else {
            false
        };

        if send_event(&events, TransportEvent::Failed).is_err() {
            return;
        }
        if saw_response {
            backoff.reset();
        }
        runtime.sleep(backoff.next_backoff()).await;
    }
}

/// Writes queued requests, and forwards decoded responses to the worker. It
/// runs until one of the following happens:
/// * the stream fails,
/// * a response can't be decoded,
/// * the server ends the stream, or
/// * the worker cancels it.
///
/// It returns whether a response was decoded, however the stream ended.
///
/// Once the worker closes the write queue, after its final report, the stream
/// is half-closed when the queued requests have been written, and responses
/// are read until the server ends the stream. Dropping the receiving half
/// instead may cancel the call, and discard requests that the transport has
/// accepted but not yet sent.
async fn run_stream<T: Transport, C: LrsCodec>(
    mut stream_tx: T::Sender,
    mut stream_rx: T::Receiver,
    mut writes_rx: mpsc::UnboundedReceiver<Bytes>,
    cancelled: oneshot::Receiver<()>,
    codec: &C,
    events_tx: &mpsc::WeakUnboundedSender<TransportEvent>,
) -> bool {
    let mut saw_response = false;
    let read_loop = async {
        while let Ok(Some(bytes)) = stream_rx.recv().await {
            // An invalid response ends the stream.
            let Ok(response) = codec.decode_load_stats_response(bytes) else {
                break;
            };
            saw_response = true;
            // Once the worker has stopped, no one handles responses, but
            // reading continues until the server ends the stream, or the
            // worker stops waiting for it to.
            let _ = send_event(events_tx, TransportEvent::Response(response));
        }
    };
    let io = async {
        // Polled by reference, so that a receive in progress when the write
        // loop finishes isn't cancelled.
        let mut read_loop = pin!(read_loop);
        // Returns whether the worker closed the queue, after every request
        // was written.
        let write_loop = async {
            while let Some(bytes) = writes_rx.recv().await {
                if stream_tx.send(bytes).await.is_err() {
                    return false;
                }
            }
            true
        };
        tokio::select! {
            queue_closed = write_loop => {
                if !queue_closed {
                    // The stream failed.
                    return;
                }
            }
            () = &mut read_loop => return,
        }
        // Every queued request was written, and the worker closed the queue:
        // it has sent its final report, or dropped the stream, which also
        // cancels it. Half-close the stream, and read until the server ends it.
        drop(stream_tx);
        read_loop.await;
    };
    tokio::select! {
        () = io => {}
        _ = cancelled => {}
    }
    saw_response
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use tokio::time::Instant;
    use tokio::time::sleep;
    use tokio::time::timeout;

    use super::*;
    use crate::lrs::CallOutcome;
    use crate::lrs::LrsClient;
    use crate::lrs::message::ClusterStats;
    use crate::message::Locality;
    use crate::runtime::tokio::TokioRuntime;
    use crate::transport::mock::MockServer;
    use crate::transport::mock::mock_transport;

    const SERVER: &str = "lrs.example.com";

    impl WorkerHandle {
        /// Returns a handle that keeps no worker running, for testing load
        /// stores without a worker.
        pub(in crate::lrs) fn detached() -> Self {
            Self {
                _events: mpsc::unbounded_channel().0,
            }
        }
    }

    /// A request encoded by [`FakeCodec`].
    #[derive(Debug, Clone)]
    struct RecordedRequest {
        node_id: Option<String>,
        client_features: Vec<String>,
        cluster_stats: Vec<ClusterStats>,
    }

    /// An `LrsCodec` without a wire format: requests are recorded and encoded
    /// as their index, and responses are registered by the test, which gets
    /// back the bytes to send.
    #[derive(Clone, Default)]
    struct FakeCodec {
        state: Arc<Mutex<FakeCodecState>>,
    }

    #[derive(Default)]
    struct FakeCodecState {
        requests: Vec<RecordedRequest>,
        responses: Vec<LoadStatsResponse>,
    }

    impl FakeCodec {
        /// Returns the request encoded as `bytes`.
        fn request(&self, bytes: &Bytes) -> RecordedRequest {
            let index: usize = std::str::from_utf8(bytes)
                .ok()
                .and_then(|s| s.strip_prefix("req:"))
                .and_then(|i| i.parse().ok())
                .expect("bytes of a request encoded by FakeCodec");
            self.state.lock().unwrap().requests[index].clone()
        }

        /// Registers `response`, and returns the bytes that decode to it.
        fn response(&self, response: LoadStatsResponse) -> Bytes {
            let mut state = self.state.lock().unwrap();
            state.responses.push(response);
            Bytes::from(format!("resp:{}", state.responses.len() - 1))
        }
    }

    impl LrsCodec for FakeCodec {
        fn encode_load_stats_request(&self, request: &LoadStatsRequest<'_>) -> Result<Bytes> {
            let mut state = self.state.lock().unwrap();
            state.requests.push(RecordedRequest {
                node_id: request.node.id.clone(),
                client_features: request
                    .client_features
                    .iter()
                    .map(|f| f.to_string())
                    .collect(),
                cluster_stats: request.cluster_stats.to_vec(),
            });
            Ok(Bytes::from(format!("req:{}", state.requests.len() - 1)))
        }

        fn decode_load_stats_response(&self, bytes: Bytes) -> Result<LoadStatsResponse> {
            let state = self.state.lock().unwrap();
            std::str::from_utf8(&bytes)
                .ok()
                .and_then(|s| s.strip_prefix("resp:"))
                .and_then(|i| i.parse::<usize>().ok())
                .and_then(|i| state.responses.get(i).cloned())
                .ok_or_else(|| Error::Validation("invalid response".into()))
        }
    }

    struct Harness {
        client: LrsClient,
        codec: FakeCodec,
        servers: mpsc::UnboundedReceiver<MockServer>,
    }

    impl Harness {
        fn new() -> Self {
            let (transport_builder, servers) = mock_transport();
            let codec = FakeCodec::default();
            let node = Node::new("test", "1.0").with_id("node-1");
            let retry_policy = RetryPolicy::default()
                .with_jitter(0.0)
                .expect("valid jitter");
            let client = LrsClient::builder(node, transport_builder, codec.clone(), TokioRuntime)
                .with_retry_policy(retry_policy)
                .build();
            Self {
                client,
                codec,
                servers,
            }
        }

        fn load_store(&self, server: &str) -> LoadStore {
            self.client.load_store(&ServerConfig::new(server))
        }

        async fn next_stream(&mut self) -> MockServer {
            self.servers.recv().await.expect("a new stream")
        }

        /// Returns the next stream, after checking its initial request.
        async fn next_stream_with_initial_request(&mut self) -> MockServer {
            let mut server = self.next_stream().await;
            let request = self.next_request(&mut server).await;
            assert!(request.cluster_stats.is_empty());
            server
        }

        async fn next_request(&self, server: &mut MockServer) -> RecordedRequest {
            let bytes = server.requests.recv().await.expect("a request");
            self.codec.request(&bytes)
        }

        fn respond(&self, server: &MockServer, response: LoadStatsResponse) {
            let bytes = self.codec.response(response);
            server.responses.send(Ok(Some(bytes))).unwrap();
        }
    }

    /// Fails if a request arrives within `duration`.
    async fn expect_no_request(server: &mut MockServer, duration: Duration) {
        let result = timeout(duration, server.requests.recv()).await;
        assert!(result.is_err(), "unexpected request: {result:?}");
    }

    fn all_clusters(interval: Duration) -> LoadStatsResponse {
        LoadStatsResponse::new(interval).with_send_all_clusters(true)
    }

    fn record_call(store: &LoadStore, cluster: &str) {
        let locality = Locality::default();
        store
            .locality_stats(cluster, "eds", &locality, Arc::default())
            .start_call()
            .finish(CallOutcome::Succeeded);
    }

    fn cluster_names(request: &RecordedRequest) -> Vec<&str> {
        let mut names: Vec<_> = request
            .cluster_stats
            .iter()
            .map(|s| s.cluster_name.as_str())
            .collect();
        names.sort_unstable();
        names
    }

    fn issued_calls(request: &RecordedRequest) -> u64 {
        request
            .cluster_stats
            .iter()
            .flat_map(|s| &s.upstream_locality_stats)
            .map(|l| l.total_issued_requests)
            .sum()
    }

    #[tokio::test(start_paused = true)]
    async fn opens_lrs_stream_with_initial_request() {
        let mut harness = Harness::new();
        let _store = harness.load_store(SERVER);
        let mut server = harness.next_stream().await;
        assert_eq!(server.method, LRS_METHOD);

        let request = harness.next_request(&mut server).await;
        assert_eq!(request.node_id.as_deref(), Some("node-1"));
        assert_eq!(request.client_features, [SEND_ALL_CLUSTERS_FEATURE]);
        assert!(request.cluster_stats.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn no_reports_before_first_response() {
        let mut harness = Harness::new();
        let store = harness.load_store(SERVER);
        let mut server = harness.next_stream_with_initial_request().await;
        record_call(&store, "a");
        expect_no_request(&mut server, Duration::from_secs(60)).await;
    }

    #[tokio::test(start_paused = true)]
    async fn reports_at_interval() {
        let mut harness = Harness::new();
        let store = harness.load_store(SERVER);
        let mut server = harness.next_stream_with_initial_request().await;
        record_call(&store, "a");

        let start = Instant::now();
        harness.respond(&server, all_clusters(Duration::from_secs(10)));
        let request = harness.next_request(&mut server).await;
        assert_eq!(start.elapsed(), Duration::from_secs(10));
        assert_eq!(cluster_names(&request), ["a"]);
        assert_eq!(issued_calls(&request), 1);
        assert_eq!(
            request.cluster_stats[0].load_report_interval,
            Duration::from_secs(10)
        );

        // The next report is due one interval later.
        record_call(&store, "a");
        record_call(&store, "a");
        let request = harness.next_request(&mut server).await;
        assert_eq!(start.elapsed(), Duration::from_secs(20));
        assert_eq!(issued_calls(&request), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn reports_selected_clusters() {
        let mut harness = Harness::new();
        let store = harness.load_store(SERVER);
        let mut server = harness.next_stream_with_initial_request().await;
        record_call(&store, "a");
        record_call(&store, "b");
        record_call(&store, "c");

        let response = LoadStatsResponse::new(Duration::from_secs(1))
            .with_clusters(vec!["a".to_owned(), "c".to_owned()]);
        harness.respond(&server, response);
        let request = harness.next_request(&mut server).await;
        assert_eq!(cluster_names(&request), ["a", "c"]);
    }

    #[tokio::test(start_paused = true)]
    async fn applies_later_responses() {
        let mut harness = Harness::new();
        let store = harness.load_store(SERVER);
        let mut server = harness.next_stream_with_initial_request().await;
        record_call(&store, "a");
        record_call(&store, "b");

        let start = Instant::now();
        harness.respond(&server, all_clusters(Duration::from_secs(10)));
        sleep(Duration::from_secs(5)).await;

        // A new interval restarts the timer from when it arrives, and new
        // clusters apply from the next report.
        let response =
            LoadStatsResponse::new(Duration::from_secs(4)).with_clusters(vec!["b".to_owned()]);
        harness.respond(&server, response.clone());
        let request = harness.next_request(&mut server).await;
        assert_eq!(start.elapsed(), Duration::from_secs(9));
        assert_eq!(cluster_names(&request), ["b"]);

        // An identical response doesn't restart the timer.
        sleep(Duration::from_secs(2)).await;
        harness.respond(&server, response);
        record_call(&store, "b");
        let request = harness.next_request(&mut server).await;
        assert_eq!(start.elapsed(), Duration::from_secs(13));
        assert_eq!(cluster_names(&request), ["b"]);
    }

    #[tokio::test(start_paused = true)]
    async fn clamps_short_intervals() {
        for interval in [Duration::ZERO, Duration::from_millis(100)] {
            let mut harness = Harness::new();
            let _store = harness.load_store(SERVER);
            let mut server = harness.next_stream_with_initial_request().await;

            let start = Instant::now();
            harness.respond(&server, all_clusters(interval));
            harness.next_request(&mut server).await;
            assert_eq!(start.elapsed(), MIN_LOAD_REPORTING_INTERVAL, "{interval:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn skips_consecutive_empty_reports() {
        let mut harness = Harness::new();
        let store = harness.load_store(SERVER);
        let mut server = harness.next_stream_with_initial_request().await;

        let start = Instant::now();
        harness.respond(&server, all_clusters(Duration::from_secs(1)));
        // The first empty report is sent, so the server learns load is zero.
        let request = harness.next_request(&mut server).await;
        assert_eq!(start.elapsed(), Duration::from_secs(1));
        assert!(request.cluster_stats.is_empty());

        // The second one isn't.
        expect_no_request(&mut server, Duration::from_millis(1500)).await;

        // Reports resume once there is load.
        record_call(&store, "a");
        let request = harness.next_request(&mut server).await;
        assert_eq!(start.elapsed(), Duration::from_secs(3));
        assert_eq!(issued_calls(&request), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn closes_stream_on_invalid_response() {
        let mut harness = Harness::new();
        let _store = harness.load_store(SERVER);
        let mut server = harness.next_stream_with_initial_request().await;
        harness.respond(&server, all_clusters(Duration::from_secs(10)));

        // The stream is closed, without a report, and a new one is started
        // after the backoff.
        let start = Instant::now();
        server
            .responses
            .send(Ok(Some(Bytes::from_static(b"invalid"))))
            .unwrap();
        assert!(server.requests.recv().await.is_none());
        harness.next_stream_with_initial_request().await;
        assert_eq!(start.elapsed(), Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn reconnects_after_stream_failure() {
        let mut harness = Harness::new();
        let store = harness.load_store(SERVER);
        let mut server = harness.next_stream_with_initial_request().await;
        harness.respond(&server, all_clusters(Duration::from_secs(1)));
        harness.next_request(&mut server).await;

        // Loads recorded while disconnected are reported on the next stream.
        let start = Instant::now();
        server
            .responses
            .send(Err(Error::Connection("broken".into())))
            .unwrap();
        record_call(&store, "a");
        let mut server = harness.next_stream().await;
        // The stream saw a response, so the backoff was reset to 1s.
        assert_eq!(start.elapsed(), Duration::from_secs(1));
        let request = harness.next_request(&mut server).await;
        assert_eq!(request.client_features, [SEND_ALL_CLUSTERS_FEATURE]);
        assert!(request.cluster_stats.is_empty());

        harness.respond(&server, all_clusters(Duration::from_secs(1)));
        let request = harness.next_request(&mut server).await;
        assert_eq!(issued_calls(&request), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn resets_backoff_only_after_valid_response() {
        let mut harness = Harness::new();
        let _store = harness.load_store(SERVER);
        let fail = |server: &MockServer| {
            server
                .responses
                .send(Err(Error::Connection("broken".into())))
                .unwrap();
        };

        // Streams without a valid response double the backoff. An invalid
        // response ends the stream, like an error.
        let server = harness.next_stream_with_initial_request().await;
        let start = Instant::now();
        fail(&server);
        let server = harness.next_stream_with_initial_request().await;
        assert_eq!(start.elapsed(), Duration::from_secs(1));
        let start = Instant::now();
        server
            .responses
            .send(Ok(Some(Bytes::from_static(b"invalid"))))
            .unwrap();
        let server = harness.next_stream_with_initial_request().await;
        assert_eq!(start.elapsed(), Duration::from_secs(2));

        // A valid response resets it.
        harness.respond(&server, all_clusters(Duration::from_secs(10)));
        let start = Instant::now();
        fail(&server);
        harness.next_stream_with_initial_request().await;
        assert_eq!(start.elapsed(), Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn sends_final_report_when_load_stores_dropped() {
        let mut harness = Harness::new();
        let store = harness.load_store(SERVER);
        let mut server = harness.next_stream_with_initial_request().await;
        harness.respond(&server, all_clusters(Duration::from_secs(10)));
        // Let the worker apply the response.
        sleep(Duration::from_secs(1)).await;
        record_call(&store, "a");

        // The loads are reported right away, rather than at the next
        // interval, and the stream is half-closed after that.
        let start = Instant::now();
        drop(store);
        let request = harness.next_request(&mut server).await;
        assert_eq!(start.elapsed(), Duration::ZERO);
        assert_eq!(issued_calls(&request), 1);
        assert!(server.requests.recv().await.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn reports_calls_finishing_after_load_stores_dropped() {
        let mut harness = Harness::new();
        let store = harness.load_store(SERVER);
        let mut server = harness.next_stream_with_initial_request().await;
        harness.respond(&server, all_clusters(Duration::from_secs(1)));
        let tracker = store
            .locality_stats("a", "eds", &Locality::default(), Arc::default())
            .start_call();
        drop(store);

        // The call in progress keeps reporting running.
        let request = harness.next_request(&mut server).await;
        let locality = &request.cluster_stats[0].upstream_locality_stats[0];
        assert_eq!(locality.total_requests_in_progress, 1);

        // Its end is in the final report.
        tracker.finish(CallOutcome::Succeeded);
        let request = harness.next_request(&mut server).await;
        let locality = &request.cluster_stats[0].upstream_locality_stats[0];
        assert_eq!(locality.total_successful_requests, 1);
        assert_eq!(locality.total_requests_in_progress, 0);
        assert!(server.requests.recv().await.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn final_report_waits_for_server_to_end_stream() {
        let mut harness = Harness::new();
        let store = harness.load_store(SERVER);
        let mut server = harness.next_stream_with_initial_request().await;
        harness.respond(&server, all_clusters(Duration::from_secs(10)));
        sleep(Duration::from_secs(1)).await;
        record_call(&store, "a");

        drop(store);
        harness.next_request(&mut server).await;
        // The stream is half-closed after the final report, but not
        // cancelled, which could discard the report: it's still read.
        assert!(server.requests.recv().await.is_none());
        assert!(!server.responses.is_closed(), "stream was cancelled");

        // It ends when the server ends it.
        let start = Instant::now();
        server.responses.send(Ok(None)).unwrap();
        server.responses.closed().await;
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn final_report_cancels_stream_after_timeout() {
        let mut harness = Harness::new();
        let store = harness.load_store(SERVER);
        let mut server = harness.next_stream_with_initial_request().await;
        harness.respond(&server, all_clusters(Duration::from_secs(10)));
        sleep(Duration::from_secs(1)).await;
        record_call(&store, "a");

        // If the server doesn't end the stream after the final report, the
        // stream is cancelled.
        let start = Instant::now();
        drop(store);
        harness.next_request(&mut server).await;
        server.responses.closed().await;
        assert_eq!(start.elapsed(), FINAL_REPORT_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn final_report_written_despite_response_after_load_stores_dropped() {
        let mut harness = Harness::new();
        let store = harness.load_store(SERVER);
        let mut server = harness.next_stream_with_initial_request().await;
        harness.respond(&server, all_clusters(Duration::from_secs(10)));
        sleep(Duration::from_secs(1)).await;
        record_call(&store, "a");

        // A response that the stopping worker can't handle doesn't end the
        // stream before the final report is written.
        harness.respond(&server, all_clusters(Duration::from_secs(10)));
        drop(store);
        let request = harness.next_request(&mut server).await;
        assert_eq!(issued_calls(&request), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn stops_when_load_stores_dropped() {
        let mut harness = Harness::new();
        let store = harness.load_store(SERVER);
        let clone = store.clone();
        let mut server = harness.next_stream_with_initial_request().await;

        drop(store);
        expect_no_request(&mut server, Duration::from_secs(10)).await;
        drop(clone);
        let closed = timeout(Duration::from_secs(10), server.requests.recv()).await;
        assert!(matches!(closed, Ok(None)), "stream still open: {closed:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn shares_worker_per_server() {
        let mut harness = Harness::new();
        let first = harness.load_store(SERVER);
        let second = harness.load_store(SERVER);
        let mut server = harness.next_stream_with_initial_request().await;
        let other = timeout(Duration::from_secs(10), harness.servers.recv()).await;
        assert!(other.is_err(), "a second stream was opened");

        record_call(&first, "a");
        record_call(&second, "a");
        harness.respond(&server, all_clusters(Duration::from_secs(1)));
        let request = harness.next_request(&mut server).await;
        assert_eq!(issued_calls(&request), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn shares_worker_kept_alive_by_recorders() {
        let mut harness = Harness::new();
        let store = harness.load_store(SERVER);
        let _recorder = store.cluster_level_stats("a", "eds");
        // Keep the stream open.
        let _server = harness.next_stream_with_initial_request().await;
        drop(store);

        // The recorder keeps the worker running, so it is reused.
        let _store = harness.load_store(SERVER);
        let other = timeout(Duration::from_secs(10), harness.servers.recv()).await;
        assert!(other.is_err(), "a second stream was opened");
    }

    #[tokio::test(start_paused = true)]
    async fn separate_workers_per_server() {
        let mut harness = Harness::new();
        let _first = harness.load_store("lrs1.example.com");
        let _second = harness.load_store("lrs2.example.com");
        harness.next_stream_with_initial_request().await;
        harness.next_stream_with_initial_request().await;
    }

    #[tokio::test(start_paused = true)]
    async fn restarts_worker_after_load_stores_dropped() {
        let mut harness = Harness::new();
        let store = harness.load_store(SERVER);
        let mut server = harness.next_stream_with_initial_request().await;
        drop(store);
        assert!(server.requests.recv().await.is_none());

        let _store = harness.load_store(SERVER);
        harness.next_stream_with_initial_request().await;
    }
}
