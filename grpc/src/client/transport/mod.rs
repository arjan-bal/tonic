use std::{sync::Arc, time::Duration};

use crate::{rt::Runtime, service::Service};

mod registry;
mod tonic;

use ::tonic::async_trait;
pub use registry::{TransportRegistry, GLOBAL_TRANSPORT_REGISTRY};
use tokio::sync::oneshot;

pub struct ConnectedTransport {
    pub service: Box<dyn Service>,
    pub disconnection_listener: oneshot::Receiver<Result<(), String>>,
}

#[derive(Default)]
pub struct TransportOptions {
    pub init_stream_window_size: Option<u32>,
    pub init_connection_window_size: Option<u32>,
    pub http2_keep_alive_interval: Option<Duration>,
    pub http2_keep_alive_timeout: Option<Duration>,
    pub http2_keep_alive_while_idle: Option<bool>,
    pub http2_max_header_list_size: Option<u32>,
    pub http2_adaptive_window: Option<bool>,
    pub concurrency_limit: Option<usize>,
    pub rate_limit: Option<(u64, Duration)>,
    pub tcp_keepalive: Option<Duration>,
    pub tcp_nodelay: bool,
    pub connect_timeout: Option<Duration>,
}

#[async_trait]
pub trait Transport: Send + Sync {
    async fn connect(
        &self,
        address: String,
        runtime: Arc<dyn Runtime>,
        opts: &TransportOptions,
    ) -> Result<ConnectedTransport, String>;
}
