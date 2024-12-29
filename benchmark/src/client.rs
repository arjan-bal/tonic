use std::sync::{Arc, Mutex};

use hdrhistogram::Histogram;
use nix::sys::{
    resource::{getrusage, Usage, UsageWho},
    time::TimeValLike,
};
use tokio_util::sync::CancellationToken;
use tonic::{
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint},
    Request, Status,
};

use crate::{
    protobuf_benchmark_service::{self, Payload, PayloadType, SimpleRequest},
    worker::{
        self,
        payload_config::Payload::{BytebufParams, SimpleParams},
        ClientConfig, ClientStats, HistogramData, HistogramParams,
    },
};

pub struct BenchmarkClient {
    histograms: Vec<Arc<Mutex<Histogram<u64>>>>,
    histogram_params: HistogramParams,
    last_reset_time: std::time::Instant,
    last_rusage: Usage,
    cancellation_token: CancellationToken,
}

impl BenchmarkClient {
    pub fn start(config: ClientConfig) -> Result<BenchmarkClient, Status> {
        println!("{:?}", config);
        // Parse and validate the config.

        match config.client_type() {
            worker::ClientType::SyncClient => (),
            worker::ClientType::AsyncClient => (),
            _ => return Err(Status::invalid_argument("Invalid client_type")),
        };

        let payload_type = config
            .payload_config
            .ok_or(Status::invalid_argument("payload_config missing"))?
            .payload
            .ok_or(Status::invalid_argument("payload missing"))?;

        let (payload_req_size, payload_resp_size) = match payload_type {
            BytebufParams(_) => return Err(Status::unimplemented("bytebuf codec not implemented")),
            SimpleParams(params) => (params.req_size as usize, params.resp_size as usize),
            _ => {
                return Err(Status::invalid_argument(format!(
                    "unknown payload type: {:?}",
                    payload_type
                )))
            }
        };

        let load = config
            .load_params
            .ok_or(Status::invalid_argument("load_params missing"))?
            .load
            .ok_or(Status::invalid_argument("load missing"))?;

        // If set, perform an open loop, if not perform a closed loop. An open
        // loop asynchronously starts RPCs based on random start times derived
        // from a Poisson distribution. A closed loop performs RPCs in a
        // blocking manner, and runs the next RPC after the previous RPC
        // completes and returns.
        match load {
            worker::load_params::Load::ClosedLoop(_) => {}
            worker::load_params::Load::Poisson(_) => {
                // There don't seem to be any test scenarios in the new
                // framework that use this. It can be implemented if the need
                // arises in the future.
                return Err(Status::unimplemented(
                    "Poisson load generation not supported",
                ));
            }
        };

        let channel_count = config.client_channels as usize;
        let histogram_params = config
            .histogram_params
            .ok_or(Status::invalid_argument("missing histogram_params"))?;

        // Check and set security options.
        let tls = if let Some(params) = &config.security_params {
            let tls_config = if params.use_test_ca {
                let data_path = std::env::var("DATA_PATH")
                    .unwrap_or_else(|_| std::env!("CARGO_MANIFEST_DIR").to_string());
                let data_dir = std::path::PathBuf::from_iter([data_path, "data".to_string()]);
                println!("Loading TLS certs from {:?}", data_dir);
                let pem = std::fs::read_to_string(data_dir.join("tls/ca.pem"))?;
                let ca = Certificate::from_pem(pem);
                ClientTlsConfig::new()
                    .ca_certificate(ca)
                    .domain_name(params.server_host_override.to_string())
                    .assume_http2(true)
            } else {
                ClientTlsConfig::new()
            };
            Some(tls_config)
        } else {
            None
        };

        let rpc_count_per_conn = config.outstanding_rpcs_per_channel as usize;

        match config.rpc_type() {
            worker::RpcType::Unary => {}
            worker::RpcType::Streaming => {
                // TODO: Support streaming RPCs.
                return Err(Status::unimplemented("streaming RPCs not supported"));
            }
            _ => return Err(Status::invalid_argument("invalid rpc_type")),
        };

        let num_servers = config.server_targets.len();
        let mut histograms = Vec::with_capacity(channel_count * rpc_count_per_conn);
        let cancellation_token = CancellationToken::new();
        let server_targets: Vec<String> = config
            .server_targets
            .iter()
            .map(|s| {
                if tls.is_some() {
                    format!("https://{}", s)
                } else {
                    format!("http://{}", s)
                }
            })
            .collect();

        for i in 0..channel_count {
            let endpoint =
                Channel::from_shared(server_targets[i % num_servers].clone()).map_err(|err| {
                    Status::invalid_argument(format!(
                        "failed to create channel: {}",
                        err.to_string()
                    ))
                })?;
            let endpoint = if let Some(tls) = tls.as_ref() {
                endpoint.tls_config(tls.clone()).map_err(|err| {
                    Status::invalid_argument(format!("bad TLS config: {}", err.to_string()))
                })?
            } else {
                endpoint
            };

            // Create one histogram per client RPC to minimise contention for
            // the lock. These histograms will be merged when querying stats.
            let mut channel_histograms = Vec::with_capacity(rpc_count_per_conn);

            for _ in 0..rpc_count_per_conn {
                let histogram = Histogram::new_with_max(histogram_params.max_possible as u64, 3)
                    .map_err(|err| {
                        Status::invalid_argument(format!(
                            "failed to build histogram with given max_possible value: {}",
                            err
                        ))
                    })?;
                let histogram = Arc::new(Mutex::new(histogram));
                channel_histograms.push(histogram.clone());
                histograms.push(histogram.clone());
            }
            let args = TestArgs {
                histograms: channel_histograms,
                payload_req_size,
                payload_resp_size,
                endpoint,
                rpc_count_per_conn,
            };
            let cloned_token = cancellation_token.clone();
            tokio::spawn(perform_rpcs(args, cloned_token));
        }

        Ok(BenchmarkClient {
            histograms,
            histogram_params,
            last_reset_time: std::time::Instant::now(),
            cancellation_token,
            last_rusage: getrusage(UsageWho::RUSAGE_SELF).map_err(|err| {
                Status::internal(format!(
                    "failed to query system resource usage: {}",
                    err.to_string()
                ))
            })?,
        })
    }

    pub fn get_stats(&mut self, reset: bool) -> Result<worker::ClientStats, Status> {
        let mut aggregated =
            Histogram::new_with_max(self.histogram_params.max_possible as u64, 3).unwrap();

        if reset {
            // Merging histogram may take some time.
            // Put all histograms aside and merge later.
            for histogram in self.histograms.iter() {
                let new =
                    Histogram::new_with_max(self.histogram_params.max_possible as u64, 3).unwrap();
                let mut lock = histogram.lock().unwrap();
                let old = std::mem::replace(&mut *lock, new);
                drop(lock);
                aggregated.add(old).map_err(|err| {
                    Status::internal(format!(
                        "error while merging histograms: {}",
                        err.to_string()
                    ))
                })?;
            }
        } else {
            // Merge only, don't reset.
            for histogram in self.histograms.iter() {
                let lock = histogram.lock().unwrap();
                aggregated.add(&*lock).map_err(|err| {
                    Status::internal(format!(
                        "error while merging histograms: {}",
                        err.to_string()
                    ))
                })?;
            }
        }

        let now = std::time::Instant::now();
        let wall_time_elapsed = now.duration_since(self.last_reset_time);
        let latest_rusage = getrusage(UsageWho::RUSAGE_SELF).map_err(|err| {
            Status::internal(format!(
                "failed to query system resource usage: {}",
                err.to_string()
            ))
        })?;
        let user_time = latest_rusage.user_time() - self.last_rusage.user_time();
        let system_time = latest_rusage.system_time() - self.last_rusage.system_time();

        if reset {
            self.last_rusage = latest_rusage;
            self.last_reset_time = now;
        }
        let resolution = 1.0 + self.histogram_params.resolution.max(0.01 as f64);
        let mut base = 1 as f64;
        // Calculating the mean and stddev involves iterating over the
        // histogram, so save the values.
        let mean = aggregated.mean() as f64;
        let stddev = aggregated.stdev();
        let variance = stddev * stddev;
        let mut histogram_data = HistogramData {
            bucket: Vec::new(),
            min_seen: aggregated.min() as f64,
            max_seen: aggregated.max() as f64,
            sum: mean * aggregated.len() as f64,
            sum_of_squares: variance * aggregated.len() as f64
                + aggregated.len() as f64 * mean * mean,
            count: aggregated.len() as f64,
        };

        for freq in aggregated.iter_log(1, resolution).skip(1) {
            histogram_data
                .bucket
                .push(freq.count_since_last_iteration() as u32);
            base = base * resolution;
        }

        // The driver expects values for all buckets in the range, not just the
        // range of buckets that have values.
        while base < self.histogram_params.max_possible {
            histogram_data.bucket.push(0);
            base = base * resolution;
        }

        Ok(ClientStats {
            latencies: Some(histogram_data),
            time_elapsed: wall_time_elapsed.as_nanos() as f64 / 1e9,
            time_user: user_time.num_nanoseconds() as f64 / 1e9,
            time_system: system_time.num_nanoseconds() as f64 / 1e9,
            // The following fields are not set by Java and Go.
            request_results: Vec::new(),
            cq_poll_count: 0,
        })
    }
}

impl Drop for BenchmarkClient {
    fn drop(&mut self) {
        println!("Client is being closed");
        self.cancellation_token.cancel();
    }
}

#[derive(Debug)]
struct TestArgs {
    histograms: Vec<Arc<Mutex<Histogram<u64>>>>,
    payload_req_size: usize,
    payload_resp_size: usize,
    endpoint: Endpoint,
    rpc_count_per_conn: usize,
}

async fn perform_rpcs(args: TestArgs, cancellation_token: CancellationToken) {
    let client = match ProtoClient::new(&args).await {
        Ok(client) => client,
        Err(err) => {
            println!("Failed to create client: {:?}", err);
            return;
        }
    };
    for i in 0..args.rpc_count_per_conn {
        let histogram = args.histograms[i].clone();
        let token_copy = cancellation_token.clone();
        tokio::spawn(blocking_unary(client.clone(), histogram, token_copy));
    }
}

#[derive(Clone, Debug)]
struct ProtoClient {
    client: protobuf_benchmark_service::benchmark_service_client::BenchmarkServiceClient<Channel>,
    payload_req_size: usize,
    payload_resp_size: usize,
}

impl ProtoClient {
    async fn new(args: &TestArgs) -> Result<Self, tonic::transport::Error> {
        let channel = args.endpoint.connect().await?;
        Ok(ProtoClient {
            client:
                protobuf_benchmark_service::benchmark_service_client::BenchmarkServiceClient::new(
                    channel,
                ),
            payload_req_size: args.payload_req_size,
            payload_resp_size: args.payload_resp_size,
        })
    }

    fn new_payload(&self) -> Payload {
        Payload {
            r#type: PayloadType::Compressable as i32,
            body: vec![0; self.payload_req_size],
        }
    }

    async fn unary_call(&mut self) -> Result<(), Status> {
        let req = SimpleRequest {
            response_type: protobuf_benchmark_service::PayloadType::Compressable as i32,
            response_size: self.payload_resp_size as i32,
            payload: Some(self.new_payload()),
            fill_username: false,
            fill_oauth_scope: false,
            response_compressed: None,
            response_status: None,
            expect_compressed: None,
            fill_server_id: false,
            fill_grpclb_route_type: false,
            orca_per_query_report: None,
        };
        self.client.unary_call(Request::new(req)).await.and(Ok(()))
    }
}

async fn blocking_unary(
    client: ProtoClient,
    histogram: Arc<Mutex<Histogram<u64>>>,
    cancellation_token: CancellationToken,
) {
    let mut client = client;
    let mut histogram = histogram;
    loop {
        if cancellation_token.is_cancelled() {
            return;
        }
        let start = std::time::Instant::now();
        let res = (&mut client).unary_call().await;
        if res.is_err() {
            continue;
        }
        let elapsed = std::time::Instant::now().duration_since(start);
        (&mut histogram)
            .lock()
            .unwrap()
            .record(elapsed.as_nanos() as u64)
            .expect("Recorded value greater than configured maximum");
    }
}
