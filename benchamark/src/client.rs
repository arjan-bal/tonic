use std::{
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
    usize,
};

use bytes::Bytes;
use hdrhistogram::Histogram;
use nix::sys::{
    resource::{getrusage, Usage, UsageWho},
    time::TimeValLike,
};
use rand::thread_rng;
use rand_distr::{Distribution, Exp};
use tokio::{runtime::Runtime, time};
use tonic::{
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Uri},
    Code, Request, Status,
};

use crate::{
    bytebuf_benchmark_service,
    protobuf_benchmark_service::{self, Payload, SimpleRequest},
    worker::{
        self,
        payload_config::Payload::{BytebufParams, SimpleParams},
        ClientConfig, ClientStats, HistogramData, HistogramParams,
    },
};

pub struct BenchmarkClient {
    histograms: Vec<Arc<Mutex<Histogram<u64>>>>,
    histogram_params: HistogramParams,
    runtime: Option<Runtime>,
    last_reset_time: Instant,
    last_rusage: Usage,
}

#[derive(Debug, Copy, Clone)]
enum PayloadType {
    ByteBuf,
    Protobuf,
}

impl BenchmarkClient {
    pub fn shutdown(&mut self) -> Result<(), Status> {
        // Dropping the runtime will stop all the futures when they yield.
        if let Some(runtime) = self.runtime.take() {
            drop(runtime);
        }
        Ok(())
    }

    pub fn start(config: ClientConfig) -> Result<BenchmarkClient, Status> {
        println!("{:?}", config);
        // Parse and validate the config.

        match config.client_type() {
            worker::ClientType::SyncClient => (),
            worker::ClientType::AsyncClient => (),
            _ => return Err(Status::new(Code::InvalidArgument, "Invalid client_type")),
        };

        let payload_type = config
            .payload_config
            .ok_or(Status::new(Code::InvalidArgument, "payload_config missing"))?
            .payload
            .ok_or(Status::new(Code::InvalidArgument, "payload missing"))?;

        let (payload_req_size, payload_resp_size, payload_type) = match payload_type {
            BytebufParams(params) => (
                params.req_size as usize,
                params.resp_size as usize,
                PayloadType::ByteBuf,
            ),
            SimpleParams(params) => (
                params.req_size as usize,
                params.resp_size as usize,
                PayloadType::Protobuf,
            ),
            _ => {
                return Err(Status::new(
                    tonic::Code::InvalidArgument,
                    format!("unknown payload type: {:?}", payload_type),
                ))
            }
        };

        let load = config
            .load_params
            .ok_or(Status::new(Code::InvalidArgument, "load_params missing"))?
            .load
            .ok_or(Status::new(Code::InvalidArgument, "load missing"))?;

        // If set, perform an open loop, if not perform a closed loop. An open
        // loop asynchronously starts RPCs based on random start times derived
        // from a Poisson distribution. A closed loop performs RPCs in a
        // blocking manner, and runs the next RPC after the previous RPC
        // completes and returns.
        // The time between two events (rpcs) in a Poisson process follows an
        // exponential distribution with parameter λ, where λ represents the
        // number of events per unit time for the poisson process.
        let distribution: Option<Exp<f64>> = match load {
            worker::load_params::Load::ClosedLoop(_) => None,
            worker::load_params::Load::Poisson(poisson_params) => {
                Some(Exp::new(poisson_params.offered_load).map_err(|err| {
                    Status::new(
                        Code::InvalidArgument,
                        format!(
                            "failed to create exponential distribution: {}",
                            err.to_string()
                        ),
                    )
                })?)
            }
        };

        let channel_count = config.client_channels as usize;
        let histogram_params = config.histogram_params.unwrap();

        // Check and set security options.
        let tls = if let Some(params) = &config.security_params {
            Some(if params.use_test_ca {
                let data_dir =
                    std::path::PathBuf::from_iter([std::env!("CARGO_MANIFEST_DIR"), "data"]);
                let pem = std::fs::read_to_string(data_dir.join("tls/ca.pem"))?;
                let ca = Certificate::from_pem(pem);
                ClientTlsConfig::new()
                    .ca_certificate(ca)
                    .domain_name(params.server_host_override.to_string())
            } else {
                ClientTlsConfig::new()
            })
        } else {
            None
        };

        let rpc_count_per_conn = config.outstanding_rpcs_per_channel as usize;

        let thread_count = std::cmp::max(config.async_client_threads as usize, num_cpus::get());
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .thread_name("client-pool")
            .worker_threads(thread_count)
            .enable_all()
            .build()
            .map_err(|err| Status::new(Code::Internal, err.to_string()))?;

        let rpc_type = match config.rpc_type() {
            worker::RpcType::Unary => RpcType::Unary,
            worker::RpcType::Streaming => RpcType::Streaming,
            _ => return Err(Status::new(Code::InvalidArgument, "invalid rpc_type")),
        };

        let num_servers = config.server_targets.len();
        let mut histograms = Vec::with_capacity(channel_count * rpc_count_per_conn);
        for i in 0..channel_count {
            let uri = Uri::from_str(&config.server_targets[i % num_servers]).map_err(|err| {
                Status::new(
                    Code::InvalidArgument,
                    format!("failed to parse URI: {}", err.to_string()),
                )
            })?;
            let endpoint = Channel::builder(uri);
            let endpoint = if let Some(tls) = tls.as_ref() {
                endpoint.tls_config(tls.clone()).map_err(|err| {
                    Status::new(
                        Code::InvalidArgument,
                        format!("bad TLS config: {}", err.to_string()),
                    )
                })?
            } else {
                endpoint
            };

            // Create one histogram per client rpc to minimise contention for
            // the lock. These histograms will be merged when querying stats.
            let mut channel_histograms = Vec::with_capacity(rpc_count_per_conn);

            for _ in 0..rpc_count_per_conn {
                let histogram = Histogram::new_with_max(histogram_params.max_possible as u64, 3)
                    .map_err(|err| {
                        Status::new(
                            Code::InvalidArgument,
                            format!(
                                "failed to build histogram with given max_possible value: {}",
                                err
                            ),
                        )
                    })?;
                let histogram = Arc::new(Mutex::new(histogram));
                channel_histograms.push(histogram.clone());
                histograms.push(histogram.clone());
            }
            let args = TestArgs {
                histograms: channel_histograms,
                distribution: distribution.clone(),
                payload_req_size,
                payload_resp_size,
                endpoint,
                rpc_count_per_conn,
                rpc_type: rpc_type.clone(),
                payload_type,
            };
            runtime.spawn(perform_rpcs(args));
        }

        Ok(BenchmarkClient {
            histograms,
            histogram_params,
            runtime: Some(runtime),
            last_reset_time: Instant::now(),
            last_rusage: getrusage(UsageWho::RUSAGE_SELF).map_err(|err| {
                Status::new(
                    Code::Internal,
                    format!("failed to query system resource usage: {}", err.to_string()),
                )
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
                    Status::new(
                        Code::Internal,
                        format!("error while merging histograms: {}", err.to_string()),
                    )
                })?;
            }
        } else {
            // Merge only, don't reset.
            for histogram in self.histograms.iter() {
                let lock = histogram.lock().unwrap();
                aggregated.add(&*lock).map_err(|err| {
                    Status::new(
                        Code::Internal,
                        format!("error while merging histograms: {}", err.to_string()),
                    )
                })?;
            }
        }

        let now = Instant::now();
        let wall_time_elapsed = now.duration_since(self.last_reset_time);
        let latest_rusage = getrusage(UsageWho::RUSAGE_SELF).map_err(|err| {
            Status::new(
                Code::Internal,
                format!("failed to query system resource usage: {}", err.to_string()),
            )
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
            time_elapsed: wall_time_elapsed.as_nanos() as f64,
            time_user: user_time.num_nanoseconds() as f64,
            time_system: system_time.num_nanoseconds() as f64,
            // The following fields are not set by Java and Go.
            request_results: Vec::new(),
            cq_poll_count: 0,
        })
    }
}

#[derive(Debug)]
struct TestArgs {
    histograms: Vec<Arc<Mutex<Histogram<u64>>>>,
    distribution: Option<Exp<f64>>,
    payload_req_size: usize,
    payload_resp_size: usize,
    endpoint: Endpoint,
    rpc_count_per_conn: usize,
    rpc_type: RpcType,
    payload_type: PayloadType,
}

#[derive(Debug, Clone)]
enum RpcType {
    Unary,
    Streaming,
}

async fn perform_rpcs(args: TestArgs) {
    let client = Client::new(&args).await;
    match args.rpc_type {
        RpcType::Unary => {
            for i in 0..args.rpc_count_per_conn {
                let histogram = args.histograms[i].clone();
                match &args.distribution {
                    Some(distibution) => {
                        // Open loop.
                        tokio::spawn(poisson_unary(
                            client.clone(),
                            distibution.clone(),
                            histogram.clone(),
                        ));
                    }
                    None => {
                        // Closed loop.
                        tokio::spawn(blocking_unary(client.clone(), histogram.clone()));
                    }
                }
            }
        }
        RpcType::Streaming => todo!(),
    };
}

#[derive(Clone, Debug)]
enum Client {
    ProtoClient(ProtoClient),
    ByteBufClient(ByteBufClient),
}

impl Client {
    async fn new(args: &TestArgs) -> Self {
        match args.payload_type {
            PayloadType::ByteBuf => Client::ByteBufClient(ByteBufClient{
               client: bytebuf_benchmark_service::benchmark_service_client::BenchmarkServiceClient::connect(args.endpoint.clone()).await.unwrap(),
            payload_req_size: args.payload_req_size,
            }),
            PayloadType::Protobuf => Client::ProtoClient(ProtoClient{
                client: protobuf_benchmark_service::benchmark_service_client::BenchmarkServiceClient::connect(args.endpoint.clone())
                .await
                .unwrap(),
            payload_req_size: args.payload_req_size,
            payload_resp_size: args.payload_resp_size,
            }),
        }
    }

    async fn unary_call(&mut self) -> Result<(), Status> {
        match self {
            Client::ProtoClient(client) => client.unary_call().await,
            Client::ByteBufClient(client) => client.unary_call().await,
        }
    }
}

#[derive(Clone, Debug)]
struct ProtoClient {
    client: protobuf_benchmark_service::benchmark_service_client::BenchmarkServiceClient<Channel>,
    payload_req_size: usize,
    payload_resp_size: usize,
}

impl ProtoClient {
    fn new_payload(&self) -> Payload {
        Payload {
            r#type: PayloadType::Protobuf as i32,
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

#[derive(Debug, Clone)]
struct ByteBufClient {
    client: bytebuf_benchmark_service::benchmark_service_client::BenchmarkServiceClient<Channel>,
    payload_req_size: usize,
}

impl ByteBufClient {
    async fn unary_call(&mut self) -> Result<(), Status> {
        self.client
            .unary_call(Request::new(Bytes::from(vec![0u8; self.payload_req_size])))
            .await?;
        Ok(())
    }
}

async fn blocking_unary(client: Client, histogram: Arc<Mutex<Histogram<u64>>>) {
    loop {
        let mut client = client.clone();
        let mut histogram = histogram.clone();
        let start = time::Instant::now();
        if let Ok(_) = (&mut client).unary_call().await {
            let elapsed = time::Instant::now().duration_since(start);
            (&mut histogram)
                .lock()
                .unwrap()
                .record(elapsed.as_nanos() as u64)
                .unwrap();
        }
    }
}

async fn poisson_unary(
    client: Client,
    distribution: Exp<f64>,
    histogram: Arc<Mutex<Histogram<u64>>>,
) {
    loop {
        let time_between_rpcs = distribution.sample(&mut thread_rng()) * 1e9;
        time::sleep(Duration::from_nanos(time_between_rpcs.round() as u64)).await;

        let histogram_copy = histogram.clone();
        let mut client_copy = client.clone();
        tokio::spawn(async move {
            let start = time::Instant::now();
            if let Ok(_) = client_copy.unary_call().await {
                let elapsed = time::Instant::now().duration_since(start);
                histogram_copy
                    .lock()
                    .unwrap()
                    .record(elapsed.as_nanos() as u64)
                    .unwrap();
            }
        });
    }
}
