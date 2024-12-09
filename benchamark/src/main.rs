#![recursion_limit = "1024"]

use std::{pin::Pin, time::Duration};

use benchmark::client::BenchmarkClient;
use benchmark::worker::{
    client_args, worker_service_server::WorkerService, worker_service_server::WorkerServiceServer,
    ClientArgs, ClientStatus, CoreRequest, CoreResponse, ServerArgs, ServerStatus, Void,
};
use clap::Parser;
use tokio::{sync::mpsc, time};
use tokio_stream::{Stream, StreamExt};
use tonic::{transport::Server, Response, Status};

#[derive(Parser, Debug)]
struct Args {
    /// Port to start load servers on, if not specified by the server config
    #[arg(long = "server_port")]
    server_port: Option<u16>,
    /// Port to expose grpc.testing.WorkerService, Used by driver to initiate work.
    #[arg(long = "driver_port")]
    driver_port: u16,
}

#[derive(Debug)]
struct DriverService {
    shutdowon_channel: mpsc::Sender<()>,
}

#[tonic::async_trait]
impl WorkerService for DriverService {
    // Server streaming response type for the RunServer method.
    type RunServerStream =
        Pin<Box<dyn Stream<Item = Result<ServerStatus, Status>> + Send + 'static>>;

    async fn run_server(
        &self,
        _request: tonic::Request<tonic::Streaming<ServerArgs>>,
    ) -> std::result::Result<Response<Self::RunServerStream>, Status> {
        unimplemented!()
    }

    type RunClientStream =
        Pin<Box<dyn Stream<Item = Result<ClientStatus, Status>> + Send + 'static>>;

    async fn run_client(
        &self,
        request: tonic::Request<tonic::Streaming<ClientArgs>>,
    ) -> std::result::Result<Response<Self::RunClientStream>, Status> {
        let mut benchmark_client: Option<BenchmarkClient> = None;
        let mut stream = request.into_inner();

        let output = async_stream::try_stream! {
            while let Some(request) = stream.next().await {
                let request = request?;
                let mut reset_stats = false;
                match request.argtype.unwrap() {
                    client_args::Argtype::Setup(client_config) => {
                        if let Some(mut client) = benchmark_client {
                            println!("client setup received when client already exists, shutting down the existing client");
                            client.shutdown()?;
                        }
                        benchmark_client = Some(BenchmarkClient::start(client_config)?);
                    }
                    client_args::Argtype::Mark(mark) => {
                        benchmark_client.as_ref().ok_or(Status::new(tonic::Code::InvalidArgument, "client setup received when client already exists, shutting down the existing client"))?;
                        reset_stats = mark.reset;
                    }
                };
                let stats = benchmark_client.as_mut().unwrap().get_stats(reset_stats)?;
                yield ClientStatus {
                    stats: Some(stats),
                };
            }
        };

        Ok(Response::new(Box::pin(output) as Self::RunClientStream))
    }

    async fn core_count(
        &self,
        _request: tonic::Request<CoreRequest>,
    ) -> std::result::Result<Response<CoreResponse>, Status> {
        return Ok(Response::new(CoreResponse {
            cores: num_cpus::get() as i32,
        }));
    }

    async fn quit_worker(
        &self,
        _request: tonic::Request<Void>,
    ) -> std::result::Result<Response<Void>, Status> {
        match self.shutdowon_channel.send(()).await {
            Ok(()) => Ok(Response::new(Void {})),
            Err(err) => Err(Status::new(
                tonic::Code::Internal,
                format!("failed to stop server: {}", err),
            )),
        }
    }
}

async fn run_worker() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    println!("{:?}", args);

    let addr = format!("127.0.0.1:{}", args.driver_port).parse().unwrap();
    let (tx, mut rx) = mpsc::channel(1);

    let svc = WorkerServiceServer::new(DriverService {
        shutdowon_channel: tx,
    });

    Server::builder()
        .add_service(svc)
        .serve_with_shutdown(addr, async {
            rx.recv().await;
            // Wait for the quit_worker response to be sent.
            time::sleep(Duration::from_secs(1)).await;
        })
        .await?;

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    runtime.block_on(run_worker())?;
    Ok(())
}
