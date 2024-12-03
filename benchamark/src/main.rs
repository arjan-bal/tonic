use std::pin::Pin;

use crate::worker::worker_service_server::WorkerService;
use clap::Parser;
use tokio::sync::mpsc;
use tokio_stream::Stream;
use tonic::{transport::Server, Response, Status};
use worker::{
    worker_service_server::WorkerServiceServer, ClientArgs, ClientStatus, CoreRequest,
    CoreResponse, ServerArgs, ServerStatus, Void,
};

#[derive(Parser, Debug)]
struct Args {
    /// Port to start load servers on, if not specified by the server config
    #[arg(long = "server_port")]
    server_port: Option<u16>,
    /// Port to expose grpc.testing.WorkerService, Used by driver to initiate work.
    #[arg(long = "driver_port")]
    driver_port: u16,
}

pub mod worker {
    tonic::include_proto!("grpc.testing");
}

#[derive(Debug)]
struct DriverService {
    shutdowon_channel: mpsc::Sender<()>,
}

#[tonic::async_trait]
impl WorkerService for DriverService {
    /// Server streaming response type for the RunServer method.
    type RunServerStream =
        Pin<Box<dyn Stream<Item = Result<ServerStatus, Status>> + Send + 'static>>;

    async fn run_server(
        &self,
        request: tonic::Request<tonic::Streaming<ServerArgs>>,
    ) -> std::result::Result<Response<Self::RunServerStream>, Status> {
        unimplemented!()
    }

    type RunClientStream =
        Pin<Box<dyn Stream<Item = Result<ClientStatus, Status>> + Send + 'static>>;

    async fn run_client(
        &self,
        request: tonic::Request<tonic::Streaming<ClientArgs>>,
    ) -> std::result::Result<Response<Self::RunClientStream>, Status> {
        unimplemented!()
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
        })
        .await?;

    Ok(())
}
