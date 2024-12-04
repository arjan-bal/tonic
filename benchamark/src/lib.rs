#![recursion_limit = "1024"]

pub mod benchmark_client;

pub mod worker {
    tonic::include_proto!("grpc.testing");
}
