#![recursion_limit = "1024"]

pub mod client;
pub mod common;
pub mod stats;

pub mod worker {
    include!(concat!(env!("OUT_DIR"), "/worker_service/grpc.testing.rs"));
}

pub mod benchmark_service {
    include!(concat!(
        env!("OUT_DIR"),
        "/benchmark_service/simple/grpc.testing.rs"
    ));
}
