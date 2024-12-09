use std::{env, path::PathBuf};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let worker_service = out_dir.join("worker_service");
    let _ = std::fs::create_dir(worker_service.clone()); // This will panic below if the directory failed to create
    tonic_build::configure()
        .out_dir(worker_service)
        .compile_protos(
            &["proto/grpc/testing/worker_service.proto"],
            &["proto/grpc/testing/"],
        )
        .unwrap();

    let behchmark_service_path = out_dir.join("benchmark_service");
    let _ = std::fs::create_dir(behchmark_service_path.clone());

    let protobuf_copy = behchmark_service_path.join("protobuf");
    let _ = std::fs::create_dir(protobuf_copy.clone());
    tonic_build::configure()
        .out_dir(protobuf_copy)
        .compile_protos(
            &["proto/grpc/testing/benchmark_service.proto"],
            &["proto/grpc/testing/"],
        )
        .unwrap();

    build_bytebuf_codec_service();
}

fn build_bytebuf_codec_service() {
    let benchmark_service = tonic_build::manual::Service::builder()
        .name("BenchmarkService")
        .package("bytebuf.grpc.testing")
        .method(
            tonic_build::manual::Method::builder()
                .name("unary_call")
                .route_name("UnaryCall")
                .input_type("bytes::Bytes")
                .output_type("bytes::Bytes")
                .codec_path("crate::common::BytesCodec")
                .build(),
        )
        .build();

    tonic_build::manual::Builder::new().compile(&[benchmark_service]);
}
