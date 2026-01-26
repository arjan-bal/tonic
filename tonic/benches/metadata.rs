use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tonic::metadata::MetadataMap;
use tonic::metadata::MetadataValue;

fn fill_metadata(map: &mut MetadataMap) {
    map.insert("ascii-1", "value-0001".parse().unwrap());
    map.insert("ascii-2", "value-0002".parse().unwrap());
    map.insert("ascii-3", "value-0003".parse().unwrap());
    map.insert("ascii-4", "value-0004".parse().unwrap());
    map.insert("ascii-5", "value-0005".parse().unwrap());
    map.insert("ascii-6", "value-0006".parse().unwrap());
    map.insert("ascii-7", "value-0007".parse().unwrap());
    map.insert("ascii-8", "value-0008".parse().unwrap());
    map.insert("ascii-9", "value-0009".parse().unwrap());
    map.insert("ascii-10", "value-0010".parse().unwrap());

    map.insert_bin("bin-1-bin", MetadataValue::from_bytes(b"bin-value-1"));
    map.insert_bin("bin-2-bin", MetadataValue::from_bytes(b"bin-value-2"));
    map.insert_bin("bin-3-bin", MetadataValue::from_bytes(b"bin-value-3"));
    map.insert_bin("bin-4-bin", MetadataValue::from_bytes(b"bin-value-4"));
    map.insert_bin("bin-5-bin", MetadataValue::from_bytes(b"bin-value-5"));
}

fn metadata_iter(c: &mut Criterion) {
    let mut map = MetadataMap::new();
    fill_metadata(&mut map);

    c.bench_function("metadata_iter", |b| {
        b.iter(|| {
            for kv in map.iter() {
                black_box(kv);
            }
        })
    });
}

fn metadata_into_headers(c: &mut Criterion) {
    c.bench_function("metadata_into_headers", |b| {
        b.iter(|| {
            let mut map = MetadataMap::new();

            // Insert a few ascii and binary values
            fill_metadata(&mut map);

            // Convert into an http::HeaderMap
            let header_map = map.into_headers();
            black_box(header_map);
        })
    });
}

fn metadata_flow(c: &mut Criterion) {
    c.bench_function("metadata_flow", |b| {
        b.iter(|| {
            let mut map = MetadataMap::new();

            // Insert a few ascii and binary values
            fill_metadata(&mut map);

            // Convert into an http::HeaderMap
            let header_map = map.into_headers();

            // Do the reverse, convert the http::HeaderMap back into a MetadataMap
            map = MetadataMap::from_headers(header_map);
            black_box(map);
        })
    });
}

criterion_group!(benches, metadata_iter, metadata_flow, metadata_into_headers);
criterion_main!(benches);
