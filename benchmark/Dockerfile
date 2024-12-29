FROM debian:latest
COPY . release/
RUN chmod +x release/benchmark
# Copy TLS certs.
ENV DATA_PATH=/release/
ENTRYPOINT ["/release/benchmark", "--driver_port=50001"]
