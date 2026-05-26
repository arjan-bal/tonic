/*
 *
 * Copyright 2026 gRPC authors.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 */

use bytes::Bytes;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

use crate::client::name_resolution::proxy_resolver::ProxyOptions;
use crate::client::transport::http_connect::rewind::Rewind;
use crate::rt::AsyncIoAdapter;
use crate::rt::BoxEndpoint;
use crate::rt::tokio::TokioIoStream;

mod rewind;

pub(crate) async fn do_connect_handshake(
    input: BoxEndpoint,
    opts: &ProxyOptions,
) -> Result<BoxEndpoint, String> {
    let mut io = AsyncIoAdapter::new(input);

    // 2. Write http connect request with dest as opts.connect_addr and
    // optionally, the opts.credentials header value.
    let mut req = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n",
        opts.connect_addr(),
        opts.connect_addr()
    )
    .into_bytes();
    if let Some(creds) = opts.credentials() {
        req.extend_from_slice(b"Proxy-Authorization: ");
        req.extend_from_slice(creds.header_value().as_bytes());
        req.extend_from_slice(b"\r\n");
    }
    // headers end
    req.extend_from_slice(b"\r\n");

    io.write_all(&req).await.map_err(|e| e.to_string())?;
    io.flush().await.map_err(|e| e.to_string())?;

    const READ_BUF_SIZE: usize = 8192;
    let mut buf = vec![0u8; READ_BUF_SIZE];
    let mut read = 0;

    // 4. Read response in buffer. Parse response using httparse crate. Check
    // success.
    loop {
        let n = io.read(&mut buf[read..]).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("Connection closed by proxy".to_string());
        }
        read += n;

        // Allocate space on the stack to read up to 16 headers from the proxy.
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut res = httparse::Response::new(&mut headers);
        match res.parse(&buf[..read]) {
            Ok(httparse::Status::Complete(len)) => {
                if res.code != Some(200) {
                    return Err(format!("Proxy returned status {}", res.code.unwrap_or(0)));
                }
                // Success!
                let remaining = read - len;
                let buffered_data = if remaining > 0 {
                    Some(Bytes::copy_from_slice(&buf[len..read]))
                } else {
                    None
                };

                let local_addr = io
                    .get_ref()
                    .get_local_address()
                    .to_string()
                    .into_boxed_str();
                let peer_addr = io.get_ref().get_peer_address().to_string().into_boxed_str();
                let network_type = io.get_ref().get_network_type();

                // 5. If there is buffered data, return Rewind, else return the
                // input endpoint directly.
                // 6. To get a BoxEndpoint from AsyncRead + AsyncWrite use TokioIoAdapeter.
                // Add a new pub(crate) constructor that accepts peer address and local addresses.
                // In most cases, the buffer should be empty as the server waits
                // for the client to send the first message, e.g. in TLS.
                let endpoint: BoxEndpoint = if let Some(data) = buffered_data {
                    let rewind = Rewind::new_buffered(io, data);
                    Box::new(TokioIoStream::new(
                        rewind,
                        local_addr,
                        peer_addr,
                        network_type,
                    ))
                } else {
                    io.into_inner()
                };
                return Ok(endpoint);
            }
            Ok(httparse::Status::Partial) => {
                if read >= READ_BUF_SIZE {
                    return Err("Response too large".to_string());
                }
            }
            Err(e) => {
                return Err(format!("Failed to parse HTTP response: {}", e));
            }
        }
    }
}
