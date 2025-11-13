use std::{any::Any, env, net::IpAddr, os::fd::AsFd, pin::Pin, sync::Arc};

use boring::{
    pkey::PKey,
    ssl::{NameType, SniError, SslAcceptor, SslConnector, SslContext, SslMethod, SslVerifyMode},
    x509::X509,
};
use socket2::SockRef;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
};
use tokio_boring::SslStream;
use tonic::async_trait;
use tower::builder;

use crate::byte_str::ByteStr;

#[derive(Clone, Default, Debug)]
pub(crate) struct ReadOptions {
    min_progress_size: Option<u64>,
}

pub(crate) trait GrpcEndpoint: AsyncRead + AsyncWrite + Send + Unpin {
    fn set_read_options(&mut self, opts: ReadOptions) -> Result<(), String>;
    fn get_local_address(&self) -> &ByteStr;
    fn get_peer_address(&self) -> &ByteStr;
}

pub(crate) type BoxGrpcEndpoint = Box<dyn GrpcEndpoint>;

impl GrpcEndpoint for TcpStream {
    fn set_read_options(&mut self, opts: ReadOptions) -> Result<(), String> {
        if let Some(progress_size) = opts.min_progress_size {
            self.as_fd();
            // TODO: Set SO_RCVLOWAT.
        }
        Ok(())
    }

    fn get_local_address(&self) -> &ByteStr {
        // TODO: cache the address when the stream is created.
        todo!()
    }

    fn get_peer_address(&self) -> &ByteStr {
        todo!()
    }
}

#[async_trait]
pub(crate) trait ClientChannelCredential: Send {
    async fn connect(
        &self,
        authority: ByteStr,
        source: BoxGrpcEndpoint,
    ) -> Result<(BoxGrpcEndpoint, ConnectionSecurityInfo), String>;

    fn protocol_info(&self) -> ProtocolInfo;

    fn clone(&self) -> Box<dyn ClientChannelCredential>;
}

#[async_trait]
pub(crate) trait ServerChannelCredentials: Send {
    async fn accept(
        &self,
        source: BoxGrpcEndpoint,
    ) -> Result<(BoxGrpcEndpoint, ConnectionSecurityInfo), String>;

    fn protocol_info(&self) -> ProtocolInfo;

    fn clone(&self) -> Box<dyn ServerChannelCredentials>;
}

#[derive(Clone)]
pub(crate) struct PemKeyCertPair {
    pub(crate) private_key: ByteStr,
    pub(crate) cert_chain: ByteStr,
}

#[derive(Default)]
pub(crate) struct ClientTlsConfig {
    pub(crate) pem_root_certs: Option<ByteStr>,
    pub(crate) identity: Option<PemKeyCertPair>,
}

#[derive(Clone)]
pub(crate) struct ClientTlsCredendials {
    connector: SslConnector,
}

const ALPN_H2: &[u8] = b"\x02h2";

pub(crate) fn new_client_tls_credentials(
    config: &ClientTlsConfig,
) -> Result<Box<dyn ClientChannelCredential>, String> {
    let mut builder = SslConnector::builder(SslMethod::tls_client()).map_err(|e| e.to_string())?;
    builder.set_verify(SslVerifyMode::PEER);
    builder
        .set_alpn_protos(ALPN_H2)
        .map_err(|e| e.to_string())?;

    // Set trust store.
    if let Some(ca_pem) = &config.pem_root_certs {
        let ca_certs = X509::stack_from_pem(ca_pem.as_bytes()).map_err(|e| e.to_string())?;
        let cert_store = builder.cert_store_mut();
        for cert in ca_certs {
            cert_store.add_cert(cert).map_err(|e| e.to_string())?;
        }
    } else if let Ok(path) = env::var("GRPC_DEFAULT_SSL_ROOTS_FILE_PATH") {
        builder.set_ca_file(path).map_err(|e| e.to_string())?;
    } else {
        builder
            .set_default_verify_paths()
            .map_err(|e| e.to_string())?;
    }

    if let Some(identity) = &config.identity {
        let mut chain =
            X509::stack_from_pem(identity.cert_chain.as_bytes()).map_err(|e| e.to_string())?;
        if chain.len() == 0 {
            return Err("empty client cert chain".to_string());
        }
        let client_cert = chain.remove(0);
        builder
            .set_certificate(&client_cert)
            .map_err(|e| e.to_string())?;

        for intermediate_cert in chain {
            builder
                .add_extra_chain_cert(intermediate_cert)
                .map_err(|e| e.to_string())?;
        }

        let pkey = PKey::private_key_from_pem(identity.private_key.as_bytes())
            .map_err(|e| e.to_string())?;
        builder.set_private_key(&pkey).map_err(|e| e.to_string())?;
    }
    let connector = builder.build();
    Ok(Box::new(ClientTlsCredendials { connector }))
}

pub trait AuthorityValidator: Send {
    fn validate_authority(&self, authority: &str) -> Result<(), String>;
}

#[derive(Debug)]
pub enum SecurityLevel {
    NoSecurity,
    IntegrityOnly,
    PrivacyAndIntegrity,
}

pub(crate) struct ConnectionSecurityInfo {
    auth_type: ByteStr,
    validator: Option<Box<dyn AuthorityValidator>>,
    security_level: SecurityLevel,
    // arbitrary information that can be consumed by the application or call
    // credentials.
    connection_security_context: Box<dyn Any + Send + Sync>,
}

pub(crate) struct ProtocolInfo {
    security_protocol: ByteStr,
}

#[async_trait]
impl ClientChannelCredential for ClientTlsCredendials {
    async fn connect(
        &self,
        authority: ByteStr,
        source: BoxGrpcEndpoint,
    ) -> Result<(BoxGrpcEndpoint, ConnectionSecurityInfo), String> {
        // TODO: Write code to remove the port from the authority.
        let tls_stream =
            tokio_boring::connect(self.connector.configure().unwrap(), &authority, source)
                .await
                .map_err(|e| e.to_string())?;

        let cs_info = ConnectionSecurityInfo {
            auth_type: ByteStr::from("tls".to_string()),
            validator: None,
            security_level: SecurityLevel::PrivacyAndIntegrity,
            connection_security_context: Box::new(()),
        };
        let ep: BoxGrpcEndpoint = Box::new(TlsStream { inner: tls_stream });
        Ok((ep, cs_info))
    }

    fn protocol_info(&self) -> ProtocolInfo {
        ProtocolInfo {
            security_protocol: ByteStr::from("tls".to_string()),
        }
    }

    fn clone(&self) -> Box<dyn ClientChannelCredential> {
        Box::new(Clone::clone(self))
    }
}

pub(crate) enum TlsClientCertificateRequestType {
    DontRequestClientCertificate,
    RequestClientCertificateButDontVerify,
    RequestClientCertificateAndVerify { pem_root_certs: ByteStr },
    RequestAndRequireClientCertificateButDontVerify,
    RequestAndRequireClientCertificateAndVerify { pem_root_certs: ByteStr },
}

#[derive(Clone)]
pub(crate) struct ServerTlsCredendials {
    acceptor: SslAcceptor,
}

pub(crate) struct ServerTlsConfig {
    pub(crate) identities: Vec<PemKeyCertPair>,
    pub(crate) request_type: TlsClientCertificateRequestType,
}

pub(crate) fn new_server_tls_credentials(
    config: &ServerTlsConfig,
) -> Result<ServerTlsCredendials, String> {
    if config.identities.len() < 1 {
        return Err("need at least one server identity.".to_string());
    }
    let mut contexts = Vec::new();
    let mut verify_mode = SslVerifyMode::NONE;
    let mut bypass_cert_verification = false;

    for identity in &config.identities {
        let mut context =
            SslContext::builder(SslMethod::tls_server()).map_err(|e| e.to_string())?;
        context.set_alpn_select_callback(|_ssl_ref, a| Ok(b"h2"));

        let mut chain =
            X509::stack_from_pem(identity.cert_chain.as_bytes()).map_err(|e| e.to_string())?;
        if chain.len() == 0 {
            return Err("empty client cert chain".to_string());
        }
        let server_cert = chain.remove(0);
        context
            .set_certificate(&server_cert)
            .map_err(|e| e.to_string())?;

        for intermediate_cert in chain {
            context
                .add_extra_chain_cert(intermediate_cert)
                .map_err(|e| e.to_string())?;
        }

        let pkey = PKey::private_key_from_pem(identity.private_key.as_bytes())
            .map_err(|e| e.to_string())?;
        context.set_private_key(&pkey).map_err(|e| e.to_string())?;

        match &config.request_type {
            TlsClientCertificateRequestType::DontRequestClientCertificate => {
                verify_mode = SslVerifyMode::NONE;
                context.set_verify(verify_mode)
            }
            TlsClientCertificateRequestType::RequestClientCertificateButDontVerify => {
                verify_mode = SslVerifyMode::PEER;
                bypass_cert_verification = true;
                // Disable cryptographic verification.
                // By default, OpenSSL attempts to verify the chain against trusted roots
                // if a cert is presented. We override this to always say "valid".
                context.set_custom_verify_callback(verify_mode, |_ssl_ref| {
                    // Return Ok(()) unconditionally to accept ANY certificate (expired, self-signed, etc.)
                    Ok(())
                });
            }
            TlsClientCertificateRequestType::RequestClientCertificateAndVerify {
                pem_root_certs,
            } => {
                verify_mode = SslVerifyMode::PEER;
                context.set_verify(verify_mode);
                let certs =
                    X509::stack_from_pem(pem_root_certs.as_bytes()).map_err(|e| e.to_string())?;
                let store = context.cert_store_mut();
                for cert in certs {
                    store.add_cert(cert).map_err(|e| e.to_string())?;
                }
            }
            TlsClientCertificateRequestType::RequestAndRequireClientCertificateButDontVerify => {
                // Disable cryptographic verification.
                // By default, OpenSSL attempts to verify the chain against trusted roots
                // if a cert is presented. We override this to always say "valid".
                verify_mode = SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT;
                bypass_cert_verification = true;
                context.set_custom_verify_callback(verify_mode, |_ssl_ref| {
                    // Return Ok(()) unconditionally to accept ANY certificate (expired, self-signed, etc.)
                    Ok(())
                });
            }
            TlsClientCertificateRequestType::RequestAndRequireClientCertificateAndVerify {
                pem_root_certs,
            } => {
                context.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
                let certs =
                    X509::stack_from_pem(pem_root_certs.as_bytes()).map_err(|e| e.to_string())?;
                let store = context.cert_store_mut();
                for cert in certs {
                    store.add_cert(cert).map_err(|e| e.to_string())?;
                }
            }
        };
        contexts.push(context.build());
    }

    let mut ssl_builder = boring::ssl::SslAcceptor::mozilla_modern(SslMethod::tls_server())
        .map_err(|e| e.to_string())?;

    ssl_builder.set_servername_callback(move |ssl, _alert| {
        let Some(requested_name) = ssl.servername(NameType::HOST_NAME) else {
            if let Some(default_ctx) = contexts.first() {
                ssl.set_ssl_context(default_ctx)
                    .map_err(|_| SniError::ALERT_FATAL)?;
                return Ok(());
            }
            return Err(SniError::ALERT_FATAL);
        };
        // 2. OPTIMIZATION: Parse the IP address ONLY ONCE here.
        // This creates an Option<IpAddr> that we can reuse in the loop.
        let parsed_ip = requested_name
            .parse::<IpAddr>()
            .ok()
            .map(|ip| ip.to_string());

        for ctx in &contexts {
            let Some(cert) = ctx.certificate() else {
                continue;
            };
            let is_match = if let Some(ip) = &parsed_ip {
                cert.check_ip_asc(ip).unwrap_or(false)
            } else {
                // CASE B: It is a Hostname
                // check_host(name, flags). 0 = default flags.
                // It returns Ok(_) on match, Err on mismatch.
                cert.check_host(requested_name).unwrap_or(false)
            };

            if !is_match {
                continue;
            }
            // Switch the Context (Loads certs, keys, CAs).
            ssl.set_ssl_context(ctx)
                .map_err(|_| SniError::ALERT_FATAL)?;
            ssl.set_verify(ctx.verify_mode());
            if bypass_cert_verification {
                ssl.set_custom_verify_callback(verify_mode, |_ssl_ref| {
                    // Return Ok(()) unconditionally to accept ANY certificate (expired, self-signed, etc.)
                    println!("Verification skipped");
                    Ok(())
                });
            } else {
                ssl.set_verify(verify_mode);
            }
            return Ok(());
        }
        // No match found in any context.
        Err(SniError::ALERT_FATAL)
    });

    let acceptor = ssl_builder.build();
    Ok(ServerTlsCredendials { acceptor })
}

pub(crate) struct ServerTlsContext {
    peer_cert_chain: Option<Vec<X509>>,
}

fn get_full_peer_chain_server_side(stream: &SslStream<BoxGrpcEndpoint>) -> Option<Vec<X509>> {
    let ssl = stream.ssl();
    let mut full_chain = Vec::new();

    // 1. Get the Leaf (The Client Identity)
    // On the server, this is NOT included in peer_cert_chain()
    if let Some(leaf) = ssl.peer_certificate() {
        full_chain.push(leaf);
    } else {
        // If there is no leaf, there is no chain.
        return None;
    }

    // 2. Get the rest of the chain (Intermediates)
    if let Some(chain_stack) = ssl.peer_cert_chain() {
        for cert in chain_stack {
            // We must clone/to_owned because the stack returns references,
            // but we want an owned Vector.
            full_chain.push(cert.to_owned());
        }
    }

    Some(full_chain)
}

#[async_trait]
impl ServerChannelCredentials for ServerTlsCredendials {
    async fn accept(
        &self,
        source: BoxGrpcEndpoint,
    ) -> Result<(BoxGrpcEndpoint, ConnectionSecurityInfo), String> {
        let tls_stream = tokio_boring::accept(&self.acceptor, source)
            .await
            .map_err(|e| e.to_string())?;
        let tls_ctx = ServerTlsContext {
            peer_cert_chain: get_full_peer_chain_server_side(&tls_stream),
        };
        let auth_info = ConnectionSecurityInfo {
            auth_type: ByteStr::from("tls".to_string()),
            validator: None,
            security_level: SecurityLevel::PrivacyAndIntegrity,
            connection_security_context: Box::new(tls_ctx),
        };
        let ep: BoxGrpcEndpoint = Box::new(TlsStream { inner: tls_stream });
        Ok((ep, auth_info))
    }

    fn protocol_info(&self) -> ProtocolInfo {
        ProtocolInfo {
            security_protocol: ByteStr::from("tls".to_string()),
        }
    }

    fn clone(&self) -> Box<dyn ServerChannelCredentials> {
        Box::new(Clone::clone(self))
    }
}

struct TlsStream {
    inner: SslStream<BoxGrpcEndpoint>,
}

impl AsyncRead for TlsStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl GrpcEndpoint for TlsStream {
    fn set_read_options(&mut self, opts: ReadOptions) -> Result<(), String> {
        self.inner.get_mut().set_read_options(opts)
    }

    fn get_local_address(&self) -> &ByteStr {
        self.inner.get_ref().get_local_address()
    }

    fn get_peer_address(&self) -> &ByteStr {
        self.inner.get_ref().get_peer_address()
    }
}

#[cfg(test)]
mod test {

    use crate::{
        byte_str::ByteStr,
        endpoint::{
            new_client_tls_credentials, new_server_tls_credentials, BoxGrpcEndpoint,
            ClientChannelCredential, ClientTlsConfig, ClientTlsCredendials, PemKeyCertPair,
            ServerChannelCredentials, ServerTlsConfig, TlsClientCertificateRequestType,
        },
    };
    use std::{env, fs, path::PathBuf};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    pub async fn test_tls() {
        let hostname = "google.com";
        let stream = tokio::net::TcpStream::connect((hostname, 443))
            .await
            .unwrap();
        let ge: BoxGrpcEndpoint = Box::new(stream);
        let creds = new_client_tls_credentials(&ClientTlsConfig::default()).unwrap();
        let authenticated = creds
            .connect(ByteStr::from("google.com".to_string()), ge)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_mtls_handshake() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let base = PathBuf::from(env::var("GRPC_GO_HOME").unwrap()).join("testdata/x509/");
        let base_copy = base.clone();
        let server = tokio::spawn(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tx.send(addr).unwrap();

            let (stream, _) = listener.accept().await.unwrap();

            let ca = fs::read(base.join("client_ca_cert.pem")).unwrap();
            let cert = fs::read(base.join("server1_cert.pem")).unwrap();
            let key = fs::read(base.join("server1_key.pem")).unwrap();

            let config = ServerTlsConfig {
                identities: vec![PemKeyCertPair {
                    private_key: ByteStr::from(String::from_utf8(key).unwrap()),
                    cert_chain: ByteStr::from(String::from_utf8(cert).unwrap()),
                }],
                request_type:
                    TlsClientCertificateRequestType::RequestAndRequireClientCertificateAndVerify {
                        pem_root_certs: ByteStr::from(String::from_utf8(ca).unwrap()),
                    },
            };
            let creds = new_server_tls_credentials(&config).unwrap();
            let stream = creds.accept(Box::new(stream)).await.unwrap();
        });

        let client = tokio::spawn(async move {
            let addr = rx.await.unwrap();

            let socket = TcpStream::connect(addr).await.unwrap();

            let ca = fs::read(base_copy.join("server_ca_cert.pem")).unwrap();
            let cert = fs::read(base_copy.join("client1_cert.pem")).unwrap();
            let key = fs::read(base_copy.join("client1_key.pem")).unwrap();

            let config = ClientTlsConfig {
                pem_root_certs: Some(ByteStr::from(String::from_utf8(ca).unwrap())),
                identity: Some(PemKeyCertPair {
                    private_key: ByteStr::from(String::from_utf8(key).unwrap()),
                    cert_chain: ByteStr::from(String::from_utf8(cert).unwrap()),
                }),
            };
            let creds = new_client_tls_credentials(&config).unwrap();
            let stream = creds
                .connect(
                    ByteStr::from("abc.test.example.com".to_string()),
                    Box::new(socket),
                )
                .await
                .unwrap();
        });

        client.await.unwrap();
        server.await.unwrap();
    }
}
