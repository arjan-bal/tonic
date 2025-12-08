use std::{
    any::Any,
    borrow::Cow,
    env,
    io::IoSlice,
    net::IpAddr,
    os::fd::AsFd,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use http::uri::Authority;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
};
use tokio_boring::SslStream;
use tonic::async_trait;

use crate::{attributes::Attributes, byte_str::ByteStr, rt::Runtime};

mod private {
    pub struct Token;
}

/// Conn is a generic stream-oriented network connection.
pub(crate) trait GrpcEndpoint: Send + Unpin {
    /// Returns the local address that this stream is bound to.
    fn get_local_address(&self) -> ByteStr;

    /// Returns the remote address that this stream is connected to.
    fn get_peer_address(&self) -> ByteStr;

    #[doc(hidden)]
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
        _: private::Token,
    ) -> Poll<std::io::Result<()>>;

    #[doc(hidden)]
    fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
        _: private::Token,
    ) -> Poll<Result<usize, std::io::Error>>;

    #[doc(hidden)]
    fn poll_flush(
        &mut self,
        cx: &mut Context<'_>,
        _: private::Token,
    ) -> Poll<Result<(), std::io::Error>>;

    #[doc(hidden)]
    fn poll_shutdown(
        &mut self,
        cx: &mut Context<'_>,
        _: private::Token,
    ) -> Poll<Result<(), std::io::Error>>;

    #[doc(hidden)]
    fn poll_write_vectored(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
        token: private::Token,
    ) -> Poll<Result<usize, std::io::Error>> {
        let buf = bufs
            .iter()
            .find(|b| !b.is_empty())
            .map_or(&[][..], |b| &**b);
        self.poll_write(cx, buf, token)
    }

    #[doc(hidden)]
    fn is_write_vectored(&self, _: private::Token) -> bool {
        false
    }
}

pub(crate) type BoxGrpcEndpoint = Box<dyn GrpcEndpoint>;

/// This wrapper is pub(crate). It is the only place authorized to
/// mint the PrivateToken.
pub(crate) struct GrpcStreamWrapper {
    inner: BoxGrpcEndpoint,
}

impl GrpcStreamWrapper {
    pub fn new(inner: BoxGrpcEndpoint) -> Self {
        Self { inner }
    }

    /// Helper to get the token.
    /// Since we are in the same crate, we can construct it.
    fn token() -> private::Token {
        private::Token {}
    }

    fn get_ref(&self) -> &BoxGrpcEndpoint {
        &self.inner
    }
}

// -------------------------------------------------------------------------
// 4. Implementing Standard AsyncRead/AsyncWrite for the Wrapper
// -------------------------------------------------------------------------

impl AsyncRead for GrpcStreamWrapper {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.inner.poll_read(cx, buf, Self::token())
    }
}

impl AsyncWrite for GrpcStreamWrapper {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.inner.poll_write(cx, buf, Self::token())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.inner.poll_flush(cx, Self::token())
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.inner.poll_shutdown(cx, Self::token())
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.inner.poll_write_vectored(cx, bufs, Self::token())
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored(Self::token())
    }
}

impl GrpcEndpoint for TcpStream {
    fn get_local_address(&self) -> ByteStr {
        // TODO: cache the address when the stream is created.
        todo!()
    }

    fn get_peer_address(&self) -> ByteStr {
        todo!()
    }

    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
        _: private::Token,
    ) -> Poll<std::io::Result<()>> {
        let pinned = std::pin::Pin::new(self);
        AsyncRead::poll_read(pinned, cx, buf)
    }

    fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
        _: private::Token,
    ) -> Poll<Result<usize, std::io::Error>> {
        let pinned = std::pin::Pin::new(self);
        AsyncWrite::poll_write(pinned, cx, buf)
    }

    fn poll_flush(
        &mut self,
        cx: &mut Context<'_>,
        _: private::Token,
    ) -> Poll<Result<(), std::io::Error>> {
        let pinned = std::pin::Pin::new(self);
        AsyncWrite::poll_flush(pinned, cx)
    }

    fn poll_shutdown(
        &mut self,
        cx: &mut Context<'_>,
        _: private::Token,
    ) -> Poll<Result<(), std::io::Error>> {
        let pinned = std::pin::Pin::new(self);
        AsyncWrite::poll_shutdown(pinned, cx)
    }

    fn poll_write_vectored(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
        token: private::Token,
    ) -> Poll<Result<usize, std::io::Error>> {
        let pinned = std::pin::Pin::new(self);
        AsyncWrite::poll_write_vectored(pinned, cx, bufs)
    }

    fn is_write_vectored(&self, _: private::Token) -> bool {
        AsyncWrite::is_write_vectored(self)
    }
}

/// Holds data to be passed during the connection handshake.
///
/// This mechanism allows arbitrary data to flow from gRPC core components—such as
/// resolvers and load balancers—down to the credential implementations.
///
/// Individual credential implementations are responsible for validating and
/// interpreting the format of the data they receive.
#[derive(Default)]
#[non_exhaustive]
pub(crate) struct ClientHandshakeInfo {
    /// The bag of attributes containing the handshake data.
    pub(crate) attributes: Attributes,
}

/// Defines the common interface for all live gRPC wire protocols and supported
/// transport security protocols (e.g., TLS, SSL).
#[async_trait]
pub(crate) trait ClientChannelCredential: Send + Sync {
    /// Performs the client-side authentication handshake on a raw endpoint.
    ///
    /// This method wraps the provided `source` endpoint with the security protocol
    /// (e.g., TLS) and returns the authenticated endpoint along with its security details.
    ///
    /// # Arguments
    ///
    /// * `authority` - The `:authority` header value to be used when creating new streams.
    ///   **Important:** Implementations must use this value as the server name
    ///   (e.g., for SNI) during the handshake.
    /// * `source` - The raw connection handle.
    /// * `info` - Additional context passed from the resolver or load balancer.
    async fn connect(
        &self,
        authority: &http::uri::Authority,
        source: BoxGrpcEndpoint,
        info: ClientHandshakeInfo,
        runtime: Arc<dyn Runtime>,
    ) -> Result<(BoxGrpcEndpoint, ClientConnectionSecurityInfo), String>;

    //// Provides the ProtocolInfo of this ClientChannelCredential.
    fn info(&self) -> &ProtocolInfo;

    /// Clones these credentials.
    fn clone(&self) -> Box<dyn ClientChannelCredential>;
}

#[async_trait]
pub(crate) trait ServerChannelCredentials: Send + Sync {
    /// Performs the server-side authentication handshake.
    ///
    /// This method wraps the incoming raw `source` connection with the configured
    /// security protocol (e.g., TLS).
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// 1. The authenticated endpoint (ready for reading/writing frames).
    /// 2. The security context describing the connection (e.g., peer certificates).
    async fn accept(
        &self,
        source: BoxGrpcEndpoint,
        runtime: Arc<dyn Runtime>,
    ) -> Result<(BoxGrpcEndpoint, ServerConnectionSecurityInfo), String>;

    //// Provides the ProtocolInfo of this ServerChannelCredentials.
    fn info(&self) -> &ProtocolInfo;

    /// Clones these credentials.
    fn clone(&self) -> Box<dyn ServerChannelCredentials>;
}

/// Defines the level of protection provided by an established connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecurityLevel {
    /// The connection is insecure; no protection is applied.
    NoSecurity,
    /// The connection guarantees data integrity (tamper-proofing) but not privacy.
    ///
    /// Payloads are visible to observers but cannot be modified without detection.
    IntegrityOnly,
    /// The connection guarantees both privacy (confidentiality) and data integrity.
    ///
    /// This is the standard level for secure transports like TLS.
    PrivacyAndIntegrity,
}

/// Represents the security state of an established client-side connection.
///
/// This trait abstracts over specific security protocols (e.g., TLS, ALTS) to allow
/// the transport layer to query security properties without knowing the implementation details.
pub(crate) trait ClientConnectionSecurityContext: Send + Sync + 'static {
    /// Checks if the established connection is authorized to send requests to the given authority.
    ///
    /// This is primarily used for HTTP/2 connection reuse (coalescing). If the
    /// underlying security handshake (e.g., a TLS certificate) covers the provided
    /// `authority`, the existing connection may be reused for that host.
    ///
    /// # Returns
    ///
    /// * `true` - The connection is valid for this authority.
    /// * `false` - The connection cannot be reused; a new connection must be created.
    fn validate_authority(&self, authority: &Authority) -> bool {
        false
    }

    /// Upcasts the reference to [`Any`] to enable downcasting to the concrete implementation.
    ///
    /// This allows access to protocol-specific fields (e.g., accessing the raw `SSL` object)
    /// that are not part of the generic interface.
    fn as_any(&self) -> &dyn Any;
}

pub(crate) struct ClientConnectionSecurityInfo {
    pub(crate) security_protocol: &'static str,
    pub(crate) security_level: SecurityLevel,
    pub(crate) security_context: Box<dyn ClientConnectionSecurityContext>,
}

/// Represents the security state of an established server-side connection.
///
/// Contains authentication information about the connected client (e.g., mTLS identity).
pub(crate) trait ServerConnectionSecurityContext: Send + Sync + 'static {
    /// Upcasts the reference to [`Any`] to enable downcasting to the concrete implementation.
    fn as_any(&self) -> &dyn Any;
}

pub(crate) struct ServerConnectionSecurityInfo {
    pub(crate) security_protocol: &'static str,
    pub(crate) security_level: SecurityLevel,
    pub(crate) security_context: Box<dyn ServerConnectionSecurityContext>,
}

#[non_exhaustive]
pub(crate) struct ProtocolInfo {
    pub(crate) security_protocol: &'static str,
}

pub(crate) mod tls {
    use std::{
        any::Any,
        borrow::Cow,
        env,
        io::IoSlice,
        net::IpAddr,
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
    };

    use boring::{
        pkey::PKey,
        ssl::{
            NameType, SniError, SslAcceptor, SslConnector, SslContext, SslMethod, SslVerifyMode,
        },
        x509::X509,
    };
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio_boring::SslStream;
    use tonic::async_trait;

    use crate::{
        byte_str::ByteStr,
        endpoint::{
            private, BoxGrpcEndpoint, ClientChannelCredential, ClientConnectionSecurityContext,
            ClientConnectionSecurityInfo, ClientHandshakeInfo, GrpcEndpoint, GrpcStreamWrapper,
            ProtocolInfo, SecurityLevel, ServerChannelCredentials, ServerConnectionSecurityContext,
            ServerConnectionSecurityInfo,
        },
        rt::Runtime,
    };

    /// Represents a X509 certificate chain.
    #[derive(Debug, Clone)]
    pub struct Certificats {
        pub(crate) pem: Vec<u8>,
    }

    /// Represents a private key and X509 certificate.
    #[derive(Debug, Clone)]
    pub struct Identity {
        pub(crate) cert: Certificats,
        pub(crate) key: Vec<u8>,
    }

    impl Certificats {
        /// Parse a PEM encoded X509 Certificate.
        ///
        /// The provided PEM should include at least one PEM encoded certificate.
        pub fn from_pem(pem: impl AsRef<[u8]>) -> Self {
            let pem = pem.as_ref().into();
            Self { pem }
        }

        /// Get a immutable reference to underlying certificate
        pub fn get_ref(&self) -> &[u8] {
            self.pem.as_slice()
        }

        /// Get a mutable reference to underlying certificate
        pub fn get_mut(&mut self) -> &mut [u8] {
            self.pem.as_mut()
        }

        /// Consumes `self`, returning the underlying certificate
        pub fn into_inner(self) -> Vec<u8> {
            self.pem
        }
    }

    impl AsRef<[u8]> for Certificats {
        fn as_ref(&self) -> &[u8] {
            self.pem.as_ref()
        }
    }

    impl AsMut<[u8]> for Certificats {
        fn as_mut(&mut self) -> &mut [u8] {
            self.pem.as_mut()
        }
    }

    impl Identity {
        /// Parse a PEM encoded certificate and private key.
        ///
        /// The provided cert must contain at least one PEM encoded certificate.
        pub fn from_pem(cert: impl AsRef<[u8]>, key: impl AsRef<[u8]>) -> Self {
            let cert = Certificats::from_pem(cert);
            let key = key.as_ref().into();
            Self { cert, key }
        }
    }

    /// Configuration for client-side TLS settings.
    #[derive(Default)]
    pub(crate) struct ClientTlsConfig {
        /// The set of PEM-encoded root certificates (CA) to trust.
        ///
        /// If `Some`, these certificates are used to validate the server's
        /// certificate chain. If `None`, the client generally defaults to using
        /// the system's native certificate store.
        pub(crate) pem_root_certs: Option<Certificats>,

        /// The client's identity for Mutual TLS (mTLS).
        ///
        /// Contains the client's certificate chain and private key. If `None`,
        /// the client will not present a certificate to the server
        /// (standard one-way TLS).
        pub(crate) identity: Option<Identity>,
    }

    #[derive(Clone)]
    pub(crate) struct ClientTlsCredendials {
        connector: SslConnector,
    }

    static TLS_PROTO_INFO: ProtocolInfo = ProtocolInfo {
        security_protocol: "tls",
    };

    const ALPN_H2: &[u8] = b"\x02h2";

    impl ClientTlsCredendials {
        pub(crate) fn new(
            config: &ClientTlsConfig,
        ) -> Result<Box<dyn ClientChannelCredential>, String> {
            let mut builder =
                SslConnector::builder(SslMethod::tls_client()).map_err(|e| e.to_string())?;
            builder.set_verify(SslVerifyMode::PEER);
            builder
                .set_alpn_protos(ALPN_H2)
                .map_err(|e| e.to_string())?;

            // Set trust store.
            if let Some(ca_pem) = &config.pem_root_certs {
                let ca_certs = X509::stack_from_pem(ca_pem.as_ref()).map_err(|e| e.to_string())?;
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
                    X509::stack_from_pem(identity.cert.get_ref()).map_err(|e| e.to_string())?;
                if chain.is_empty() {
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

                let pkey = PKey::private_key_from_pem(&identity.key).map_err(|e| e.to_string())?;
                builder.set_private_key(&pkey).map_err(|e| e.to_string())?;
            }
            let connector = builder.build();
            Ok(Box::new(ClientTlsCredendials { connector }))
        }
    }

    struct ClientTlsSecContext {
        peer_cert_chain: Vec<X509>,
    }

    impl ClientConnectionSecurityContext for ClientTlsSecContext {
        fn validate_authority(&self, authority: &http::uri::Authority) -> bool {
            for cert in &self.peer_cert_chain {
                if cert.check_host(authority.host()).is_ok_and(|x| x) {
                    return true;
                }
            }
            false
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[async_trait]
    impl ClientChannelCredential for ClientTlsCredendials {
        async fn connect(
            &self,
            authority: &http::uri::Authority,
            source: BoxGrpcEndpoint,
            _info: ClientHandshakeInfo,
            _rt: Arc<dyn Runtime>,
        ) -> Result<(BoxGrpcEndpoint, ClientConnectionSecurityInfo), String> {
            let wrapper = GrpcStreamWrapper::new(source);
            let tls_stream = tokio_boring::connect(
                self.connector.configure().unwrap(),
                authority.host(),
                wrapper,
            )
            .await
            .map_err(|e| e.to_string())?;

            let cs_info = ClientConnectionSecurityInfo {
                security_protocol: "tls",
                security_level: SecurityLevel::PrivacyAndIntegrity,
                security_context: Box::new(ClientTlsSecContext {
                    peer_cert_chain: Vec::new(),
                }),
            };
            let ep: BoxGrpcEndpoint = Box::new(TlsStream { inner: tls_stream });
            Ok((ep, cs_info))
        }

        fn info(&self) -> &ProtocolInfo {
            &TLS_PROTO_INFO
        }

        fn clone(&self) -> Box<dyn ClientChannelCredential> {
            Box::new(Clone::clone(self))
        }
    }

    pub(crate) enum TlsClientCertificateRequestType {
        /// Server does not request client certificate.
        ///
        /// The certificate presented by the client is not checked by the server at
        /// all. (A client may present a self-signed or signed certificate or not
        /// present a certificate at all and any of those option would be accepted).
        DontRequestClientCertificate,

        /// Server requests client certificate but does not enforce that the client
        /// presents a certificate.
        ///
        /// If the client presents a certificate, the client authentication is left to
        /// the application (the necessary metadata will be available to the
        /// application via authentication context properties).
        ///
        /// The client's key certificate pair must be valid for the SSL connection to
        /// be established.
        RequestClientCertificateButDontVerify,

        /// Server requests client certificate but does not enforce that the client
        /// presents a certificate.
        ///
        /// If the client presents a certificate, the client authentication is done by
        /// the gRPC framework. For a successful connection the client needs to either
        /// present a certificate that can be verified against the `pem_root_certs`
        /// or not present a certificate at all.
        ///
        /// The client's key certificate pair must be valid for the SSL connection to
        /// be established.
        RequestClientCertificateAndVerify { pem_root_certs: Certificats },

        /// Server requests client certificate and enforces that the client presents a
        /// certificate.
        ///
        /// If the client presents a certificate, the client authentication is left to
        /// the application (the necessary metadata will be available to the
        /// application via authentication context properties).
        ///
        /// The client's key certificate pair must be valid for the SSL connection to
        /// be established.
        RequestAndRequireClientCertificateButDontVerify,

        /// Server requests client certificate and enforces that the client presents a
        /// certificate.
        ///
        /// The certificate presented by the client is verified by the gRPC framework.
        /// For a successful connection the client needs to present a certificate that
        /// can be verified against the `pem_root_certs`.
        ///
        /// The client's key certificate pair must be valid for the SSL connection to
        /// be established.
        RequestAndRequireClientCertificateAndVerify { pem_root_certs: Certificats },
    }

    #[derive(Clone)]
    pub(crate) struct ServerTlsCredendials {
        acceptor: SslAcceptor,
    }

    pub(crate) struct ServerTlsConfig {
        pub(crate) identities: Vec<Identity>,
        pub(crate) request_type: TlsClientCertificateRequestType,
    }

    pub(crate) struct ServerSecContext {
        peer_cert_chain: Option<Vec<X509>>,
    }

    impl ServerConnectionSecurityContext for ServerSecContext {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    impl ServerTlsCredendials {
        pub(crate) fn new(config: &ServerTlsConfig) -> Result<ServerTlsCredendials, String> {
            if config.identities.is_empty() {
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
                    X509::stack_from_pem(identity.cert.as_ref()).map_err(|e| e.to_string())?;
                if chain.is_empty() {
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

                let pkey = PKey::private_key_from_pem(&identity.key).map_err(|e| e.to_string())?;
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
                    X509::stack_from_pem(&pem_root_certs.pem).map_err(|e| e.to_string())?;
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
                    X509::stack_from_pem(&pem_root_certs.pem).map_err(|e| e.to_string())?;
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
    }

    fn get_full_peer_chain_server_side(stream: &SslStream<GrpcStreamWrapper>) -> Option<Vec<X509>> {
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
            _rt: Arc<dyn Runtime>,
        ) -> Result<(BoxGrpcEndpoint, ServerConnectionSecurityInfo), String> {
            let wrapper = GrpcStreamWrapper::new(source);
            let tls_stream = tokio_boring::accept(&self.acceptor, wrapper)
                .await
                .map_err(|e| e.to_string())?;
            let tls_ctx = ServerSecContext {
                peer_cert_chain: get_full_peer_chain_server_side(&tls_stream),
            };
            let auth_info = ServerConnectionSecurityInfo {
                security_protocol: "tls",
                security_level: SecurityLevel::PrivacyAndIntegrity,
                security_context: Box::new(tls_ctx),
            };
            let ep: BoxGrpcEndpoint = Box::new(TlsStream { inner: tls_stream });
            Ok((ep, auth_info))
        }

        fn info(&self) -> &ProtocolInfo {
            &TLS_PROTO_INFO
        }

        fn clone(&self) -> Box<dyn ServerChannelCredentials> {
            Box::new(Clone::clone(self))
        }
    }

    struct TlsStream {
        inner: SslStream<GrpcStreamWrapper>,
    }

    impl GrpcEndpoint for TlsStream {
        fn get_local_address(&self) -> ByteStr {
            self.inner.get_ref().get_ref().get_local_address()
        }

        fn get_peer_address(&self) -> ByteStr {
            self.inner.get_ref().get_ref().get_peer_address()
        }

        fn poll_read(
            &mut self,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
            _: private::Token,
        ) -> Poll<std::io::Result<()>> {
            let pinned = Pin::new(&mut self.inner);
            AsyncRead::poll_read(pinned, cx, buf)
        }

        fn poll_write(
            &mut self,
            cx: &mut Context<'_>,
            buf: &[u8],
            _: private::Token,
        ) -> Poll<Result<usize, std::io::Error>> {
            let pinned = Pin::new(&mut self.inner);
            AsyncWrite::poll_write(pinned, cx, buf)
        }

        fn poll_flush(
            &mut self,
            cx: &mut Context<'_>,
            _: private::Token,
        ) -> Poll<Result<(), std::io::Error>> {
            let pinned = Pin::new(&mut self.inner);
            AsyncWrite::poll_flush(pinned, cx)
        }

        fn poll_shutdown(
            &mut self,
            cx: &mut Context<'_>,
            _: private::Token,
        ) -> Poll<Result<(), std::io::Error>> {
            let pinned = Pin::new(&mut self.inner);
            AsyncWrite::poll_shutdown(pinned, cx)
        }

        fn poll_write_vectored(
            &mut self,
            cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
            token: private::Token,
        ) -> Poll<Result<usize, std::io::Error>> {
            let pinned = Pin::new(&mut self.inner);
            AsyncWrite::poll_write_vectored(pinned, cx, bufs)
        }

        fn is_write_vectored(&self, _: private::Token) -> bool {
            AsyncWrite::is_write_vectored(&self.inner)
        }
    }
}

#[cfg(test)]
mod test {

    use crate::{
        byte_str::ByteStr,
        endpoint::{
            tls::{
                Certificats, ClientTlsConfig, ClientTlsCredendials, Identity, ServerTlsConfig,
                ServerTlsCredendials, TlsClientCertificateRequestType,
            },
            BoxGrpcEndpoint, ClientChannelCredential, ClientHandshakeInfo,
            ServerChannelCredentials,
        },
        rt,
    };
    use http::uri::Authority;
    use std::{env, fs, path::PathBuf};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    pub async fn test_tls() {
        let hostname = "google.com";
        let stream = tokio::net::TcpStream::connect((hostname, 443))
            .await
            .unwrap();
        let ge: BoxGrpcEndpoint = Box::new(stream);
        let creds = ClientTlsCredendials::new(&ClientTlsConfig::default()).unwrap();
        let authority: Authority = "google.com".parse().unwrap();
        let authenticated = creds
            .connect(
                &authority,
                ge,
                ClientHandshakeInfo::default(),
                rt::default_runtime(),
            )
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
                identities: vec![Identity {
                    key: key,
                    cert: crate::endpoint::tls::Certificats { pem: cert },
                }],
                request_type:
                    TlsClientCertificateRequestType::RequestAndRequireClientCertificateAndVerify {
                        pem_root_certs: Certificats::from_pem(ca),
                    },
            };
            let creds = ServerTlsCredendials::new(&config).unwrap();
            let stream = creds
                .accept(Box::new(stream), rt::default_runtime())
                .await
                .unwrap();
        });

        let client = tokio::spawn(async move {
            let addr = rx.await.unwrap();

            let socket = TcpStream::connect(addr).await.unwrap();

            let ca = fs::read(base_copy.join("server_ca_cert.pem")).unwrap();
            let cert = fs::read(base_copy.join("client1_cert.pem")).unwrap();
            let key = fs::read(base_copy.join("client1_key.pem")).unwrap();

            let config = ClientTlsConfig {
                pem_root_certs: Some(Certificats { pem: ca }),
                identity: Some(Identity {
                    key: key,
                    cert: crate::endpoint::tls::Certificats { pem: cert },
                }),
            };
            let creds = ClientTlsCredendials::new(&config).unwrap();
            let stream = creds
                .connect(
                    &"abc.test.example.com".parse().unwrap(),
                    Box::new(socket),
                    ClientHandshakeInfo::default(),
                    rt::default_runtime(),
                )
                .await
                .unwrap();
        });

        client.await.unwrap();
        server.await.unwrap();
    }
}
