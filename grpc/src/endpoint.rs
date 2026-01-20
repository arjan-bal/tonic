use std::{
    any::Any,
    env,
    io::IoSlice,
    net::IpAddr,
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
    pub trait Sealed: tokio::io::AsyncRead + tokio::io::AsyncWrite {}
}

/// GrpcEndpoint is a generic stream-oriented network connection.
pub(crate) trait GrpcEndpoint: private::Sealed + Send + Unpin {
    /// Returns the local address that this stream is bound to.
    fn get_local_address(&self) -> ByteStr;

    /// Returns the remote address that this stream is connected to.
    fn get_peer_address(&self) -> ByteStr;
}

pub(crate) type BoxGrpcEndpoint = Box<dyn GrpcEndpoint>;

pub(crate) struct GrpcStreamWrapper<T> {
    inner: T,
}

impl<T> GrpcStreamWrapper<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    fn get_ref(&self) -> &T {
        &self.inner
    }
}

impl<T> private::Sealed for GrpcStreamWrapper<T> where T: AsyncRead + AsyncWrite + Unpin {}

// -------------------------------------------------------------------------
// 4. Implementing Standard AsyncRead/AsyncWrite for the Wrapper
// -------------------------------------------------------------------------

impl<T> AsyncRead for GrpcStreamWrapper<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for GrpcStreamWrapper<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

impl private::Sealed for TcpStream {}

impl GrpcEndpoint for TcpStream {
    fn get_local_address(&self) -> ByteStr {
        // TODO: cache the address when the stream is created.
        todo!()
    }

    fn get_peer_address(&self) -> ByteStr {
        todo!()
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
    type ContextType: ClientConnectionSecurityContext;
    type Output<I>;
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
    async fn connect<Input: GrpcEndpoint + 'static>(
        &self,
        authority: &http::uri::Authority,
        source: Input,
        info: ClientHandshakeInfo,
        runtime: Arc<dyn Runtime>,
    ) -> Result<
        (
            Self::Output<Input>,
            ClientConnectionSecurityInfo<Self::ContextType>,
        ),
        String,
    >;

    //// Provides the ProtocolInfo of this ClientChannelCredential.
    fn info(&self) -> &ProtocolInfo;
}

impl ClientConnectionSecurityContext for Box<dyn ClientConnectionSecurityContext> {}
impl private::Sealed for Box<dyn GrpcEndpoint> {}

impl GrpcEndpoint for Box<dyn GrpcEndpoint> {
    fn get_local_address(&self) -> ByteStr {
        (**self).get_local_address()
    }

    fn get_peer_address(&self) -> ByteStr {
        (**self).get_peer_address()
    }
}

// This effectively erases the generic types by forcing them into Boxes.
#[async_trait]
trait DynClientChannelCredential: Send + Sync {
    async fn connect_dyn(
        &self,
        authority: &http::uri::Authority,
        source: Box<dyn GrpcEndpoint>,
        info: ClientHandshakeInfo,
        runtime: Arc<dyn Runtime>,
    ) -> Result<
        (
            Box<dyn GrpcEndpoint>,
            ClientConnectionSecurityInfo<Box<dyn ClientConnectionSecurityContext>>,
        ),
        String,
    >;

    fn info_dyn(&self) -> &ProtocolInfo;
}

#[async_trait]
impl<T> DynClientChannelCredential for T
where
    T: ClientChannelCredential,
    // We require that the specific Output T produces can be boxed into the dyn trait
    // and the Context can be boxed.
    T::Output<Box<dyn GrpcEndpoint>>: GrpcEndpoint + 'static,
{
    async fn connect_dyn(
        &self,
        authority: &http::uri::Authority,
        source: Box<dyn GrpcEndpoint>,
        info: ClientHandshakeInfo,
        runtime: Arc<dyn Runtime>,
    ) -> Result<
        (
            Box<dyn GrpcEndpoint>,
            ClientConnectionSecurityInfo<Box<dyn ClientConnectionSecurityContext>>,
        ),
        String,
    > {
        let (stream, sec_info) = self.connect(authority, source, info, runtime).await?;

        let boxed_stream: Box<dyn GrpcEndpoint> = Box::new(stream);

        let boxed_sec_info = ClientConnectionSecurityInfo {
            security_protocol: sec_info.security_protocol,
            security_level: sec_info.security_level,
            security_context: Box::new(sec_info.security_context)
                as Box<dyn ClientConnectionSecurityContext>,
            attributes: sec_info.attributes,
        };

        Ok((boxed_stream, boxed_sec_info))
    }

    fn info_dyn(&self) -> &ProtocolInfo {
        self.info()
    }
}

#[async_trait]
pub(crate) trait ServerChannelCredentials: Send + Sync {
    type Output<I>;
    /// Performs the server-side authentication handshake.
    ///
    /// This method wraps the incoming raw `source` connection with the configured
    /// security protocol (e.g., TLS).
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// 1. The authenticated endpoint (ready for reading/writing frames).
    async fn accept<Input: GrpcEndpoint + 'static>(
        &self,
        source: Input,
        runtime: Arc<dyn Runtime>,
    ) -> Result<(Self::Output<Input>, ServerConnectionSecurityInfo), String>;

    //// Provides the ProtocolInfo of this ServerChannelCredentials.
    fn info(&self) -> &ProtocolInfo;
}

// Bridge trait for type erasure
#[async_trait]
trait DynServerChannelCredentials: Send + Sync {
    async fn accept_dyn(
        &self,
        source: Box<dyn GrpcEndpoint>,
        runtime: Arc<dyn Runtime>,
    ) -> Result<(Box<dyn GrpcEndpoint>, ServerConnectionSecurityInfo), String>;

    fn info_dyn(&self) -> &ProtocolInfo;
}

// Blanket implementation to bridge generic to dynamic
#[async_trait]
impl<T> DynServerChannelCredentials for T
where
    T: ServerChannelCredentials,
    T::Output<Box<dyn GrpcEndpoint>>: GrpcEndpoint + 'static,
{
    async fn accept_dyn(
        &self,
        source: Box<dyn GrpcEndpoint>,
        runtime: Arc<dyn Runtime>,
    ) -> Result<(Box<dyn GrpcEndpoint>, ServerConnectionSecurityInfo), String> {
        let (stream, sec_info) = self.accept(source, runtime).await?;
        let boxed_stream: Box<dyn GrpcEndpoint> = Box::new(stream);
        Ok((boxed_stream, sec_info))
    }

    fn info_dyn(&self) -> &ProtocolInfo {
        self.info()
    }
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
}

pub(crate) struct ClientConnectionSecurityInfo<C> {
    pub(crate) security_protocol: &'static str,
    pub(crate) security_level: SecurityLevel,
    pub(crate) security_context: C,
    /// Stores extra data derived from the underlying protocol.
    pub(crate) attributes: Attributes,
}

pub(crate) struct ServerConnectionSecurityInfo {
    pub(crate) security_protocol: &'static str,
    pub(crate) security_level: SecurityLevel,
    /// Stores extra data derived from the underlying protocol.
    pub(crate) attributes: Attributes,
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
        path::PathBuf,
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
    use google_cloud_auth::credentials::api_key_credentials;
    use tokio::{
        io::{AsyncRead, AsyncWrite, ReadBuf},
        sync::watch::{self, Receiver},
    };
    use tokio_boring::SslStream;
    use tonic::async_trait;

    use crate::{
        attributes::Attributes,
        byte_str::ByteStr,
        endpoint::{
            private, tls::provider::Sealed as _, ClientChannelCredential,
            ClientConnectionSecurityContext, ClientConnectionSecurityInfo, ClientHandshakeInfo,
            GrpcEndpoint, GrpcStreamWrapper, ProtocolInfo, SecurityLevel, ServerChannelCredentials,
            ServerConnectionSecurityInfo,
        },
        rt::Runtime,
    };

    /// Represents a X509 certificate chain.
    #[derive(Debug, Clone)]
    pub struct Roots {
        pem: Vec<u8>,
    }

    impl Roots {
        /// Parse a PEM encoded X509 Certificate.
        ///
        /// The provided PEM should include at least one PEM encoded certificate.
        pub fn from_pem(pem: impl AsRef<[u8]>) -> Self {
            let pem = pem.as_ref().into();
            Self { pem }
        }

        /// Get a immutable reference to underlying certificate
        fn get_ref(&self) -> &[u8] {
            self.pem.as_slice()
        }

        /// Get a mutable reference to underlying certificate
        fn get_mut(&mut self) -> &mut [u8] {
            self.pem.as_mut()
        }

        /// Consumes `self`, returning the underlying certificate
        fn into_inner(self) -> Vec<u8> {
            self.pem
        }
    }

    impl AsRef<[u8]> for Roots {
        fn as_ref(&self) -> &[u8] {
            self.pem.as_ref()
        }
    }

    impl AsMut<[u8]> for Roots {
        fn as_mut(&mut self) -> &mut [u8] {
            self.pem.as_mut()
        }
    }

    /// Represents a private key and X509 certificate chain.
    #[derive(Debug, Clone)]
    pub struct Identity {
        cert: Vec<u8>,
        key: Vec<u8>,
    }

    impl Identity {
        /// Parse a PEM encoded certificate and private key.
        ///
        /// The provided cert must contain at least one PEM encoded certificate.
        pub fn from_pem(cert: impl AsRef<[u8]>, key: impl AsRef<[u8]>) -> Self {
            let cert = cert.as_ref().into();
            let key = key.as_ref().into();
            Self { cert, key }
        }
    }

    /// Configuration for client-side TLS settings.
    pub(crate) struct ClientTlsConfig {
        pem_roots_provider: Option<Receiver<Roots>>,
        identity_provider: Option<Receiver<Identity>>,
        key_log_path: Option<PathBuf>,
    }

    mod provider {
        use tokio::sync::watch::Receiver;

        /// A sealed trait to prevent downstream implementations of `Provider`.
        ///
        /// This trait exposes the internal mechanism (Tokio watch channel) used to
        /// receive updates. It is kept private/restricted to ensure that `Provider`
        /// can only be implemented by types defined within this crate.
        pub trait Sealed<T> {
            /// Returns a clone of the underlying watch receiver.
            ///
            /// This allows the consumer to observe the current value and await
            /// future updates.
            fn get_receiver(self) -> Receiver<T>;
        }
    }

    /// A source of configuration or state of type `T` that allows for dynamic
    /// updates.
    ///
    /// This trait abstracts over the source of the data (e.g., static memory,
    /// file system, network) and provides a uniform interface for consumers to
    /// access the current value and subscribe to changes.
    ///
    /// # Underlying Mechanism
    ///
    /// Implementations use a [`tokio::sync::watch::Receiver`] internally. This supports:
    /// * **Instant Access:** The current value is always available via `borrow()`.
    /// * **Change Notification:** Consumers can `await` changes using `changed()`.
    ///
    /// # Sealed Trait
    ///
    /// This trait is **sealed**. It cannot be implemented by downstream crates.
    /// Users should rely on the provided implementations (e.g.,
    /// `StaticIdentityProvider`, `StaticRootsProvider`).
    pub trait Provider<T>: provider::Sealed<T> {}

    pub type StaticRootsProvider = StaticProvider<Roots>;
    pub type StaticIdentityProvider = StaticProvider<Identity>;

    impl ClientTlsConfig {
        pub fn new() -> Self {
            ClientTlsConfig {
                pem_roots_provider: None,
                identity_provider: None,
                key_log_path: None,
            }
        }

        /// Configures the set of PEM-encoded root certificates (CA) to trust.
        ///
        /// These certificates are used to validate the server's certificate chain.
        /// If this is not called, the client generally defaults to using the
        /// system's native certificate store.
        pub fn with_roots_provider<R>(mut self, provider: R) -> Self
        where
            R: Provider<Roots>,
        {
            self.pem_roots_provider = Some(provider.get_receiver());
            self
        }

        /// Configures the client's identity for Mutual TLS (mTLS).
        ///
        /// This provides the client's certificate chain and private key.
        /// If this is not called, the client will not present a certificate
        /// to the server (standard one-way TLS).
        pub fn with_identity_provider<I>(mut self, provider: I) -> Self
        where
            I: Provider<Identity>,
        {
            self.identity_provider = Some(provider.get_receiver());
            self
        }

        /// Sets the path where TLS session keys will be logged.
        ///
        /// # Security
        ///
        /// This should be used **only for debugging purposes**. It should never be
        /// used in a production environment due to security concerns.
        pub fn with_key_log_path(mut self, path: impl Into<PathBuf>) -> Self {
            self.key_log_path = Some(path.into());
            self
        }
    }

    #[derive(Clone)]
    pub struct ClientTlsCredendials {
        connector: SslConnector,
    }

    static TLS_PROTO_INFO: ProtocolInfo = ProtocolInfo {
        security_protocol: "tls",
    };

    const ALPN_H2: &[u8] = b"\x02h2";

    impl ClientTlsCredendials {
        /// Constructs a new `ClientTlsCredendials` instance from the provided
        /// configuration.
        pub fn new(mut config: ClientTlsConfig) -> Result<ClientTlsCredendials, String> {
            let mut builder =
                SslConnector::builder(SslMethod::tls_client()).map_err(|e| e.to_string())?;
            builder.set_verify(SslVerifyMode::PEER);
            builder
                .set_alpn_protos(ALPN_H2)
                .map_err(|e| e.to_string())?;

            // Set trust store.
            if let Some(mut roots_provider) = config.pem_roots_provider.take() {
                let ca_pem = roots_provider.borrow_and_update();
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

            if let Some(mut identity_provider) = config.identity_provider.take() {
                let identity = identity_provider.borrow_and_update();
                let mut chain =
                    X509::stack_from_pem(identity.cert.as_ref()).map_err(|e| e.to_string())?;
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
            Ok(ClientTlsCredendials { connector })
        }
    }

    pub(crate) struct ClientTlsSecContext {
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
    }

    #[async_trait]
    impl ClientChannelCredential for ClientTlsCredendials {
        type ContextType = ClientTlsSecContext;
        type Output<I> = TlsStream<I>;
        async fn connect<Input: GrpcEndpoint + 'static>(
            &self,
            authority: &http::uri::Authority,
            source: Input,
            _info: ClientHandshakeInfo,
            _rt: Arc<dyn Runtime>,
        ) -> Result<
            (
                TlsStream<Input>,
                ClientConnectionSecurityInfo<ClientTlsSecContext>,
            ),
            String,
        > {
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
                security_context: ClientTlsSecContext {
                    peer_cert_chain: Vec::new(),
                },
                attributes: Attributes {},
            };
            let ep = TlsStream { inner: tls_stream };
            Ok((ep, cs_info))
        }

        fn info(&self) -> &ProtocolInfo {
            &TLS_PROTO_INFO
        }
    }

    #[non_exhaustive]
    pub enum TlsClientCertificateRequestType<R = StaticRootsProvider> {
        /// Server does not request client certificate.
        ///
        /// The certificate presented by the client is not checked by the server at
        /// all. (A client may present a self-signed or signed certificate or not
        /// present a certificate at all and any of those option would be accepted).
        DontRequestClientCertificate,

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
        RequestClientCertificateAndVerify { roots_provider: R },

        /// Server requests client certificate and enforces that the client presents a
        /// certificate.
        ///
        /// The certificate presented by the client is verified by the gRPC framework.
        /// For a successful connection the client needs to present a certificate that
        /// can be verified against the `pem_root_certs`.
        ///
        /// The client's key certificate pair must be valid for the SSL connection to
        /// be established.
        RequestAndRequireClientCertificateAndVerify { roots_provider: R },
    }

    enum InnerClientCertificateRequestType {
        DontRequestClientCertificate,
        RequestClientCertificateAndVerify { roots_provider: Receiver<Roots> },
        RequestAndRequireClientCertificateAndVerify { roots_provider: Receiver<Roots> },
    }

    impl From<TlsClientCertificateRequestType> for InnerClientCertificateRequestType {
        fn from(value: TlsClientCertificateRequestType) -> Self {
            match value {
                TlsClientCertificateRequestType::DontRequestClientCertificate => {
                    InnerClientCertificateRequestType::DontRequestClientCertificate
                }
                TlsClientCertificateRequestType::RequestClientCertificateAndVerify {
                    roots_provider,
                } => InnerClientCertificateRequestType::RequestClientCertificateAndVerify {
                    roots_provider: roots_provider.get_receiver(),
                },
                TlsClientCertificateRequestType::RequestAndRequireClientCertificateAndVerify {
                    roots_provider,
                } => {
                    InnerClientCertificateRequestType::RequestAndRequireClientCertificateAndVerify {
                        roots_provider: roots_provider.get_receiver(),
                    }
                }
            }
        }
    }

    #[derive(Clone)]
    pub(crate) struct ServerTlsCredendials {
        acceptor: SslAcceptor,
    }

    /// A provider that supplies a constant, immutable value.
    ///
    /// This implementation is useful when dynamic updates are not required,
    /// such  simple configurations where certificates or identities are loaded
    /// once at startup and never change.
    pub struct StaticProvider<T> {
        inner: T,
    }

    impl<T> StaticProvider<T> {
        /// Creates a new `StaticProvider` with the given fixed value.
        pub(crate) fn new(value: T) -> Self {
            Self { inner: value }
        }
    }

    impl<T> provider::Sealed<T> for StaticProvider<T> {
        fn get_receiver(self) -> Receiver<T> {
            // We drop the sender (_) immediately.
            // This ensures the receiver sees the initial value but knows
            // no future updates will arrive.
            let (_, rx) = watch::channel(self.inner);
            rx
        }
    }

    impl<T> Provider<T> for StaticProvider<T> {}

    pub type IdentityList = Vec<Identity>;
    pub type StaticIdentityListProvider = StaticProvider<IdentityList>;

    /// Configuration for server-side TLS settings.
    pub struct ServerTlsConfig {
        identities_provider: Receiver<IdentityList>,
        request_type: InnerClientCertificateRequestType,
        key_log_path: Option<PathBuf>,
    }

    impl ServerTlsConfig {
        pub fn new<I>(identities_provider: I, request_type: TlsClientCertificateRequestType) -> Self
        where
            I: Provider<IdentityList>,
        {
            ServerTlsConfig {
                identities_provider: identities_provider.get_receiver(),
                request_type: request_type.into(),
                key_log_path: None,
            }
        }

        /// Sets the path where TLS session keys will be logged.
        ///
        /// # Security
        ///
        /// This should be used **only for debugging purposes**. It should never be
        /// used in a production environment due to security concerns.
        pub(crate) fn with_key_log_path(mut self, path: impl Into<PathBuf>) -> Self {
            self.key_log_path = Some(path.into());
            self
        }
    }

    impl ServerTlsCredendials {
        pub fn new(mut config: ServerTlsConfig) -> Result<ServerTlsCredendials, String> {
            let id_list = config.identities_provider.borrow_and_update().clone();
            if id_list.is_empty() {
                return Err("need at least one server identity.".to_string());
            }
            let mut contexts = Vec::new();
            let verify_mode;
            let roots_pem = match config.request_type {
                InnerClientCertificateRequestType::RequestClientCertificateAndVerify {
               mut     roots_provider,
                } => {
                    verify_mode = SslVerifyMode::PEER;
                    Some(roots_provider.borrow_and_update().pem.clone())
                }
                InnerClientCertificateRequestType::DontRequestClientCertificate => {
                    verify_mode = SslVerifyMode::NONE;
                    None
                }
                InnerClientCertificateRequestType::RequestAndRequireClientCertificateAndVerify {
                    mut roots_provider,
                } => {
                    verify_mode = SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT;
                    Some(roots_provider.borrow_and_update().pem.clone())
                }
            };

            for identity in id_list {
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
                context.set_verify(verify_mode);

                if let Some(pem) = roots_pem.as_ref() {
                    let certs = X509::stack_from_pem(pem).map_err(|e| e.to_string())?;
                    let store = context.cert_store_mut();
                    for cert in certs {
                        store.add_cert(cert).map_err(|e| e.to_string())?;
                    }
                }
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
                    ssl.set_verify(verify_mode);
                    return Ok(());
                }
                // No match found in any context.
                Err(SniError::ALERT_FATAL)
            });

            let acceptor = ssl_builder.build();
            Ok(ServerTlsCredendials { acceptor })
        }
    }

    fn get_full_peer_chain_server_side<T>(
        stream: &SslStream<GrpcStreamWrapper<T>>,
    ) -> Option<Vec<X509>> {
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
        type Output<Input> = TlsStream<Input>;

        async fn accept<Input: GrpcEndpoint + 'static>(
            &self,
            source: Input,
            _rt: Arc<dyn Runtime>,
        ) -> Result<(TlsStream<Input>, ServerConnectionSecurityInfo), String> {
            let wrapper = GrpcStreamWrapper::new(source);
            let tls_stream = tokio_boring::accept(&self.acceptor, wrapper)
                .await
                .map_err(|e| e.to_string())?;
            let peer_cert_chain = get_full_peer_chain_server_side(&tls_stream);
            // TODO: Put cert chain in attributes.
            let auth_info = ServerConnectionSecurityInfo {
                security_protocol: "tls",
                security_level: SecurityLevel::PrivacyAndIntegrity,
                attributes: Attributes {},
            };
            let ep = TlsStream { inner: tls_stream };
            Ok((ep, auth_info))
        }

        fn info(&self) -> &ProtocolInfo {
            &TLS_PROTO_INFO
        }
    }

    pub(crate) struct TlsStream<T> {
        inner: SslStream<GrpcStreamWrapper<T>>,
    }

    impl<T> AsyncRead for TlsStream<T>
    where
        T: GrpcEndpoint,
    {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let pinned = Pin::new(&mut self.get_mut().inner);
            AsyncRead::poll_read(pinned, cx, buf)
        }
    }

    impl<T> AsyncWrite for TlsStream<T>
    where
        T: GrpcEndpoint,
    {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            let pinned = Pin::new(&mut self.get_mut().inner);
            AsyncWrite::poll_write(pinned, cx, buf)
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            let pinned = Pin::new(&mut self.get_mut().inner);
            AsyncWrite::poll_flush(pinned, cx)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            let pinned = Pin::new(&mut self.get_mut().inner);
            AsyncWrite::poll_shutdown(pinned, cx)
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<Result<usize, std::io::Error>> {
            let pinned = Pin::new(&mut self.get_mut().inner);
            AsyncWrite::poll_write_vectored(pinned, cx, bufs)
        }

        fn is_write_vectored(&self) -> bool {
            AsyncWrite::is_write_vectored(&self.inner)
        }
    }

    impl<T> private::Sealed for TlsStream<T> where T: GrpcEndpoint {}

    impl<T> GrpcEndpoint for TlsStream<T>
    where
        T: GrpcEndpoint,
    {
        fn get_local_address(&self) -> ByteStr {
            self.inner.get_ref().get_ref().get_local_address()
        }

        fn get_peer_address(&self) -> ByteStr {
            self.inner.get_ref().get_ref().get_peer_address()
        }
    }
}

pub(crate) mod call_credentials {
    use super::ClientConnectionSecurityInfo;
    use crate::{attributes::Attributes, byte_str::ByteStr, endpoint::SecurityLevel};
    use tonic::{async_trait, metadata::MetadataMap, Status};

    /// Details regarding the RPC call.
    ///
    /// The fully qualified method name is constructed as:
    /// `service_url` + "/" + `method_name`
    pub(crate) struct CallDetails<'a> {
        pub service_url: &'a str,

        /// The method name suffix (e.g., `Method` or `package.Service/Method`).
        pub method_name: &'a str,
    }

    pub(crate) struct ChannelSecurityInfo {
        pub(crate) security_protocol: &'static str,
        pub(crate) security_level: SecurityLevel,
        /// Stores extra data derived from the underlying protocol.
        pub(crate) attributes: Attributes,
    }

    /// Defines the interface for credentials that need to attach security information
    /// to every individual RPC (e.g., OAuth2 tokens, JWTs).
    #[async_trait]
    pub(crate) trait CallCredentials {
        /// Generates the authentication metadata for a specific RPC call.
        ///
        /// This method is called by the transport layer on each request.
        /// Implementations should populate the provided `metadata` map with the
        /// necessary authorization headers (e.g., `authorization: Bearer <token>`).
        ///
        /// If this returns an `Err`, the RPC will fail immediately with a status
        /// derived from the error if the status code is in the range defined in
        /// gRFC A54. Otherwise, the RPC is failed with an internal status.
        async fn get_metadata(
            &self,
            call_details: &CallDetails,
            auth_info: &ChannelSecurityInfo,
            metadata: &mut MetadataMap,
        ) -> Result<(), Status>;

        /// Indicates the minimum transport security level required to send
        /// these credentials.
        fn minimum_channel_security_level(&self) -> SecurityLevel {
            SecurityLevel::PrivacyAndIntegrity
        }

        /// Type of credentials this plugin is implementing.
        fn get_type(&self) -> &'static str;
    }
}

mod gcp {
    use google_cloud_auth::build_errors::Error;
    use google_cloud_auth::credentials::{CacheableResource, Credentials};
    use serde::de::value;
    use tonic::{async_trait, metadata::MetadataMap, Status};

    use crate::endpoint::call_credentials::{CallCredentials, CallDetails, ChannelSecurityInfo};
    use crate::endpoint::SecurityLevel;

    pub(crate) struct GcpCallCredentials {
        credentials: Credentials,
    }

    impl GcpCallCredentials {
        pub(crate) async fn new() -> Result<GcpCallCredentials, Error> {
            let creds = google_cloud_auth::credentials::Builder::default()
                .with_scopes(["https://www.googleapis.com/auth/cloud-platform"])
                .build()?;
            Ok(GcpCallCredentials { credentials: creds })
        }
    }

    #[async_trait]
    impl CallCredentials for GcpCallCredentials {
        async fn get_metadata(
            &self,
            call_details: &CallDetails,
            auth_info: &ChannelSecurityInfo,
            metadata: &mut MetadataMap,
        ) -> Result<(), Status> {
            let extensions = http::Extensions::new();
            // let audience = format!("{}/{}", call_details.service_url, call_details.method_name);
            let resource = self
                .credentials
                .headers(extensions)
                .await
                .map_err(|e| Status::unavailable(e.to_string()))?;
            match resource {
                CacheableResource::New { data, .. } => {
                    if let Some(auth_val) = data.get("authorization") {
                        // 4. Convert http::HeaderValue -> tonic::metadata::MetadataValue
                        // Tonic's MetadataValue can be created from bytes, which avoids string parsing risks
                        metadata.append("authorization", auth_val.as_bytes().try_into().unwrap());
                    } else {
                        return Err(Status::internal(
                            "Credentials provider returned no Authorization header",
                        ));
                    }
                }
                CacheableResource::NotModified => {
                    // This happens only if you pass an ETag in extensions.
                    // Since we passed empty extensions, we expect 'New'.
                }
            }
            Ok(())
        }

        /// Indicates the minimum transport security level required to send
        /// these credentials.
        fn minimum_channel_security_level(&self) -> SecurityLevel {
            SecurityLevel::PrivacyAndIntegrity
        }

        /// Type of credentials this plugin is implementing.
        fn get_type(&self) -> &'static str {
            "gcp"
        }
    }
}

#[cfg(test)]
mod test {

    use crate::{
        byte_str::ByteStr,
        endpoint::{
            call_credentials::{CallCredentials, CallDetails, ChannelSecurityInfo},
            gcp,
            tls::{
                ClientTlsConfig, ClientTlsCredendials, Identity, Roots, ServerTlsConfig,
                ServerTlsCredendials, StaticIdentityListProvider, StaticIdentityProvider,
                StaticRootsProvider, TlsClientCertificateRequestType,
            },
            ClientChannelCredential, ClientHandshakeInfo, DynClientChannelCredential,
            DynServerChannelCredentials, ServerChannelCredentials,
        },
        rt,
    };
    use http::uri::Authority;
    use std::{env, fs, path::PathBuf};
    use tokio::net::{TcpListener, TcpStream};
    use tonic::metadata::MetadataMap;

    #[tokio::test]
    pub async fn test_tls() {
        let hostname = "google.com";
        let stream = tokio::net::TcpStream::connect((hostname, 443))
            .await
            .unwrap();
        let ge = stream;
        let creds = ClientTlsCredendials::new(ClientTlsConfig::new()).unwrap();
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

            let config = ServerTlsConfig::new(
                StaticIdentityListProvider::new(vec![Identity::from_pem(cert, key)]),
                TlsClientCertificateRequestType::RequestAndRequireClientCertificateAndVerify {
                    roots_provider: StaticRootsProvider::new(Roots::from_pem(ca)),
                },
            );
            let creds = ServerTlsCredendials::new(config).unwrap();
            let any_creds: Box<dyn DynServerChannelCredentials> = Box::new(creds);
            let stream = any_creds
                .accept_dyn(Box::new(stream), rt::default_runtime())
                .await
                .unwrap();
        });

        let client = tokio::spawn(async move {
            let addr = rx.await.unwrap();

            let socket = TcpStream::connect(addr).await.unwrap();

            let ca = fs::read(base_copy.join("server_ca_cert.pem")).unwrap();
            let cert = fs::read(base_copy.join("client1_cert.pem")).unwrap();
            let key = fs::read(base_copy.join("client1_key.pem")).unwrap();

            let config = ClientTlsConfig::new()
                .with_roots_provider(StaticRootsProvider::new(Roots::from_pem(ca)))
                .with_identity_provider(StaticIdentityProvider::new(Identity::from_pem(cert, key)));
            let creds = ClientTlsCredendials::new(config).unwrap();
            let any_creds: Box<dyn DynClientChannelCredential> = Box::new(creds);
            let stream = any_creds
                .connect_dyn(
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

    #[tokio::test]
    pub async fn test_metadata() {
        let call_creds = gcp::GcpCallCredentials::new().await.unwrap();
        let mut md = MetadataMap::new();
        let call_details = CallDetails {
            service_url: "https://www.googleapis.com",
            method_name: "auth/devstorage.read_write",
        };
        let auth_info = ChannelSecurityInfo {
            security_protocol: "tls",
            security_level: crate::endpoint::SecurityLevel::PrivacyAndIntegrity,
            attributes: crate::attributes::Attributes {},
        };
        call_creds
            .get_metadata(&call_details, &auth_info, &mut md)
            .await
            .unwrap();
        assert!(md.get("authorization").is_some());
        dbg!(md);
    }
}
