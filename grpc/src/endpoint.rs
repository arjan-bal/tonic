use std::{any::Any, env, os::fd::AsFd, pin::Pin, sync::Arc};

use boring::{
    pkey::PKey,
    ssl::{SslConnector, SslMethod, SslVerifyMode},
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

use crate::byte_str::ByteStr;

pub(crate) trait ReadHalf: AsyncRead + Send + Unpin {
    fn set_read_options(&mut self, opts: ReadOptions) -> Result<(), String>;
}

#[derive(Clone, Default, Debug)]
pub(crate) struct ReadOptions {
    min_progress_size: Option<u64>,
}

pub(crate) trait WriteHalf: AsyncWrite + Send + Unpin {}

pub(crate) trait GrpcEndpoint: ReadHalf + WriteHalf {
    fn split(self: Box<Self>) -> (Box<dyn ReadHalf>, Box<dyn WriteHalf>);
}

pub(crate) type BoxGrpcEndpoint = Box<dyn GrpcEndpoint>;

pub(crate) struct TokioReadHalf {
    inner: tokio::net::tcp::OwnedReadHalf,
}

impl ReadHalf for TokioReadHalf {
    fn set_read_options(&mut self, opts: ReadOptions) -> Result<(), String> {
        if let Some(progress_size) = opts.min_progress_size {
            self.inner.as_ref().as_fd();
            // TODO: Set SO_RCVLOWAT.
        }
        Ok(())
    }
}

impl AsyncRead for TokioReadHalf {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

pub(crate) struct TokioWriteHalf {
    inner: tokio::net::tcp::OwnedWriteHalf,
}

impl WriteHalf for TokioWriteHalf {}

impl AsyncWrite for TokioWriteHalf {
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

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

impl WriteHalf for TcpStream {}

impl ReadHalf for TcpStream {
    fn set_read_options(&mut self, opts: ReadOptions) -> Result<(), String> {
        if let Some(progress_size) = opts.min_progress_size {
            self.as_fd();
            // TODO: Set SO_RCVLOWAT.
        }
        Ok(())
    }
}

impl GrpcEndpoint for TcpStream {
    fn split(self: Box<Self>) -> (Box<dyn ReadHalf>, Box<dyn WriteHalf>) {
        let (r, w) = self.into_split();
        let read_half = Box::new(TokioReadHalf { inner: r });
        let write_half = Box::new(TokioWriteHalf { inner: w });
        (read_half, write_half)
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

pub(crate) trait ServerChannelCredentials: Send {
    async fn accept(
        &self,
        source: BoxGrpcEndpoint,
    ) -> Result<(BoxGrpcEndpoint, ConnectionSecurityInfo), String>;

    fn protocol_info(&self) -> ProtocolInfo;

    fn clone(&self) -> Box<dyn ClientChannelCredential>;
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

impl ServerChannelCredentials for ClientTlsCredendials {
    async fn accept(
        &self,
        source: BoxGrpcEndpoint,
    ) -> Result<(BoxGrpcEndpoint, ConnectionSecurityInfo), String> {
        let mut ssl_builder = boring::ssl::SslAcceptor::mozilla_modern(SslMethod::tls_server())
            .map_err(|e| e.to_string())?;
        ssl_builder
            .set_default_verify_paths()
            .map_err(|e| e.to_string())?;
        ssl_builder.set_verify(SslVerifyMode::NONE);
        let acceptor = ssl_builder.build();
        let tls_stream = tokio_boring::accept(&acceptor, source)
            .await
            .map_err(|e| e.to_string())?;
        let auth_info = ConnectionSecurityInfo {
            auth_type: ByteStr::from("tls".to_string()),
            validator: None,
            security_level: SecurityLevel::PrivacyAndIntegrity,
            connection_security_context: Box::new(()),
        };
        let ep: BoxGrpcEndpoint = Box::new(TlsStream { inner: tls_stream });
        Ok((ep, auth_info))
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

impl WriteHalf for TlsStream {}

impl ReadHalf for TlsStream {
    fn set_read_options(&mut self, opts: ReadOptions) -> Result<(), String> {
        self.inner.get_mut().set_read_options(opts)
    }
}

impl GrpcEndpoint for TlsStream {
    fn split(self: Box<Self>) -> (Box<dyn ReadHalf>, Box<dyn WriteHalf>) {
        let (left, right) = tokio::io::split(self.inner);
        (
            Box::new(TlsReadHalf { inner: left }),
            Box::new(TlsWriteHalf { inner: right }),
        )
    }
}

pub(crate) struct TlsReadHalf {
    inner: tokio::io::ReadHalf<SslStream<BoxGrpcEndpoint>>,
}

impl ReadHalf for TlsReadHalf {
    fn set_read_options(&mut self, opts: ReadOptions) -> Result<(), String> {
        // TODO: Implement a way to support setting ReadOptions on an SslStream's
        // ReadHalf. This would probably require implementing our own split
        // operation that allows getting a mutable reference to the underlying
        // BoxGrpcEndpoint for delegation.
        Ok(())
    }
}

impl AsyncRead for TlsReadHalf {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

pub(crate) struct TlsWriteHalf {
    inner: tokio::io::WriteHalf<SslStream<BoxGrpcEndpoint>>,
}

impl WriteHalf for TlsWriteHalf {}

impl AsyncWrite for TlsWriteHalf {
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

#[cfg(test)]
mod test {

    use crate::{
        byte_str::ByteStr,
        endpoint::{
            new_client_tls_credentials, BoxGrpcEndpoint, ClientChannelCredential, ClientTlsConfig,
            ClientTlsCredendials,
        },
    };

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
}
