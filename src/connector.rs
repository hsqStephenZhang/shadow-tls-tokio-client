use std::ptr::copy_nonoverlapping;
use std::sync::Arc;

use rand::Rng;

use rand::distributions::Distribution;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use crate::prelude::*;

use crate::stream::{ProxyTlsStream, VerifiedStream};
use crate::utils::{resolve, Hmac};

pub struct Opts {
    pub fastopen: bool,
    pub sni: String,
    pub strcit: bool,
}

pub struct Connector {
    pub password: String,
    pub server_addr: String,
    pub tls_config: ClientConfig,
    pub connector: TlsConnector,
}

impl Connector {
    pub fn new(password: String, server_addr: String, alpn: Option<Vec<Vec<u8>>>) -> Self {
        let mut root_cert_store = RootCertStore::empty();
        root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut tls_config = ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();

        // Set tls config
        if let Some(alpn) = alpn {
            tls_config.alpn_protocols = alpn;
        }

        let connector = TlsConnector::from(Arc::new(tls_config.clone()));

        Self {
            password,
            server_addr,
            tls_config,
            connector,
        }
    }

    pub fn with_alpn(mut self, alpn: Vec<Vec<u8>>) -> Self {
        self.tls_config.alpn_protocols = alpn;
        self.connector = TlsConnector::from(Arc::new(self.tls_config.clone()));
        self
    }

    pub async fn connect(&self, opts: Opts) -> anyhow::Result<VerifiedStream<TcpStream>> {
        let addr = resolve(&self.server_addr).await?;
        // TODO: @zhangchong set keepalive and fastopen option to the tls_stream
        let stream = TcpStream::connect(addr).await?;
        let proxy_stream = ProxyTlsStream::new(stream, &self.password);

        tracing::trace!("tcp connected, start handshaking");

        let hamc_handshake = Hmac::new(&self.password, (&[], &[]));
        let sni_name = ServerName::try_from(opts.sni)?;
        let session_id_generator = move |data: &_| generate_session_id(&hamc_handshake, data);
        let mut tls = self
            .connector
            .connect_with(sni_name, proxy_stream, Some(session_id_generator), |_| {})
            .await?;
        // perform a fake request, will do the handshake
        tracing::trace!("handshake done");

        let authorized = tls.get_mut().0.authorized();
        let maybe_server_random_and_hamc = tls
            .get_mut()
            .0
            .state()
            .as_ref()
            .map(|s| (s.server_random, s.hmac.to_owned()));

        if (!authorized || maybe_server_random_and_hamc.is_none()) && opts.strcit {
            tracing::warn!("V3 strict enabled: traffic hijacked or TLS1.3 is not supported, perform fake request");

            tls.get_mut().0.fake_request = true;

            let r = fake_request(tls).await;

            anyhow::bail!("V3 strict enabled: traffic hijacked or TLS1.3 is not supported, fake request, res:{:?}", r);
        }

        let (server_random, hmac_nop) = match maybe_server_random_and_hamc {
            Some(inner) => inner,
            None => anyhow::bail!(
                "server random and hmac not extracted from handshake, fail to connect"
            ),
        };

        let hmac_client = Hmac::new(&self.password, (&server_random, "C".as_bytes()));
        let hmac_server = Hmac::new(&self.password, (&server_random, "S".as_bytes()));

        let verified_stream = VerifiedStream::new(
            tls.into_inner().0.raw,
            hmac_client,
            hmac_server,
            Some(hmac_nop),
        );

        Ok(verified_stream)
    }
}

/// Take a slice of tls message[5..] and returns signed session id.
///
/// Only used by V3 protocol.
fn generate_session_id(hmac: &Hmac, buf: &[u8]) -> [u8; TLS_SESSION_ID_SIZE] {
    /// Note: SESSION_ID_START does not include 5 TLS_HEADER_SIZE.
    const SESSION_ID_START: usize = 1 + 3 + 2 + TLS_RANDOM_SIZE + 1;

    if buf.len() < SESSION_ID_START + TLS_SESSION_ID_SIZE {
        tracing::warn!("unexpected client hello length");
        return [0; TLS_SESSION_ID_SIZE];
    }

    let mut session_id = [0; TLS_SESSION_ID_SIZE];
    rand::thread_rng().fill(&mut session_id[..TLS_SESSION_ID_SIZE - HMAC_SIZE]);
    let mut hmac = hmac.to_owned();
    hmac.update(&buf[0..SESSION_ID_START]);
    hmac.update(&session_id);
    hmac.update(&buf[SESSION_ID_START + TLS_SESSION_ID_SIZE..]);
    let hmac_val = hmac.finalize();
    unsafe {
        copy_nonoverlapping(
            hmac_val.as_ptr(),
            session_id.as_mut_ptr().add(TLS_SESSION_ID_SIZE - HMAC_SIZE),
            HMAC_SIZE,
        )
    }
    tracing::debug!("ClientHello before sign: {buf:?}, session_id {session_id:?}");
    session_id
}

/// Doing fake request.
///
/// Only used by V3 protocol.
async fn fake_request<S: tokio::io::AsyncRead + AsyncWrite + Unpin>(
    mut stream: TlsStream<S>,
) -> std::io::Result<()> {
    const HEADER: &[u8; 207] = b"GET / HTTP/1.1\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36\nAccept: gzip, deflate, br\nConnection: Close\nCookie: sessionid=";
    const FAKE_REQUEST_LENGTH_RANGE: (usize, usize) = (16, 64);
    let cnt =
        rand::thread_rng().gen_range(FAKE_REQUEST_LENGTH_RANGE.0..FAKE_REQUEST_LENGTH_RANGE.1);
    let mut buffer = Vec::with_capacity(cnt + HEADER.len() + 1);

    buffer.extend_from_slice(HEADER);
    rand::distributions::Alphanumeric
        .sample_iter(rand::thread_rng())
        .take(cnt)
        .for_each(|c| buffer.push(c));
    buffer.push(b'\n');

    stream.write_all(&buffer).await?;
    let _ = stream.shutdown().await;

    // read until eof
    let mut buf = Vec::with_capacity(1024);
    let r = stream.read_to_end(&mut buf).await;
    r.map(|_| ())
}

#[cfg(test)]
mod tests {

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub const HTTP_REQUEST_TEST: &[u8] = b"GET / HTTP/1.1\r\nHost: bing.com\r\nAccept: */*\r\n\r\n";
    pub const EXPECTED_RESP: &[u8] = b"HTTP/1.1 301";

    use super::*;

    #[tokio::test]
    async fn test_pure_shadow_tls_connector() -> anyhow::Result<()> {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .init();
        let connector = Connector::new("test".to_string(), "127.0.0.1:31003".to_owned(), None);
        let mut r = connector
            .connect(Opts {
                fastopen: false,
                sni: "captive.apple.com".to_owned(),
                strcit: true,
            })
            .await?;

        r.write(HTTP_REQUEST_TEST).await.unwrap();
        let mut resp = vec![0u8; EXPECTED_RESP.len()];
        r.read_exact(&mut resp).await.unwrap();
        println!("{}", String::from_utf8_lossy(&resp));
        assert_eq!(resp, EXPECTED_RESP);
        Ok(())
    }

    #[tokio::test]
    async fn test_copy_bidirectional() -> anyhow::Result<()> {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .init();
        let listern_addr = "127.0.0.1:31002";
        let listener = tokio::net::TcpListener::bind(listern_addr).await?;

        tokio::spawn(async move {
            let connector = Connector::new("test".to_string(), "127.0.0.1:31003".to_owned(), None);
            loop {
                let (mut upstream, _) = listener.accept().await.unwrap();
                let mut downstream = connector
                    .connect(Opts {
                        fastopen: false,
                        sni: "captive.apple.com".to_owned(),
                        strcit: true,
                    })
                    .await
                    .unwrap();

                // upper <-> shadow-tls-client <-> shadow-tls-server <-> target data server
                tokio::spawn(async move {
                    let res = tokio::io::copy_bidirectional(&mut upstream, &mut downstream).await;
                    tracing::debug!(
                        "io copy finished, upstream:{:?}, res:{:?}",
                        upstream.peer_addr(),
                        res
                    );
                });
            }
        });

        // wait for the listener to be ready
        std::thread::sleep(std::time::Duration::from_secs(3));

        // request and get response
        let mut r = TcpStream::connect(listern_addr).await.unwrap();
        r.write(HTTP_REQUEST_TEST).await.unwrap();
        let mut resp = vec![0u8; EXPECTED_RESP.len()];
        r.read_exact(&mut resp).await.unwrap();
        println!("{}", String::from_utf8_lossy(&resp));
        assert_eq!(resp, EXPECTED_RESP);

        Ok(())
    }
}
