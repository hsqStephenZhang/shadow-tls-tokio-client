use std::{
    mem::MaybeUninit,
    pin::Pin,
    ptr::{copy, copy_nonoverlapping},
    task::{ready, Poll},
};

use byteorder::{BigEndian, WriteBytesExt};
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::utils::{prelude::*, Hmac, *};

#[derive(Default, Debug)]
pub enum TlsMsgReadState {
    #[default]
    WaitingHeader,
    WaitingData(usize, [u8; TLS_HEADER_SIZE]),
    FlushingData,
}

#[derive(Default, Debug)]
pub enum TlsMsgWriteState {
    #[default]
    BuildingData,
    // consume, totol, written
    // consume should be the size of the buf in the argument of poll_write
    // or it will lead to assert failure in copy_bidirectional in tokio:
    // please refer to: tokio-1.35.1/src/io/util/copy.rs:126:13
    //    debug_assert!(
    //        self.pos <= self.cap,
    //        "writer returned length larger than input slice"
    //    );
    FlushingData(usize, usize, usize),
}

pub trait AsyncReadUnpin: AsyncRead + Unpin {}

impl<T: AsyncRead + Unpin> AsyncReadUnpin for T {}

pub trait ReadExtBase {
    fn prepare(&mut self) -> (&mut dyn AsyncReadUnpin, &mut BytesMut, &mut usize);
}

pub trait ReadExt {
    fn poll_read_exact(
        &mut self,
        cx: &mut std::task::Context,
        size: usize,
    ) -> Poll<std::io::Result<()>>;
}

impl<T: ReadExtBase> ReadExt for T {
    fn poll_read_exact(
        &mut self,
        cx: &mut std::task::Context,
        size: usize,
    ) -> Poll<std::io::Result<()>> {
        let (raw, read_buf, read_pos) = self.prepare();
        read_buf.reserve(size);
        // # safety: read_buf has reserved `size`
        unsafe { read_buf.set_len(size) }
        tracing::debug!(
            "poll read exact: {}, read_pos: {}, buf: {}",
            size,
            read_pos,
            read_buf.len()
        );
        loop {
            if *read_pos < size {
                // # safety: read_pos<size==read_buf.len(), and read_buf[0..read_pos] is initialized
                let dst = unsafe {
                    &mut *((&mut read_buf[*read_pos..size]) as *mut _ as *mut [MaybeUninit<u8>])
                };
                let mut buf = ReadBuf::uninit(dst);
                let ptr = buf.filled().as_ptr();
                ready!(Pin::new(&mut *raw).poll_read(cx, &mut buf))?;
                assert_eq!(ptr, buf.filled().as_ptr());
                if buf.filled().is_empty() {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "unexpected eof",
                    )));
                }
                *read_pos += buf.filled().len();
            } else {
                assert!(*read_pos == size);
                *read_pos = 0;
                return Poll::Ready(Ok(()));
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Certs {
    pub(crate) server_random: [u8; TLS_RANDOM_SIZE],
    pub(crate) hmac: Hmac,
    pub(crate) key: Vec<u8>,
}

pub struct ProxyTlsStream<S> {
    pub raw: S,
    password: String,

    pub read_state: TlsMsgReadState,
    pub read_pos: usize,
    pub read_buf: BytesMut,

    // need to get from the handshake packets
    pub certs: Option<Certs>,
    read_authorized: bool,
    tls13: bool,

    // if true, the stream will only act as a wrapper, and won't modify the inner byte stream
    pub fake_request: bool,
}

impl<S> ProxyTlsStream<S> {
    pub fn new(raw: S, password: &str) -> Self {
        Self {
            // buf: BytesMut::new(),
            // read_pos: 0,
            raw,
            password: password.to_string(),

            read_state: Default::default(),
            read_pos: Default::default(),
            read_buf: Default::default(),

            certs: None,
            read_authorized: false,
            tls13: false,

            fake_request: false,
        }
    }

    pub fn authorized(&self) -> bool {
        self.read_authorized
    }

    pub fn state(&self) -> &Option<Certs> {
        &self.certs
    }

    pub fn tls13(&self) -> bool {
        self.tls13
    }
}

impl<S: AsyncReadUnpin> ReadExtBase for ProxyTlsStream<S> {
    fn prepare(&mut self) -> (&mut dyn AsyncReadUnpin, &mut BytesMut, &mut usize) {
        (&mut self.raw, &mut self.read_buf, &mut self.read_pos)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ProxyTlsStream<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if this.fake_request {
            return Pin::new(&mut this.raw).poll_read(cx, buf);
        }

        // let r = Pin::new(&mut this.raw).poll_read(cx, buf);

        loop {
            match this.read_state {
                TlsMsgReadState::WaitingHeader => {
                    ready!(this.poll_read_exact(cx, TLS_HEADER_SIZE))?;
                    let buf = this.read_buf.split().freeze().to_vec();

                    let mut size: [u8; 2] = Default::default();
                    size.copy_from_slice(&buf[3..5]);
                    let data_size = u16::from_be_bytes(size) as usize;

                    let mut header = [0u8; TLS_HEADER_SIZE];
                    header.copy_from_slice(&buf[..TLS_HEADER_SIZE]);

                    this.read_state = TlsMsgReadState::WaitingData(data_size, header);
                }
                TlsMsgReadState::WaitingData(size, mut header) => {
                    ready!(this.poll_read_exact(cx, size))?;
                    // now the data is ready with the required size
                    let mut body = this.read_buf.split().freeze().to_vec();

                    match header[0] {
                        HANDSHAKE => {
                            if body.len() > SERVER_RANDOM_OFFSET + TLS_RANDOM_SIZE
                                && body[0] == SERVER_HELLO
                            {
                                let mut server_random = [0; TLS_RANDOM_SIZE];
                                unsafe {
                                    copy_nonoverlapping(
                                        body.as_ptr().add(SERVER_RANDOM_OFFSET),
                                        server_random.as_mut_ptr(),
                                        TLS_RANDOM_SIZE,
                                    )
                                }
                                tracing::debug!("ServerRandom extracted: {server_random:?}");
                                let hmac = Hmac::new(&this.password, (&server_random, &[]));
                                let key = kdf(&this.password, &server_random);
                                this.certs = Some(Certs {
                                    server_random,
                                    hmac,
                                    key,
                                });
                                this.tls13 = support_tls13(&body);
                            }
                        }
                        APPLICATION_DATA => {
                            this.read_authorized = false;
                            if body.len() > HMAC_SIZE {
                                if let Some(Certs { hmac, key, .. }) = this.certs.as_mut() {
                                    hmac.update(&body[HMAC_SIZE..]);
                                    if hmac.finalize() == body[0..HMAC_SIZE] {
                                        // 1. xor to the the original data
                                        xor_slice(&mut body[HMAC_SIZE..], key);
                                        // 2. remove the hmac
                                        unsafe {
                                            copy(
                                                body.as_ptr().add(HMAC_SIZE),
                                                body.as_mut_ptr(),
                                                body.len() - HMAC_SIZE,
                                            )
                                        };
                                        // 3. rewrite the data size in the header
                                        (&mut header[3..5])
                                            .write_u16::<BigEndian>(size as u16 - HMAC_SIZE as u16)
                                            .unwrap();
                                        this.read_authorized = true;
                                        // 4. rewrite the body length to be put into the read buf
                                        unsafe {
                                            body.set_len(body.len() - HMAC_SIZE);
                                        }
                                        // 4. put the header and body into our own read buf
                                        tracing::debug!("authorization sucess");
                                    } else {
                                        tracing::debug!("app data verification failed");
                                    }
                                }
                            }
                        }
                        _ => {}
                    }

                    this.read_buf.put(&header[..]);
                    this.read_buf.put(&body[..]);
                    this.read_state = TlsMsgReadState::FlushingData;
                }
                TlsMsgReadState::FlushingData => {
                    // now the data is ready in the read_buf
                    let size = this.read_buf.len();
                    let to_read = std::cmp::min(buf.remaining(), size);
                    let payload = this.read_buf.split_to(to_read);
                    buf.put_slice(&payload);
                    if to_read < size {
                        // there're unread data, continues in next poll
                        this.read_state = TlsMsgReadState::FlushingData;
                    } else {
                        // all data consumed, ready to read next chunk
                        this.read_state = TlsMsgReadState::WaitingHeader;
                    }

                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ProxyTlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let this = self.get_mut();
        Pin::new(&mut this.raw).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let this = self.get_mut();
        Pin::new(&mut this.raw).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let this = self.get_mut();
        Pin::new(&mut this.raw).poll_shutdown(cx)
    }
}

pub struct VerifiedStream<S> {
    pub raw: S,
    client_cert: Hmac,
    server_cert: Hmac,
    nop_cert: Option<Hmac>,

    pub read_buf: BytesMut,
    pub read_pos: usize,
    pub read_state: TlsMsgReadState,

    pub write_buf: BytesMut,
    pub write_state: TlsMsgWriteState,
}

impl<S> VerifiedStream<S> {
    pub(crate) fn new(
        raw: S,
        client_cert: Hmac,
        server_cert: Hmac,
        nop_cert: Option<Hmac>,
    ) -> Self {
        Self {
            raw,
            client_cert,
            server_cert,
            nop_cert,
            read_buf: Default::default(),
            read_pos: Default::default(),
            read_state: Default::default(),
            write_buf: Default::default(),
            write_state: Default::default(),
        }
    }
}

impl<S: AsyncReadUnpin> ReadExtBase for VerifiedStream<S> {
    fn prepare(&mut self) -> (&mut dyn AsyncReadUnpin, &mut BytesMut, &mut usize) {
        (&mut self.raw, &mut self.read_buf, &mut self.read_pos)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VerifiedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        loop {
            match this.read_state {
                TlsMsgReadState::WaitingHeader => {
                    ready!(this.poll_read_exact(cx, TLS_HEADER_SIZE))?;
                    let buf = this.read_buf.split().freeze().to_vec();

                    let mut size: [u8; 2] = Default::default();
                    size.copy_from_slice(&buf[3..5]);
                    let data_size = u16::from_be_bytes(size) as usize;

                    let mut header = [0u8; TLS_HEADER_SIZE];
                    header.copy_from_slice(&buf[..TLS_HEADER_SIZE]);

                    this.read_state = TlsMsgReadState::WaitingData(data_size, header);
                }
                TlsMsgReadState::WaitingData(size, header) => {
                    ready!(this.poll_read_exact(cx, size))?;
                    // now the data is ready with the required size
                    let mut data = this.read_buf.split().freeze().to_vec();

                    match header[0] {
                        APPLICATION_DATA => {
                            // ignore the rest useless data
                            if let Some(ref mut nop_cert) = this.nop_cert {
                                if verify_appdata(&header, &mut data, nop_cert, false) {
                                    tracing::debug!("receive nop appdata");
                                    this.read_state = TlsMsgReadState::WaitingHeader;
                                    continue;
                                } else {
                                    this.nop_cert.take();
                                }
                            }

                            // the application data from the data server
                            // we need to verfiy and removec the hmac(4 bytes)
                            if verify_appdata(&header, &mut data, &mut this.server_cert, true) {
                                // modify data, reuse the read buf
                                tracing::trace!("verify appdata success, strip the hamc");
                                this.read_buf.clear();
                                this.read_buf.put(&data[HMAC_SIZE..]);
                                this.read_state = TlsMsgReadState::FlushingData;
                            } else {
                                tracing::error!("appdata verify failed");
                                return Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "appdata verify failed",
                                )));
                            }
                        }
                        _ => {}
                    }
                }
                TlsMsgReadState::FlushingData => {
                    // now the data is ready in the read_buf
                    let size = this.read_buf.len();
                    let to_read = std::cmp::min(buf.remaining(), size);
                    let payload = this.read_buf.split_to(to_read);
                    buf.put_slice(&payload);
                    if to_read < size {
                        // there're unread data, continues in next poll
                        this.read_state = TlsMsgReadState::FlushingData;
                    } else {
                        // all data consumed, ready to read next chunk
                        this.read_state = TlsMsgReadState::WaitingHeader;
                    }

                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VerifiedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let this = self.get_mut();
        loop {
            match this.write_state {
                TlsMsgWriteState::BuildingData => {
                    // header(5 bytes) + zero hmac(4 bytes)
                    const DEFAULT_HEADER_HMAC: [u8; TLS_HMAC_HEADER_SIZE] =
                        [APPLICATION_DATA, TLS_MAJOR, TLS_MINOR.0, 0, 0, 0, 0, 0, 0];

                    let mut header_body = Vec::with_capacity(COPY_BUF_SIZE);
                    header_body.extend_from_slice(&DEFAULT_HEADER_HMAC);

                    (&mut header_body[3..5])
                        .write_u16::<BigEndian>((buf.len() + HMAC_SIZE) as u16)
                        .unwrap();
                    header_body.extend_from_slice(buf);

                    this.client_cert.update(buf);
                    let hmac_val = this.client_cert.finalize();
                    this.client_cert.update(&hmac_val);
                    tracing::debug!("hmac updated: {:x?}", &hmac_val);
                    unsafe {
                        copy_nonoverlapping(
                            hmac_val.as_ptr(),
                            header_body.as_mut_ptr().add(TLS_HEADER_SIZE),
                            HMAC_SIZE,
                        )
                    };

                    this.write_buf.put_slice(&header_body);
                    this.write_state =
                        TlsMsgWriteState::FlushingData(buf.len(), header_body.len(), 0);
                }
                TlsMsgWriteState::FlushingData(consume, total, written) => {
                    let nw = ready!(tokio_util::io::poll_write_buf(
                        Pin::new(&mut this.raw),
                        cx,
                        &mut this.write_buf
                    ))?;
                    if nw == 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "failed to write whole data",
                        ))
                        .into();
                    }

                    if written + nw >= total {
                        debug_assert_eq!(written + nw, total);
                        // data chunk written, go to next chunk
                        this.write_state = TlsMsgWriteState::BuildingData;
                        tracing::debug!("buf size:{}, return size:{}", buf.len(), total);
                        return Poll::Ready(Ok(consume));
                    }

                    this.write_state =
                        TlsMsgWriteState::FlushingData(consume, total, written + nw);
                }
            }
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let this = self.get_mut();
        Pin::new(&mut this.raw).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let this = self.get_mut();
        Pin::new(&mut this.raw).poll_shutdown(cx)
    }
}

fn verify_appdata(
    header: &[u8; TLS_HEADER_SIZE],
    data: &mut [u8],
    hmac: &mut Hmac,
    sep: bool,
) -> bool {
    if header[1] != TLS_MAJOR || header[2] != TLS_MINOR.0 {
        return false;
    }
    hmac.update(&data[HMAC_SIZE..]);
    let hmac_real = hmac.finalize();
    tracing::debug!("verify data, hmac updated: {:x?}", &hmac_real);
    if sep {
        hmac.update(&hmac_real);
    }
    data[0..HMAC_SIZE] == hmac_real
}
