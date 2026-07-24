//! Tokio-based driver for [`proto::Connection`]
//!
//! [`Session`] runs a QMux connection over any `AsyncRead + AsyncWrite` transport (TCP,
//! TLS, UNIX sockets, an in-memory duplex, ...). A single background task owns the
//! transport: it feeds received bytes into the sans-IO state machine, writes out records,
//! and services timeouts. Application handles operate on the shared state machine directly
//! and park themselves on wakers or notifies that the driver fires as events surface,
//! mirroring the design of the `quinn` crate.

use std::{
    future::{Future, poll_fn},
    pin::pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
    time::Instant,
};

use bytes::Bytes;
use rustc_hash::FxHashMap;
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::Notify,
};
use tracing::debug;

use quinn_proto::{Chunk, Dir, Side, StreamEvent, StreamId, VarInt};

use crate::{
    config::Config,
    proto::{self, ConnectionError, Event, SendDatagramError},
};

/// Errors from writing to a [`SendStream`]
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum WriteError {
    /// The peer stopped accepting data on this stream
    #[error("stream stopped by peer: code {}", .0.into_inner())]
    Stopped(VarInt),
    /// The connection was lost
    #[error("connection lost: {0}")]
    ConnectionLost(#[from] ConnectionError),
    /// The stream was already finished or reset
    #[error("closed stream")]
    ClosedStream,
}

/// Errors from reading from a [`RecvStream`]
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ReadError {
    /// The peer abandoned the stream
    #[error("stream reset by peer: code {}", .0.into_inner())]
    Reset(VarInt),
    /// The connection was lost
    #[error("connection lost: {0}")]
    ConnectionLost(#[from] ConnectionError),
    /// The stream was already stopped or its end already read
    #[error("closed stream")]
    ClosedStream,
}

struct State {
    conn: proto::Connection,
    blocked_writers: FxHashMap<StreamId, Waker>,
    blocked_readers: FxHashMap<StreamId, Waker>,
}

struct Shared {
    state: Mutex<State>,
    /// Wakes the driver after application-side calls mutate the state machine
    driver: Notify,
    /// Handshake completion or termination
    connected: Notify,
    /// Peer-opened streams available to accept, per direction
    incoming: [Notify; 2],
    /// Stream credit available to open, per direction
    available: [Notify; 2],
    /// Datagrams available to receive
    datagrams: Notify,
    /// Connection terminated
    closed: Notify,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }

    /// Drain state machine events into task wakeups; call after any state mutation
    fn dispatch(&self, state: &mut State) {
        while let Some(event) = state.conn.poll() {
            match event {
                Event::Connected => self.connected.notify_waiters(),
                Event::Stream(StreamEvent::Opened { dir }) => {
                    self.incoming[dir as usize].notify_waiters()
                }
                Event::Stream(StreamEvent::Available { dir }) => {
                    self.available[dir as usize].notify_waiters()
                }
                Event::Stream(StreamEvent::Readable { id }) => {
                    if let Some(waker) = state.blocked_readers.remove(&id) {
                        waker.wake();
                    }
                }
                Event::Stream(StreamEvent::Writable { id })
                | Event::Stream(StreamEvent::Stopped { id, .. }) => {
                    if let Some(waker) = state.blocked_writers.remove(&id) {
                        waker.wake();
                    }
                }
                Event::Stream(StreamEvent::Finished { .. }) => {}
                Event::DatagramReceived => self.datagrams.notify_waiters(),
                Event::ConnectionLost { reason } => {
                    debug!(%reason, "connection lost");
                    self.connected.notify_waiters();
                    self.closed.notify_waiters();
                    self.datagrams.notify_waiters();
                    for dir in [Dir::Bi, Dir::Uni] {
                        self.incoming[dir as usize].notify_waiters();
                        self.available[dir as usize].notify_waiters();
                    }
                    for (_, waker) in state.blocked_writers.drain() {
                        waker.wake();
                    }
                    for (_, waker) in state.blocked_readers.drain() {
                        waker.wake();
                    }
                }
            }
        }
    }
}

/// Closes the connection when the last handle (session or stream) is dropped
struct CloseGuard {
    shared: Arc<Shared>,
}

impl Drop for CloseGuard {
    fn drop(&mut self) {
        let mut state = self.shared.lock();
        state.conn.close(VarInt::from_u32(0), Bytes::new());
        self.shared.dispatch(&mut state);
        drop(state);
        self.shared.driver.notify_one();
    }
}

/// A QMux connection over a reliable, ordered transport
///
/// Cheap to clone. The connection is closed (with error code 0) when every [`Session`],
/// [`SendStream`], and [`RecvStream`] handle referencing it has been dropped.
#[derive(Clone)]
pub struct Session {
    shared: Arc<Shared>,
    guard: Arc<CloseGuard>,
}

impl Session {
    /// Establish a QMux connection as the client over `io`
    ///
    /// `io` must provide an ordered, reliable byte stream, with any security layer (e.g.
    /// TLS) already established. Resolves once the peer's transport parameters arrive.
    pub async fn connect<T>(io: T, config: Config) -> Result<Self, ConnectionError>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        Self::start(io, config, Side::Client).await
    }

    /// Establish a QMux connection as the server over `io`
    pub async fn accept<T>(io: T, config: Config) -> Result<Self, ConnectionError>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        Self::start(io, config, Side::Server).await
    }

    async fn start<T>(io: T, config: Config, side: Side) -> Result<Self, ConnectionError>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let conn = proto::Connection::new(Arc::new(config), side, Instant::now());
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                conn,
                blocked_writers: FxHashMap::default(),
                blocked_readers: FxHashMap::default(),
            }),
            driver: Notify::new(),
            connected: Notify::new(),
            incoming: [Notify::new(), Notify::new()],
            available: [Notify::new(), Notify::new()],
            datagrams: Notify::new(),
            closed: Notify::new(),
        });
        tokio::spawn(drive(io, shared.clone()));

        let session = Self {
            guard: Arc::new(CloseGuard {
                shared: shared.clone(),
            }),
            shared,
        };
        session
            .wait_for(|conn| match conn.error() {
                Some(reason) => Some(Err(reason.clone())),
                None => conn.is_established().then(|| Ok(())),
            })
            .await?;
        Ok(session)
    }

    /// Wait on the connection state until `f` produces an outcome
    async fn wait_for<U>(
        &self,
        f: impl Fn(&mut proto::Connection) -> Option<U>,
    ) -> U {
        loop {
            let notified = {
                let mut state = self.shared.lock();
                if let Some(out) = f(&mut state.conn) {
                    self.shared.dispatch(&mut state);
                    drop(state);
                    self.shared.driver.notify_one();
                    return out;
                }
                // Register interest in everything that could change the outcome; the
                // caller-specific notify would be sharper, but connection-level waits are
                // rare enough that waking on any event is fine
                self.notified_any()
            };
            notified.await;
        }
    }

    /// A future resolving on the next connection-level notification
    fn notified_any(&self) -> impl Future<Output = ()> + '_ {
        let connected = self.shared.connected.notified();
        let closed = self.shared.closed.notified();
        let incoming_bi = self.shared.incoming[Dir::Bi as usize].notified();
        let incoming_uni = self.shared.incoming[Dir::Uni as usize].notified();
        let available_bi = self.shared.available[Dir::Bi as usize].notified();
        let available_uni = self.shared.available[Dir::Uni as usize].notified();
        let datagrams = self.shared.datagrams.notified();
        async move {
            tokio::select! {
                _ = connected => {}
                _ = closed => {}
                _ = incoming_bi => {}
                _ = incoming_uni => {}
                _ = available_bi => {}
                _ = available_uni => {}
                _ = datagrams => {}
            }
        }
    }

    fn streams(&self, id: StreamId) -> (SendStream, RecvStream) {
        (
            SendStream {
                shared: self.shared.clone(),
                guard: self.guard.clone(),
                id,
                finished: false,
            },
            RecvStream {
                shared: self.shared.clone(),
                guard: self.guard.clone(),
                id,
                ended: false,
            },
        )
    }

    /// Open a bidirectional stream, waiting for stream credit if necessary
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream), ConnectionError> {
        let id = self.open_stream(Dir::Bi).await?;
        Ok(self.streams(id))
    }

    /// Open a unidirectional stream, waiting for stream credit if necessary
    pub async fn open_uni(&self) -> Result<SendStream, ConnectionError> {
        let id = self.open_stream(Dir::Uni).await?;
        Ok(SendStream {
            shared: self.shared.clone(),
            guard: self.guard.clone(),
            id,
            finished: false,
        })
    }

    async fn open_stream(&self, dir: Dir) -> Result<StreamId, ConnectionError> {
        self.wait_for(|conn| match conn.error() {
            Some(reason) => Some(Err(reason.clone())),
            None => conn.streams().open(dir).map(Ok),
        })
        .await
    }

    /// Accept the next bidirectional stream opened by the peer
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), ConnectionError> {
        let id = self.accept_stream(Dir::Bi).await?;
        Ok(self.streams(id))
    }

    /// Accept the next unidirectional stream opened by the peer
    pub async fn accept_uni(&self) -> Result<RecvStream, ConnectionError> {
        let id = self.accept_stream(Dir::Uni).await?;
        Ok(RecvStream {
            shared: self.shared.clone(),
            guard: self.guard.clone(),
            id,
            ended: false,
        })
    }

    async fn accept_stream(&self, dir: Dir) -> Result<StreamId, ConnectionError> {
        self.wait_for(|conn| match conn.error() {
            Some(reason) => Some(Err(reason.clone())),
            None => conn.streams().accept(dir).map(Ok),
        })
        .await
    }

    /// Queue a datagram for transmission
    ///
    /// QMux datagrams are delivered reliably and in order once sent, subject to the same
    /// head-of-line blocking as stream data.
    pub fn send_datagram(&self, data: Bytes) -> Result<(), SendDatagramError> {
        let mut state = self.shared.lock();
        let result = state.conn.send_datagram(data);
        drop(state);
        self.shared.driver.notify_one();
        result
    }

    /// Receive the next datagram
    pub async fn recv_datagram(&self) -> Result<Bytes, ConnectionError> {
        self.wait_for(|conn| match conn.recv_datagram() {
            Some(data) => Some(Ok(data)),
            None => conn.error().cloned().map(Err),
        })
        .await
    }

    /// Largest datagram payload the peer accepts, if datagrams are supported
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.shared.lock().conn.max_datagram_size()
    }

    /// Close the connection, sending an APPLICATION_CLOSE frame to the peer
    pub fn close(&self, error_code: VarInt, reason: Bytes) {
        let mut state = self.shared.lock();
        state.conn.close(error_code, reason);
        self.shared.dispatch(&mut state);
        drop(state);
        self.shared.driver.notify_one();
    }

    /// Wait for the connection to terminate, returning the reason
    pub async fn closed(&self) -> ConnectionError {
        loop {
            let notified = {
                let state = self.shared.lock();
                if let Some(reason) = state.conn.error() {
                    return reason.clone();
                }
                self.shared.closed.notified()
            };
            notified.await;
        }
    }
}

/// The sending half of a QMux stream
///
/// If dropped without [`SendStream::finish`] being called, the stream is reset with error
/// code 0.
pub struct SendStream {
    shared: Arc<Shared>,
    guard: Arc<CloseGuard>,
    id: StreamId,
    finished: bool,
}

impl SendStream {
    /// This stream's identifier
    pub fn id(&self) -> StreamId {
        self.id
    }

    /// Write some data, returning how much was accepted
    ///
    /// Waits when blocked by flow control or the local send window.
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize, WriteError> {
        poll_fn(|cx| self.poll_write(cx, buf)).await
    }

    /// Write an entire buffer
    pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), WriteError> {
        let mut written = 0;
        while written < buf.len() {
            written += poll_fn(|cx| self.poll_write(cx, &buf[written..])).await?;
        }
        Ok(())
    }

    fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, WriteError>> {
        use quinn_proto::WriteError as Proto;
        let mut state = self.shared.lock();
        if let Some(reason) = state.conn.error() {
            return Poll::Ready(Err(WriteError::ConnectionLost(reason.clone())));
        }
        // Surface a peer STOP_SENDING as an error rather than silently discarding data
        if let Ok(Some(code)) = state.conn.send_stream(self.id).stopped() {
            return Poll::Ready(Err(WriteError::Stopped(code)));
        }
        match state.conn.send_stream(self.id).write(buf) {
            Ok(n) => {
                self.shared.dispatch(&mut state);
                drop(state);
                self.shared.driver.notify_one();
                Poll::Ready(Ok(n))
            }
            Err(Proto::Blocked) => {
                state.blocked_writers.insert(self.id, cx.waker().clone());
                Poll::Pending
            }
            Err(Proto::Stopped(code)) => Poll::Ready(Err(WriteError::Stopped(code))),
            Err(Proto::ClosedStream) => Poll::Ready(Err(WriteError::ClosedStream)),
        }
    }

    /// Signal the end of the stream
    ///
    /// Data already written is still delivered; [`StreamEvent::Finished`] semantics follow
    /// the draft, treating serialization into a record as acknowledgment.
    pub fn finish(&mut self) -> Result<(), WriteError> {
        let mut state = self.shared.lock();
        if let Some(reason) = state.conn.error() {
            return Err(WriteError::ConnectionLost(reason.clone()));
        }
        match state.conn.send_stream(self.id).finish() {
            Ok(()) => {
                self.finished = true;
                drop(state);
                self.shared.driver.notify_one();
                Ok(())
            }
            Err(quinn_proto::FinishError::Stopped(code)) => Err(WriteError::Stopped(code)),
            Err(quinn_proto::FinishError::ClosedStream) => Err(WriteError::ClosedStream),
        }
    }

    /// Abandon the stream, notifying the peer with the given error code
    pub fn reset(&mut self, error_code: VarInt) -> Result<(), WriteError> {
        let mut state = self.shared.lock();
        if let Some(reason) = state.conn.error() {
            return Err(WriteError::ConnectionLost(reason.clone()));
        }
        match state.conn.send_stream(self.id).reset(error_code) {
            Ok(()) => {
                self.finished = true;
                drop(state);
                self.shared.driver.notify_one();
                Ok(())
            }
            Err(_) => Err(WriteError::ClosedStream),
        }
    }

    /// Set this stream's priority; higher values are transmitted first
    pub fn set_priority(&self, priority: i32) {
        let mut state = self.shared.lock();
        let _ = state.conn.send_stream(self.id).set_priority(priority);
    }
}

impl Drop for SendStream {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let mut state = self.shared.lock();
        let _ = state.conn.send_stream(self.id).reset(VarInt::from_u32(0));
        drop(state);
        self.shared.driver.notify_one();
        let _ = &self.guard;
    }
}

/// The receiving half of a QMux stream
///
/// If dropped before the stream's end has been read, the peer is asked to stop sending
/// with error code 0.
pub struct RecvStream {
    shared: Arc<Shared>,
    guard: Arc<CloseGuard>,
    id: StreamId,
    /// Whether the stream's end (FIN, reset, or stop) has been observed
    ended: bool,
}

impl RecvStream {
    /// This stream's identifier
    pub fn id(&self) -> StreamId {
        self.id
    }

    /// Read data into `buf`, returning how much was read or `None` at the end of the stream
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, ReadError> {
        match self.read_chunk(buf.len()).await? {
            Some(chunk) => {
                buf[..chunk.bytes.len()].copy_from_slice(&chunk.bytes);
                Ok(Some(chunk.bytes.len()))
            }
            None => Ok(None),
        }
    }

    /// Read the next chunk of data, at most `max_length` bytes, or `None` at the end
    pub async fn read_chunk(&mut self, max_length: usize) -> Result<Option<Chunk>, ReadError> {
        poll_fn(|cx| self.poll_read_chunk(cx, max_length)).await
    }

    /// Buffer the entire remainder of the stream, erroring if it exceeds `size_limit`
    pub async fn read_to_end(&mut self, size_limit: usize) -> Result<Vec<u8>, ReadError> {
        let mut data = Vec::new();
        while let Some(chunk) = self.read_chunk(size_limit - data.len()).await? {
            if data.len() + chunk.bytes.len() > size_limit {
                return Err(ReadError::ClosedStream);
            }
            data.extend_from_slice(&chunk.bytes);
        }
        Ok(data)
    }

    fn poll_read_chunk(
        &mut self,
        cx: &mut Context<'_>,
        max_length: usize,
    ) -> Poll<Result<Option<Chunk>, ReadError>> {
        use quinn_proto::ReadError as Proto;
        if self.ended {
            return Poll::Ready(Err(ReadError::ClosedStream));
        }
        let mut guard = self.shared.lock();
        let state = &mut *guard;
        if let Some(reason) = state.conn.error() {
            return Poll::Ready(Err(ReadError::ConnectionLost(reason.clone())));
        }
        let mut recv = state.conn.recv_stream(self.id);
        let mut chunks = match recv.read(true) {
            Ok(chunks) => chunks,
            Err(_) => {
                self.ended = true;
                return Poll::Ready(Err(ReadError::ClosedStream));
            }
        };
        let result = match chunks.next(max_length) {
            Ok(Some(chunk)) => Poll::Ready(Ok(Some(chunk))),
            Ok(None) => {
                self.ended = true;
                Poll::Ready(Ok(None))
            }
            Err(Proto::Blocked) => {
                state.blocked_readers.insert(self.id, cx.waker().clone());
                Poll::Pending
            }
            Err(Proto::Reset(code)) => {
                self.ended = true;
                Poll::Ready(Err(ReadError::Reset(code)))
            }
        };
        // Reading frees flow control credit; let the driver send window updates
        let transmit = chunks.finalize();
        self.shared.dispatch(state);
        drop(guard);
        if transmit.should_transmit() || result.is_ready() {
            self.shared.driver.notify_one();
        }
        result
    }

    /// Discard the rest of the stream, asking the peer to stop sending
    pub fn stop(&mut self, error_code: VarInt) -> Result<(), ReadError> {
        let mut state = self.shared.lock();
        if let Some(reason) = state.conn.error() {
            return Err(ReadError::ConnectionLost(reason.clone()));
        }
        match state.conn.recv_stream(self.id).stop(error_code) {
            Ok(()) => {
                self.ended = true;
                drop(state);
                self.shared.driver.notify_one();
                Ok(())
            }
            Err(_) => Err(ReadError::ClosedStream),
        }
    }
}

impl Drop for RecvStream {
    fn drop(&mut self) {
        if self.ended {
            return;
        }
        let mut state = self.shared.lock();
        let _ = state.conn.recv_stream(self.id).stop(VarInt::from_u32(0));
        self.shared.dispatch(&mut state);
        drop(state);
        self.shared.driver.notify_one();
        let _ = &self.guard;
    }
}

/// Drive the connection over the transport until it terminates
async fn drive<T>(io: T, shared: Arc<Shared>)
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(io);
    let mut buf = [0u8; 16 * 1024];

    'outer: loop {
        // Flush everything the state machine wants to send
        loop {
            let record = {
                let mut state = shared.lock();
                let record = state.conn.poll_transmit(Instant::now());
                shared.dispatch(&mut state);
                record
            };
            let Some(record) = record else { break };
            if let Err(e) = writer.write_all(&record).await {
                debug!("transport write failed: {e}");
                let mut state = shared.lock();
                state.conn.transport_closed();
                shared.dispatch(&mut state);
                break 'outer;
            }
        }

        let (done, timeout) = {
            let state = shared.lock();
            (
                state.conn.is_closed(),
                state.conn.poll_timeout().map(tokio::time::Instant::from_std),
            )
        };
        if done {
            break;
        }

        let driver_notified = shared.driver.notified();
        let timer = async move {
            match timeout {
                Some(at) => tokio::time::sleep_until(at).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            result = reader.read(&mut buf) => {
                let mut state = shared.lock();
                match result {
                    Ok(0) => {
                        // Peer EOF: graceful only after a close frame was exchanged
                        state.conn.transport_closed();
                        shared.dispatch(&mut state);
                        break;
                    }
                    Ok(n) => {
                        // A protocol error still leaves a CONNECTION_CLOSE record to flush
                        let _ = state.conn.handle_input(&buf[..n], Instant::now());
                        shared.dispatch(&mut state);
                    }
                    Err(e) => {
                        debug!("transport read failed: {e}");
                        state.conn.transport_closed();
                        shared.dispatch(&mut state);
                        break;
                    }
                }
            }
            _ = timer => {
                let mut state = shared.lock();
                state.conn.handle_timeout(Instant::now());
                shared.dispatch(&mut state);
            }
            _ = driver_notified => {}
        }
    }

    // Flush any final record (e.g. CONNECTION_CLOSE queued after the loop decided to exit)
    // and shut our sending side down gracefully
    let record = {
        let mut state = shared.lock();
        let record = state.conn.poll_transmit(Instant::now());
        shared.dispatch(&mut state);
        record
    };
    if let Some(record) = record {
        let _ = writer.write_all(&record).await;
    }
    let _ = writer.shutdown().await;

    // Drain the peer briefly so their close isn't met with a connection reset
    let drain = async {
        let mut sink = [0u8; 4 * 1024];
        while matches!(reader.read(&mut sink).await, Ok(n) if n > 0) {}
    };
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), pin!(drain)).await;
}
