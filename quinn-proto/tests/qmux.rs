//! Deterministic tests driving two sans-IO connections against each other
//!
//! Not built for wasm targets, where the state machine uses `web_time::Instant` instead
//! of `std::time::Instant`.
#![cfg(not(all(target_family = "wasm", target_os = "unknown")))]

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use quinn_proto::{
    Dir, Side, StreamEvent, StreamId, TransportErrorCode, VarInt,
    coding::Codec,
    qmux::{Config, Connection, ConnectionError, Event, SendDatagramError, WriteError},
};

struct Pair {
    client: Connection,
    server: Connection,
    now: Instant,
}

impl Pair {
    fn new(client_config: Config, server_config: Config) -> Self {
        let now = Instant::now();
        Self {
            client: Connection::new(Arc::new(client_config), Side::Client, now),
            server: Connection::new(Arc::new(server_config), Side::Server, now),
            now,
        }
    }

    fn default() -> Self {
        Self::new(Config::default(), Config::default())
    }

    /// Shuttle records both ways until neither side has anything to send
    fn drive(&mut self) {
        loop {
            let mut progress = false;
            while let Some(record) = self.client.poll_transmit(self.now) {
                progress = true;
                let _ = self.server.handle_input(&record, self.now);
            }
            while let Some(record) = self.server.poll_transmit(self.now) {
                progress = true;
                let _ = self.client.handle_input(&record, self.now);
            }
            if !progress {
                break;
            }
        }
    }

    fn connect(&mut self) {
        self.drive();
        assert!(self.client.is_established());
        assert!(self.server.is_established());
    }
}

fn events(conn: &mut Connection) -> Vec<Event> {
    std::iter::from_fn(|| conn.poll()).collect()
}

fn read_all(conn: &mut Connection, id: StreamId) -> (Vec<u8>, bool) {
    let mut data = Vec::new();
    let mut fin = false;
    let mut recv = conn.recv_stream(id);
    let mut chunks = recv.read(true).unwrap();
    loop {
        match chunks.next(usize::MAX) {
            Ok(Some(chunk)) => data.extend_from_slice(&chunk.bytes),
            Ok(None) => {
                fin = true;
                break;
            }
            Err(quinn_proto::qmux::ReadError::Blocked) => break,
            Err(e) => panic!("read failed: {e}"),
        }
    }
    let _ = chunks.finalize();
    (data, fin)
}

#[test]
fn handshake() {
    let mut pair = Pair::default();
    assert!(!pair.client.is_established());
    pair.connect();
    assert!(matches!(
        events(&mut pair.client).first(),
        Some(Event::Connected)
    ));
    assert!(matches!(
        events(&mut pair.server).first(),
        Some(Event::Connected)
    ));
}

#[test]
fn bidi_transfer() {
    let mut pair = Pair::default();
    pair.connect();

    let id = pair.client.streams().open(Dir::Bi).expect("open bi");
    pair.client.send_stream(id).write(b"hello qmux").unwrap();
    pair.client.send_stream(id).finish().unwrap();
    pair.drive();

    assert!(
        events(&mut pair.server)
            .iter()
            .any(|e| matches!(e, Event::Stream(StreamEvent::Opened { dir: Dir::Bi })))
    );
    let accepted = pair.server.streams().accept(Dir::Bi).expect("accept");
    assert_eq!(accepted, id);
    let (data, fin) = read_all(&mut pair.server, id);
    assert_eq!(data, b"hello qmux");
    assert!(fin);

    // Serializing the FIN acted as its acknowledgment
    assert!(
        events(&mut pair.client)
            .iter()
            .any(|e| matches!(e, Event::Stream(StreamEvent::Finished { id: got }) if *got == id))
    );

    // Echo something back
    pair.server.send_stream(id).write(b"pong").unwrap();
    pair.server.send_stream(id).finish().unwrap();
    pair.drive();
    let (data, fin) = read_all(&mut pair.client, id);
    assert_eq!(data, b"pong");
    assert!(fin);
}

#[test]
fn large_transfer_with_flow_control() {
    // Windows far smaller than the payload force MAX_DATA / MAX_STREAM_DATA exchanges
    let mut config = Config::default();
    config
        .receive_window(VarInt::from_u32(16 * 1024))
        .stream_receive_window(VarInt::from_u32(8 * 1024))
        .send_window(4 * 1024);
    let mut pair = Pair::new(config.clone(), config);
    pair.connect();

    let payload: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
    let id = pair.client.streams().open(Dir::Uni).expect("open uni");

    let mut sent = 0;
    let mut received = Vec::new();
    let mut finished = false;
    // Interleave writing, transferring, and reading, as a driver would
    for _ in 0..10_000 {
        if sent < payload.len() {
            match pair.client.send_stream(id).write(&payload[sent..]) {
                Ok(n) => sent += n,
                Err(WriteError::Blocked) => {}
                Err(e) => panic!("write failed: {e}"),
            }
            if sent == payload.len() {
                pair.client.send_stream(id).finish().unwrap();
            }
        }
        pair.drive();
        let _ = pair.server.streams().accept(Dir::Uni);
        let (chunk, fin) = read_all(&mut pair.server, id);
        received.extend_from_slice(&chunk);
        if fin {
            finished = true;
            break;
        }
    }
    assert!(finished, "transfer stalled");
    assert_eq!(received.len(), payload.len());
    assert_eq!(received, payload);
}

#[test]
fn send_window_blocked_writer_wakes() {
    let mut config = Config::default();
    config.send_window(8);
    let mut pair = Pair::new(config, Config::default());
    pair.connect();
    let _ = events(&mut pair.client);

    let id = pair.client.streams().open(Dir::Uni).expect("open uni");
    assert_eq!(pair.client.send_stream(id).write(&[0; 64]).unwrap(), 8);
    assert!(matches!(
        pair.client.send_stream(id).write(&[0; 64]),
        Err(WriteError::Blocked)
    ));

    // Serialization acknowledges the buffered data, freeing the send window
    pair.drive();
    assert!(
        events(&mut pair.client)
            .iter()
            .any(|e| matches!(e, Event::Stream(StreamEvent::Writable { id: got }) if *got == id)),
        "writer blocked on send_window was not woken"
    );
    assert_eq!(pair.client.send_stream(id).write(&[0; 64]).unwrap(), 8);
}

#[test]
fn stream_limits_recycle() {
    let mut config = Config::default();
    config.max_concurrent_uni_streams(VarInt::from_u32(2));
    let mut pair = Pair::new(Config::default(), config);
    pair.connect();

    for round in 0..5 {
        let id = pair
            .client
            .streams()
            .open(Dir::Uni)
            .unwrap_or_else(|| panic!("stream limit not recycled on round {round}"));
        pair.client.send_stream(id).finish().unwrap();
        pair.drive();
        let accepted = pair.server.streams().accept(Dir::Uni).expect("accept");
        let (_, fin) = read_all(&mut pair.server, accepted);
        assert!(fin);
        // Reading the FIN frees the stream; a MAX_STREAMS update flows back
        pair.drive();
        let _ = events(&mut pair.client);
    }
}

#[test]
fn reset_and_stop() {
    let mut pair = Pair::default();
    pair.connect();

    // Client resets a stream after writing
    let id = pair.client.streams().open(Dir::Uni).expect("open");
    pair.client.send_stream(id).write(b"partial").unwrap();
    pair.drive();
    pair.client
        .send_stream(id)
        .reset(VarInt::from_u32(42))
        .unwrap();
    pair.drive();
    let _ = pair.server.streams().accept(Dir::Uni);
    let reset = pair.server.recv_stream(id).received_reset().unwrap();
    assert_eq!(reset, Some(VarInt::from_u32(42)));

    // Server stops a stream; client sees Stopped
    let id2 = pair.client.streams().open(Dir::Uni).expect("open");
    pair.client.send_stream(id2).write(b"data").unwrap();
    pair.drive();
    let _ = pair.server.streams().accept(Dir::Uni);
    pair.server
        .recv_stream(id2)
        .stop(VarInt::from_u32(7))
        .unwrap();
    pair.drive();
    assert!(events(&mut pair.client).iter().any(|e| matches!(
        e,
        Event::Stream(StreamEvent::Stopped { id, error_code })
            if *id == id2 && *error_code == VarInt::from_u32(7)
    )));
}

#[test]
fn datagrams() {
    let mut pair = Pair::default();
    assert_eq!(
        pair.client.send_datagram(Bytes::from_static(b"early")),
        Err(SendDatagramError::NotYetReady)
    );
    pair.connect();

    pair.client
        .send_datagram(Bytes::from_static(b"hello datagram"))
        .unwrap();
    pair.drive();
    assert!(
        events(&mut pair.server)
            .iter()
            .any(|e| matches!(e, Event::DatagramReceived))
    );
    assert_eq!(
        pair.server.recv_datagram(),
        Some(Bytes::from_static(b"hello datagram"))
    );
    assert_eq!(pair.server.recv_datagram(), None);

    let too_large = vec![0; 64 * 1024];
    assert_eq!(
        pair.client.send_datagram(too_large.into()),
        Err(SendDatagramError::TooLarge)
    );
}

#[test]
fn datagrams_disabled() {
    let mut receiver = Config::default();
    receiver.max_datagram_frame_size(None);
    let mut pair = Pair::new(Config::default(), receiver);
    pair.connect();
    assert_eq!(
        pair.client.send_datagram(Bytes::from_static(b"nope")),
        Err(SendDatagramError::UnsupportedByPeer)
    );
}

#[test]
fn application_close() {
    let mut pair = Pair::default();
    pair.connect();
    pair.client
        .close(VarInt::from_u32(3), Bytes::from_static(b"bye"));
    pair.drive();
    assert!(matches!(
        pair.client.error(),
        Some(ConnectionError::LocallyClosed)
    ));
    match pair.server.error() {
        Some(ConnectionError::ApplicationClosed { error_code, reason }) => {
            assert_eq!(*error_code, VarInt::from_u32(3));
            assert_eq!(reason.as_ref(), b"bye");
        }
        other => panic!("unexpected server error: {other:?}"),
    }
    // Draining connections go quiet
    assert!(pair.server.poll_transmit(pair.now).is_none());
    assert!(pair.client.poll_transmit(pair.now).is_none());
}

/// Wrap a frames payload in a record Size prefix
fn record(frames: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    VarInt::from_u64(frames.len() as u64)
        .unwrap()
        .encode(&mut out);
    out.extend_from_slice(frames);
    out
}

fn expect_transport_error(result: Result<(), ConnectionError>, code: TransportErrorCode) {
    match result {
        Err(ConnectionError::TransportError(e)) => assert_eq!(e.code, code),
        other => panic!("expected {code}, got {other:?}"),
    }
}

#[test]
fn first_frame_must_be_params() {
    let mut pair = Pair::default();
    // A lone MAX_DATA frame before any QX_TRANSPORT_PARAMETERS
    let mut frames = Vec::new();
    VarInt::from_u32(0x10).encode(&mut frames);
    VarInt::from_u32(1234).encode(&mut frames);
    expect_transport_error(
        pair.server.handle_input(&record(&frames), pair.now),
        TransportErrorCode::PROTOCOL_VIOLATION,
    );
    // The failure produces a final CONNECTION_CLOSE record and nothing after it
    let close = pair.server.poll_transmit(pair.now).expect("close record");
    assert!(!close.is_empty());
    assert!(pair.server.poll_transmit(pair.now).is_none());
}

#[test]
fn prohibited_frame() {
    let mut pair = Pair::default();
    pair.connect();
    // QUIC PING (0x01) is prohibited in QMux
    let mut frames = Vec::new();
    VarInt::from_u32(0x01).encode(&mut frames);
    expect_transport_error(
        pair.server.handle_input(&record(&frames), pair.now),
        TransportErrorCode::FRAME_ENCODING_ERROR,
    );
}

#[test]
fn stream_offset_gap() {
    let mut pair = Pair::default();
    pair.connect();
    // STREAM frame with OFF|LEN set (0x0e) for client uni stream 2 at offset 100
    let mut frames = Vec::new();
    VarInt::from_u32(0x0e).encode(&mut frames);
    VarInt::from_u32(2).encode(&mut frames); // client-initiated uni stream id
    VarInt::from_u32(100).encode(&mut frames); // offset: not 0
    VarInt::from_u32(3).encode(&mut frames); // length
    frames.extend_from_slice(b"abc");
    expect_transport_error(
        pair.server.handle_input(&record(&frames), pair.now),
        TransportErrorCode::PROTOCOL_VIOLATION,
    );
}

#[test]
fn unsolicited_ping_response() {
    let mut pair = Pair::default();
    pair.connect();
    let mut frames = Vec::new();
    VarInt::from_u64(0x348c67529ef8c7be)
        .unwrap()
        .encode(&mut frames);
    VarInt::from_u32(5).encode(&mut frames);
    expect_transport_error(
        pair.server.handle_input(&record(&frames), pair.now),
        TransportErrorCode::PROTOCOL_VIOLATION,
    );
}

#[test]
fn keepalive_and_idle_timeout() {
    let mut config = Config::default();
    config.max_idle_timeout(Some(Duration::from_secs(3)));
    let mut pair = Pair::new(config, Config::default());
    pair.connect();

    // A keep-alive ping request goes out at a third of the idle timeout
    let at = pair.client.poll_timeout().expect("timeout scheduled");
    assert!(at <= pair.now + Duration::from_secs(1));
    pair.now = at;
    pair.client.handle_timeout(pair.now);
    let ping = pair.client.poll_transmit(pair.now).expect("ping record");
    pair.server.handle_input(&ping, pair.now).unwrap();
    // The server responds; the response is valid at the client
    let response = pair.server.poll_transmit(pair.now).expect("ping response");
    pair.client.handle_input(&response, pair.now).unwrap();
    assert!(!pair.client.is_closed());

    // Going silent past the effective timeout expires the connection
    pair.now += Duration::from_secs(10);
    pair.client.handle_timeout(pair.now);
    assert!(matches!(
        pair.client.error(),
        Some(ConnectionError::TimedOut)
    ));
    // Idle timeout sends nothing
    assert!(pair.client.poll_transmit(pair.now).is_none());
}

#[test]
fn record_size_limit_enforced() {
    let mut pair = Pair::default();
    pair.connect();
    // A record claiming a payload larger than our advertised max_record_size
    let mut input = Vec::new();
    VarInt::from_u32(1_000_000).encode(&mut input);
    expect_transport_error(
        pair.server.handle_input(&input, pair.now),
        TransportErrorCode::PROTOCOL_VIOLATION,
    );
}

#[test]
fn data_after_fin_rejected() {
    let mut pair = Pair::default();
    pair.connect();
    let id = pair.client.streams().open(Dir::Uni).expect("open");
    pair.client.send_stream(id).write(b"abc").unwrap();
    pair.client.send_stream(id).finish().unwrap();
    pair.drive();

    // Hand-crafted extra data for the finished stream at its correct next offset;
    // sending anything after FIN violates the stream's final size
    let mut frames = Vec::new();
    VarInt::from_u32(0x0e).encode(&mut frames);
    VarInt::from_u64(id.into()).unwrap().encode(&mut frames);
    VarInt::from_u32(3).encode(&mut frames); // offset == final size
    VarInt::from_u32(1).encode(&mut frames);
    frames.push(b'x');
    expect_transport_error(
        pair.server.handle_input(&record(&frames), pair.now),
        TransportErrorCode::PROTOCOL_VIOLATION,
    );
}
