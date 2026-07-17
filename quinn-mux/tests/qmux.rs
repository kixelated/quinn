use bytes::{Bytes, BytesMut};
use quinn_mux::{
    Close, Config, Connection, DEFAULT_MAX_RECORD_SIZE, Dir, Error, Event, ReadError, Side, VarInt,
    WriteError,
};
use quinn_proto::streams::Event as StreamEvent;
use quinn_proto::{TransportErrorCode, coding::Codec};

const QX_PING_REQUEST: u64 = 0x348c_6752_9ef8_c7bd;
const QX_PING_RESPONSE: u64 = 0x348c_6752_9ef8_c7be;

fn ping_record(sequence: u32, response: bool) -> Bytes {
    let mut payload = BytesMut::new();
    VarInt::try_from(if response {
        QX_PING_RESPONSE
    } else {
        QX_PING_REQUEST
    })
    .unwrap()
    .encode(&mut payload);
    VarInt::from_u32(sequence).encode(&mut payload);

    let mut record = BytesMut::new();
    VarInt::try_from(payload.len()).unwrap().encode(&mut record);
    record.extend_from_slice(&payload);
    record.freeze()
}

fn transfer(from: &mut Connection, to: &mut Connection) {
    while let Some(transmit) = from.poll_transmit().unwrap() {
        let bytes = transmit.bytes.clone();
        to.received(bytes).unwrap();
        from.transmitted(transmit).unwrap();
    }
}

fn pair(config: Config) -> (Connection, Connection) {
    let mut client = Connection::new(Side::Client, config).unwrap();
    let mut server = Connection::new(Side::Server, config).unwrap();
    transfer(&mut client, &mut server);
    transfer(&mut server, &mut client);
    assert!(matches!(client.poll(), Some(Event::PeerParameters(_))));
    assert!(matches!(server.poll(), Some(Event::PeerParameters(_))));
    (client, server)
}

#[test]
fn bidirectional_stream_round_trip() {
    let (mut client, mut server) = pair(Config::default());

    let id = client.streams().open(Dir::Bi).unwrap();
    assert_eq!(client.send_stream(id).write(b"request").unwrap(), 7);
    client.send_stream(id).finish().unwrap();
    transfer(&mut client, &mut server);

    assert!(matches!(
        server.poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Bi }))
    ));
    assert_eq!(server.streams().accept(Dir::Bi), Some(id));
    assert!(matches!(
        server.poll(),
        Some(Event::Stream(StreamEvent::Readable { id: readable })) if readable == id
    ));
    let mut recv = server.recv_stream(id);
    let mut chunks = recv.read(true).unwrap();
    assert_eq!(
        &chunks.next(usize::MAX).unwrap().unwrap().bytes[..],
        b"request"
    );
    assert!(chunks.next(usize::MAX).unwrap().is_none());
    let _ = chunks.finalize();

    assert_eq!(server.send_stream(id).write(b"response").unwrap(), 8);
    server.send_stream(id).finish().unwrap();
    transfer(&mut server, &mut client);

    assert!(matches!(
        client.poll(),
        Some(Event::Stream(StreamEvent::Finished { id: finished })) if finished == id
    ));
    assert!(matches!(
        client.poll(),
        Some(Event::Stream(StreamEvent::Readable { id: readable })) if readable == id
    ));
    let mut recv = client.recv_stream(id);
    let mut chunks = recv.read(true).unwrap();
    assert_eq!(
        &chunks.next(usize::MAX).unwrap().unwrap().bytes[..],
        b"response"
    );
    assert!(chunks.next(usize::MAX).unwrap().is_none());
}

#[test]
fn flow_control_round_trip_unblocks_writer() {
    let mut config = Config::default();
    config.receive_window = 5u32.into();
    config.stream_receive_window = 5u32.into();
    config.send_window = 64;
    let (mut client, mut server) = pair(config);

    let id = client.streams().open(Dir::Uni).unwrap();
    assert_eq!(client.send_stream(id).write(b"abcdefgh").unwrap(), 5);
    assert_eq!(
        client.send_stream(id).write(b"fgh"),
        Err(WriteError::Blocked)
    );
    transfer(&mut client, &mut server);

    assert!(matches!(
        server.poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Uni }))
    ));
    assert_eq!(server.streams().accept(Dir::Uni), Some(id));
    assert!(matches!(
        server.poll(),
        Some(Event::Stream(StreamEvent::Readable { id: readable })) if readable == id
    ));
    let mut recv = server.recv_stream(id);
    let mut chunks = recv.read(true).unwrap();
    assert_eq!(
        &chunks.next(usize::MAX).unwrap().unwrap().bytes[..],
        b"abcde"
    );
    assert_eq!(chunks.next(usize::MAX), Err(ReadError::Blocked));
    let _ = chunks.finalize();

    transfer(&mut server, &mut client);
    assert!(matches!(
        client.poll(),
        Some(Event::Stream(StreamEvent::Writable { id: writable })) if writable == id
    ));
    assert_eq!(client.send_stream(id).write(b"fgh").unwrap(), 3);
    client.send_stream(id).finish().unwrap();
    transfer(&mut client, &mut server);

    assert!(matches!(
        server.poll(),
        Some(Event::Stream(StreamEvent::Readable { id: readable })) if readable == id
    ));
    let mut recv = server.recv_stream(id);
    let mut chunks = recv.read(true).unwrap();
    assert_eq!(&chunks.next(usize::MAX).unwrap().unwrap().bytes[..], b"fgh");
    assert!(chunks.next(usize::MAX).unwrap().is_none());
}

#[test]
fn large_stream_is_split_across_ordered_records() {
    let (mut client, mut server) = pair(Config::default());
    let payload = vec![0x5a; 40_000];

    let id = client.streams().open(Dir::Uni).unwrap();
    assert_eq!(
        client.send_stream(id).write(&payload).unwrap(),
        payload.len()
    );
    client.send_stream(id).finish().unwrap();

    let mut records = 0;
    while let Some(transmit) = client.poll_transmit().unwrap() {
        records += 1;
        let bytes = transmit.bytes.clone();
        server.received(bytes).unwrap();
        client.transmitted(transmit).unwrap();
    }
    assert!(records >= 3, "payload should span multiple QMUX records");

    assert!(matches!(
        server.poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Uni }))
    ));
    assert_eq!(server.streams().accept(Dir::Uni), Some(id));
    let mut received = Vec::new();
    loop {
        assert!(matches!(
            server.poll(),
            Some(Event::Stream(StreamEvent::Readable { id: readable })) if readable == id
        ));
        let mut recv = server.recv_stream(id);
        let mut chunks = recv.read(true).unwrap();
        loop {
            match chunks.next(usize::MAX) {
                Ok(Some(chunk)) => received.extend_from_slice(&chunk.bytes),
                Ok(None) => break,
                Err(ReadError::Blocked) => break,
                Err(error) => panic!("unexpected stream error: {error}"),
            }
        }
        let finished = received.len() == payload.len();
        let _ = chunks.finalize();
        if finished {
            break;
        }
    }
    assert_eq!(received, payload);
}

#[test]
fn stream_priorities_drive_record_scheduling() {
    let (mut client, mut server) = pair(Config::default());
    let low = client.streams().open(Dir::Uni).unwrap();
    let high = client.streams().open(Dir::Uni).unwrap();
    client.send_stream(low).set_priority(-1).unwrap();
    client.send_stream(high).set_priority(1).unwrap();
    client.send_stream(low).write(&[0; 16_000]).unwrap();
    client.send_stream(high).write(&[0; 16_000]).unwrap();

    let transmit = client.poll_transmit().unwrap().unwrap();
    server.received(transmit.bytes.clone()).unwrap();
    client.transmitted(transmit).unwrap();

    assert!(matches!(
        server.poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Uni }))
    ));
    assert!(matches!(
        server.poll(),
        Some(Event::Stream(StreamEvent::Readable { id })) if id == high
    ));
}

#[test]
fn reset_ping_datagram_and_close_use_the_same_record_engine() {
    let mut config = Config::default();
    config.max_datagram_frame_size = 1200u32.into();
    let (mut client, mut server) = pair(config);

    let id = client.streams().open(Dir::Uni).unwrap();
    client.send_stream(id).reset(42u32.into()).unwrap();
    client.ping(7u32.into()).unwrap();
    client
        .send_datagram(Bytes::from_static(b"unreliable"))
        .unwrap();
    transfer(&mut client, &mut server);

    assert!(matches!(
        server.poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Uni }))
    ));
    assert_eq!(server.streams().accept(Dir::Uni), Some(id));
    assert!(matches!(
        server.poll(),
        Some(Event::Stream(StreamEvent::Readable { id: readable })) if readable == id
    ));
    {
        let mut recv = server.recv_stream(id);
        let mut chunks = recv.read(true).unwrap();
        assert_eq!(
            chunks.next(usize::MAX),
            Err(ReadError::Reset(VarInt::from_u32(42)))
        );
    }
    assert!(matches!(
        server.poll(),
        Some(Event::Datagram(data)) if data == Bytes::from_static(b"unreliable")
    ));

    transfer(&mut server, &mut client);
    assert!(matches!(
        client.poll(),
        Some(Event::PingResponse(sequence)) if sequence == VarInt::from_u32(7)
    ));

    client.close(9u32.into(), Bytes::from_static(b"done"));
    transfer(&mut client, &mut server);
    assert!(matches!(
        server.poll(),
        Some(Event::Closed(Close::Application(close)))
            if close.error_code == VarInt::from_u32(9) && close.reason.as_ref() == b"done"
    ));
    assert!(client.is_closed());
    assert!(server.is_closed());
    assert!(matches!(
        client.ping(8u32.into()),
        Err(Error::ConnectionClosed)
    ));
}

#[test]
fn ping_sequences_are_validated_and_violations_are_closed() {
    let (mut client, mut server) = pair(Config::default());

    client.ping(2u32.into()).unwrap();
    assert!(matches!(client.ping(2u32.into()), Err(Error::PingSequence)));
    assert!(matches!(client.ping(1u32.into()), Err(Error::PingSequence)));

    assert!(matches!(
        server.received(ping_record(7, true)),
        Err(Error::Protocol(error))
            if error.code == TransportErrorCode::PROTOCOL_VIOLATION
    ));
    let close = server.poll_transmit().unwrap().unwrap();
    client.received(close.bytes.clone()).unwrap();
    server.transmitted(close).unwrap();
    assert!(matches!(
        client.poll(),
        Some(Event::Closed(Close::Transport(close)))
            if close.error_code == TransportErrorCode::PROTOCOL_VIOLATION
    ));
}

#[test]
fn incoming_ping_requests_must_strictly_increase() {
    let (_, mut server) = pair(Config::default());

    server.received(ping_record(3, false)).unwrap();
    assert!(matches!(
        server.received(ping_record(3, false)),
        Err(Error::Protocol(error))
            if error.code == TransportErrorCode::PROTOCOL_VIOLATION
    ));
}

#[test]
fn close_before_first_write_preserves_parameter_order_and_truncates_reason() {
    let mut client = Connection::new(Side::Client, Config::default()).unwrap();
    let mut server = Connection::new(Side::Server, Config::default()).unwrap();
    client.close(4u32.into(), Bytes::from(vec![b'x'; 32_000]));

    let parameters = client.poll_transmit().unwrap().unwrap();
    server.received(parameters.bytes.clone()).unwrap();
    client.transmitted(parameters).unwrap();
    assert!(matches!(server.poll(), Some(Event::PeerParameters(_))));

    let close = client.poll_transmit().unwrap().unwrap();
    assert!(close.bytes.len() <= DEFAULT_MAX_RECORD_SIZE as usize + 2);
    server.received(close.bytes.clone()).unwrap();
    client.transmitted(close).unwrap();
    assert!(matches!(
        server.poll(),
        Some(Event::Closed(Close::Application(close)))
            if close.error_code == VarInt::from_u32(4)
                && !close.reason.is_empty()
                && close.reason.len() < 32_000
    ));
}

#[test]
fn advertised_datagram_size_is_capped_by_record_size() {
    let mut config = Config::default();
    config.max_datagram_frame_size = 20_000u32.into();
    let (mut client, _) = pair(config);

    assert_eq!(
        client.local_parameters().max_datagram_frame_size,
        client.local_parameters().max_record_size
    );
    let payload = Bytes::from(vec![0; 16_380]);
    assert!(matches!(
        client.send_datagram(payload),
        Err(Error::DatagramTooLarge { .. })
    ));
}

#[test]
fn transmit_tokens_are_connection_bound_and_ordered() {
    let mut first = Connection::new(Side::Client, Config::default()).unwrap();
    let mut second = Connection::new(Side::Client, Config::default()).unwrap();

    let foreign = first.poll_transmit().unwrap().unwrap();
    assert!(matches!(
        second.transmitted(foreign),
        Err(Error::WrongConnection)
    ));

    let mut ordered = Connection::new(Side::Client, Config::default()).unwrap();
    ordered.ping(1u32.into()).unwrap();
    let first_transmit = ordered.poll_transmit().unwrap().unwrap();
    let second_transmit = ordered.poll_transmit().unwrap().unwrap();
    assert!(matches!(
        ordered.transmitted(second_transmit),
        Err(Error::OutOfOrderTransmit)
    ));
    ordered.transmitted(first_transmit).unwrap();
}
