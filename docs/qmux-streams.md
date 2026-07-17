# Using `quinn-proto::streams` for QMUX

`quinn-proto::streams` is the stream subsystem shared by Quinn's QUIC packet
connection and reliable ordered carriers such as
[QMUX draft-02](https://www.ietf.org/archive/id/draft-ietf-quic-qmux-02.txt).

The implementation lives in `quinn-proto/src/streams`. Quinn imports its
internal `StreamsState`; other transports use the public `streams::Connection`
facade. Both paths therefore share stream identifiers and lifecycle validation,
connection- and stream-level flow control, send/receive buffering, final-size
checks, priority scheduling, resets, and stream-count accounting.

## Public API

The reliable-carrier facade consists of:

- `Connection`: owns all stream state for one endpoint;
- `Config`: local stream-count and receive/send window configuration;
- `Parameters`: the stream-related subset of peer transport parameters;
- `Frame`: typed inbound stream and flow-control frames;
- `wire::Frame` and `wire::decode`: the shared standard QUIC wire decoder for
  mixed carrier records;
- `Transmit`: an encoded QUIC v1 frame payload ready for a reliable carrier;
- `Event`: application-facing stream readiness and lifecycle events.

The module also exports the shared `Dir`, `Side`, `StreamId`, and `VarInt`
types, plus Quinn's existing `Streams`, `SendStream`, `RecvStream`, `Chunks`,
and their result/error types.

## Carrier integration

Construct a connection from local configuration, then apply the peer's QMUX
transport parameters:

```rust
use quinn_proto::streams::{Config, Connection, Parameters, Side};

let mut streams = Connection::new(
    Side::Client,
    Config {
        max_remote_bidi: 100u32.into(),
        max_remote_uni: 100u32.into(),
        send_window: 8 * 1024 * 1024,
        receive_window: (8 * 1024 * 1024u32).into(),
        stream_receive_window: (1024 * 1024u32).into(),
    },
);

streams.set_peer_parameters(Parameters {
    initial_max_data: (8 * 1024 * 1024u32).into(),
    initial_max_stream_data_bidi_local: (1024 * 1024u32).into(),
    initial_max_stream_data_bidi_remote: (1024 * 1024u32).into(),
    initial_max_stream_data_uni: (1024 * 1024u32).into(),
    initial_max_streams_bidi: 100u32.into(),
    initial_max_streams_uni: 100u32.into(),
});
```

For input, the QMUX record decoder repeatedly calls `streams::wire::decode`.
Quinn decodes STREAM and flow-control frames,
DATAGRAM, PADDING, and connection close using the same parser as the packet
connection. `wire::Frame::Other` consumes the type but leaves the frame body at
the front of the record cursor for QMUX to decode
QX_TRANSPORT_PARAMETERS and QX_PING. Stream-related results are forwarded through
`Connection::received_frame`; its `allocation_size` argument accounts for a
STREAM frame retaining its enclosing record allocation.

The facade handles `RESET_STREAM`. Draft-02 also permits the optional
`RESET_STREAM_AT` extension, but it is not advertised by `quinn-mux` yet. A
nonzero Reliable Size cannot be translated to `Frame::Reset`, because the
reliable prefix must remain readable before the reset is reported; supporting
that extension requires partial-delivery reset state in the shared stream core.

For output, repeatedly call `Connection::poll_transmit(max_record_size)`. Its
`Transmit::payload` contains one or more complete QUIC v1 stream/control frames
without a QMUX record header. Wrap that payload in a QMUX record and write it to
the carrier. Only after the write succeeds, call `Connection::transmitted` with
the same `Transmit`; this transfers responsibility for reliable delivery to the
carrier and releases Quinn's retransmission copy. If the write fails, close the
carrier and drop both `Transmit` and `Connection`.

The carrier remains responsible for QMUX record framing, transport-parameter
policy, QX_PING, idle timeout, datagram and close scheduling, TLS/TCP/WS I/O,
and async task coordination. Quinn supplies the zero-copy
`transport_parameters::ParameterIter` and standard DATAGRAM and connection-close
codecs under `streams::wire`.

## Internal adapters

The stream subsystem has no production dependency on Quinn's packet spaces,
connection state, complete QUIC transport parameters, or connection-wide frame
statistics:

- stream pending/retransmit state is stored separately and embedded by the QUIC
  packet adapter;
- the stream accessors take a plain closed flag;
- Quinn and QMUX convert their transport parameters into `streams::Parameters`;
  and
- stream frame counts are returned to Quinn's connection adapter.

Quinn reports packet ACK and loss back to the shared send buffers. A reliable
carrier instead treats successful write completion as transfer of ownership and
immediately confirms the corresponding `Transmit`.
