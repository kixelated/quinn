# quinn-qmux

Tokio runtime for [QMux] (draft-ietf-quic-qmux-02), whose protocol logic lives in
`quinn_proto::qmux`.

QMux brings QUIC's multiplexed streams, flow control, and datagrams to reliable, ordered
transports such as TCP, TLS, UNIX sockets, and WebSockets. It lets applications built for
QUIC fall back to TCP when UDP is blocked, without maintaining a second protocol
implementation.

## Design

The draft was written so that a QUIC stack can be reused with minimal changes: QUIC v1
frame formats are kept verbatim (even where the ordered transport makes fields redundant),
flow control uses the QUIC v1 transport parameters, and "references to acknowledgment are
interpreted as though acknowledgment occurs as soon as data is passed to the underlying
transport."

The `qmux` module in quinn-proto takes that literally. `StreamsState` — the engine behind
quinn's streams, flow control, stream limits, and priority-aware fair scheduling — is
driven unmodified:

- Incoming STREAM / RESET_STREAM / STOP_SENDING / MAX_* frames are fed to the same
  `received_*` entry points quinn's own `Connection` uses.
- Outgoing frames are serialized by `write_control_frames` / `write_stream_frames` into a
  QMux record, and then immediately fed back through `received_ack_of` / `reset_acked`:
  handing data to the transport *is* the acknowledgment. Nothing is ever retransmitted at
  this layer, and send buffers free as soon as data is serialized.

Because the module lives inside quinn-proto's `connection` module tree, it uses the
existing internals as-is; the change to preexisting quinn-proto code is just the module
registration. What the module adds is the genuinely QMux-specific ~1k lines: record
framing, the `QX_TRANSPORT_PARAMETERS` handshake, `QX_PING` keep-alives, transport
parameter validation, reliable datagrams, in-order offset enforcement, and record-based
idle timeout semantics.

## Layout

- `quinn_proto::qmux::Connection` — sans-IO state machine, mirroring
  `quinn_proto::Connection` (`handle_input` / `poll_transmit` / `poll_timeout` /
  `handle_timeout` / `poll`). Re-exported here as `quinn_qmux::proto`.
- `Session`, `SendStream`, `RecvStream` (this crate) — tokio layer over any
  `AsyncRead + AsyncWrite` transport, following the `quinn` crate's driver/waker design.

Transport adapters (TLS, WebSocket), ALPN negotiation, and older draft versions are out of
scope here; they layer on top, e.g. in [moq-dev/web-transport].

```rust,no_run
use quinn_qmux::{Config, Session};

async fn run(tcp: tokio::net::TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let session = Session::connect(tcp, Config::default()).await?;
    let (mut send, mut recv) = session.open_bi().await?;
    send.write_all(b"hello").await?;
    send.finish()?;
    let reply = recv.read_to_end(64 * 1024).await?;
    Ok(())
}
```

Run the demo: `cargo run -p quinn-qmux --example echo`

[QMux]: https://www.ietf.org/archive/id/draft-ietf-quic-qmux-02.html
[moq-dev/web-transport]: https://github.com/moq-dev/web-transport
