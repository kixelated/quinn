# quinn-mux

`quinn-mux` is a QMUX draft-02 protocol-engine prototype built on
`quinn_proto::streams`.

It owns QMUX record framing, QX transport parameters and ping frames,
datagram and connection-close scheduling, and QMUX validation policy. Quinn
owns standard QUIC frame parsing and encoding, transport-parameter TLV framing,
stream identifiers, opening and acceptance, flow control, buffering,
priorities, and resets.

The crate is intentionally record-oriented. An I/O adapter writes
`Transmit::bytes` to a reliable ordered carrier and then calls
`Connection::transmitted`. Bytes received from that carrier are split into
complete QMUX records before being passed to `Connection::received`.

The engine enforces draft-02 QX_PING sequencing and ordered STREAM offsets.
Malformed input queues a typed transport close before returning the diagnostic
error; peer transport and application close details remain available in
`Event::Closed` without UTF-8 conversion.

The validation suite drives bidirectional and unidirectional streams through
two endpoints, including flow-control blocking and recovery, multi-record
stream data, priorities and resets, datagrams, ping, close, and transmit
completion ordering. It also checks the QMUX transport-parameter and DATAGRAM
wire encodings used by the original `qmux` crate.

`RESET_STREAM_AT` is not advertised because Quinn's stream core does not yet
preserve a reliable prefix before reporting a partial-delivery reset.
