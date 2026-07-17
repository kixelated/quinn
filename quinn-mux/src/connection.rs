use std::{
    collections::VecDeque,
    sync::atomic::{AtomicU64, Ordering},
};

use bytes::Bytes;
use quinn_proto::{ApplicationClose, ConnectionClose, TransportError, TransportErrorCode, streams};

use crate::{DEFAULT_MAX_RECORD_SIZE, Error, Parameters, codec};

static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

/// Local QMUX configuration.
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub struct Config {
    /// Number of peer-initiated bidirectional streams initially permitted.
    pub max_remote_bidi: streams::VarInt,
    /// Number of peer-initiated unidirectional streams initially permitted.
    pub max_remote_uni: streams::VarInt,
    /// Maximum stream bytes retained until carrier writes complete.
    pub send_window: u64,
    /// Connection-level receive flow-control window.
    pub receive_window: streams::VarInt,
    /// Per-stream receive flow-control window.
    pub stream_receive_window: streams::VarInt,
    /// Maximum idle timeout advertised to the peer, in milliseconds.
    pub max_idle_timeout: streams::VarInt,
    /// Maximum accepted QMUX Frames field size.
    pub max_record_size: streams::VarInt,
    /// Maximum accepted encoded DATAGRAM frame size, or zero to disable datagrams.
    pub max_datagram_frame_size: streams::VarInt,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_remote_bidi: 100u32.into(),
            max_remote_uni: 100u32.into(),
            send_window: 8 * 1024 * 1024,
            receive_window: (8 * 1024 * 1024u32).into(),
            stream_receive_window: (1024 * 1024u32).into(),
            max_idle_timeout: 0u32.into(),
            max_record_size: streams::VarInt::try_from(DEFAULT_MAX_RECORD_SIZE).unwrap(),
            max_datagram_frame_size: 0u32.into(),
        }
    }
}

impl Config {
    fn parameters(self) -> Parameters {
        Parameters {
            max_idle_timeout: self.max_idle_timeout,
            initial_max_data: self.receive_window,
            initial_max_stream_data_bidi_local: self.stream_receive_window,
            initial_max_stream_data_bidi_remote: self.stream_receive_window,
            initial_max_stream_data_uni: self.stream_receive_window,
            initial_max_streams_bidi: self.max_remote_bidi,
            initial_max_streams_uni: self.max_remote_uni,
            max_datagram_frame_size: std::cmp::min(
                self.max_datagram_frame_size,
                self.max_record_size,
            ),
            max_record_size: self.max_record_size,
        }
    }
}

/// Application-visible QMUX event.
#[derive(Debug)]
#[non_exhaustive]
pub enum Event {
    /// A stream became open, readable, writable, finished, or stopped.
    Stream(streams::Event),
    /// The peer's QMUX transport parameters were accepted.
    PeerParameters(Parameters),
    /// An unreliable datagram was received.
    Datagram(Bytes),
    /// A valid response to a locally requested QX_PING was received.
    PingResponse(streams::VarInt),
    /// The peer closed the connection.
    Closed(Close),
}

/// Reason the peer closed the QMUX connection.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Close {
    /// Transport-level close, including the triggering frame when supplied.
    Transport(ConnectionClose),
    /// Application-level close.
    Application(ApplicationClose),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum State {
    Open,
    Closing,
    Closed,
}

#[derive(Debug, Clone)]
enum Control {
    Parameters(Parameters),
    Ping {
        sequence: streams::VarInt,
        response: bool,
    },
    Datagram(Bytes),
    Close(Close),
}

impl Control {
    fn encode(&self, max_size: usize) -> Result<Bytes, Error> {
        match self {
            Self::Parameters(params) => codec::encode_parameters(params),
            Self::Ping { sequence, response } => codec::encode_ping(*sequence, *response),
            Self::Datagram(data) => codec::encode_datagram(data),
            Self::Close(Close::Transport(close)) => codec::encode_connection_close(close, max_size),
            Self::Close(Close::Application(close)) => {
                codec::encode_application_close(close.error_code, &close.reason, max_size)
            }
        }
    }
}

/// A complete length-prefixed QMUX record ready for an ordered carrier.
#[derive(Debug)]
#[must_use = "write bytes to the carrier, then call Connection::transmitted"]
pub struct Transmit {
    /// The complete size-prefixed QMUX record to write to the carrier.
    pub bytes: Bytes,
    connection: u64,
    sequence: u64,
    streams: Option<streams::Transmit>,
    closes: bool,
}

/// QMUX protocol state for one endpoint.
pub struct Connection {
    id: u64,
    streams: streams::Connection,
    local_parameters: Parameters,
    peer_parameters: Option<Parameters>,
    urgent: VecDeque<Control>,
    auxiliary: VecDeque<Control>,
    events: VecDeque<Event>,
    next_transmit: u64,
    next_completion: u64,
    last_ping_sent: Option<streams::VarInt>,
    last_ping_received: Option<streams::VarInt>,
    state: State,
}

impl Connection {
    /// Construct one endpoint and queue its transport parameters as the first frame.
    pub fn new(side: streams::Side, config: Config) -> Result<Self, Error> {
        let local_parameters = config.parameters();
        local_parameters.validate()?;
        let streams = streams::Connection::new(
            side,
            streams::Config {
                max_remote_bidi: config.max_remote_bidi,
                max_remote_uni: config.max_remote_uni,
                send_window: config.send_window,
                receive_window: config.receive_window,
                stream_receive_window: config.stream_receive_window,
            },
        );
        let mut urgent = VecDeque::new();
        urgent.push_back(Control::Parameters(local_parameters));
        Ok(Self {
            id: NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed),
            streams,
            local_parameters,
            peer_parameters: None,
            urgent,
            auxiliary: VecDeque::new(),
            events: VecDeque::new(),
            next_transmit: 0,
            next_completion: 0,
            last_ping_sent: None,
            last_ping_received: None,
            state: State::Open,
        })
    }

    /// Return the transport parameters advertised by this endpoint.
    pub fn local_parameters(&self) -> Parameters {
        self.local_parameters
    }

    /// Return the peer's transport parameters once received.
    pub fn peer_parameters(&self) -> Option<Parameters> {
        self.peer_parameters
    }

    /// Whether this endpoint has entered the terminal closed state.
    pub fn is_closed(&self) -> bool {
        self.state == State::Closed
    }

    /// Open and accept streams.
    pub fn streams(&mut self) -> streams::Streams<'_> {
        self.streams.streams()
    }

    /// Access the sending half of a stream.
    pub fn send_stream(&mut self, id: streams::StreamId) -> streams::SendStream<'_> {
        self.streams.send_stream(id)
    }

    /// Access the receiving half of a stream.
    pub fn recv_stream(&mut self, id: streams::StreamId) -> streams::RecvStream<'_> {
        self.streams.recv_stream(id)
    }

    /// Yield the next carrier or stream event.
    pub fn poll(&mut self) -> Option<Event> {
        self.events
            .pop_front()
            .or_else(|| self.streams.poll().map(Event::Stream))
    }

    /// Queue a QX_PING request.
    pub fn ping(&mut self, sequence: streams::VarInt) -> Result<(), Error> {
        self.ensure_open()?;
        if self
            .last_ping_sent
            .is_some_and(|previous| sequence <= previous)
        {
            return Err(Error::PingSequence);
        }
        self.last_ping_sent = Some(sequence);
        self.auxiliary.push_back(Control::Ping {
            sequence,
            response: false,
        });
        Ok(())
    }

    /// Queue an unreliable datagram if the peer advertised support and sufficient size.
    pub fn send_datagram(&mut self, data: Bytes) -> Result<(), Error> {
        self.ensure_open()?;
        let Some(peer) = self.peer_parameters else {
            return Err(Error::DatagramsUnsupported);
        };
        let size = 1 + codec::varint_size(data.len() as u64)? + data.len();
        let limit = std::cmp::min(
            peer.max_datagram_frame_size.into_inner(),
            peer.max_record_size.into_inner(),
        );
        if limit == 0 {
            return Err(Error::DatagramsUnsupported);
        }
        if size as u64 > limit {
            return Err(Error::DatagramTooLarge { size, limit });
        }
        self.auxiliary.push_back(Control::Datagram(data));
        Ok(())
    }

    /// Queue an application close frame.
    pub fn close(&mut self, code: streams::VarInt, reason: impl Into<Bytes>) {
        self.start_close(Close::Application(ApplicationClose {
            error_code: code,
            reason: reason.into(),
        }));
    }

    /// Process one complete size-prefixed QMUX record from the carrier.
    pub fn received(&mut self, record: Bytes) -> Result<(), Error> {
        if self.state == State::Closed {
            return Ok(());
        }
        let result = self.received_inner(record);
        if let Err(error) = &result {
            self.start_close(Close::Transport(error.close_reason()));
        }
        result
    }

    fn received_inner(&mut self, record: Bytes) -> Result<(), Error> {
        let payload = codec::decode_record(record)?;
        let local_limit = self
            .local_parameters
            .max_record_size
            .into_inner()
            .try_into()
            .unwrap_or(usize::MAX);
        if payload.len() > local_limit {
            return Err(Error::RecordTooLarge {
                size: payload.len(),
                limit: local_limit,
            });
        }
        let allocation_size = payload.len();
        for frame in codec::decode_frames(payload)? {
            if self.peer_parameters.is_none() && !matches!(frame, codec::Frame::Parameters(_)) {
                return Err(Error::ParametersNotFirst);
            }
            match frame {
                codec::Frame::Padding => {}
                codec::Frame::Stream(frame) => {
                    self.streams.received_frame(frame, allocation_size)?;
                    while let Some(event) = self.streams.poll() {
                        self.events.push_back(Event::Stream(event));
                    }
                }
                codec::Frame::Parameters(params) => {
                    if self.peer_parameters.is_some() {
                        return Err(Error::DuplicateParameters);
                    }
                    params.validate()?;
                    self.streams.set_peer_parameters(params.streams());
                    self.peer_parameters = Some(params);
                    self.events.push_back(Event::PeerParameters(params));
                }
                codec::Frame::Ping { sequence, response } => {
                    if response {
                        if self
                            .last_ping_sent
                            .is_none_or(|last_sent| sequence > last_sent)
                        {
                            return Err(TransportError::new(
                                TransportErrorCode::PROTOCOL_VIOLATION,
                                "QX_PING response sequence was not sent".into(),
                            )
                            .into());
                        }
                        self.events.push_back(Event::PingResponse(sequence));
                    } else {
                        if self
                            .last_ping_received
                            .is_some_and(|previous| sequence <= previous)
                        {
                            return Err(TransportError::new(
                                TransportErrorCode::PROTOCOL_VIOLATION,
                                "QX_PING request sequence did not increase".into(),
                            )
                            .into());
                        }
                        self.last_ping_received = Some(sequence);
                        self.urgent.push_back(Control::Ping {
                            sequence,
                            response: true,
                        });
                    }
                }
                codec::Frame::Datagram { data, frame_size } => {
                    let limit = self.local_parameters.max_datagram_frame_size.into_inner();
                    if limit == 0 || frame_size as u64 > limit {
                        return Err(Error::DatagramTooLarge {
                            size: frame_size,
                            limit,
                        });
                    }
                    self.events.push_back(Event::Datagram(data));
                }
                codec::Frame::ConnectionClose(close) => {
                    self.peer_closed(Close::Transport(close));
                    break;
                }
                codec::Frame::ApplicationClose(close) => {
                    self.peer_closed(Close::Application(close));
                    break;
                }
            }
        }
        Ok(())
    }

    /// Build the next complete QMUX record to write to the carrier.
    pub fn poll_transmit(&mut self) -> Result<Option<Transmit>, Error> {
        if self.state == State::Closed {
            return Ok(None);
        }
        let limit = self
            .peer_parameters
            .map_or(DEFAULT_MAX_RECORD_SIZE, |params| {
                params.max_record_size.into_inner()
            })
            .try_into()
            .unwrap_or(usize::MAX);

        let closes = matches!(self.urgent.front(), Some(Control::Close(_)));
        let (payload, streams) = if let Some(payload) = encode_front(&self.urgent, limit)? {
            self.urgent.pop_front();
            (payload, None)
        } else if self.state == State::Closing {
            return Ok(None);
        } else if let Some(transmit) = self.streams.poll_transmit(limit) {
            (transmit.payload.clone(), Some(transmit))
        } else if let Some(payload) = encode_front(&self.auxiliary, limit)? {
            self.auxiliary.pop_front();
            (payload, None)
        } else {
            return Ok(None);
        };

        let sequence = self.next_transmit;
        self.next_transmit += 1;
        Ok(Some(Transmit {
            bytes: codec::encode_record(payload)?,
            connection: self.id,
            sequence,
            streams,
            closes,
        }))
    }

    /// Report successful ordered completion of a carrier write.
    pub fn transmitted(&mut self, transmit: Transmit) -> Result<(), Error> {
        if transmit.connection != self.id {
            return Err(Error::WrongConnection);
        }
        if transmit.sequence != self.next_completion {
            return Err(Error::OutOfOrderTransmit);
        }
        self.next_completion += 1;
        let closes = transmit.closes;
        if let Some(transmit) = transmit.streams {
            self.streams.transmitted(transmit);
        }
        if closes {
            self.state = State::Closed;
            self.urgent.clear();
            self.auxiliary.clear();
        }
        Ok(())
    }

    fn ensure_open(&self) -> Result<(), Error> {
        if self.state == State::Open {
            Ok(())
        } else {
            Err(Error::ConnectionClosed)
        }
    }

    fn start_close(&mut self, close: Close) {
        if self.state != State::Open {
            return;
        }
        self.streams.close();
        self.state = State::Closing;
        self.auxiliary.clear();

        // Transport parameters must remain the first frame even when the
        // application closes before its first carrier write. Other queued
        // responses are superseded by the close.
        let parameters = match self.urgent.front() {
            Some(Control::Parameters(_)) => self.urgent.pop_front(),
            _ => None,
        };
        self.urgent.clear();
        if let Some(parameters) = parameters {
            self.urgent.push_back(parameters);
        }
        self.urgent.push_back(Control::Close(close));
    }

    fn peer_closed(&mut self, close: Close) {
        self.streams.close();
        self.state = State::Closed;
        self.urgent.clear();
        self.auxiliary.clear();
        self.events.push_back(Event::Closed(close));
    }
}

impl Error {
    fn close_reason(&self) -> ConnectionClose {
        let error = match self {
            Self::Protocol(error) => return error.clone().into(),
            Self::TransportParameter(_) => TransportError::new(
                TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                self.to_string(),
            ),
            Self::DuplicateParameters | Self::ParametersNotFirst => {
                TransportError::new(TransportErrorCode::PROTOCOL_VIOLATION, self.to_string())
            }
            _ => TransportError::new(TransportErrorCode::FRAME_ENCODING_ERROR, self.to_string()),
        };
        error.into()
    }
}

fn encode_front(queue: &VecDeque<Control>, limit: usize) -> Result<Option<Bytes>, Error> {
    let Some(control) = queue.front() else {
        return Ok(None);
    };
    let payload = control.encode(limit)?;
    if payload.len() > limit {
        return Err(Error::FrameTooLarge {
            size: payload.len(),
            limit,
        });
    }
    Ok(Some(payload))
}
