//! QMux additions to the QUIC wire format (draft-ietf-quic-qmux-02)
//!
//! QMux reuses the QUIC version 1 frame formats verbatim, so records are parsed with the
//! crate's regular [`frame::Iter`]. This module supplies only what that parser does not
//! know: the QMux extension frames (`QX_TRANSPORT_PARAMETERS`, `QX_PING`) and
//! RESET_STREAM_AT from the partial-delivery extension, which are intercepted by peeking
//! each frame's type before handing the buffer to the shared parser.

use bytes::{Buf, BufMut, Bytes};

use crate::{
    TransportError, TransportErrorCode, VarInt,
    coding::{BufExt, Codec},
    frame::{self, ResetStream},
};

/// Encodes as `\xffQMX\r\n\r\n` on the wire, disambiguating QMux from HTTP/1.1 and HTTP/2
const QX_TRANSPORT_PARAMETERS: u64 = 0x3f5153300d0a0d0a;
const QX_PING_REQUEST: u64 = 0x348c67529ef8c7bd;
const QX_PING_RESPONSE: u64 = 0x348c67529ef8c7be;
/// From the Stream Resets with Partial Delivery extension; accepted but never sent
const RESET_STREAM_AT: u64 = 0x24;

/// One frame of a QMux record
#[derive(Debug)]
pub(super) enum QmuxFrame {
    /// A standard QUIC frame, parsed by [`frame::Iter`]
    ///
    /// Includes frames QMux prohibits (ACK, CRYPTO, ...); the connection rejects those
    /// after dispatch.
    Quic(frame::Frame),
    TransportParameters(Bytes),
    PingRequest(VarInt),
    PingResponse(VarInt),
    /// Validated at decode; the reliable size is irrelevant on a reliable transport
    ResetStreamAt(ResetStream),
}

fn truncated() -> TransportError {
    TransportError::new(
        TransportErrorCode::FRAME_ENCODING_ERROR,
        "truncated frame".into(),
    )
}

/// Decode the next frame from a record's frames payload
///
/// Returns `None` once the record is exhausted. A frame never spans records.
pub(super) fn next_frame(bytes: &mut Bytes) -> Result<Option<QmuxFrame>, TransportError> {
    if bytes.is_empty() {
        return Ok(None);
    }

    // Peek the frame type to intercept the QMux extension frames `frame::Iter` doesn't
    // recognize; everything else is parsed by the shared QUIC frame parser
    let mut peek = &bytes[..];
    let ty = peek.get_var().map_err(|_| truncated())?;
    let frame = match ty {
        QX_TRANSPORT_PARAMETERS | QX_PING_REQUEST | QX_PING_RESPONSE | RESET_STREAM_AT => {
            bytes.advance(bytes.len() - peek.len());
            match ty {
                QX_TRANSPORT_PARAMETERS => {
                    let len = bytes.get_var().map_err(|_| truncated())?;
                    let len = usize::try_from(len).map_err(|_| truncated())?;
                    if bytes.remaining() < len {
                        return Err(truncated());
                    }
                    QmuxFrame::TransportParameters(bytes.split_to(len))
                }
                QX_PING_REQUEST => QmuxFrame::PingRequest(bytes.get().map_err(|_| truncated())?),
                QX_PING_RESPONSE => QmuxFrame::PingResponse(bytes.get().map_err(|_| truncated())?),
                _ => {
                    let reset = ResetStream {
                        id: bytes.get().map_err(|_| truncated())?,
                        error_code: bytes.get().map_err(|_| truncated())?,
                        final_offset: bytes.get().map_err(|_| truncated())?,
                    };
                    let reliable_size: VarInt = bytes.get().map_err(|_| truncated())?;
                    if reliable_size > reset.final_offset {
                        return Err(TransportError::new(
                            TransportErrorCode::FRAME_ENCODING_ERROR,
                            "RESET_STREAM_AT reliable size exceeds final size".into(),
                        ));
                    }
                    QmuxFrame::ResetStreamAt(reset)
                }
            }
        }
        _ => {
            let mut iter = frame::Iter::new(std::mem::take(bytes))?;
            let frame = iter
                .next()
                .expect("payload is non-empty")
                .map_err(TransportError::from)?;
            *bytes = iter.into_rest();
            QmuxFrame::Quic(frame)
        }
    };
    Ok(Some(frame))
}

pub(super) fn encode_transport_parameters<B: BufMut>(buf: &mut B, params: &[u8]) {
    VarInt::from_u64(QX_TRANSPORT_PARAMETERS)
        .unwrap()
        .encode(buf);
    VarInt::from_u64(params.len() as u64)
        .expect("oversized transport parameters")
        .encode(buf);
    buf.put_slice(params);
}

pub(super) fn encode_ping<B: BufMut>(buf: &mut B, response: bool, seq: VarInt) {
    VarInt::from_u64(match response {
        true => QX_PING_RESPONSE,
        false => QX_PING_REQUEST,
    })
    .unwrap()
    .encode(buf);
    seq.encode(buf);
}

/// Size of an encoded QX_PING frame with the given sequence number
pub(super) fn ping_size(seq: VarInt) -> usize {
    8 + seq.size()
}
