//! Standard QUIC wire frames used by reliable carriers.

use bytes::Bytes;

use super::reliable::{Frame as StreamFrame, public_frame};
use crate::{
    ApplicationClose, ConnectionClose, TransportError, VarInt,
    coding::Codec,
    frame::{self, Close, Frame as WireFrame, FrameType},
};

/// A standard QUIC frame that is meaningful on a reliable carrier.
///
/// Frame types not represented here are left to the carrier. This lets a
/// protocol such as QMUX interleave its extension frames with standard QUIC
/// frames without duplicating Quinn's standard frame parser.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Frame {
    /// A frame type outside the standard reliable-carrier subset.
    ///
    /// The type has been consumed, while its body remains at the front of the
    /// input buffer for the carrier to decode.
    Other(VarInt),
    /// Padding.
    Padding,
    /// A stream lifecycle or flow-control frame.
    Stream(StreamFrame),
    /// An unreliable datagram.
    Datagram {
        /// Datagram payload.
        data: Bytes,
        /// Encoded frame size, including the frame type and optional length.
        encoded_size: usize,
    },
    /// A transport-level connection close.
    ConnectionClose(ConnectionClose),
    /// An application-level connection close.
    ApplicationClose(ApplicationClose),
}

/// Decode one standard QUIC frame used by a reliable carrier.
///
/// Other frame types are returned as [`Frame::Other`] after consuming only the
/// type, so the carrier can decode an extension or reject a prohibited standard
/// frame. Malformed recognized frames are reported as QUIC frame-encoding
/// errors.
pub fn decode(payload: &mut Bytes) -> Result<Frame, TransportError> {
    let encoded_size = payload.len();
    let ty = VarInt::decode(payload)
        .map_err(|_| TransportError::FRAME_ENCODING_ERROR("unexpected end"))?;
    let frame_type = FrameType::from_varint(ty);
    if !frame_type.reliable() {
        return Ok(Frame::Other(ty));
    }

    let frame = frame::decode_with_type(frame_type, payload)?;
    let encoded_size = encoded_size - payload.len();
    Ok(match frame {
        WireFrame::Padding => Frame::Padding,
        WireFrame::Datagram(frame) => Frame::Datagram {
            data: frame.data,
            encoded_size,
        },
        WireFrame::Close(Close::Connection(frame)) => Frame::ConnectionClose(frame),
        WireFrame::Close(Close::Application(frame)) => Frame::ApplicationClose(frame),
        frame => Frame::Stream(
            public_frame(frame).expect("recognized reliable frame must be stream-related"),
        ),
    })
}

/// Encode a length-prefixed QUIC DATAGRAM frame for a reliable carrier.
pub fn encode_datagram(data: Bytes) -> Bytes {
    let frame = crate::Datagram { data };
    let mut encoded = Vec::with_capacity(frame.size(true));
    frame.encode(true, &mut encoded);
    encoded.into()
}

/// Encode an application-level QUIC connection-close frame without truncation.
pub fn encode_application_close(error_code: VarInt, reason: Bytes) -> Bytes {
    let frame = ApplicationClose { error_code, reason };
    let mut encoded = Vec::with_capacity(1 + error_code.size() + 8 + frame.reason.len());
    frame.encode(&mut encoded, usize::MAX);
    encoded.into()
}

/// Encode a transport-level QUIC connection-close frame without truncation.
pub fn encode_connection_close(frame: ConnectionClose) -> Bytes {
    let mut encoded = Vec::with_capacity(32 + frame.reason.len());
    frame.encode(&mut encoded, usize::MAX);
    encoded.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_stream_offsets() {
        let mut payload = Bytes::from_static(&[0x0e, 0x02, 0x40, 0x40, 0x02, b'h', b'i']);
        assert!(matches!(
            decode(&mut payload).unwrap(),
            Frame::Stream(StreamFrame::Stream {
                id,
                offset: 64,
                fin: false,
                data,
            }) if u64::from(id) == 2 && data.as_ref() == b"hi"
        ));
        assert!(payload.is_empty());
    }

    #[test]
    fn leaves_other_frame_bodies_untouched() {
        let mut payload = Bytes::from_static(&[
            0xff, 0x51, 0x53, 0x30, 0x0d, 0x0a, 0x0d, 0x0a, b'b', b'o', b'd', b'y',
        ]);
        assert!(matches!(
            decode(&mut payload).unwrap(),
            Frame::Other(ty) if ty.into_inner() == 0x3f51_5330_0d0a_0d0a
        ));
        assert_eq!(payload.as_ref(), b"body");
    }

    #[test]
    fn carrier_codecs_round_trip() {
        let mut datagram = encode_datagram(Bytes::from_static(b"hi"));
        assert!(matches!(
            decode(&mut datagram).unwrap(),
            Frame::Datagram {
                data,
                encoded_size: 4,
            } if data.as_ref() == b"hi"
        ));

        let mut close = encode_application_close(42u32.into(), Bytes::from_static(b"bye"));
        assert!(matches!(
            decode(&mut close).unwrap(),
            Frame::ApplicationClose(ApplicationClose {
                error_code,
                reason,
            }) if error_code == VarInt::from_u32(42) && reason.as_ref() == b"bye"
        ));

        let mut close = encode_connection_close(ConnectionClose {
            error_code: crate::TransportErrorCode::PROTOCOL_VIOLATION,
            frame_type: None,
            reason: Bytes::from_static(b"bad frame"),
        });
        assert!(matches!(
            decode(&mut close).unwrap(),
            Frame::ConnectionClose(ConnectionClose {
                error_code,
                frame_type: None,
                reason,
            }) if error_code == crate::TransportErrorCode::PROTOCOL_VIOLATION
                && reason.as_ref() == b"bad frame"
        ));
    }

    #[test]
    fn datagram_size_includes_non_minimal_frame_type() {
        let mut datagram = Bytes::from_static(&[0x40, 0x31, 0x02, b'h', b'i']);
        assert!(matches!(
            decode(&mut datagram).unwrap(),
            Frame::Datagram {
                data,
                encoded_size: 5,
            } if data.as_ref() == b"hi"
        ));
    }
}
