use bytes::{Buf, Bytes, BytesMut};
use quinn_proto::{
    ApplicationClose, ConnectionClose, VarInt,
    coding::Codec,
    streams::wire::{self, Frame as WireFrame},
};

use crate::{Error, Parameters};

pub(crate) const QX_TRANSPORT_PARAMETERS: u64 = 0x3f51_5330_0d0a_0d0a;
pub(crate) const QX_PING_REQUEST: u64 = 0x348c_6752_9ef8_c7bd;
pub(crate) const QX_PING_RESPONSE: u64 = 0x348c_6752_9ef8_c7be;

pub(crate) enum Frame {
    Padding,
    Stream(quinn_proto::streams::Frame),
    Parameters(Parameters),
    Ping { sequence: VarInt, response: bool },
    Datagram { data: Bytes, frame_size: usize },
    ConnectionClose(ConnectionClose),
    ApplicationClose(ApplicationClose),
}

pub(crate) fn varint_size(value: u64) -> Result<usize, Error> {
    Ok(VarInt::try_from(value)?.size())
}

pub(crate) fn put_varint(buf: &mut BytesMut, value: impl Into<u64>) -> Result<(), Error> {
    VarInt::try_from(value.into())?.encode(buf);
    Ok(())
}

pub(crate) fn get_varint(buf: &mut Bytes) -> Result<VarInt, Error> {
    VarInt::decode(buf).map_err(|_| Error::Truncated)
}

fn get_length(buf: &mut Bytes) -> Result<usize, Error> {
    usize::try_from(get_varint(buf)?.into_inner())
        .map_err(|_| Error::FrameEncoding("length exceeds platform capacity"))
}

pub(crate) fn encode_record(payload: Bytes) -> Result<Bytes, Error> {
    let mut record = BytesMut::with_capacity(varint_size(payload.len() as u64)? + payload.len());
    put_varint(&mut record, payload.len() as u64)?;
    record.extend_from_slice(&payload);
    Ok(record.freeze())
}

pub(crate) fn decode_record(mut record: Bytes) -> Result<Bytes, Error> {
    let size = get_varint(&mut record)?.into_inner();
    if size != record.len() as u64 {
        return Err(Error::RecordSizeMismatch);
    }
    Ok(record)
}

pub(crate) fn decode_frames(mut payload: Bytes) -> Result<Vec<Frame>, Error> {
    let mut frames = Vec::new();
    while payload.has_remaining() {
        frames.push(decode_frame(&mut payload)?);
    }
    Ok(frames)
}

fn decode_frame(data: &mut Bytes) -> Result<Frame, Error> {
    match wire::decode(data)? {
        WireFrame::Other(ty) => match ty.into_inner() {
            0x24 => Err(Error::InvalidFrame(0x24)),
            QX_TRANSPORT_PARAMETERS => {
                let len = get_length(data)?;
                if data.len() < len {
                    return Err(Error::Truncated);
                }
                Ok(Frame::Parameters(Parameters::decode(data.split_to(len))?))
            }
            value @ (QX_PING_REQUEST | QX_PING_RESPONSE) => Ok(Frame::Ping {
                sequence: get_varint(data)?,
                response: value == QX_PING_RESPONSE,
            }),
            value => Err(Error::InvalidFrame(value)),
        },
        WireFrame::Padding => Ok(Frame::Padding),
        WireFrame::Stream(frame) => Ok(Frame::Stream(frame)),
        WireFrame::Datagram { data, encoded_size } => Ok(Frame::Datagram {
            data,
            frame_size: encoded_size,
        }),
        WireFrame::ConnectionClose(frame) => Ok(Frame::ConnectionClose(frame)),
        WireFrame::ApplicationClose(frame) => Ok(Frame::ApplicationClose(frame)),
        _ => Err(Error::FrameEncoding(
            "unsupported frame returned by quinn-proto",
        )),
    }
}

pub(crate) fn encode_parameters(params: &Parameters) -> Result<Bytes, Error> {
    let encoded = params.encode()?;
    let mut frame = BytesMut::new();
    put_varint(&mut frame, QX_TRANSPORT_PARAMETERS)?;
    put_varint(&mut frame, encoded.len() as u64)?;
    frame.extend_from_slice(&encoded);
    Ok(frame.freeze())
}

pub(crate) fn encode_ping(sequence: VarInt, response: bool) -> Result<Bytes, Error> {
    let mut frame = BytesMut::new();
    put_varint(
        &mut frame,
        if response {
            QX_PING_RESPONSE
        } else {
            QX_PING_REQUEST
        },
    )?;
    put_varint(&mut frame, sequence)?;
    Ok(frame.freeze())
}

pub(crate) fn encode_datagram(data: &Bytes) -> Result<Bytes, Error> {
    Ok(wire::encode_datagram(data.clone()))
}

pub(crate) fn encode_application_close(
    code: VarInt,
    reason: &Bytes,
    max_size: usize,
) -> Result<Bytes, Error> {
    // Type, error code, and reason length are each at most one QUIC varint.
    let max_reason = max_size.saturating_sub(3 * VarInt::MAX_SIZE);
    Ok(wire::encode_application_close(
        code,
        reason.slice(..reason.len().min(max_reason)),
    ))
}

pub(crate) fn encode_connection_close(
    close: &ConnectionClose,
    max_size: usize,
) -> Result<Bytes, Error> {
    // Type, error code, triggering frame type, and reason length are each at
    // most one QUIC varint.
    let max_reason = max_size.saturating_sub(4 * VarInt::MAX_SIZE);
    let mut close = close.clone();
    close.reason = close.reason.slice(..close.reason.len().min(max_reason));
    Ok(wire::encode_connection_close(close))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use quinn_proto::streams::Frame as StreamFrame;

    use super::*;

    #[test]
    fn matches_existing_qmux_wire_fixtures() {
        assert_eq!(
            encode_datagram(&Bytes::from_static(b"hi")).unwrap(),
            Bytes::from_static(&[0x31, 0x02, b'h', b'i'])
        );
        assert_eq!(
            encode_parameters(&Parameters::default()).unwrap(),
            Bytes::from_static(&[0xff, 0x51, 0x53, 0x30, 0x0d, 0x0a, 0x0d, 0x0a, 0x00])
        );
    }

    #[test]
    fn application_close_uses_quic_v1_layout() {
        assert_eq!(
            encode_application_close(42u32.into(), &Bytes::from_static(b"bye"), usize::MAX)
                .unwrap(),
            Bytes::from_static(&[0x1d, 0x2a, 0x03, b'b', b'y', b'e'])
        );
    }

    #[test]
    fn preserves_transport_close_details() {
        let frames = decode_frames(Bytes::from_static(&[
            0x1c, 0x01, 0x10, 0x03, b'b', b'a', b'd',
        ]))
        .unwrap();
        assert!(matches!(
            frames.as_slice(),
            [Frame::ConnectionClose(close)]
                if close.error_code == quinn_proto::TransportErrorCode::INTERNAL_ERROR
                    && close.frame_type.is_some()
                    && close.reason.as_ref() == b"bad"
        ));
    }

    #[test]
    fn preserves_stream_offsets() {
        let frames = decode_frames(Bytes::from_static(&[
            0x0e, 0x02, 0x40, 0x40, 0x02, b'h', b'i',
        ]))
        .unwrap();
        assert!(matches!(
            frames.as_slice(),
            [Frame::Stream(StreamFrame::Stream {
                id,
                offset: 64,
                fin: false,
                data,
            })] if u64::from(*id) == 2 && data.as_ref() == b"hi"
        ));
    }
}
