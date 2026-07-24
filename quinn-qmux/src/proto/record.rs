//! Record layer (draft-ietf-quic-qmux-02 §3)
//!
//! On a byte-stream transport, frames are carried in records: a variable-length integer
//! `Size` followed by `Size` bytes of frames. A frame never spans records.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use quinn_proto::{TransportError, TransportErrorCode, VarInt, coding::Codec};

/// Incremental parser splitting a byte stream into records
#[derive(Debug, Default)]
pub(crate) struct Deframer {
    buf: BytesMut,
}

impl Deframer {
    /// Buffer freshly received transport bytes
    pub(crate) fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Extract the frames payload of the next complete record, if any
    ///
    /// `max_size` is our advertised `max_record_size`; a larger Size field is a protocol
    /// violation by the peer.
    pub(crate) fn next(&mut self, max_size: u64) -> Result<Option<Bytes>, TransportError> {
        let mut peek = &self.buf[..];
        let Ok(size) = VarInt::decode(&mut peek) else {
            return Ok(None);
        };
        if size.into_inner() > max_size {
            return Err(TransportError::new(
                TransportErrorCode::PROTOCOL_VIOLATION,
                "record exceeds max_record_size".into(),
            ));
        }
        let header = self.buf.len() - peek.len();
        let size = size.into_inner() as usize;
        if self.buf.len() < header + size {
            return Ok(None);
        }
        self.buf.advance(header);
        Ok(Some(self.buf.split_to(size).freeze()))
    }
}

/// Prefix an assembled frames buffer with its record Size field
pub(crate) fn wrap(frames: &[u8]) -> Bytes {
    let size = VarInt::from_u64(frames.len() as u64).expect("record too large");
    let prefix = crate::proto::frame::varint_size(frames.len() as u64);
    let mut record = BytesMut::with_capacity(prefix + frames.len());
    size.encode(&mut record);
    record.put_slice(frames);
    record.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_delivery() {
        let record = wrap(&[1, 2, 3, 4, 5]);
        let mut deframer = Deframer::default();
        for chunk in record.chunks(2) {
            deframer.push(chunk);
        }
        assert_eq!(
            deframer.next(16382).unwrap().unwrap(),
            Bytes::from_static(&[1, 2, 3, 4, 5])
        );
        assert!(deframer.next(16382).unwrap().is_none());
    }

    #[test]
    fn multiple_records() {
        let mut deframer = Deframer::default();
        deframer.push(&wrap(b"aa"));
        deframer.push(&wrap(b"bbb"));
        assert_eq!(deframer.next(16382).unwrap().unwrap(), &b"aa"[..]);
        assert_eq!(deframer.next(16382).unwrap().unwrap(), &b"bbb"[..]);
        assert!(deframer.next(16382).unwrap().is_none());
    }

    #[test]
    fn oversized_record() {
        let mut deframer = Deframer::default();
        deframer.push(&wrap(&[0; 100]));
        assert!(deframer.next(50).is_err());
    }
}
