//! QMux transport parameters (draft-ietf-quic-qmux-02 §4)
//!
//! Carried in the QX_TRANSPORT_PARAMETERS frame rather than a TLS extension. Only the
//! flow-control related QUIC v1 parameters are permitted, plus the QMux-specific
//! `max_record_size` and negotiated extensions; the remaining QUIC v1 parameters are
//! prohibited and produce a `TRANSPORT_PARAMETER_ERROR`.

use std::collections::HashSet;

use crate::{TransportError, TransportErrorCode, VarInt, coding::Codec};
use bytes::{Buf, BufMut, Bytes};

const MAX_IDLE_TIMEOUT: u64 = 0x01;
const INITIAL_MAX_DATA: u64 = 0x04;
const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
const INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
const INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
const INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
const MAX_DATAGRAM_FRAME_SIZE: u64 = 0x20;
const MAX_RECORD_SIZE: u64 = 0x0571c59429cd0845;

/// Default and minimum value of `max_record_size` (16 KiB minus a 2-byte size prefix)
pub(crate) const DEFAULT_MAX_RECORD_SIZE: u64 = 16382;

/// QUIC v1 transport parameters QMux prohibits
///
/// original_destination_connection_id, stateless_reset_token, max_udp_payload_size,
/// ack_delay_exponent, max_ack_delay, disable_active_migration, preferred_address,
/// active_connection_id_limit, initial_source_connection_id, retry_source_connection_id.
fn is_forbidden(id: u64) -> bool {
    matches!(id, 0x00 | 0x02 | 0x03 | 0x0a..=0x10)
}

/// The transport parameters QMux endpoints exchange
///
/// Zero-valued parameters are omitted on the wire; `max_record_size` is omitted when it
/// equals the default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QmuxParams {
    /// Milliseconds; 0 disables the idle timeout
    pub(crate) max_idle_timeout: VarInt,
    pub(crate) initial_max_data: VarInt,
    pub(crate) initial_max_stream_data_bidi_local: VarInt,
    pub(crate) initial_max_stream_data_bidi_remote: VarInt,
    pub(crate) initial_max_stream_data_uni: VarInt,
    pub(crate) initial_max_streams_bidi: VarInt,
    pub(crate) initial_max_streams_uni: VarInt,
    /// Largest Size field the peer may use in records it sends to us
    pub(crate) max_record_size: VarInt,
    /// None disables datagram support
    pub(crate) max_datagram_frame_size: Option<VarInt>,
}

impl Default for QmuxParams {
    fn default() -> Self {
        Self {
            max_idle_timeout: VarInt::from_u32(0),
            initial_max_data: VarInt::from_u32(0),
            initial_max_stream_data_bidi_local: VarInt::from_u32(0),
            initial_max_stream_data_bidi_remote: VarInt::from_u32(0),
            initial_max_stream_data_uni: VarInt::from_u32(0),
            initial_max_streams_bidi: VarInt::from_u32(0),
            initial_max_streams_uni: VarInt::from_u32(0),
            max_record_size: VarInt::from_u64(DEFAULT_MAX_RECORD_SIZE).unwrap(),
            max_datagram_frame_size: None,
        }
    }
}

fn err(reason: &str) -> TransportError {
    TransportError::new(TransportErrorCode::TRANSPORT_PARAMETER_ERROR, reason.into())
}

fn write_param<B: BufMut>(buf: &mut B, id: u64, value: VarInt) {
    VarInt::from_u64(id).unwrap().encode(buf);
    let size = super::frame::varint_size(value.into_inner());
    VarInt::from_u64(size as u64).unwrap().encode(buf);
    value.encode(buf);
}

impl QmuxParams {
    pub(crate) fn encode<B: BufMut>(&self, buf: &mut B) {
        let varints = [
            (MAX_IDLE_TIMEOUT, self.max_idle_timeout),
            (INITIAL_MAX_DATA, self.initial_max_data),
            (
                INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                self.initial_max_stream_data_bidi_local,
            ),
            (
                INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                self.initial_max_stream_data_bidi_remote,
            ),
            (
                INITIAL_MAX_STREAM_DATA_UNI,
                self.initial_max_stream_data_uni,
            ),
            (INITIAL_MAX_STREAMS_BIDI, self.initial_max_streams_bidi),
            (INITIAL_MAX_STREAMS_UNI, self.initial_max_streams_uni),
        ];
        for (id, value) in varints {
            if value.into_inner() != 0 {
                write_param(buf, id, value);
            }
        }
        if self.max_record_size.into_inner() != DEFAULT_MAX_RECORD_SIZE {
            write_param(buf, MAX_RECORD_SIZE, self.max_record_size);
        }
        if let Some(size) = self.max_datagram_frame_size {
            write_param(buf, MAX_DATAGRAM_FRAME_SIZE, size);
        }
    }

    pub(crate) fn decode(mut buf: Bytes) -> Result<Self, TransportError> {
        let mut params = Self::default();
        let mut seen = HashSet::new();
        while buf.has_remaining() {
            let id = VarInt::decode(&mut buf)
                .map_err(|_| err("truncated parameter id"))?
                .into_inner();
            let len = VarInt::decode(&mut buf)
                .map_err(|_| err("truncated parameter length"))?
                .into_inner();
            let len = usize::try_from(len).map_err(|_| err("oversized parameter"))?;
            if buf.remaining() < len {
                return Err(err("truncated parameter value"));
            }
            let mut value = buf.split_to(len);

            if is_forbidden(id) {
                return Err(err("prohibited QUIC v1 transport parameter"));
            }
            if !seen.insert(id) {
                return Err(err("duplicate transport parameter"));
            }

            let field = match id {
                MAX_IDLE_TIMEOUT => &mut params.max_idle_timeout,
                INITIAL_MAX_DATA => &mut params.initial_max_data,
                INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                    &mut params.initial_max_stream_data_bidi_local
                }
                INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                    &mut params.initial_max_stream_data_bidi_remote
                }
                INITIAL_MAX_STREAM_DATA_UNI => &mut params.initial_max_stream_data_uni,
                INITIAL_MAX_STREAMS_BIDI => &mut params.initial_max_streams_bidi,
                INITIAL_MAX_STREAMS_UNI => &mut params.initial_max_streams_uni,
                MAX_RECORD_SIZE => &mut params.max_record_size,
                MAX_DATAGRAM_FRAME_SIZE => {
                    params.max_datagram_frame_size = Some(decode_value(&mut value)?);
                    continue;
                }
                // Unknown parameters (including grease) are ignored
                _ => continue,
            };
            *field = decode_value(&mut value)?;
        }

        if params.max_record_size.into_inner() < DEFAULT_MAX_RECORD_SIZE {
            return Err(err("max_record_size below the required minimum"));
        }

        Ok(params)
    }
}

fn decode_value(value: &mut Bytes) -> Result<VarInt, TransportError> {
    let x = VarInt::decode(value).map_err(|_| err("malformed parameter value"))?;
    match value.has_remaining() {
        true => Err(err("malformed parameter value")),
        false => Ok(x),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let params = QmuxParams {
            max_idle_timeout: VarInt::from_u32(30_000),
            initial_max_data: VarInt::from_u32(1 << 20),
            initial_max_stream_data_bidi_local: VarInt::from_u32(1 << 16),
            initial_max_stream_data_bidi_remote: VarInt::from_u32(1 << 16),
            initial_max_stream_data_uni: VarInt::from_u32(1 << 16),
            initial_max_streams_bidi: VarInt::from_u32(16),
            initial_max_streams_uni: VarInt::from_u32(16),
            max_record_size: VarInt::from_u32(32_768),
            max_datagram_frame_size: Some(VarInt::from_u32(4096)),
        };
        let mut buf = Vec::new();
        params.encode(&mut buf);
        assert_eq!(QmuxParams::decode(buf.into()).unwrap(), params);
    }

    #[test]
    fn defaults_encode_empty() {
        let mut buf = Vec::new();
        QmuxParams::default().encode(&mut buf);
        assert!(buf.is_empty());
        assert_eq!(
            QmuxParams::decode(Bytes::new()).unwrap(),
            QmuxParams::default()
        );
    }

    #[test]
    fn forbidden_param() {
        // stateless_reset_token (0x02)
        let buf: &[u8] = &[0x02, 0x00];
        assert!(QmuxParams::decode(Bytes::copy_from_slice(buf)).is_err());
    }

    #[test]
    fn duplicate_param() {
        let mut buf = Vec::new();
        write_param(&mut buf, INITIAL_MAX_DATA, VarInt::from_u32(1));
        write_param(&mut buf, INITIAL_MAX_DATA, VarInt::from_u32(1));
        assert!(QmuxParams::decode(buf.into()).is_err());
    }

    #[test]
    fn unknown_param_ignored() {
        let mut buf = Vec::new();
        write_param(&mut buf, 0x1234, VarInt::from_u32(7));
        write_param(&mut buf, INITIAL_MAX_DATA, VarInt::from_u32(42));
        let params = QmuxParams::decode(buf.into()).unwrap();
        assert_eq!(params.initial_max_data, VarInt::from_u32(42));
    }

    #[test]
    fn record_size_below_minimum() {
        let mut buf = Vec::new();
        write_param(&mut buf, MAX_RECORD_SIZE, VarInt::from_u32(1024));
        assert!(QmuxParams::decode(buf.into()).is_err());
    }
}
