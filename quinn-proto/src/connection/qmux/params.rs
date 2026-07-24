//! QMux transport parameters (draft-ietf-quic-qmux-02 §4)
//!
//! Carried in the QX_TRANSPORT_PARAMETERS frame rather than a TLS extension. The wire
//! format and the standard parameters are QUIC v1's, so encoding and decoding delegate to
//! [`TransportParameters`]; this module adds only the QMux policy: an allow-list that hard
//! rejects the QUIC v1 parameters the draft prohibits, duplicate detection across all
//! parameter ids, and the QMux-specific `max_record_size` parameter, which the shared
//! codec would otherwise ignore as unknown.

use std::collections::HashSet;

use bytes::{Buf, BufMut, Bytes};

use crate::{
    Side, TransportError, TransportErrorCode, VarInt, coding::Codec,
    transport_parameters::TransportParameters,
};

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QmuxParams {
    /// The standard QUIC parameters (flow control, stream limits, idle timeout, datagrams)
    pub(crate) tp: TransportParameters,
    /// Largest record Size field the peer may use in records it sends to us
    pub(crate) max_record_size: VarInt,
}

fn err(reason: &str) -> TransportError {
    TransportError::new(TransportErrorCode::TRANSPORT_PARAMETER_ERROR, reason.into())
}

impl QmuxParams {
    pub(crate) fn encode<B: BufMut>(&self, buf: &mut B) {
        self.tp.write(buf);
        if self.max_record_size.into_inner() != DEFAULT_MAX_RECORD_SIZE {
            VarInt::from_u64(MAX_RECORD_SIZE).unwrap().encode(buf);
            VarInt::from_u64(self.max_record_size.size() as u64)
                .unwrap()
                .encode(buf);
            self.max_record_size.encode(buf);
        }
    }

    pub(crate) fn decode(side: Side, blob: Bytes) -> Result<Self, TransportError> {
        // QMux-specific validation pass: enforce the allow-list and duplicate rules over
        // every parameter (the shared codec cannot see prohibited-with-default-value,
        // duplicated-unknown, or QMux-only parameters), and pluck out max_record_size
        let mut max_record_size = VarInt::from_u64(DEFAULT_MAX_RECORD_SIZE).unwrap();
        let mut seen = HashSet::new();
        let mut scan = &blob[..];
        while scan.has_remaining() {
            let id = VarInt::decode(&mut scan)
                .map_err(|_| err("truncated parameter id"))?
                .into_inner();
            let len = VarInt::decode(&mut scan)
                .map_err(|_| err("truncated parameter length"))?
                .into_inner();
            let len = usize::try_from(len).map_err(|_| err("oversized parameter"))?;
            if scan.remaining() < len {
                return Err(err("truncated parameter value"));
            }
            let mut value = &scan[..len];
            scan.advance(len);

            if is_forbidden(id) {
                return Err(err("prohibited QUIC v1 transport parameter"));
            }
            if !seen.insert(id) {
                return Err(err("duplicate transport parameter"));
            }
            if id == MAX_RECORD_SIZE {
                max_record_size =
                    VarInt::decode(&mut value).map_err(|_| err("malformed parameter value"))?;
                if value.has_remaining() {
                    return Err(err("malformed parameter value"));
                }
            }
        }
        if max_record_size.into_inner() < DEFAULT_MAX_RECORD_SIZE {
            return Err(err("max_record_size below the required minimum"));
        }

        // The standard parameters are parsed by the shared codec
        let tp = TransportParameters::read(side, &mut &blob[..])?;
        Ok(Self {
            tp,
            max_record_size,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(max_record_size: u32) -> QmuxParams {
        QmuxParams {
            tp: TransportParameters {
                max_idle_timeout: VarInt::from_u32(30_000),
                initial_max_data: VarInt::from_u32(1 << 20),
                initial_max_stream_data_bidi_local: VarInt::from_u32(1 << 16),
                initial_max_stream_data_bidi_remote: VarInt::from_u32(1 << 16),
                initial_max_stream_data_uni: VarInt::from_u32(1 << 16),
                initial_max_streams_bidi: VarInt::from_u32(16),
                initial_max_streams_uni: VarInt::from_u32(16),
                max_datagram_frame_size: Some(VarInt::from_u32(4096)),
                ..TransportParameters::default()
            },
            max_record_size: VarInt::from_u32(max_record_size),
        }
    }

    fn write_param(buf: &mut Vec<u8>, id: u64, value: VarInt) {
        VarInt::from_u64(id).unwrap().encode(buf);
        VarInt::from_u64(value.size() as u64).unwrap().encode(buf);
        value.encode(buf);
    }

    #[test]
    fn round_trip() {
        let params = params(32_768);
        let mut buf = Vec::new();
        params.encode(&mut buf);
        assert_eq!(
            QmuxParams::decode(Side::Server, buf.into()).unwrap(),
            params
        );
    }

    #[test]
    fn defaults_encode_empty() {
        let defaults = QmuxParams {
            tp: TransportParameters::default(),
            max_record_size: VarInt::from_u64(DEFAULT_MAX_RECORD_SIZE).unwrap(),
        };
        let mut buf = Vec::new();
        defaults.encode(&mut buf);
        assert!(buf.is_empty());
        assert_eq!(
            QmuxParams::decode(Side::Client, Bytes::new()).unwrap(),
            defaults
        );
    }

    #[test]
    fn forbidden_param() {
        // stateless_reset_token (0x02)
        let buf: &[u8] = &[0x02, 0x00];
        assert!(QmuxParams::decode(Side::Client, Bytes::copy_from_slice(buf)).is_err());
    }

    #[test]
    fn duplicate_param() {
        let mut buf = Vec::new();
        write_param(&mut buf, 0x04, VarInt::from_u32(1)); // initial_max_data
        write_param(&mut buf, 0x04, VarInt::from_u32(1));
        assert!(QmuxParams::decode(Side::Client, buf.into()).is_err());
    }

    #[test]
    fn duplicate_unknown_param() {
        // The shared codec skips unknown ids, so only the QMux scan can catch this
        let mut buf = Vec::new();
        write_param(&mut buf, 0x1234, VarInt::from_u32(7));
        write_param(&mut buf, 0x1234, VarInt::from_u32(7));
        assert!(QmuxParams::decode(Side::Client, buf.into()).is_err());
    }

    #[test]
    fn unknown_param_ignored() {
        let mut buf = Vec::new();
        write_param(&mut buf, 0x1234, VarInt::from_u32(7));
        write_param(&mut buf, 0x04, VarInt::from_u32(42)); // initial_max_data
        let params = QmuxParams::decode(Side::Client, buf.into()).unwrap();
        assert_eq!(params.tp.initial_max_data, VarInt::from_u32(42));
    }

    #[test]
    fn record_size_below_minimum() {
        let mut buf = Vec::new();
        write_param(&mut buf, MAX_RECORD_SIZE, VarInt::from_u32(1024));
        assert!(QmuxParams::decode(Side::Client, buf.into()).is_err());
    }

    #[test]
    fn oversized_stream_limit_rejected() {
        // MAX_STREAM_COUNT enforcement comes from the shared codec
        let mut buf = Vec::new();
        write_param(&mut buf, 0x08, VarInt::from_u64(1 << 61).unwrap());
        assert!(QmuxParams::decode(Side::Client, buf.into()).is_err());
    }
}
