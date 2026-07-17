use std::collections::HashSet;

use bytes::{Buf, Bytes, BytesMut};
use quinn_proto::{VarInt, coding::Codec, transport_parameters};

use crate::{DEFAULT_MAX_RECORD_SIZE, Error};

const MAX_RECORD_SIZE_ID: u64 = 0x0571_c594_29cd_0845;
const MAX_STREAM_COUNT: u64 = 1 << 60;

/// QMUX and stream-related transport parameters.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct Parameters {
    /// Maximum idle timeout in milliseconds, or zero for no idle timeout.
    pub max_idle_timeout: VarInt,
    /// Initial connection-level stream-data credit.
    pub initial_max_data: VarInt,
    /// Initial stream-data credit for locally initiated bidirectional streams.
    pub initial_max_stream_data_bidi_local: VarInt,
    /// Initial stream-data credit for remotely initiated bidirectional streams.
    pub initial_max_stream_data_bidi_remote: VarInt,
    /// Initial stream-data credit for unidirectional streams.
    pub initial_max_stream_data_uni: VarInt,
    /// Initial number of bidirectional streams the peer may initiate.
    pub initial_max_streams_bidi: VarInt,
    /// Initial number of unidirectional streams the peer may initiate.
    pub initial_max_streams_uni: VarInt,
    /// Largest encoded DATAGRAM frame accepted, or zero when unsupported.
    pub max_datagram_frame_size: VarInt,
    /// Largest QMUX Frames field accepted in one record.
    pub max_record_size: VarInt,
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            max_idle_timeout: 0u32.into(),
            initial_max_data: 0u32.into(),
            initial_max_stream_data_bidi_local: 0u32.into(),
            initial_max_stream_data_bidi_remote: 0u32.into(),
            initial_max_stream_data_uni: 0u32.into(),
            initial_max_streams_bidi: 0u32.into(),
            initial_max_streams_uni: 0u32.into(),
            max_datagram_frame_size: 0u32.into(),
            max_record_size: VarInt::try_from(DEFAULT_MAX_RECORD_SIZE).unwrap(),
        }
    }
}

impl Parameters {
    pub(crate) fn streams(self) -> quinn_proto::streams::Parameters {
        quinn_proto::streams::Parameters {
            initial_max_data: self.initial_max_data,
            initial_max_stream_data_bidi_local: self.initial_max_stream_data_bidi_local,
            initial_max_stream_data_bidi_remote: self.initial_max_stream_data_bidi_remote,
            initial_max_stream_data_uni: self.initial_max_stream_data_uni,
            initial_max_streams_bidi: self.initial_max_streams_bidi,
            initial_max_streams_uni: self.initial_max_streams_uni,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.max_record_size.into_inner() < DEFAULT_MAX_RECORD_SIZE {
            return Err(Error::TransportParameter(
                "max_record_size is smaller than the draft default",
            ));
        }
        for count in [self.initial_max_streams_bidi, self.initial_max_streams_uni] {
            if count.into_inner() > MAX_STREAM_COUNT {
                return Err(Error::TransportParameter(
                    "initial_max_streams exceeds the QUIC limit",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> Result<Bytes, Error> {
        let mut out = BytesMut::new();
        encode_parameter(&mut out, 0x01, self.max_idle_timeout, false)?;
        encode_parameter(&mut out, 0x04, self.initial_max_data, false)?;
        encode_parameter(
            &mut out,
            0x05,
            self.initial_max_stream_data_bidi_local,
            false,
        )?;
        encode_parameter(
            &mut out,
            0x06,
            self.initial_max_stream_data_bidi_remote,
            false,
        )?;
        encode_parameter(&mut out, 0x07, self.initial_max_stream_data_uni, false)?;
        encode_parameter(&mut out, 0x08, self.initial_max_streams_bidi, false)?;
        encode_parameter(&mut out, 0x09, self.initial_max_streams_uni, false)?;
        encode_parameter(&mut out, 0x20, self.max_datagram_frame_size, false)?;
        encode_parameter(
            &mut out,
            MAX_RECORD_SIZE_ID,
            self.max_record_size,
            self.max_record_size.into_inner() == DEFAULT_MAX_RECORD_SIZE,
        )?;
        Ok(out.freeze())
    }

    pub(crate) fn decode(data: Bytes) -> Result<Self, Error> {
        let mut result = Self::default();
        let mut seen = HashSet::new();
        for parameter in transport_parameters::ParameterIter::new(data) {
            let parameter =
                parameter.map_err(|_| Error::TransportParameter("malformed parameter"))?;
            let id = parameter.id.into_inner();
            let mut value = parameter.value;
            if matches!(id, 0x00 | 0x02 | 0x03 | 0x0a..=0x10) {
                return Err(Error::TransportParameter("prohibited QUIC v1 parameter"));
            }
            if matches!(id, 0x01 | 0x04..=0x09 | 0x20 | MAX_RECORD_SIZE_ID) && !seen.insert(id) {
                return Err(Error::TransportParameter("duplicate parameter"));
            }
            let decoded = if matches!(id, 0x01 | 0x04..=0x09 | 0x20 | MAX_RECORD_SIZE_ID) {
                let decoded = VarInt::decode(&mut value)
                    .map_err(|_| Error::TransportParameter("malformed parameter value"))?;
                if value.has_remaining() {
                    return Err(Error::TransportParameter(
                        "parameter value has trailing bytes",
                    ));
                }
                Some(decoded)
            } else {
                None
            };
            match (id, decoded) {
                (0x01, Some(x)) => result.max_idle_timeout = x,
                (0x04, Some(x)) => result.initial_max_data = x,
                (0x05, Some(x)) => result.initial_max_stream_data_bidi_local = x,
                (0x06, Some(x)) => result.initial_max_stream_data_bidi_remote = x,
                (0x07, Some(x)) => result.initial_max_stream_data_uni = x,
                (0x08, Some(x)) => result.initial_max_streams_bidi = x,
                (0x09, Some(x)) => result.initial_max_streams_uni = x,
                (0x20, Some(x)) => result.max_datagram_frame_size = x,
                (MAX_RECORD_SIZE_ID, Some(x)) => result.max_record_size = x,
                _ => {}
            }
        }
        result.validate()?;
        Ok(result)
    }
}

fn encode_parameter(out: &mut BytesMut, id: u64, value: VarInt, omit: bool) -> Result<(), Error> {
    if value.into_inner() == 0 || omit {
        return Ok(());
    }
    let mut encoded = BytesMut::with_capacity(value.size());
    value.encode(&mut encoded);
    transport_parameters::write_parameter(out, VarInt::try_from(id)?, &encoded)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    #[test]
    fn rejects_prohibited_quic_v1_parameters() {
        assert!(matches!(
            Parameters::decode(Bytes::from_static(&[0x03, 0x01, 0x01])),
            Err(Error::TransportParameter("prohibited QUIC v1 parameter"))
        ));
    }

    #[test]
    fn ignores_unknown_extensions() {
        assert_eq!(
            Parameters::decode(Bytes::from_static(&[0x21, 0x00])).unwrap(),
            Parameters::default()
        );
    }
}
