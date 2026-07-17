#![no_main]

use arbitrary::Arbitrary;
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;

extern crate proto;
use proto::streams::{Config, Connection, Frame, Parameters};
use proto::{Dir, Side, StreamId, VarInt};

#[derive(Arbitrary, Debug)]
struct StreamParams {
    side: Side,
    max_remote_uni: u16,
    max_remote_bi: u16,
    send_window: u16,
    receive_window: u16,
    stream_receive_window: u16,
    dir: Dir,
}

#[derive(Arbitrary, Debug)]
enum Operation {
    Open,
    Accept(Dir),
    Finish(StreamId),
    ReceivedStopSending(StreamId, VarInt),
    ReceivedReset {
        id: StreamId,
        error_code: VarInt,
        final_offset: VarInt,
    },
    Reset(StreamId),
    Decode(Vec<u8>),
}

fuzz_target!(|input: (StreamParams, Vec<Operation>)| {
    let (params, operations) = input;
    let mut connection = Connection::new(
        params.side,
        Config {
            max_remote_uni: params.max_remote_uni.into(),
            max_remote_bidi: params.max_remote_bi.into(),
            send_window: params.send_window.into(),
            receive_window: params.receive_window.into(),
            stream_receive_window: params.stream_receive_window.into(),
        },
    );
    connection.set_peer_parameters(Parameters {
        initial_max_data: params.receive_window.into(),
        initial_max_stream_data_bidi_local: params.stream_receive_window.into(),
        initial_max_stream_data_bidi_remote: params.stream_receive_window.into(),
        initial_max_stream_data_uni: params.stream_receive_window.into(),
        initial_max_streams_bidi: params.max_remote_bi.into(),
        initial_max_streams_uni: params.max_remote_uni.into(),
    });

    for operation in operations {
        match operation {
            Operation::Open => {
                connection.streams().open(params.dir);
            }
            Operation::Accept(dir) => {
                connection.streams().accept(dir);
            }
            Operation::Finish(id) => {
                let _ = connection.send_stream(id).finish();
            }
            Operation::ReceivedStopSending(sid, err_code) => {
                let _ = connection.received_frame(
                    Frame::StopSending {
                        id: sid,
                        error_code: err_code,
                    },
                    0,
                );
            }
            Operation::ReceivedReset {
                id,
                error_code,
                final_offset,
            } => {
                let _ = connection.received_frame(
                    Frame::Reset {
                        id,
                        error_code,
                        final_offset,
                    },
                    0,
                );
            }
            Operation::Reset(id) => {
                let _ = connection.send_stream(id).reset(0u32.into());
            }
            Operation::Decode(bytes) => {
                let allocation_size = bytes.len();
                let mut payload = Bytes::from(bytes);
                while !payload.is_empty() {
                    match proto::streams::wire::decode(&mut payload) {
                        Ok(proto::streams::wire::Frame::Stream(frame)) => {
                            let _ = connection.received_frame(frame, allocation_size);
                        }
                        Ok(proto::streams::wire::Frame::Other(_)) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
            }
        }
    }
});
