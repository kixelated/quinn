//! End-to-end tests over an in-memory duplex transport

use bytes::Bytes;
use quinn_qmux::{Config, ConnectionError, ReadError, Session, VarInt, WriteError};

async fn pair(client: Config, server: Config) -> (Session, Session) {
    // A small duplex buffer forces transport-level backpressure
    let (a, b) = tokio::io::duplex(2048);
    let (client, server) = tokio::join!(Session::connect(a, client), Session::accept(b, server));
    (client.expect("connect"), server.expect("accept"))
}

#[tokio::test]
async fn echo() {
    let (client, server) = pair(Config::default(), Config::default()).await;

    let ((), outcome) = tokio::join!(
        async {
            let (mut send, mut recv) = client.open_bi().await.expect("open_bi");
            send.write_all(b"hello over qmux").await.expect("write");
            send.finish().expect("finish");
            let reply = recv.read_to_end(1024).await.expect("read reply");
            assert_eq!(reply, b"HELLO OVER QMUX".to_vec());
        },
        async {
            let (mut send, mut recv) = server.accept_bi().await.expect("accept_bi");
            let data = recv.read_to_end(1024).await.expect("read");
            send.write_all(&data.to_ascii_uppercase()).await.expect("write");
            send.finish().expect("finish");
        },
    );
    outcome
}

#[tokio::test]
async fn large_uni_transfer_with_backpressure() {
    // Windows much smaller than the payload, so MAX_DATA/MAX_STREAM_DATA must flow the
    // other way while data is in flight
    let mut config = Config::default();
    config
        .receive_window(VarInt::from_u32(64 * 1024))
        .stream_receive_window(VarInt::from_u32(32 * 1024))
        .send_window(16 * 1024);
    let (client, server) = pair(config.clone(), config).await;

    let payload: Vec<u8> = (0..1_000_000).map(|i| (i % 241) as u8).collect();
    let expected = payload.clone();

    let (send_result, received) = tokio::join!(
        async {
            let mut send = client.open_uni().await.expect("open_uni");
            send.write_all(&payload).await.expect("write_all");
            send.finish().expect("finish");
            // Keep the handles alive until the peer has read everything
            client.closed().await
        },
        async {
            let mut recv = server.accept_uni().await.expect("accept_uni");
            let data = recv.read_to_end(2_000_000).await.expect("read_to_end");
            server.close(VarInt::from_u32(0), Bytes::from_static(b"done"));
            data
        },
    );
    assert_eq!(received.len(), expected.len());
    assert_eq!(received, expected);
    assert!(matches!(
        send_result,
        ConnectionError::ApplicationClosed { .. }
    ));
}

#[tokio::test]
async fn datagrams() {
    let (client, server) = pair(Config::default(), Config::default()).await;
    client
        .send_datagram(Bytes::from_static(b"unreliable but reliable"))
        .expect("send_datagram");
    let received = server.recv_datagram().await.expect("recv_datagram");
    assert_eq!(received, Bytes::from_static(b"unreliable but reliable"));
}

#[tokio::test]
async fn close_reaches_peer() {
    let (client, server) = pair(Config::default(), Config::default()).await;
    client.close(VarInt::from_u32(7), Bytes::from_static(b"goodbye"));
    match server.closed().await {
        ConnectionError::ApplicationClosed { error_code, reason } => {
            assert_eq!(error_code, VarInt::from_u32(7));
            assert_eq!(reason.as_ref(), b"goodbye");
        }
        other => panic!("unexpected close reason: {other:?}"),
    }
}

#[tokio::test]
async fn drop_closes() {
    let (client, server) = pair(Config::default(), Config::default()).await;
    drop(client);
    assert!(matches!(
        server.closed().await,
        ConnectionError::ApplicationClosed { error_code, .. } if error_code == VarInt::from_u32(0)
    ));
}

#[tokio::test]
async fn stop_surfaces_to_writer() {
    let (client, server) = pair(Config::default(), Config::default()).await;

    let mut send = client.open_uni().await.expect("open_uni");
    send.write_all(b"start").await.expect("write");
    let mut recv = server.accept_uni().await.expect("accept_uni");
    recv.stop(VarInt::from_u32(9)).expect("stop");

    // The writer eventually observes STOP_SENDING as an error
    let error = loop {
        match send.write(&[0; 1024]).await {
            Ok(_) => tokio::task::yield_now().await,
            Err(e) => break e,
        }
    };
    assert_eq!(error, WriteError::Stopped(VarInt::from_u32(9)));
}

#[tokio::test]
async fn reset_surfaces_to_reader() {
    let (client, server) = pair(Config::default(), Config::default()).await;

    let mut send = client.open_uni().await.expect("open_uni");
    send.write_all(b"partial").await.expect("write");
    let mut recv = server.accept_uni().await.expect("accept_uni");
    send.reset(VarInt::from_u32(11)).expect("reset");

    let error = loop {
        match recv.read_chunk(1024).await {
            Ok(Some(_)) => {}
            Ok(None) => panic!("stream finished cleanly despite reset"),
            Err(e) => break e,
        }
    };
    assert_eq!(error, ReadError::Reset(VarInt::from_u32(11)));
}

#[tokio::test]
async fn many_concurrent_streams() {
    let (client, server) = pair(Config::default(), Config::default()).await;

    let server_task = tokio::spawn(async move {
        for _ in 0..50 {
            let (mut send, mut recv) = server.accept_bi().await.expect("accept_bi");
            tokio::spawn(async move {
                let data = recv.read_to_end(4096).await.expect("read");
                send.write_all(&data).await.expect("write");
                send.finish().expect("finish");
            });
        }
        // Keep the session alive until the client is done with it
        server.closed().await
    });

    let mut tasks = Vec::new();
    for i in 0..50u32 {
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            let (mut send, mut recv) = client.open_bi().await.expect("open_bi");
            let msg = format!("stream number {i}");
            send.write_all(msg.as_bytes()).await.expect("write");
            send.finish().expect("finish");
            let echo = recv.read_to_end(4096).await.expect("read");
            assert_eq!(echo, msg.as_bytes());
        }));
    }
    for task in tasks {
        task.await.expect("client stream task");
    }
    drop(client);
    server_task.await.expect("server task");
}
