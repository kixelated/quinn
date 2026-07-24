//! QMux echo demo over plain TCP on localhost
//!
//! Runs a server and a client in one process. The server uppercases whatever each stream
//! sends; the client opens a few streams and a datagram and prints the results.
//!
//! In a real deployment the `TcpStream` would be wrapped in TLS (e.g. tokio-rustls) with
//! an ALPN identifier distinct from the QUIC mapping of the same protocol.

use bytes::Bytes;
use quinn_qmux::{Config, Session, VarInt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("tcp accept");
        stream.set_nodelay(true).expect("nodelay");
        let session = Session::accept(stream, Config::default())
            .await
            .expect("qmux accept");
        loop {
            let (mut send, mut recv) = match session.accept_bi().await {
                Ok(pair) => pair,
                Err(_) => break, // client closed
            };
            tokio::spawn(async move {
                let data = recv.read_to_end(1 << 20).await.expect("read");
                send.write_all(&data.to_ascii_uppercase())
                    .await
                    .expect("write");
                send.finish().expect("finish");
            });
        }
    });

    let stream = TcpStream::connect(addr).await?;
    stream.set_nodelay(true)?;
    let session = Session::connect(stream, Config::default()).await?;

    for message in ["hello", "qmux over tcp", "goodbye"] {
        let (mut send, mut recv) = session.open_bi().await?;
        send.write_all(message.as_bytes()).await?;
        send.finish()?;
        let reply = recv.read_to_end(1 << 20).await?;
        println!("{message} -> {}", String::from_utf8_lossy(&reply));
    }

    session.close(VarInt::from_u32(0), Bytes::from_static(b"done"));
    server.await?;
    Ok(())
}
