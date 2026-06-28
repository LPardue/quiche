// Copyright (C) 2026, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! QMux demo server supporting HTTP/3 and HTTP/0.9.

use std::collections::HashMap;
use std::path;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use quiche::h3;
use quiche::h3::NameValue;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::net::TcpListener;
use tokio::net::UnixListener;
use tokio_boring::SslStream;

use octets::Octets;
use octets::OctetsMut;
use qmux_demo::accept_tls_stream;
use qmux_demo::create_qmux_config;
use qmux_demo::create_server_acceptor;
use qmux_demo::get_negotiated_protocol;
use qmux_demo::setup_qlog;
use qmux_demo::NegotiatedProtocol;
use qmux_demo::QmuxOverTls;
use qmux_demo::Result;

/// Prefix for stream-bytes endpoint.
const STREAM_BYTES_PREFIX: &str = "/stream-bytes/";

/// Send an HTTP/3 DATAGRAM with the given flow_id and content.
fn send_h3_dgram(
    conn: &mut quiche::Connection, flow_id: u64, dgram_content: &[u8],
) -> quiche::Result<()> {
    let len = octets::varint_len(flow_id) + dgram_content.len();
    let mut d = vec![0; len];
    let mut b = OctetsMut::with_slice(&mut d);

    b.put_varint(flow_id)
        .map_err(|_| quiche::Error::BufferTooShort)?;
    b.put_bytes(dgram_content)
        .map_err(|_| quiche::Error::BufferTooShort)?;

    conn.dgram_send(&d)
}

/// Receive DATAGRAMs and echo them back.
fn recv_and_echo_dgrams(conn: &mut quiche::Connection) -> u64 {
    let mut buf = [0u8; 65535];
    let mut count = 0u64;
    while let Ok(len) = conn.dgram_recv(&mut buf) {
        // Parse H3 DATAGRAM: flow_id (varint) + data
        let mut b = Octets::with_slice(&buf[..len]);
        if let Ok(flow_id) = b.get_varint() {
            let data = &buf[b.off()..len];
            log::info!(
                "Received DATAGRAM flow_id={} len={} data={:?}",
                flow_id,
                data.len(),
                String::from_utf8_lossy(data)
            );

            // Echo back with same flow_id.
            if let Err(e) = send_h3_dgram(conn, flow_id, data) {
                log::error!("Failed to echo DATAGRAM: {:?}", e);
            } else {
                log::info!(
                    "Echoed DATAGRAM flow_id={} len={}",
                    flow_id,
                    data.len()
                );
            }
        }
        count += 1;
    }
    count
}

/// Fill byte for stream-bytes responses.
const STREAM_BYTES_FILL: u8 = 0x57; // 'W'

/// HTTP server over QMux (TCP+TLS)
///
/// Supports both HTTP/3 (h3qx-01 ALPN) and HTTP/0.9 (hqx-01 ALPN).
/// The protocol is selected based on ALPN negotiation during TLS handshake.
#[derive(Parser, Clone)]
#[command(name = "qmux-server")]
struct Args {
    /// Address to listen on (TCP)
    #[arg(
        long,
        default_value = "127.0.0.1:4433",
        conflicts_with = "unix_socket"
    )]
    listen: String,

    /// Listen on Unix socket instead of TCP
    #[arg(long, conflicts_with = "listen")]
    unix_socket: Option<PathBuf>,

    /// TLS certificate file (PEM)
    #[arg(long, default_value = "quiche/examples/cert.crt")]
    cert: String,

    /// TLS private key file (PEM)
    #[arg(long, default_value = "quiche/examples/cert.key")]
    key: String,

    /// Root directory for serving files
    #[arg(long, default_value = ".")]
    root: String,

    /// Default index file name
    #[arg(long, default_value = "index.html")]
    index: String,

    // Flow control options (same defaults as quiche-server)
    /// Connection-wide flow control limit
    #[arg(long, default_value = "10000000")]
    max_data: u64,

    /// Per-stream flow control limit
    #[arg(long, default_value = "1000000")]
    max_stream_data: u64,

    /// Number of allowed concurrent bidirectional streams
    #[arg(long, default_value = "100")]
    max_streams_bidi: u64,

    /// Number of allowed concurrent unidirectional streams
    #[arg(long, default_value = "100")]
    max_streams_uni: u64,

    /// Idle timeout in milliseconds (0 = no timeout)
    #[arg(long, default_value = "30000")]
    idle_timeout: u64,

    /// Enable DATAGRAM support and echo received datagrams
    #[arg(long)]
    dgram_echo: bool,

    /// Max bytes per TLS write (0 = unlimited). Forces QMux records to span
    /// multiple TLS records for testing Wireshark desegmentation.
    #[arg(long, default_value = "0")]
    max_tls_write: usize,

    /// Max QMux record size in bytes (0 = default 16382). Controls how much
    /// frame data quiche packs into each QMux record.
    #[arg(long, default_value = "0")]
    max_record_size: u64,
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    let args = Args::parse();

    // Create TLS acceptor.
    let acceptor = Arc::new(create_server_acceptor(&args.cert, &args.key)?);

    if let Some(socket_path) = &args.unix_socket {
        log::info!(
            "Starting QMux server on Unix socket {:?} with cert={} key={} root={} index={}",
            socket_path,
            args.cert,
            args.key,
            args.root,
            args.index
        );

        // Remove existing socket file if it exists.
        let _ = std::fs::remove_file(socket_path);

        let listener = UnixListener::bind(socket_path)?;
        log::info!("Listening on {:?}", socket_path);

        loop {
            let (unix_stream, _peer_addr) = listener.accept().await?;
            log::info!("New Unix connection");

            let acceptor = acceptor.clone();
            let args = args.clone();

            tokio::spawn(async move {
                let result =
                    handle_connection(unix_stream, &acceptor, &args).await;
                if let Err(e) = result {
                    log::error!("Connection error: {}", e);
                }
                log::info!("Connection closed");
            });
        }
    } else {
        log::info!(
            "Starting QMux server on {} with cert={} key={} root={} index={}",
            args.listen,
            args.cert,
            args.key,
            args.root,
            args.index
        );

        let listener = TcpListener::bind(&args.listen).await?;
        log::info!("Listening on {}", args.listen);

        loop {
            let (tcp_stream, peer_addr) = listener.accept().await?;
            log::info!("New connection from {}", peer_addr);

            let acceptor = acceptor.clone();
            let args = args.clone();

            tokio::spawn(async move {
                let result =
                    handle_connection(tcp_stream, &acceptor, &args).await;
                if let Err(e) = result {
                    log::error!("Connection error from {}: {}", peer_addr, e);
                }
                log::info!("Connection closed: {}", peer_addr);
            });
        }
    }
}

/// Handle an incoming connection, dispatching based on negotiated ALPN.
async fn handle_connection<S>(
    stream: S, acceptor: &boring::ssl::SslAcceptor, args: &Args,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // TLS handshake.
    let tls_stream = accept_tls_stream(stream, acceptor).await?;
    log::info!("TLS handshake complete");

    // Dispatch based on negotiated ALPN.
    let protocol = get_negotiated_protocol(&tls_stream);
    match protocol {
        Some(NegotiatedProtocol::H3) => {
            log::info!("Negotiated protocol: HTTP/3 (h3qx-01)");
            handle_h3_connection(tls_stream, args).await
        },
        Some(NegotiatedProtocol::HqInterop) => {
            log::info!("Negotiated protocol: HTTP/0.9 (hqx-01)");
            handle_http09_connection(tls_stream, args).await
        },
        None => {
            log::error!("No supported ALPN negotiated");
            Err(qmux_demo::Error::AlpnMismatch)
        },
    }
}

/// Build response body for a given path.
///
/// Handles:
/// - `/stream-bytes/<n>` - returns n bytes of fill data
/// - File paths - reads from root directory
fn build_response(path: &str, root: &str, index: &str) -> (u16, Vec<u8>) {
    // Handle stream-bytes endpoint.
    if let Some(suffix) = path.strip_prefix(STREAM_BYTES_PREFIX) {
        let n = suffix.parse::<usize>().unwrap_or(0);
        log::info!("stream-bytes request for {} bytes", n);
        return (200, vec![STREAM_BYTES_FILL; n]);
    }

    // Build file path from URL path.
    let uri = path::Path::new(path);
    let mut file_path = path::PathBuf::from(root);

    for c in uri.components() {
        if let path::Component::Normal(v) = c {
            file_path.push(v);
        }
    }

    // Auto-index: if path is a directory, append index file.
    file_path = autoindex(file_path, index);

    log::info!("Serving file: {:?}", file_path);

    match std::fs::read(&file_path) {
        Ok(data) => (200, data),
        Err(_) => (404, b"Not Found!\r\n".to_vec()),
    }
}

/// If path is a directory, append the index file name.
fn autoindex(path: path::PathBuf, index: &str) -> path::PathBuf {
    if path.is_dir() {
        path.join(index)
    } else {
        path
    }
}

/// Create a quiche config with the given args.
fn create_config(
    args: &Args,
) -> std::result::Result<quiche::Config, quiche::Error> {
    let mut config = create_qmux_config()?;

    // Apply flow control settings from args.
    config.set_initial_max_data(args.max_data);
    config.set_initial_max_stream_data_bidi_local(args.max_stream_data);
    config.set_initial_max_stream_data_bidi_remote(args.max_stream_data);
    config.set_initial_max_stream_data_uni(args.max_stream_data);
    config.set_initial_max_streams_bidi(args.max_streams_bidi);
    config.set_initial_max_streams_uni(args.max_streams_uni);
    config.set_max_idle_timeout(args.idle_timeout);

    // Max QMux record size.
    if args.max_record_size > 0 {
        config.set_qmux_max_record_size(args.max_record_size);
        log::info!("Max QMux record size: {} bytes", args.max_record_size);
    }

    // Enable datagrams if echo mode is enabled.
    if args.dgram_echo {
        config.enable_dgram(true, 1000, 1000);
    }

    Ok(config)
}

async fn handle_h3_connection<S>(
    tls_stream: SslStream<S>, args: &Args,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Create QMux over TLS.
    let mut qmux = QmuxOverTls::new(tls_stream);
    if args.max_tls_write > 0 {
        qmux.set_max_tls_write(args.max_tls_write);
    }

    // Create quiche config and connection.
    let mut config = create_config(args)?;

    // Create server connection using accept().
    let scid = quiche::ConnectionId::from_ref(&[0u8; 16]);
    let local_addr: std::net::SocketAddr = "127.0.0.1:4433".parse().unwrap();
    let peer_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();

    let mut conn =
        quiche::accept(&scid, None, local_addr, peer_addr, &mut config)?;

    // Set up qlog if QLOGDIR is set.
    setup_qlog(&mut conn, "server");

    // Send initial QMux transport parameters.
    qmux.flush(&mut conn).await?;

    // Wait for peer's transport params.
    while !conn.is_established() {
        if !qmux.drive(&mut conn).await? {
            return Err(qmux_demo::Error::ConnectionClosed);
        }
    }
    log::info!("QMux handshake complete");

    // Create H3 connection.
    let h3_config = h3::Config::new()?;
    let mut h3_conn = h3::Connection::with_transport(&mut conn, &h3_config)?;

    // Track pending requests (stream_id -> headers).
    let mut pending_requests: HashMap<u64, Vec<h3::Header>> = HashMap::new();

    // Main event loop.
    loop {
        // Send any pending data.
        qmux.flush(&mut conn).await?;

        // Process H3 events.
        loop {
            match h3_conn.poll(&mut conn) {
                Ok((stream_id, h3::Event::Headers { list, more_frames })) => {
                    log::info!(
                        "H3 Event: Headers on stream {}: {:?} (more_frames={})",
                        stream_id,
                        format_headers(&list),
                        more_frames
                    );

                    // Store headers, wait for Finished to send response.
                    pending_requests.insert(stream_id, list);
                },

                Ok((stream_id, h3::Event::Data)) => {
                    log::info!("H3 Event: Data on stream {}", stream_id);
                    // Drain request body.
                    let mut buf = [0u8; 4096];
                    while let Ok(len) =
                        h3_conn.recv_body(&mut conn, stream_id, &mut buf)
                    {
                        log::debug!(
                            "Received {} bytes of body on stream {}",
                            len,
                            stream_id
                        );
                    }
                },

                Ok((stream_id, h3::Event::Finished)) => {
                    log::info!("H3 Event: Finished on stream {}", stream_id);

                    // Send response now that request is complete.
                    if let Some(headers) = pending_requests.remove(&stream_id) {
                        send_h3_response(
                            &mut h3_conn,
                            &mut conn,
                            stream_id,
                            &headers,
                            args,
                        )?;
                    }
                },

                Ok((stream_id, h3::Event::Reset(err))) => {
                    log::info!(
                        "H3 Event: Reset on stream {} (error={})",
                        stream_id,
                        err
                    );
                    pending_requests.remove(&stream_id);
                },

                Ok((stream_id, h3::Event::PriorityUpdate)) => {
                    log::info!(
                        "H3 Event: PriorityUpdate on stream {}",
                        stream_id
                    );
                },

                Ok((_, h3::Event::GoAway)) => {
                    log::info!("H3 Event: GoAway");
                    break;
                },

                Err(h3::Error::Done) => break,

                Err(e) => {
                    log::error!("H3 error: {:?}", e);
                    return Err(e.into());
                },
            }
        }

        // Process any received DATAGRAMs (echo them back if enabled).
        if args.dgram_echo {
            recv_and_echo_dgrams(&mut conn);
        }

        // Flush any responses we just generated.
        qmux.flush(&mut conn).await?;

        // Check if connection is closed.
        if conn.is_closed() {
            log::info!("Connection closed");
            break;
        }

        // Read more data from the qmux.
        if !qmux.recv(&mut conn).await? {
            log::info!("Peer closed connection");
            break;
        }
    }

    Ok(())
}

async fn handle_http09_connection<S>(
    tls_stream: SslStream<S>, args: &Args,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Create QMux over TLS.
    let mut qmux = QmuxOverTls::new(tls_stream);
    if args.max_tls_write > 0 {
        qmux.set_max_tls_write(args.max_tls_write);
    }

    // Create quiche config and connection.
    let mut config = create_config(args)?;

    // Create server connection using accept().
    let scid = quiche::ConnectionId::from_ref(&[0u8; 16]);
    let local_addr: std::net::SocketAddr = "127.0.0.1:4433".parse().unwrap();
    let peer_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();

    let mut conn =
        quiche::accept(&scid, None, local_addr, peer_addr, &mut config)?;

    // Set up qlog if QLOGDIR is set.
    setup_qlog(&mut conn, "server");

    // Send initial QMux transport parameters.
    qmux.flush(&mut conn).await?;

    // Wait for peer's transport params.
    while !conn.is_established() {
        if !qmux.drive(&mut conn).await? {
            return Err(qmux_demo::Error::ConnectionClosed);
        }
    }
    log::info!("QMux handshake complete");

    // Track partial requests (stream_id -> accumulated bytes).
    let mut partial_requests: HashMap<u64, Vec<u8>> = HashMap::new();
    let mut buf = [0u8; 4096];

    // Main event loop.
    loop {
        // Send any pending data.
        qmux.flush(&mut conn).await?;

        // Process readable streams.
        for stream_id in conn.readable().collect::<Vec<_>>() {
            loop {
                match conn.stream_recv(stream_id, &mut buf) {
                    Ok((len, fin)) => {
                        log::info!(
                            "HTTP/0.9: Received {} bytes on stream {} (fin={})",
                            len,
                            stream_id,
                            fin
                        );

                        // Accumulate request data.
                        let request_buf = partial_requests
                            .entry(stream_id)
                            .or_insert_with(Vec::new);
                        request_buf.extend_from_slice(&buf[..len]);

                        // Check if request is complete (ends with \r\n).
                        if request_buf.ends_with(b"\r\n") || fin {
                            if let Some(request) =
                                partial_requests.remove(&stream_id)
                            {
                                handle_http09_request(
                                    &mut conn, stream_id, &request, args,
                                )?;
                            }
                        }
                    },
                    Err(quiche::Error::Done) => break,
                    Err(e) => {
                        log::error!("Stream recv error: {:?}", e);
                        return Err(e.into());
                    },
                }
            }
        }

        // Flush any responses we just generated.
        qmux.flush(&mut conn).await?;

        // Check if connection is closed.
        if conn.is_closed() {
            log::info!("Connection closed");
            break;
        }

        // Read more data from the qmux.
        if !qmux.recv(&mut conn).await? {
            log::info!("Peer closed connection");
            break;
        }
    }

    Ok(())
}

fn handle_http09_request(
    conn: &mut quiche::Connection, stream_id: u64, request: &[u8], args: &Args,
) -> Result<()> {
    let request_str = String::from_utf8_lossy(request);
    log::info!(
        "HTTP/0.9 request on stream {}: {:?}",
        stream_id,
        request_str.trim()
    );

    // Parse "GET /path\r\n"
    let path = if request_str.starts_with("GET ") {
        request_str[4..].trim().to_string()
    } else {
        "/".to_string()
    };

    // Build response.
    let (_status, body) = build_response(&path, &args.root, &args.index);

    // Send response body directly (no headers in HTTP/0.9).
    conn.stream_send(stream_id, &body, true)?;

    log::info!(
        "Sent HTTP/0.9 response on stream {}: {} bytes",
        stream_id,
        body.len()
    );

    Ok(())
}

fn send_h3_response(
    h3_conn: &mut h3::Connection, conn: &mut quiche::Connection, stream_id: u64,
    request_headers: &[h3::Header], args: &Args,
) -> Result<()> {
    // Extract path from request.
    let path = request_headers
        .iter()
        .find(|h| h.name() == b":path")
        .map(|h| String::from_utf8_lossy(h.value()).to_string())
        .unwrap_or_else(|| "/".to_string());

    // Build response.
    let (status, body) = build_response(&path, &args.root, &args.index);

    // Send response headers (same as quiche-server: status, server,
    // content-length).
    let headers = vec![
        h3::Header::new(b":status", status.to_string().as_bytes()),
        h3::Header::new(b"server", b"qmux-demo"),
        h3::Header::new(b"content-length", body.len().to_string().as_bytes()),
    ];

    h3_conn.send_response(conn, stream_id, &headers, false)?;

    // Send response body.
    h3_conn.send_body(conn, stream_id, &body, true)?;

    log::info!(
        "Sent H3 response on stream {}: {} {} bytes",
        stream_id,
        status,
        body.len()
    );

    Ok(())
}

fn format_headers(headers: &[h3::Header]) -> String {
    headers
        .iter()
        .map(|h| {
            format!(
                "{}={}",
                String::from_utf8_lossy(h.name()),
                String::from_utf8_lossy(h.value())
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}
