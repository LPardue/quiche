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

//! QMux demo client supporting HTTP/3 and HTTP/0.9.

use std::path::PathBuf;

use clap::Parser;
use clap::ValueEnum;
use octets::Octets;
use octets::OctetsMut;
use quiche::h3;
use quiche::h3::NameValue;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use url::Url;

use qmux_demo::connect_tls;
use qmux_demo::connect_tls_stream;
use qmux_demo::create_client_connector_with_alpn;
use qmux_demo::create_qmux_config;
use qmux_demo::setup_qlog;
use qmux_demo::QmuxOverTls;
use qmux_demo::H3_OVER_QMUX_ALPN;
use qmux_demo::HQ_INTEROP_QMUX_ALPN;

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

/// Receive and log any pending DATAGRAMs.
fn recv_dgrams(conn: &mut quiche::Connection) -> u64 {
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
        }
        count += 1;
    }
    count
}

#[derive(Clone, Copy, ValueEnum, Default)]
enum HttpVersion {
    #[default]
    H3,
    #[value(name = "0.9")]
    Http09,
}

/// HTTP client over QMux (TCP+TLS)
#[derive(Parser)]
#[command(name = "qmux-client")]
struct Args {
    /// URL to fetch
    url: Url,

    /// HTTP version to use
    #[arg(long, default_value = "h3")]
    http_version: HttpVersion,

    /// Don't verify server's TLS certificate
    #[arg(long)]
    no_verify: bool,

    /// Override the server address (host:port)
    #[arg(long, conflicts_with = "unix_socket")]
    connect_to: Option<String>,

    /// Connect via Unix socket instead of TCP
    #[arg(long, conflicts_with = "connect_to")]
    unix_socket: Option<PathBuf>,

    /// Custom CA certificate file (PEM)
    #[arg(long)]
    ca_cert: Option<String>,

    // Flow control options (same defaults as quiche-client)
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

    /// Number of requests to send in parallel
    #[arg(short = 'n', long, default_value = "1")]
    requests: usize,

    /// Send a QX_PING to measure RTT
    #[arg(long)]
    ping: bool,

    /// Number of DATAGRAMs to send
    #[arg(long, default_value = "0")]
    dgram_count: u64,

    /// Data to send in each DATAGRAM
    #[arg(long, default_value = "quack")]
    dgram_data: String,
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    let args = Args::parse();

    log::info!("Fetching {} over QMux", args.url);

    // Parse URL.
    let url = &args.url;
    let host = url.host_str().ok_or("missing host")?;
    let port = url.port().unwrap_or(443);
    let path = url.path();
    let path = if path.is_empty() { "/" } else { path };

    // Create TLS connector with appropriate ALPN.
    let alpn = match args.http_version {
        HttpVersion::H3 => H3_OVER_QMUX_ALPN,
        HttpVersion::Http09 => HQ_INTEROP_QMUX_ALPN,
    };
    let connector = create_client_connector_with_alpn(
        alpn,
        args.ca_cert.as_deref(),
        !args.no_verify,
    )?;

    // Connect via Unix socket or TCP based on args.
    if let Some(socket_path) = &args.unix_socket {
        log::info!(
            "Connecting to Unix socket {:?} (host: {})",
            socket_path,
            host
        );
        let unix_stream = tokio::net::UnixStream::connect(socket_path).await?;
        let tls_stream =
            connect_tls_stream(unix_stream, host, &connector).await?;
        log::info!("TLS handshake complete");
        run_client(QmuxOverTls::new(tls_stream), host, path, &args).await
    } else {
        let addr = args
            .connect_to
            .as_deref()
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{}:{}", host, port));
        log::info!("Connecting to {} (host: {})", addr, host);
        let tls_stream = connect_tls(&addr, host, &connector).await?;
        log::info!("TLS handshake complete");
        run_client(QmuxOverTls::new(tls_stream), host, path, &args).await
    }
}

/// Run the client after TLS connection is established.
async fn run_client<S>(
    mut qmux: QmuxOverTls<S>, host: &str, path: &str, args: &Args,
) -> std::result::Result<(), Box<dyn std::error::Error>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Create quiche config and connection.
    let mut config = create_qmux_config()?;
    config.set_initial_max_data(args.max_data);
    config.set_initial_max_stream_data_bidi_local(args.max_stream_data);
    config.set_initial_max_stream_data_bidi_remote(args.max_stream_data);
    config.set_initial_max_stream_data_uni(args.max_stream_data);
    config.set_initial_max_streams_bidi(args.max_streams_bidi);
    config.set_initial_max_streams_uni(args.max_streams_uni);
    config.set_max_idle_timeout(args.idle_timeout);
    if args.dgram_count > 0 {
        config.enable_dgram(true, 1000, 1000);
    }

    // Create client connection.
    // For QMux, the connection IDs and addresses are not meaningful.
    let scid = quiche::ConnectionId::from_ref(&[0u8; 16]);
    let local_addr: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();
    let peer_addr: std::net::SocketAddr = "127.0.0.1:443".parse().unwrap();
    let mut conn =
        quiche::connect(Some(host), &scid, local_addr, peer_addr, &mut config)?;

    // Set up qlog if QLOGDIR is set.
    setup_qlog(&mut conn, "client");

    // Send initial QMux transport parameters.
    qmux.flush(&mut conn).await?;

    // Wait for peer's transport params.
    while !conn.is_established() {
        if !qmux.drive(&mut conn).await? {
            return Err("connection closed during handshake".into());
        }
    }
    log::info!("QMux handshake complete");

    // Queue a QX_PING to measure RTT (if requested).
    if args.ping {
        conn.qmux_ping();
        log::info!("Queued QX_PING request");
    }

    match args.http_version {
        HttpVersion::H3 =>
            do_h3_requests(
                &mut qmux,
                &mut conn,
                host,
                path,
                args.requests,
                args.dgram_count,
                &args.dgram_data,
            )
            .await?,
        HttpVersion::Http09 =>
            do_http09_request(&mut qmux, &mut conn, path).await?,
    }

    // Print RTT if we got a ping response.
    if let Some(rtt) = conn.qmux_ping_rtt() {
        log::info!("QX_PING RTT: {:?}", rtt);
    }

    // Graceful close. Error::Done means already closed, which is fine.
    match conn.close(true, 0, b"done") {
        Ok(()) => {
            qmux.flush(&mut conn).await?;
        },
        Err(quiche::Error::Done) => {
            // Connection already closed by peer, nothing to do.
        },
        Err(e) => return Err(e.into()),
    }

    log::info!("Done");
    Ok(())
}

async fn do_h3_requests<S>(
    qmux: &mut QmuxOverTls<S>, conn: &mut quiche::Connection, host: &str,
    path: &str, num_requests: usize, dgram_count: u64, dgram_data: &str,
) -> std::result::Result<(), Box<dyn std::error::Error>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use std::collections::HashSet;

    // Create H3 connection.
    let h3_config = h3::Config::new()?;
    let mut h3_conn = h3::Connection::with_transport(conn, &h3_config)?;

    // Send all requests.
    let headers = vec![
        h3::Header::new(b":method", b"GET"),
        h3::Header::new(b":scheme", b"https"),
        h3::Header::new(b":authority", host.as_bytes()),
        h3::Header::new(b":path", path.as_bytes()),
        h3::Header::new(
            b"user-agent",
            b"lucas-qmux-break-rules-and-buy-me-sake/0.1",
        ),
    ];

    let mut pending_streams: HashSet<u64> = HashSet::new();

    for i in 0..num_requests {
        let stream_id = h3_conn.send_request(conn, &headers, true)?;
        pending_streams.insert(stream_id);
        log::info!(
            "Sent H3 request {}/{} on stream {}: GET {}",
            i + 1,
            num_requests,
            stream_id,
            path
        );
    }

    // Send DATAGRAMs if requested.
    let mut dgrams_sent = 0u64;
    for _ in 0..dgram_count {
        match send_h3_dgram(conn, 0, dgram_data.as_bytes()) {
            Ok(()) => dgrams_sent += 1,
            Err(e) => {
                log::error!("Failed to send DATAGRAM: {:?}", e);
                break;
            },
        }
    }
    if dgrams_sent > 0 {
        log::info!("Sent {} DATAGRAMs", dgrams_sent);
    }

    // Flush all requests and datagrams.
    qmux.flush(conn).await?;

    // Read responses.
    let recv_timeout = std::time::Duration::from_millis(100);

    while !pending_streams.is_empty() {
        // Process any buffered H3 events first.
        loop {
            match h3_conn.poll(conn) {
                Ok((sid, h3::Event::Headers { list, more_frames })) => {
                    log::info!(
                        "H3 Event: Headers on stream {} (more_frames={})",
                        sid,
                        more_frames
                    );
                    if pending_streams.contains(&sid) {
                        println!("[stream {}] Response headers:", sid);
                        for h in &list {
                            println!(
                                "  {}: {}",
                                String::from_utf8_lossy(h.name()),
                                String::from_utf8_lossy(h.value())
                            );
                        }
                    }
                },

                Ok((sid, h3::Event::Data)) => {
                    log::info!("H3 Event: Data on stream {}", sid);
                    if pending_streams.contains(&sid) {
                        let mut buf = [0u8; 4096];
                        let mut total = 0;
                        while let Ok(len) = h3_conn.recv_body(conn, sid, &mut buf)
                        {
                            total += len;
                        }
                        println!("[stream {}] Received {} bytes", sid, total);
                    }
                },

                Ok((sid, h3::Event::Finished)) => {
                    log::info!("H3 Event: Finished on stream {}", sid);
                    pending_streams.remove(&sid);
                    println!(
                        "[stream {}] Complete ({} remaining)",
                        sid,
                        pending_streams.len()
                    );
                },

                Ok((sid, h3::Event::Reset(err))) => {
                    log::info!(
                        "H3 Event: Reset on stream {} (error={})",
                        sid,
                        err
                    );
                    pending_streams.remove(&sid);
                },

                Ok((sid, h3::Event::PriorityUpdate)) => {
                    log::info!("H3 Event: PriorityUpdate on stream {}", sid);
                },

                Ok((_, h3::Event::GoAway)) => {
                    log::info!("H3 Event: GoAway");
                    pending_streams.clear();
                },

                Err(h3::Error::Done) => break,

                Err(e) => {
                    log::error!("H3 error: {:?}", e);
                    return Err(e.into());
                },
            }
        }

        // Process any received DATAGRAMs.
        recv_dgrams(conn);

        if pending_streams.is_empty() {
            break;
        }

        // Check if connection is closed.
        if conn.is_closed() {
            break;
        }

        // Read more data with timeout.
        match qmux.recv_timeout(conn, recv_timeout).await? {
            Some(true) => {
                // Data received, continue processing
            },
            Some(false) => {
                // TLS connection closed by peer
                log::info!("Connection closed by peer");
                break;
            },
            None => {
                // Timeout, check if quiche connection is closed
                if conn.is_closed() {
                    break;
                }
            },
        }
    }

    Ok(())
}

async fn do_http09_request<S>(
    qmux: &mut QmuxOverTls<S>, conn: &mut quiche::Connection, path: &str,
) -> std::result::Result<(), Box<dyn std::error::Error>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Send HTTP/0.9 request: "GET /path\r\n"
    let request = format!("GET {}\r\n", path);
    let stream_id = 0u64; // Client-initiated bidi stream

    conn.stream_send(stream_id, request.as_bytes(), true)?;
    log::info!(
        "Sent HTTP/0.9 request on stream {}: GET {}",
        stream_id,
        path
    );

    // Flush the request.
    qmux.flush(conn).await?;

    // Read response.
    let mut response_complete = false;
    let recv_timeout = std::time::Duration::from_millis(100);
    let mut buf = [0u8; 4096];

    while !response_complete {
        // Check for readable streams.
        for stream in conn.readable() {
            if stream == stream_id {
                loop {
                    match conn.stream_recv(stream_id, &mut buf) {
                        Ok((len, fin)) => {
                            log::info!(
                                "HTTP/0.9: Received {} bytes on stream {} (fin={})",
                                len,
                                stream_id,
                                fin
                            );
                            print!("{}", String::from_utf8_lossy(&buf[..len]));
                            if fin {
                                response_complete = true;
                                break;
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
        }

        if response_complete || conn.is_closed() {
            break;
        }

        // Read more data with timeout.
        match qmux.recv_timeout(conn, recv_timeout).await? {
            Some(true) => {
                // Data received, continue processing
            },
            Some(false) => {
                // TLS connection closed by peer
                log::info!("Connection closed by peer");
                break;
            },
            None => {
                // Timeout, check if quiche connection is closed
                if conn.is_closed() {
                    break;
                }
            },
        }
    }

    Ok(())
}
