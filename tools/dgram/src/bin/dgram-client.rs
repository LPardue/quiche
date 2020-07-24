// Copyright (C) 2019, Cloudflare, Inc.
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

#[macro_use]
extern crate log;

use std::net::ToSocketAddrs;

use ring::rand::*;

const MAX_DATAGRAM_SIZE: usize = 1350;

const SIDUCK_ALPN: &[u8] = b"\x06siduck\x09siduck-00";
const QUICTRANSPORT_ALPN: &[u8] = b"\x09wq-vvv-01";

struct ApplicationParameters {
    proto: &'static [u8],
    initial_max_streams_bidi: u64,
    initial_max_streams_uni: u64,
}

const USAGE: &str = "Usage:
  dgram-client [options] URL
  dgram-client -h | --help

Options:
  --max-data BYTES         Connection-wide flow control limit [default: 10000000].
  --max-stream-data BYTES  Per-stream flow control limit [default: 1000000].
  --wire-version VERSION   The version number to send to the server [default: babababa].
  --no-verify              Don't verify server's certificate.
  --no-grease              Don't send GREASE.
  --max-dgram-frame BYTES  Maximum DATAGRAM frame size [default: 500].
  -a --app-proto PROTO     Application protocol (siduck, h3, wq-vvv) on which to send DATAGRAM [default: siduck]
  -d --data DATA           The DATAGRAM frame data [default: quack].
  -n --datagrams DGRAMS    Send the given number of identical DATAGRAM frames [default: 1].
  -h --help                Show this screen.
";

fn main() {
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];
    let mut dgram_buf = [0; 65535];

    env_logger::builder()
        .default_format_timestamp_nanos(true)
        .init();

    let args = docopt::Docopt::new(USAGE)
        .and_then(|dopt| dopt.parse())
        .unwrap_or_else(|e| e.exit());

    let max_data = args.get_str("--max-data");
    let max_data = u64::from_str_radix(max_data, 10).unwrap();

    let max_stream_data = args.get_str("--max-stream-data");
    let max_stream_data = u64::from_str_radix(max_stream_data, 10).unwrap();

    let version = args.get_str("--wire-version");
    let version = u32::from_str_radix(version, 16).unwrap();

    let url = url::Url::parse(args.get_str("URL")).unwrap();

    let mut app_proto = args.get_str("--app-proto");

    if url.scheme() == "quic-transport" && app_proto != "wq-vvv" {
        warn!("\"quic-transport\" scheme provided with incompatible ALPN, correcting the ALPN");

        app_proto = "wq-vvv";
    }

    let app_params = match app_proto {
        "siduck" => ApplicationParameters {
            proto: SIDUCK_ALPN,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
        },

        "h3" => ApplicationParameters {
            proto: quiche::h3::APPLICATION_PROTOCOL,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 3,
        },

        "wq-vvv" => ApplicationParameters {
            proto: QUICTRANSPORT_ALPN,
            initial_max_streams_bidi: 10,
            initial_max_streams_uni: 10,
        },

        _ => panic!("Application protocol \"{}\" not supported", app_proto),
    };

    let dgram_data = args.get_str("--data");

    let dgrams_count = args.get_str("--datagrams");
    let dgrams_count = u64::from_str_radix(dgrams_count, 10).unwrap();

    let mut dgram_echoes = 0;
    let mut dgrams_complete = false;

    let honk_count = 2;
    let mut honk_echoes = 0;
    let mut honks_sent = false;
    let mut honks_complete = false;

    // Setup the event loop.
    let poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Resolve server address.
    let peer_addr = url.to_socket_addrs().unwrap().next().unwrap();

    // Bind to INADDR_ANY or IN6ADDR_ANY depending on the IP family of the
    // server address. This is needed on macOS and BSD variants that don't
    // support binding to IN6ADDR_ANY for both v4 and v6.
    let bind_addr = match peer_addr {
        std::net::SocketAddr::V4(_) => "0.0.0.0:0",
        std::net::SocketAddr::V6(_) => "[::]:0",
    };

    // Create the UDP socket backing the QUIC connection, and register it with
    // the event loop.
    let socket = std::net::UdpSocket::bind(bind_addr).unwrap();
    socket.connect(peer_addr).unwrap();

    let socket = mio::net::UdpSocket::from_socket(socket).unwrap();
    poll.register(
        &socket,
        mio::Token(0),
        mio::Ready::readable(),
        mio::PollOpt::edge(),
    )
    .unwrap();

    // Create the configuration for the QUIC connection.
    let mut config = quiche::Config::new(version).unwrap();

    config.verify_peer(true);

    config.set_application_protos(app_params.proto).unwrap();

    config.set_max_idle_timeout(5000);
    config.set_max_udp_payload_size(MAX_DATAGRAM_SIZE as u64);
    config.set_initial_max_data(max_data);
    config.set_initial_max_stream_data_bidi_local(max_stream_data);
    config.set_initial_max_stream_data_bidi_remote(max_stream_data);
    config.set_initial_max_stream_data_uni(max_stream_data);
    config.set_initial_max_streams_bidi(app_params.initial_max_streams_bidi);
    config.set_initial_max_streams_uni(app_params.initial_max_streams_uni);
    config.set_disable_active_migration(true);
    config.set_dgram_frames_supported(true);

    let mut http3_conn = None;
    let mut quictransport_conn: Option<()> = None;

    if args.get_bool("--no-verify") {
        config.verify_peer(false);
    }

    if args.get_bool("--no-grease") {
        config.grease(false);
    }

    let mut keylog = None;
    if let Some(keylog_path) = std::env::var_os("SSLKEYLOGFILE") {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(keylog_path)
            .unwrap();

        keylog = Some(file);

        config.log_keys();
    }

    // Generate a random source connection ID for the connection.
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    SystemRandom::new().fill(&mut scid[..]).unwrap();

    // Create a QUIC connection and initiate handshake.
    let mut conn = quiche::connect(url.domain(), &scid, &mut config).unwrap();

    info!(
        "connecting to {:} from {:} with scid {}",
        peer_addr,
        socket.local_addr().unwrap(),
        hex_dump(&scid)
    );

    if let Some(keylog) = &mut keylog {
        if let Ok(keylog) = keylog.try_clone() {
            conn.set_keylog(Box::new(keylog));
        }
    }

    let write = conn.send(&mut out).expect("initial send failed");

    while let Err(e) = socket.send(&out[..write]) {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            trace!("send() would block");
            continue;
        }

        panic!("send() failed: {:?}", e);
    }

    trace!("written {}", write);

    let h3_config = quiche::h3::Config::new().unwrap();

    let mut dgrams_sent = 0;

    let dgram_start = std::time::Instant::now();

    loop {
        poll.poll(&mut events, conn.timeout()).unwrap();

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'read: loop {
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if events.is_empty() {
                trace!("timed out");

                conn.on_timeout();

                break 'read;
            }

            let len = match socket.recv(&mut buf) {
                Ok(v) => v,

                Err(e) => {
                    // There are no more UDP packets to read, so end the read
                    // loop.
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        trace!("recv() would block");
                        break 'read;
                    }

                    panic!("recv() failed: {:?}", e);
                },
            };

            trace!("got {} bytes", len);

            // Process potentially coalesced packets.
            let read = match conn.recv(&mut buf[..len]) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    trace!("done reading");
                    break;
                },

                Err(e) => {
                    error!("recv failed: {:?}", e);
                    break 'read;
                },
            };

            trace!("processed {} bytes", read);

            // If we negotiated SiDUCK, once the QUIC connection is established
            // try to read DATAGRAMs.
            if app_params.proto == SIDUCK_ALPN && conn.is_established() {
                match conn.dgram_recv(&mut dgram_buf) {
                    Ok(len) => {
                        let data = unsafe {
                            std::str::from_utf8_unchecked(&dgram_buf[..len])
                        };

                        info!("Received DATAGRAM data {:?}", data);
                        dgram_echoes += 1;

                        debug!(
                            "{}/{} dgrams received",
                            dgram_echoes, dgrams_count
                        );

                        if dgram_echoes == dgrams_count {
                            info!(
                                "{}/{} dgrams(s) received in {:?}, closing...",
                                dgram_echoes,
                                dgrams_count,
                                dgram_start.elapsed()
                            );

                            match conn.close(true, 0x00, b"kthxbye") {
                                // Already closed.
                                Ok(_) | Err(quiche::Error::Done) => (),

                                Err(e) => panic!("error closing conn: {:?}", e),
                            }

                            break;
                        }
                    },

                    Err(quiche::Error::Done) => break,

                    Err(e) => {
                        error!("failure receiving DATAGRAM failure {:?}", e);

                        break 'read;
                    },
                }
            }

            // If we negotiated WebTransport, once the QUIC connection is
            // established try to read DATAGRAMs.
            if let Some(_) = &mut quictransport_conn {


                for s in conn.readable() {
                    while let Ok((read, fin)) = conn.stream_recv(s, &mut buf) {
                        debug!("{} received {} bytes", conn.trace_id(), read);

                        let stream_buf = &buf[..read];

                        debug!(
                            "stream {} has {} bytes (fin? {})",
                            s,
                            stream_buf.len(),
                            fin
                        );

                        // TODO: store all received data and only check when fin'd
                        unsafe {
                            let echoed_len: usize =
                                std::str::from_utf8_unchecked(&stream_buf)
                                    .parse()
                                    .unwrap();

                            if echoed_len == b"HONK".len() {
                                honk_echoes += 1;

                                if honk_echoes == honk_count {
                                    honks_complete = true;
                                }
                            }
                        };

                        if fin {
                            info!("stream {} closed", s);
                        }
                    }
                }

                match conn.dgram_recv(&mut dgram_buf) {
                    Ok(len) => {
                        let data = unsafe {
                            std::str::from_utf8_unchecked(&dgram_buf[..len])
                        };

                        info!("Received DATAGRAM data {:?}", data);
                        dgram_echoes += 1;

                        debug!(
                            "{}/{} dgrams received",
                            dgram_echoes, dgrams_count
                        );

                        if dgram_echoes == dgrams_count {
                            info!(
                                "{}/{} dgrams(s) received in {:?}",
                                dgram_echoes,
                                dgrams_count,
                                dgram_start.elapsed()
                            );

                            dgrams_complete = true;

                        }
                    },

                    Err(quiche::Error::Done) => (),

                    Err(e) => {
                        error!("failure receiving DATAGRAM failure {:?}", e);

                        break 'read;
                    },
                }

                if honks_complete && dgrams_complete {
                    info!("All datagram and stream data was echoed, closing...");
                    match conn.close(true, 0x00, b"kthxbye") {
                        // Already closed.
                        Ok(_) | Err(quiche::Error::Done) => (),

                        Err(e) => panic!("error closing conn: {:?}", e),
                    }

                    break 'read;
                }
            }
        }

        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());

            if dgram_echoes != dgrams_count {
                error!("connection timed out after {:?} and only completed {}/{} requests",
                       dgram_start.elapsed(), dgram_echoes, dgrams_count);
            }

            break;
        }

        // If we negotiated SiDuck, once the QUIC connection is established send
        // QUIC DATAGRAMs until all have been sent.
        if app_params.proto == SIDUCK_ALPN && conn.is_established() {
            let mut dgrams_done = 0;

            for _ in dgrams_sent..dgrams_count {
                info!("sending QUIC DATAGRAM with data {:?}", dgram_data);

                match conn.dgram_send(dgram_data.as_bytes()) {
                    Ok(v) => v,

                    Err(e) => {
                        error!("failed to send dgram {:?}", e);

                        break;
                    },
                }

                dgrams_done += 1;
            }

            dgrams_sent += dgrams_done;
        }

        // If we negotiated HTTP/3, once the QUIC connection is established
        // create a new HTTP/3 connection.
        if app_params.proto == quiche::h3::APPLICATION_PROTOCOL &&
            conn.is_established() &&
            http3_conn.is_none()
        {
            http3_conn = Some(
                quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                    .unwrap(),
            );
        }

        // Once the HTTP/3 connection is established, send HTTP/3 DATAGRAMs until
        // all have been sent.
        if let Some(h3_conn) = &mut http3_conn {
            let mut dgrams_done = 0;

            for _ in dgrams_sent..dgrams_count {
                info!("sending HTTP/3 DATAGRAM with data {:?}", dgram_data);

                match h3_conn.dgram_send(&mut conn, 0, dgram_data.as_bytes()) {
                    Ok(v) => v,

                    Err(e) => {
                        error!("failed to send dgram {:?}", e);
                        break;
                    },
                }

                dgrams_done += 1;
            }

            dgrams_sent += dgrams_done;
        }

        // If we negotiated QuicTransport, once the QUIC connection is established
        // send the QuicTransport client indication and send datagrams.
        if app_params.proto == QUICTRANSPORT_ALPN &&
            conn.is_established() &&
            quictransport_conn.is_none()
        {
            let mut path = String::from(url.path());

            if let Some(query) = url.query() {
                path.push('?');
                path.push_str(query);
            }

            let mut d: Vec<u8> = Vec::new();

            // Origin Field
            let field_id: u16 = 0;
            d.extend_from_slice(&field_id.to_be_bytes());

            let origin = &url[..url::Position::BeforePath];
            d.extend_from_slice(&(origin.len() as u16).to_be_bytes());
            d.extend_from_slice(origin.as_bytes());

            // Path Field
            let field_id: u16 = 1;
            d.extend_from_slice(&field_id.to_be_bytes());
            let path = &url[url::Position::BeforePath..];
            d.extend_from_slice(&(path.len() as u16).to_be_bytes());
            d.extend_from_slice(path.as_bytes());

            trace!("sending client indication {:?}...", d);

            conn.stream_send(2, &d, true).ok();

            quictransport_conn = Some(());
        }

        // Once the QuicTransport connection is established, send all QUIC
        // datagrams until all have been sent.
        if let Some(_) = &mut quictransport_conn {
            if !honks_sent {
                debug!("Sending honks on stream 0 and 6");
                conn.stream_send(0, b"HONK", true).unwrap();
                conn.stream_send(6, b"HONK", true).unwrap();

                honks_sent = true;
            }

            let mut dgrams_done = 0;

            for _ in dgrams_sent..dgrams_count {
                info!(
                    "sending QuicTransport DATAGRAM with data {:?}",
                    dgram_data
                );

                match conn.dgram_send(dgram_data.as_bytes()) {
                    Ok(v) => v,

                    Err(e) => {
                        error!("failed to send dgram {:?}", e);
                        break;
                    },
                }

                dgrams_done += 1;
            }

            dgrams_sent += dgrams_done;
        }

        if let Some(http3_conn) = &mut http3_conn {
            // Process HTTP/3 events.
            loop {
                match http3_conn.poll_dgram(&mut conn, &mut dgram_buf) {
                    Ok((flow_id, quiche::h3::DatagramEvent::Received(data))) => {
                        info!(
                            "Received DATAGRAM flow_id={} dat= {:?}",
                            flow_id, data
                        );
                        dgram_echoes += 1;

                        debug!(
                            "{}/{} dgrams received",
                            dgram_echoes, dgrams_count
                        );

                        if dgram_echoes == dgrams_count {
                            info!(
                                "{}/{} dgrams(s) received in {:?}, closing...",
                                dgram_echoes,
                                dgrams_count,
                                dgram_start.elapsed()
                            );

                            match conn.close(true, 0x00, b"kthxbye") {
                                // Already closed.
                                Ok(_) | Err(quiche::Error::Done) => (),

                                Err(e) => panic!("error closing conn: {:?}", e),
                            }

                            break;
                        }
                    },

                    Err(quiche::h3::Error::Done) => {
                        break;
                    },

                    Err(e) => {
                        error!("HTTP/3 processing failed: {:?}", e);

                        break;
                    },
                }
            }
        }

        // Generate outgoing QUIC packets and send them on the UDP socket, until
        // quiche reports that there are no more packets to be sent.
        loop {
            let write = match conn.send(&mut out) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    trace!("done writing");
                    break;
                },

                Err(e) => {
                    error!("send failed: {:?}", e);

                    conn.close(false, 0x1, b"fail").ok();
                    break;
                },
            };

            if let Err(e) = socket.send(&out[..write]) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    trace!("send() would block");
                    break;
                }

                panic!("send() failed: {:?}", e);
            }

            trace!("written {}", write);
        }

        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());

            if dgram_echoes != dgrams_count {
                error!("connection timed out after {:?} and only completed {}/{} requests",
                       dgram_start.elapsed(), dgram_echoes, dgrams_count);
            }

            break;
        }
    }
}

fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{:02x}", b)).collect();

    vec.join("")
}
