// Copyright (C) 2020, Cloudflare, Inc.
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

use std::io::prelude::*;

use quiche_apps::args::*;
use quiche_apps::common::*;
use quiche_apps::masque::*;

const MAX_DATAGRAM_SIZE: usize = 1350;

const HANDSHAKE_FAIL_STATUS: i32 = -1;
const HTTP_FAIL_STATUS: i32 = -2;

fn main() {
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    env_logger::builder()
        .default_format_timestamp_nanos(true)
        .init();

    // Parse CLI parameters.
    let docopt = docopt::Docopt::new(CLIENT_USAGE).unwrap();
    let conn_args = CommonArgs::with_docopt(&docopt);
    let args = ClientArgs::with_docopt(&docopt);
    let dump_response_path = args.dump_response_path.clone();
    let dump_packet_path = conn_args.dump_packet_path.clone();

    // Setup the event loop.
    let poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Detect proxy settings
    let proxy_type = get_proxy_type();

    let connect_url = match proxy_type {
        ProxyType::Http(ref v) => url::Url::parse(v).unwrap(),

        ProxyType::Udp(ref v) => url::Url::parse(v).unwrap(),

        ProxyType::Quic(ref v) => url::Url::parse(v).unwrap(),

        ProxyType::Direct => args.urls[0].clone(),
    };

    // Resolve server address.
    let peer_addr = if let Some(addr) = &args.connect_to {
        addr.parse().unwrap()
    } else {
        connect_url.to_socket_addrs().unwrap().next().unwrap()
    };

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

    // Create a QUIC connection and initiate handshake.
    let (mut qc, scid) = Client::with_url(
        &connect_url,
        args,
        conn_args,
        MAX_DATAGRAM_SIZE,
        proxy_type,
    );

    info!(
        "connecting to {:} from {:} with scid {}",
        peer_addr,
        socket.local_addr().unwrap(),
        hex_dump(&scid)
    );

    let write = qc.conn.send(&mut out).expect("initial send failed");

    while let Err(e) = socket.send(&out[..write]) {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            trace!("send() would block");
            continue;
        }

        panic!("send() failed: {:?}", e);
    }

    trace!("written {}", write);

    let app_data_start = std::time::Instant::now();

    let mut pkt_count = 0;

    loop {
        // TODO: the timeout stuff needs work
        // poll.poll(&mut events, qc.conn.timeout()).unwrap();
        let timeout = Some(std::time::Duration::from_millis(1));
        poll.poll(&mut events, timeout).unwrap();

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'read: loop {
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if events.is_empty() {
                trace!("timed out");

                qc.conn.on_timeout();

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

            if let Some(target_path) = dump_packet_path.as_ref() {
                let path = format!("{}/{}.pkt", target_path, pkt_count);

                if let Ok(f) = std::fs::File::create(&path) {
                    let mut f = std::io::BufWriter::new(f);
                    f.write_all(&buf[..len]).ok();
                }
            }

            pkt_count += 1;

            // Process potentially coalesced packets.
            let read = match qc.conn.recv(&mut buf[..len]) {
                Ok(v) => v,

                Err(e) => {
                    error!("recv failed: {:?}", e);
                    continue 'read;
                },
            };

            trace!("processed {} bytes", read);
        }

        trace!("done reading");

        if qc.conn.is_closed() {
            info!("connection closed, {:?}", qc.conn.stats());

            if !qc.conn.is_established() {
                error!(
                    "connection timed out after {:?}",
                    app_data_start.elapsed(),
                );

                std::process::exit(HANDSHAKE_FAIL_STATUS);
            }

            if let Some(h_conn) = qc.http_conn {
                if h_conn.report_incomplete(&app_data_start) {
                    std::process::exit(HTTP_FAIL_STATUS);
                }
            }

            if let Some(si_conn) = qc.siduck_conn {
                si_conn.report_incomplete(&app_data_start);
            }

            break;
        }

        // Create a new application protocol session once the QUIC connection is
        // established.
        qc.make_app_proto();

        // If we have an HTTP connection, first issue the requests then
        // process received data.
        if let Some(h_conn) = qc.http_conn.as_mut() {
            h_conn.send_requests(&mut qc.conn, &dump_response_path);
            h_conn.handle_responses(&mut qc.conn, &mut buf, &app_data_start);
        }

        // If we have a siduck connection, first issue the quacks then
        // process received data.
        if let Some(si_conn) = qc.siduck_conn.as_mut() {
            si_conn.send_quacks(&mut qc.conn);
            si_conn.handle_quack_acks(&mut qc.conn, &mut buf, &app_data_start);
        }

        // Generate outgoing QUIC packets and send them on the UDP socket, until
        // quiche reports that there are no more packets to be sent.
        loop {
            let write = match qc.conn.send(&mut out) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    trace!("done writing");
                    break;
                },

                Err(e) => {
                    error!("send failed: {:?}", e);

                    qc.conn.close(false, 0x1, b"fail").ok();
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

        if qc.conn.is_closed() {
            info!("connection closed, {:?}", qc.conn.stats());

            if !qc.conn.is_established() {
                error!(
                    "connection timed out after {:?}",
                    app_data_start.elapsed(),
                );

                std::process::exit(HANDSHAKE_FAIL_STATUS);
            }

            if let Some(h_conn) = qc.http_conn {
                if h_conn.report_incomplete(&app_data_start) {
                    std::process::exit(HTTP_FAIL_STATUS);
                }
            }

            if let Some(si_conn) = qc.siduck_conn {
                si_conn.report_incomplete(&app_data_start);
            }

            break;
        }
    }
}
