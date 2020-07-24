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

use std::convert::TryFrom;
use std::net;

use std::collections::HashMap;
use std::collections::HashSet;

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
  dgram-server [options]
  dgram-server -h | --help

Options:
  --listen <addr>             Listen on the given IP:port [default: 127.0.0.1:4433]
  --cert <file>               TLS certificate path [default: src/bin/cert.crt]
  --key <file>                TLS certificate key path [default: src/bin/cert.key]
  --root <dir>                Root directory [default: src/bin/root/]
  --name <str>                Name of the server [default: quic.tech]
  --max-data BYTES            Connection-wide flow control limit [default: 10000000].
  --max-stream-data BYTES     Per-stream flow control limit [default: 1000000].
  --no-retry                  Disable stateless retry.
  --no-grease                 Don't send GREASE.
  -a --app-proto PROTO        Application protocol (siduck, h3, wq-vvv) on which to send DATAGRAM [default: siduck]
  --max-idle-timeout MS       Advertised timeout in milliseconds [default: 60000].
  -h --help                   Show this screen.
";

type WebTransportStreamMap = HashMap<u64, Vec<u8>>;

struct Client {
    conn: std::pin::Pin<Box<quiche::Connection>>,

    http3_conn: Option<quiche::h3::Connection>,

    quictransport_conn: Option<()>,

    qt_streams: WebTransportStreamMap,
    qt_streams_complete: HashSet<u64>,

    next_uni_stream_id: u64
}

type ClientMap = HashMap<Vec<u8>, (net::SocketAddr, Client)>;


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

    let max_idle_timeout = args.get_str("--max-idle-timeout");
    let max_idle_timeout = u64::from_str_radix(max_idle_timeout, 10).unwrap();

    // let max_streams_uni = args.get_str("--max-streams-uni");
    // let max_streams_uni = u64::from_str_radix(max_streams_uni, 10).unwrap();

    let app_proto = args.get_str("--app-proto");

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

    // Setup the event loop.
    let poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Create the UDP listening socket, and register it with the event loop.
    let socket = net::UdpSocket::bind(args.get_str("--listen")).unwrap();

    let socket = mio::net::UdpSocket::from_socket(socket).unwrap();
    poll.register(
        &socket,
        mio::Token(0),
        mio::Ready::readable(),
        mio::PollOpt::edge(),
    )
    .unwrap();

    // Create the configuration for the QUIC connections.
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    config
        .load_cert_chain_from_pem_file(args.get_str("--cert"))
        .unwrap();
    config
        .load_priv_key_from_pem_file(args.get_str("--key"))
        .unwrap();

    config.set_application_protos(app_params.proto).unwrap();

    config.set_max_idle_timeout(max_idle_timeout);
    config.set_max_udp_payload_size(MAX_DATAGRAM_SIZE as u64);
    config.set_initial_max_data(max_data);
    config.set_initial_max_stream_data_bidi_local(max_stream_data);
    config.set_initial_max_stream_data_bidi_remote(max_stream_data);
    config.set_initial_max_stream_data_uni(max_stream_data);
    config.set_initial_max_streams_bidi(app_params.initial_max_streams_bidi);
    config.set_initial_max_streams_uni(app_params.initial_max_streams_uni);
    config.set_disable_active_migration(true);
    config.set_dgram_frames_supported(true);

    if std::env::var_os("SSLKEYLOGFILE").is_some() {
        config.log_keys();
    }

    if args.get_bool("--no-grease") {
        config.grease(false);
    }

    let mut qt_client_indication_ok = false;

    let h3_config = quiche::h3::Config::new().unwrap();

    let rng = SystemRandom::new();
    let conn_id_seed =
        ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

    let mut clients = ClientMap::new();

    loop {
        // Find the shorter timeout from all the active connections.
        //
        // TODO: use event loop that properly supports timers
        let timeout =
            clients.values().filter_map(|(_, c)| c.conn.timeout()).min();

        poll.poll(&mut events, timeout).unwrap();

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'read: loop {
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if events.is_empty() {
                trace!("timed out");

                clients.values_mut().for_each(|(_, c)| c.conn.on_timeout());

                break 'read;
            }

            let (len, src) = match socket.recv_from(&mut buf) {
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

            let pkt_buf = &mut buf[..len];

            // Parse the QUIC packet's header.
            let hdr = match quiche::Header::from_slice(
                pkt_buf,
                quiche::MAX_CONN_ID_LEN,
            ) {
                Ok(v) => v,

                Err(e) => {
                    error!("Parsing packet header failed: {:?}", e);
                    continue;
                },
            };

            trace!("got packet {:?}", hdr);

            let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
            let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];

            // Lookup a connection based on the packet's connection ID. If there
            // is no connection matching, create a new one.
            let (_, client) = if !clients.contains_key(&hdr.dcid) &&
                !clients.contains_key(conn_id)
            {
                if hdr.ty != quiche::Type::Initial {
                    error!("Packet is not Initial");
                    continue 'read;
                }

                if !quiche::version_is_supported(hdr.version) {
                    warn!("Doing version negotiation");

                    let len =
                        quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)
                            .unwrap();

                    let out = &out[..len];

                    if let Err(e) = socket.send_to(out, &src) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            trace!("send() would block");
                            break;
                        }

                        panic!("send() failed: {:?}", e);
                    }
                    continue 'read;
                }

                let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                scid.copy_from_slice(&conn_id);

                let mut odcid = None;

                if !args.get_bool("--no-retry") {
                    // Token is always present in Initial packets.
                    let token = hdr.token.as_ref().unwrap();

                    // Do stateless retry if the client didn't send a token.
                    if token.is_empty() {
                        warn!("Doing stateless retry");

                        let new_token = mint_token(&hdr, &src);

                        let len = quiche::retry(
                            &hdr.scid,
                            &hdr.dcid,
                            &scid,
                            &new_token,
                            hdr.version,
                            &mut out,
                        )
                        .unwrap();

                        let out = &out[..len];

                        if let Err(e) = socket.send_to(out, &src) {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                trace!("send() would block");
                                break;
                            }

                            panic!("send() failed: {:?}", e);
                        }
                        continue 'read;
                    }

                    odcid = validate_token(&src, token);

                    // The token was not valid, meaning the retry failed, so
                    // drop the packet.
                    if odcid == None {
                        error!("Invalid address validation token");
                        continue;
                    }

                    if scid.len() != hdr.dcid.len() {
                        error!("Invalid destination connection ID");
                        continue;
                    }

                    // Reuse the source connection ID we sent in the Retry
                    // packet, instead of changing it again.
                    scid.copy_from_slice(&hdr.dcid);
                }

                debug!(
                    "New connection: dcid={} scid={}",
                    hex_dump(&hdr.dcid),
                    hex_dump(&scid)
                );

                let conn = quiche::accept(&scid, odcid, &mut config).unwrap();

                let client = Client {
                    conn,
                    http3_conn: None,
                    quictransport_conn: None,
                    qt_streams: WebTransportStreamMap::new(),
                    qt_streams_complete: HashSet::new(),
                    next_uni_stream_id: 3
                };

                clients.insert(scid.to_vec(), (src, client));

                clients.get_mut(&scid[..]).unwrap()
            } else {
                match clients.get_mut(&hdr.dcid) {
                    Some(v) => v,

                    None => clients.get_mut(conn_id).unwrap(),
                }
            };

            // Process potentially coalesced packets.
            let read = match client.conn.recv(pkt_buf) {
                Ok(v) => v,

                Err(e) => {
                    error!("{} recv failed: {:?}", client.conn.trace_id(), e);
                    continue 'read;
                },
            };

            trace!("{} processed {} bytes", client.conn.trace_id(), read);

            // If we negotiated SiDUCK, once the QUIC connection is established
            // try to read DATAGRAMs.
            if app_params.proto == SIDUCK_ALPN &&
                (client.conn.is_in_early_data() ||
                    client.conn.is_established())
            {
                match client.conn.dgram_recv(&mut dgram_buf) {
                    Ok(len) => {
                        let data = unsafe {
                            std::str::from_utf8_unchecked(&dgram_buf[..len])
                        };
                        info!("Received DATAGRAM data {:?}", data);

                        // TODO
                        if data != "quack" {
                            match client.conn.close(
                                true,
                                0x101,
                                b"only quacks echo",
                            ) {
                                // Already closed.
                                Ok(_) | Err(quiche::Error::Done) => (),

                                Err(e) => panic!("error closing conn: {:?}", e),
                            }

                            continue 'read;
                        }

                        match client
                            .conn
                            .dgram_send(format!("{}-ack", data).as_bytes())
                        {
                            Ok(v) => v,

                            Err(e) => {
                                error!("failed to send request {:?}", e);
                                continue 'read;
                            },
                        }
                    },

                    Err(quiche::Error::Done) => break,

                    Err(e) => {
                        error!("failure receiving DATAGRAM failure {:?}", e);

                        continue 'read;
                    },
                }
            }

            // If we negotiated QuicTransport, create a new QuicTransport
            // connection as soon as the QUIC connection is
            // established.
            if app_params.proto == QUICTRANSPORT_ALPN &&
                (client.conn.is_in_early_data() ||
                    client.conn.is_established()) &&
                client.quictransport_conn.is_none()
            {
                debug!(
                    "{} QUIC handshake completed, now trying QuicTransport",
                    client.conn.trace_id()
                );

                // TODO: sanity check connection before adding to map
                client.quictransport_conn = Some(());
            }

            if client.quictransport_conn.is_some() {
                // Process all readable streams.
                for s in client.conn.readable() {
                    while let Ok((read, fin)) =
                        client.conn.stream_recv(s, &mut buf)
                    {

                        debug!(
                            "{} received {} bytes on stream {}",
                            client.conn.trace_id(),
                            read,
                            s
                        );

                        if client.qt_streams_complete.contains(&s) {
                            return;
                        }

                        let qt_stream_data =
                            client.qt_streams.entry(s).or_insert(Vec::new());


                        trace!(
                            "{} steam {} has {} bytes total",
                            client.conn.trace_id(),
                            s,
                            qt_stream_data.len()
                        );


                        qt_stream_data.extend_from_slice(&buf[..read]);

                        trace!(
                            "{} steam {} now has {} bytes total",
                            client.conn.trace_id(),
                            s,
                            qt_stream_data.len()
                        );

                        if fin {
                            if s == 2 {
                                qt_client_indication_ok =
                                    process_client_indication(qt_stream_data);

                                if !qt_client_indication_ok {
                                    error!("{} QuicTransport client indication failure", client.conn.trace_id());

                                    client.conn.close(false, 0x1, b"QuicTransport client indication fail").ok();
                                }
                            } else if qt_client_indication_ok {
                                let stream_id = if s % 4 == 0 {
                                    s
                                } else {
                                    let ret = client.next_uni_stream_id;
                                    client.next_uni_stream_id += 4;
                                    ret
                                };

                                let len = qt_stream_data.len().to_string();

                                trace!(
                                    "about to reply on stream {} with {:?}",
                                    stream_id,
                                    len
                                );

                                client
                                    .conn
                                    .stream_send(stream_id, len.as_bytes(), true)
                                    .unwrap();

                                client.qt_streams_complete.insert(s);

                            }
                        }
                    }
                }

                match client.conn.dgram_recv(&mut dgram_buf) {
                    Ok(len) => {
                        let data = unsafe {
                            std::str::from_utf8_unchecked(&dgram_buf[..len])
                        };
                        info!("Received DATAGRAM data {:?}", data);

                        // TODO
                        match client
                            .conn
                            .dgram_send(format!("{}", len).as_bytes())
                        {
                            Ok(v) => v,

                            Err(e) => {
                                error!("failed to send dgram bytes back {:?}", e);
                                continue 'read;
                            },
                        }
                    },

                    Err(quiche::Error::Done) => continue 'read,

                    Err(e) => {
                        error!("failure receiving DATAGRAM failure {:?}", e);

                        continue 'read;
                    },
                }
            }

            // If we negotiated HTTP/3, create a new HTTP/3 connection as soon
            // as the QUIC connection is established.
            if app_params.proto == quiche::h3::APPLICATION_PROTOCOL &&
                (client.conn.is_in_early_data() ||
                    client.conn.is_established()) &&
                client.http3_conn.is_none()
            {
                debug!(
                    "{} QUIC handshake completed, now trying HTTP/3",
                    client.conn.trace_id()
                );

                let h3_conn = match quiche::h3::Connection::with_transport(
                    &mut client.conn,
                    &h3_config,
                ) {
                    Ok(v) => v,

                    Err(e) => {
                        error!("failed to create HTTP/3 connection: {}", e);
                        continue 'read;
                    },
                };

                // TODO: sanity check h3 connection before adding to map
                client.http3_conn = Some(h3_conn);
            }

            if client.http3_conn.is_some() {
                // Process HTTP/3 events.
                loop {
                    let http3_conn = client.http3_conn.as_mut().unwrap();

                    match http3_conn.poll_dgram(&mut client.conn, &mut dgram_buf)
                    {
                        Ok((
                            flow_id,
                            quiche::h3::DatagramEvent::Received(data),
                        )) => {
                            info!(
                                "Received DATAGRAM flow_id={} dat= {:?}",
                                flow_id, data
                            );

                            match http3_conn.dgram_send(
                                &mut client.conn,
                                flow_id,
                                &data,
                            ) {
                                Ok(v) => v,

                                Err(e) => {
                                    error!("failed to send dgram {:?}", e);
                                    break;
                                },
                            }
                        },

                        Err(quiche::h3::Error::Done) => {
                            break;
                        },

                        Err(e) => {
                            error!(
                                "{} HTTP/3 error {:?}",
                                client.conn.trace_id(),
                                e
                            );

                            break 'read;
                        },
                    }
                }
            }
        }

        // Generate outgoing QUIC packets for all active connections and send
        // them on the UDP socket, until quiche reports that there are no more
        // packets to be sent.
        for (peer, client) in clients.values_mut() {
            loop {
                let write = match client.conn.send(&mut out) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        trace!("{} done writing", client.conn.trace_id());
                        break;
                    },

                    Err(e) => {
                        error!("{} send failed: {:?}", client.conn.trace_id(), e);

                        client.conn.close(false, 0x1, b"fail").ok();
                        break;
                    },
                };

                // TODO: coalesce packets.
                if let Err(e) = socket.send_to(&out[..write], &peer) {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        trace!("send() would block");
                        break;
                    }

                    panic!("send() failed: {:?}", e);
                }

                trace!("{} written {} bytes", client.conn.trace_id(), write);
            }
        }

        // Garbage collect closed connections.
        clients.retain(|_, (_, ref mut c)| {
            trace!("Collecting garbage");

            if c.conn.is_closed() {
                info!(
                    "{} connection collected {:?}",
                    c.conn.trace_id(),
                    c.conn.stats()
                );
            }

            !c.conn.is_closed()
        });
    }
}

/// Generate a stateless retry token.
///
/// The token includes the static string `"quiche"` followed by the IP address
/// of the client and by the original destination connection ID generated by the
/// client.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn mint_token(hdr: &quiche::Header, src: &net::SocketAddr) -> Vec<u8> {
    let mut token = Vec::new();

    token.extend_from_slice(b"quiche");

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    token.extend_from_slice(&addr);
    token.extend_from_slice(&hdr.dcid);

    token
}

/// Validates a stateless retry token.
///
/// This checks that the ticket includes the `"quiche"` static string, and that
/// the client IP address matches the address stored in the ticket.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn validate_token<'a>(
    src: &net::SocketAddr, token: &'a [u8],
) -> Option<&'a [u8]> {
    if token.len() < 6 {
        return None;
    }

    if &token[..6] != b"quiche" {
        return None;
    }

    let token = &token[6..];

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
        return None;
    }

    let token = &token[addr.len()..];

    Some(&token[..])
}

fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{:02x}", b)).collect();

    vec.join("")
}

fn process_client_indication(buf: &[u8]) -> bool {
    let mut offset = 0;

    // origin
    let tmp = <[u8; 2]>::try_from(&buf[offset..offset + 2]).unwrap();
    let field = u16::from_be_bytes(tmp);
    if field != 0 {
        trace!("field key != 0");
        return false;
    }

    offset += 2;

    let tmp = <[u8; 2]>::try_from(&buf[offset..offset + 2]).unwrap();
    let origin_len = u16::from_be_bytes(tmp);
    trace!("origin_len={}", origin_len);
    offset += 2;

    let origin =
        std::str::from_utf8(&buf[offset..offset + origin_len as usize]).unwrap();

    offset += origin_len as usize;

    // path
    let tmp = <[u8; 2]>::try_from(&buf[offset..offset + 2]).unwrap();
    let field = u16::from_be_bytes(tmp);
    if field != 1 {
        error!("field key != 1");
        return false;
    }

    offset += 2;

    let tmp = <[u8; 2]>::try_from(&buf[offset..offset + 2]).unwrap();
    let path_len = u16::from_be_bytes(tmp);

    offset += 2;

    let path =
        std::str::from_utf8(&buf[offset..offset + path_len as usize]).unwrap();

    // TODO: validate origin
    // let url1 = url::Url::parse(origin);
    // let url2 = url::Url::parse(path);

    true
}
