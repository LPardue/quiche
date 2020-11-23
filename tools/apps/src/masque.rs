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

use std::net::ToSocketAddrs;

use std::io::prelude::*;

use std::collections::HashMap;

use quiche::h3::NameValue;

use super::args::*;
use super::common::*;

const MAX_INNER_DATAGRAM_SIZE: usize = 1250;

#[derive(Clone, Debug)]
pub enum ProxyType {
    Direct,
    Http(String),
    Udp(String),
    Quic(String),
}

impl Default for ProxyType {
    fn default() -> Self {
        ProxyType::Direct
    }
}

pub fn get_proxy_type() -> ProxyType {
    if let Some(p) = std::env::var_os("HTTP_PROXY") {
        return ProxyType::Http(p.to_str().unwrap().to_owned());
    }

    if let Some(p) = std::env::var_os("UDP_PROXY") {
        return ProxyType::Udp(p.to_str().unwrap().to_owned());
    }

    if let Some(p) = std::env::var_os("QUIC_PROXY") {
        return ProxyType::Quic(p.to_str().unwrap().to_owned());
    }

    ProxyType::Direct
}

fn validate_tunnel_request(
    request: &[quiche::h3::Header], stream_id: u64,
) -> std::result::Result<(ProxyType, u64), u32> {
    let mut scheme = None;
    let mut host = None;
    let mut path = None;
    let mut method = None;
    let mut dgram_flow_id = None;
    let mut masque_secret = None;

    for hdr in request {
        match hdr.name() {
            ":scheme" => {
                scheme = Some(hdr.value());
            },

            ":authority" | "host" => {
                host = Some(hdr.value().to_string());
            },

            ":path" => {
                path = Some(hdr.value());
            },

            ":method" => {
                method = Some(hdr.value());
            },

            "datagram-flow-id" => {
                dgram_flow_id = Some(hdr.value());
            },

            "masque-secret" => {
                masque_secret = Some(hdr.value().to_string());
            },

            _ => (),
        }
    }

    if scheme.is_some() || path.is_some() {
        error!("malformed CONNECT request: scheme or path is present");
        return Err(400);
    }

    // TODO validate host
    let docopt = docopt::Docopt::new(SERVER_USAGE).unwrap();
    let args = ServerArgs::with_docopt(&docopt);

    // Validate MASQUE secret.
    if args.masque_secret.is_some() && masque_secret != args.masque_secret {
        error!(
            "rejected CONNECT request: secret {:?} does not match",
            masque_secret
        );
        return Err(400);
    }

    let (proxy_type, id) = match method {
        Some("CONNECT") => (ProxyType::Http(host.unwrap()), stream_id),

        Some("CONNECT-UDP") => {
            // TODO: pick proxy mode based on headers

            match dgram_flow_id {
                Some(id) => match id.parse::<u64>() {
                    Ok(v) => (ProxyType::Udp(host.unwrap()), v),

                    Err(e) => {
                        error!(
                            "malformed CONNECT-UDP request: {}",
                            e.to_string()
                        );
                        return Err(400);
                    },
                },

                None => {
                    error!(
                        "malformed CONNECT-UDP request: datagram-flow-id missing"
                    );
                    return Err(400);
                },
            }
        },

        _ => {
            return Err(400);
        },
    };

    trace!("proxy_type={:?}", proxy_type);

    Ok((proxy_type, id))
}

fn authority_form(url: &url::Url) -> String {
    format!(
        "{}:{}",
        url.host_str().unwrap(),
        url.port_or_known_default().unwrap()
    )
}

struct MasqueRelay {
    conn: std::pin::Pin<Box<quiche::Connection>>,
    h3_conn: Option<quiche::h3::Connection>,
    req: (Vec<quiche::h3::Header>, Vec<u8>),
    req_hdrs_sent: bool,
}

pub struct Upstream {
    poll: mio::Poll,
    events: mio::Events,
    udp_socket: Option<mio::net::UdpSocket>,
    masque_relay: Option<MasqueRelay>,
    tcp_stream: Option<mio::tcp::TcpStream>,
}

pub struct ConnectContext {
    connect_reqs: Vec<Http3Request>, // vector but only need one?
    inner_h11_reqs: Option<Vec<Http11Request>>,
    inner_quic_conn: Option<Client>,
    flow_id: Option<u64>,
    proxy_type: ProxyType,
}

pub type ContextMap = HashMap<String, ConnectContext>;

pub struct MasqueConn {
    h3_conn: quiche::h3::Connection,
    reqs_sent: usize,
    reqs_complete: usize,
    reqs_failed: usize,
    client_view: ContextMap,
    _body: Option<Vec<u8>>,
    upstreams: HashMap<u64, Upstream>,
    closed_upstreams: Vec<u64>,
}

impl MasqueConn {
    pub fn with_urls(
        conn: &mut quiche::Connection, urls: &[url::Url], reqs_cardinal: u64,
        req_headers: &[String], body: &Option<Vec<u8>>, method: &str,
        _dgram_sender: Option<Http3DgramSender>, proxy_type: &ProxyType,
    ) -> Box<dyn HttpConn> {
        let mut client_view = ContextMap::new();

        let mut flow_id = 0;

        // From the given set of URLs:
        // 1) find the unique target server, there will be one CONNECT to this
        // 2) gather all URLs to the target, there will be one or more requests
        //    that get tunneled on the stream created in (1).
        for url in urls {
            let authority = authority_form(&url);

            match client_view.get_mut(&authority) {
                // Append
                Some(v) => match proxy_type {
                    ProxyType::Http(_) => {
                        let mut reqs = Http11Request::generate(
                            &[url.clone()],
                            reqs_cardinal,
                        );
                        v.inner_h11_reqs.as_mut().unwrap().append(&mut reqs);
                    },

                    _ => (),
                },

                // Populate first entry
                None => {
                    let (
                        conn_method,
                        inner_h11_reqs,
                        flow_id,
                        connect_headers,
                        inner_quic_conn,
                    ) = match proxy_type {
                        ProxyType::Http(_) => (
                            "CONNECT",
                            Some(Http11Request::generate(
                                &[url.clone()],
                                reqs_cardinal,
                            )),
                            // None,
                            None,
                            req_headers.to_vec(),
                            None,
                        ),

                        ProxyType::Udp(_) => {
                            let current_flow_id = flow_id;
                            flow_id += 4;

                            let mut connect_headers = req_headers.to_vec();
                            connect_headers.push(format!(
                                "datagram-flow-id: {}",
                                current_flow_id
                            ));

                            // Parse CLI parameters.
                            let docopt =
                                docopt::Docopt::new(CLIENT_USAGE).unwrap();
                            let conn_args = CommonArgs::with_docopt(&docopt);
                            let mut args = ClientArgs::with_docopt(&docopt);

                            // Filter the urls to the current CONNECT authority
                            args.urls.retain(|u| authority_form(u) == authority);

                            let (qc, scid) = Client::with_url(
                                url,
                                args,
                                conn_args,
                                MAX_INNER_DATAGRAM_SIZE,
                                ProxyType::Direct,
                            );

                            info!(
                                "created inner QUIC connection with SCID {:?}",
                                &scid
                            );

                            (
                                "CONNECT-UDP",
                                None,
                                Some(current_flow_id),
                                connect_headers,
                                Some(qc),
                            )
                        },

                        // TODO: this CONNECT-UDP method needs some extra
                        // headers. Figure out how to handle this.
                        ProxyType::Quic(_) => (
                            "CONNECT-UDP",
                            None,
                            None,
                            req_headers.to_vec(),
                            None,
                        ),

                        _ => (method, None, None, req_headers.to_vec(), None),
                    };

                    let cc = ConnectContext {
                        connect_reqs: Http3Request::generate(
                            &[url.clone()],
                            1,
                            conn_method,
                            &connect_headers,
                            None,
                        ),
                        inner_h11_reqs,
                        flow_id,
                        inner_quic_conn,
                        proxy_type: proxy_type.clone(),
                    };
                    client_view.insert(authority, cc);
                },
            }
        }

        // trace!("client view is {:?}", client_view);
        let mut config = quiche::h3::Config::new().unwrap();
        config.set_dgram_poll_threshold(1);
        config.set_stream_poll_threshold(1);

        let h_conn = MasqueConn {
            h3_conn: quiche::h3::Connection::with_transport(conn, &config)
                .unwrap(),
            reqs_sent: 0,
            reqs_complete: 0,
            reqs_failed: 0,
            client_view,

            _body: body.as_ref().map(|b| b.to_vec()),
            upstreams: HashMap::new(),
            closed_upstreams: Vec::new(),
        };

        Box::new(h_conn)
    }

    pub fn with_conn(
        conn: &mut quiche::Connection, _dgram_sender: Option<Http3DgramSender>,
    ) -> Box<dyn HttpConn> {
        let mut config = quiche::h3::Config::new().unwrap();
        config.set_dgram_poll_threshold(1);
        config.set_stream_poll_threshold(1);

        let h_conn = MasqueConn {
            h3_conn: quiche::h3::Connection::with_transport(conn, &config)
                .unwrap(),
            reqs_sent: 0,
            reqs_complete: 0,
            reqs_failed: 0,
            client_view: HashMap::new(),
            _body: None,
            upstreams: HashMap::new(),
            closed_upstreams: Vec::new(),
        };

        Box::new(h_conn)
    }

    fn make_upstream(
        &mut self, proxy_type: &ProxyType, upstream_key: u64,
        req_hdrs: Vec<quiche::h3::Header>,
    ) -> quiche::h3::Result<(Vec<quiche::h3::Header>, bool)> {
        let res = match proxy_type {
            ProxyType::Http(ref host) => {
                let address = match host.to_socket_addrs() {
                    Ok(mut it) => match it.next() {
                        Some(v) => v,

                        None => {
                            error!("No address found");
                            return Err(quiche::h3::Error::Done);
                        },
                    },

                    Err(e) => {
                        error!("{}", e.to_string());
                        return Err(quiche::h3::Error::Done);
                    },
                };

                let tcp_stream = match mio::net::TcpStream::connect(&address) {
                    Ok(v) => v,

                    Err(e) => {
                        error!("{}", e.to_string());
                        return Err(quiche::h3::Error::Done);
                    },
                };

                let poll = mio::Poll::new().unwrap();

                let events = mio::Events::with_capacity(1024);
                poll.register(
                    &tcp_stream,
                    mio::Token(0),
                    mio::Ready::writable(),
                    mio::PollOpt::edge(),
                )
                .unwrap();

                info!(
                    "connecting to {:} from {:}",
                    address,
                    tcp_stream.local_addr().unwrap(),
                );

                self.upstreams.insert(upstream_key, Upstream {
                    poll,
                    events,
                    udp_socket: None,
                    masque_relay: None,
                    tcp_stream: Some(tcp_stream),
                });

                Ok(())
            },

            ProxyType::Udp(ref host) => {
                let proxy_chain_type = get_proxy_type();

                let (mut masque_relay, next_hop_url) = match proxy_chain_type {
                    ProxyType::Udp(ref v) | ProxyType::Quic(ref v) => {
                        let connect_url = url::Url::parse(v).unwrap();

                        // Parse CLI parameters.
                        let docopt = docopt::Docopt::new(SERVER_USAGE).unwrap();
                        let conn_args = CommonArgs::with_docopt(&docopt);
                        let server_args = ServerArgs::with_docopt(&docopt);
                        let args = ClientArgs {
                            version: quiche::PROTOCOL_VERSION,
                            dump_response_path: None,
                            dump_json: false,
                            urls: vec![connect_url.clone()],
                            reqs_cardinal: 1,
                            req_headers: Vec::new(),
                            no_verify: server_args.no_verify,
                            body: None,
                            method: "CONNECT-UDP".to_string(),
                            connect_to: None,
                        };

                        // Create a QUIC connection and initiate
                        // handshake.
                        let (qc, _scid) = Client::with_url(
                            &connect_url,
                            args,
                            conn_args,
                            MAX_INNER_DATAGRAM_SIZE,
                            proxy_chain_type,
                        );

                        let conn = qc.conn;

                        (
                            Some(MasqueRelay {
                                conn,
                                h3_conn: None,
                                req: (req_hdrs, Vec::new()),
                                req_hdrs_sent: false,
                            }),
                            connect_url,
                        )
                    },

                    _ => (
                        None,
                        url::Url::parse(&format!("https://{}", host)).unwrap(),
                    ),
                };

                let address = match next_hop_url.to_socket_addrs() {
                    Ok(mut it) => match it.next() {
                        Some(v) => v,

                        None => {
                            error!("No address found");
                            return Err(quiche::h3::Error::Done);
                        },
                    },

                    Err(e) => {
                        error!(
                            "failed to open {} {}",
                            next_hop_url,
                            e.to_string()
                        );
                        return Err(quiche::h3::Error::Done);
                    },
                };

                // Bind to INADDR_ANY or IN6ADDR_ANY depending on the
                // IP family of the server
                // address. This is needed on macOS and BSD variants
                // that don't
                // support binding to IN6ADDR_ANY for both v4 and v6.
                let bind_addr = match address {
                    std::net::SocketAddr::V4(_) => "0.0.0.0:0",
                    std::net::SocketAddr::V6(_) => "[::]:0",
                };

                let socket = match std::net::UdpSocket::bind(bind_addr) {
                    Ok(v) => v,

                    Err(e) => {
                        error!("{}", e.to_string());
                        return Err(quiche::h3::Error::Done);
                    },
                };

                match socket.connect(address) {
                    Ok(_) => (),

                    Err(e) => {
                        error!("{}", e.to_string());
                        return Err(quiche::h3::Error::Done);
                    },
                };

                let socket = mio::net::UdpSocket::from_socket(socket).unwrap();

                let poll = mio::Poll::new().unwrap();

                let events = mio::Events::with_capacity(1024);
                poll.register(
                    &socket,
                    mio::Token(0),
                    mio::Ready::readable(),
                    mio::PollOpt::edge(),
                )
                .unwrap();

                info!(
                    "connecting to {:} from {:}",
                    address,
                    socket.local_addr().unwrap(),
                );

                // If we are want this instance to be a simple relay in a proxy
                // chain, we need to CONNECT to the next hop.
                if let Some(relay) = &mut masque_relay {
                    let mut out = [0; MAX_INNER_DATAGRAM_SIZE];
                    let write =
                        relay.conn.send(&mut out).expect("initial send failed");

                    while let Err(e) = socket.send(&out[..write]) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            trace!("send() would block");
                            continue;
                        }

                        panic!("send() failed: {:?}", e);
                    }
                }

                self.upstreams.insert(upstream_key, Upstream {
                    poll,
                    events,
                    udp_socket: Some(socket),
                    masque_relay,
                    tcp_stream: None,
                });

                Ok(())
            },

            ProxyType::Quic(_) => {
                // TODO
                Ok(())
            },

            _ => Err(quiche::h3::Error::Done),
        };

        let (headers, fin) = match (res, proxy_type) {
            (Ok(_), ProxyType::Http(_)) => (
                vec![
                    quiche::h3::Header::new(":status", &200.to_string()),
                    quiche::h3::Header::new("server", "quiche-masque"),
                ],
                false,
            ),

            (Ok(_), ProxyType::Udp(_)) | (Ok(_), ProxyType::Quic(_)) => (
                vec![
                    quiche::h3::Header::new(":status", &200.to_string()),
                    quiche::h3::Header::new("server", "quiche-masque"),
                    quiche::h3::Header::new(
                        "datagram-flow-id",
                        &upstream_key.to_string(),
                    ),
                ],
                false,
            ),

            (Ok(_), _) => (
                vec![
                    quiche::h3::Header::new(":status", &505.to_string()),
                    quiche::h3::Header::new("server", "quiche-masque"),
                ],
                true,
            ),

            (Err(_), _) => (
                vec![
                    quiche::h3::Header::new(":status", &500.to_string()),
                    quiche::h3::Header::new("server", "quiche-masque"),
                ],
                true,
            ),
        };

        Ok((headers, fin))
    }

    fn handle_tcp_upstream(
        &mut self, conn: &mut std::pin::Pin<Box<quiche::Connection>>, id: u64,
        check_timeout: bool, buf: &mut [u8],
        partial_responses: &mut HashMap<u64, PartialResponse>,
    ) {
        let upstream = match self.upstreams.get_mut(&id) {
            Some(v) => v,

            None => return,
        };

        if check_timeout {
            let timeout = Some(std::time::Duration::from_millis(1));
            upstream.poll.poll(&mut upstream.events, timeout).unwrap();

            if upstream.events.is_empty() {
                // Nothing happened to our TCP socket so just exit now.
                return;
            }
        }

        if let Some(tcp) = &mut upstream.tcp_stream {
            trace!("Reading from target TCP socket");
            match tcp.read(buf) {
                Ok(0) => {
                    // TODO: if the upstream closes connection, we should
                    // reset the stream.
                    error!("Target connection closed, deal with it!");
                },

                Ok(len) => {
                    trace!(
                        "Read {} bytes from target server: {:?}",
                        len,
                        buf[..len].to_vec()
                    );

                    let resp = partial_responses.get_mut(&id).unwrap();
                    resp.body.extend_from_slice(&buf[..len]);
                },

                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        trace!("Target server read() would block");
                        return;
                    }

                    // TODO: handle error by removing the upstream and
                    // properly closing the request stream.
                    error!("read() failed: {:?}", e);
                    self.h3_conn.send_body(conn, id, &buf[..0], true).ok();
                    self.closed_upstreams.push(id);
                },
            }
        }
    }

    fn handle_udp_upstream(
        &mut self, conn: &mut std::pin::Pin<Box<quiche::Connection>>, id: u64,
        buf: &mut [u8],
    ) {
        let upstream = match self.upstreams.get_mut(&id) {
            Some(v) => v,

            None => return,
        };

        let udp = match upstream.udp_socket.as_mut() {
            Some(v) => v,

            None => return,
        };

        // If we're a relay, keep pumping it
        if let Some(relay) = &mut upstream.masque_relay {
            if let Some(relay_h3_conn) = &mut relay.h3_conn {
                if !relay.req_hdrs_sent {
                    trace!("going to send {:?} from relay", &relay.req.0);

                    match relay_h3_conn.send_request(
                        &mut relay.conn,
                        &relay.req.0,
                        false,
                    ) {
                        Ok(_) => relay.req_hdrs_sent = true,

                        _ => relay.req_hdrs_sent = false,
                    };
                }
            }

            loop {
                let write = match relay.conn.send(buf) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        break;
                    },

                    Err(e) => {
                        error!("relay send failed: {:?}", e);

                        relay.conn.close(false, 0x1, b"fail").ok();
                        break;
                    },
                };

                if let Err(e) = udp.send(&buf[..write]) {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        trace!("send() to relay would block");
                        break;
                    }

                    panic!("relay send() failed: {:?}", e);
                }

                trace!("relay written {}", write);
            }
        }

        match udp.recv(buf) {
            Ok(len) => {
                trace!(
                    "read {} UDP bytes from target of flow {}: {:?}",
                    len,
                    id,
                    buf[..len].to_vec()
                );

                // When running in normal MASQUE mode, simply send the UDP
                // payload back to the client as HTTP/3 DATAGRAM.
                if upstream.masque_relay.is_none() {
                    match self.h3_conn.send_dgram(conn, id, &buf[..len]) {
                        Ok(v) => v,

                        Err(e) => {
                            error!("failed to send dgram {:?}", e);
                        },
                    }

                    return;
                }

                // If we're a relay, the inbound `udp` is from the next hop so
                // it needs to be decapsulated before sending to the client
                // `self.h3_conn`.
                let relay = match upstream.masque_relay.as_mut() {
                    Some(v) => v,

                    None => return,
                };

                // Process relay's received QUIC packets from next hop.
                match relay.conn.recv(&mut buf[..len]) {
                    Ok(v) => v,

                    Err(e) => {
                        // This is a pretty bad, the relay failed to communicate
                        // with the next hop for some reason. Tear everything
                        // down.
                        error!("relay quiche recv() failed: {:?}", e);

                        relay.conn.close(false, 0x1, b"fail").ok();
                        self.h3_conn.send_body(conn, 0, &buf[..0], true).ok();
                        conn.close(false, 0x1, b"fail").ok();
                        return;
                    },
                };

                // Once handshake is complete, make the relay's HTTP/3 conn.
                if relay.conn.is_established() && relay.h3_conn.is_none() {
                    let app_proto = relay.conn.application_proto();
                    let app_proto = &std::str::from_utf8(&app_proto).unwrap();

                    if alpns::HTTP_3.contains(app_proto) {
                        let mut config = quiche::h3::Config::new().unwrap();
                        config.set_dgram_poll_threshold(1);
                        config.set_stream_poll_threshold(1);
                        relay.h3_conn = Some(
                            quiche::h3::Connection::with_transport(
                                &mut relay.conn,
                                &config,
                            )
                            .unwrap(),
                        );
                    } else {
                        unreachable!();
                    }
                }

                // Process the relay's received HTTP/3 data from the next hop.
                let relay_h3_conn = match relay.h3_conn.as_mut() {
                    Some(v) => v,

                    None => return,
                };

                loop {
                    match relay_h3_conn.poll(&mut relay.conn) {
                        Ok((
                            stream_id,
                            quiche::h3::Event::Headers { list, has_body },
                        )) => {
                            trace!(
                                "{} relay got response headers {:?} on stream id {}",
                                relay.conn.trace_id(), list, stream_id
                            );

                            // Forward the received headers.
                            match self
                                .h3_conn
                                .send_response(conn, stream_id, &list, !has_body)
                            {
                                Ok(v) => v,

                                Err(e) => {
                                    error!(
                                        "{} relay stream send failed {:?}",
                                        conn.trace_id(),
                                        e
                                    );
                                },
                            }
                        },

                        Ok((stream_id, quiche::h3::Event::Data)) => {
                            if let Ok(read) = relay_h3_conn.recv_body(
                                &mut relay.conn,
                                stream_id,
                                buf,
                            ) {
                                trace!(
                                    "relay got {} bytes of response data on stream {}",
                                    read, stream_id
                                );

                                // Forward received data.
                                match self.h3_conn.send_body(
                                    conn,
                                    stream_id,
                                    &buf[..read],
                                    false,
                                ) {
                                    Ok(_v) => (),

                                    Err(e) => {
                                        error!(
                                            "{} relay stream send failed {:?}",
                                            conn.trace_id(),
                                            e
                                        );
                                    },
                                }
                            }
                        },

                        Ok((stream_id, quiche::h3::Event::Finished)) => {
                            // The upstream finished the
                            // stream, emulate with a
                            // 0-length fin.
                            match self.h3_conn.send_body(
                                conn,
                                stream_id,
                                &buf[..0],
                                true,
                            ) {
                                Ok(_v) => (),

                                Err(e) => {
                                    error!(
                                        "{} stream send failed {:?}",
                                        relay.conn.trace_id(),
                                        e
                                    );
                                },
                            }
                        },

                        Ok((_flow_id, quiche::h3::Event::Datagram)) => {
                            let (len, flow_id, flow_id_len) = relay_h3_conn
                                .recv_dgram(&mut relay.conn, buf)
                                .unwrap();

                            debug!(
                                "Received DATAGRAM flow_id={} len={}",
                                flow_id, len,
                            );

                            match self.h3_conn.send_dgram(
                                conn,
                                id,
                                &buf[flow_id_len..len],
                            ) {
                                Ok(v) => v,

                                Err(e) => {
                                    error!("failed to send dgram {:?}", e);
                                    break;
                                },
                            }
                        },

                        Ok((goaway_id, quiche::h3::Event::GoAway)) => {
                            info!(
                                "{} got GOAWAY with ID {} ",
                                relay.conn.trace_id(),
                                goaway_id
                            );
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

                if relay.conn.is_closed() {
                    error!(
                        "Relay connection connection closed, {:?}",
                        relay.conn.stats()
                    );
                }
            },

            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    // trace!("recv() would block");
                    return;
                }

                // TODO: handle error by removing the upstream and
                // closing the request stream
                error!("read() failed: {:?}", e);
                self.closed_upstreams.push(id);
            },
        }
    }
}

impl HttpConn for MasqueConn {
    // The MASQUE client sends two types of requests.
    //
    // First, an "outer" CONNECT/CONNECT-UDP request is used to initiates a
    // tunnel. Second, a set of "inner" requests are made in the established
    // tunnel.
    //
    // The CONNECT case is straightforward, it just serializes all of the
    // requests as plaintext HTTP/1.1, and sends that as a continuous bytestream
    // after the request headers.
    //
    // The CONNECT-UDP case is more complicated. The request establishes an H3
    // DATAGRAM flow ID, which is then use to carry encapsulated QUIC packets. To
    // achieve this an "inner" QUIC connection is created, which has to go through
    // all the usual handhsake procedure before the client's requests are sent on
    // independent HTTP/3 streams withing the tunnel.
    fn send_requests(
        &mut self, conn: &mut quiche::Connection, _target_path: &Option<String>,
    ) {
        let mut reqs_done = 0;

        for (target, context) in self.client_view.iter_mut().skip(self.reqs_sent)
        {
            debug!("sending HTTP CONNECT request for {}", target);

            let req = context.connect_reqs.first_mut().unwrap();
            let s = match self.h3_conn.send_request(conn, &req.hdrs, false) {
                Ok(v) => v,

                Err(quiche::h3::Error::TransportError(
                    quiche::Error::StreamLimit,
                )) => {
                    debug!("not enough stream credits, retry later...");
                    break;
                },

                Err(quiche::h3::Error::StreamBlocked) => {
                    debug!("stream is blocked, retry later...");
                    break;
                },

                Err(e) => {
                    error!("failed to send request {:?}", e);
                    break;
                },
            };

            debug!("sending HTTP CONNECT request {:?}", req.hdrs);

            req.stream_id = Some(s);

            // No response writer for CONNECT requests.
            req.response_writer = None;

            // When proxying HTTP, we'll have some requests to send on this
            // connected stream. The following code is very basic, if there is
            // any problem writing to the stream (such as if the stream is flow
            // control blocked), then we just give up. We'll never come back to
            // this stream to retry.
            if let Some(inner_reqs) = &context.inner_h11_reqs {
                for inner_req in inner_reqs.iter() {
                    if let Err(e) = self.h3_conn.send_body(
                        conn,
                        s,
                        inner_req.request.as_bytes(),
                        false,
                    ) {
                        error!("failed to send inner HTTP request {:?}", e);

                        // TODO: store and retry
                        break;
                    }
                }
            }

            reqs_done += 1;
        }

        self.reqs_sent += reqs_done;

        // We don't wait for the CONNECT-UDP response before starting to send
        // DATAGRAMS.
        let mut out = [0; MAX_INNER_DATAGRAM_SIZE];
        for (_target, context) in self.client_view.iter_mut() {
            if let Some(inner) = &mut context.inner_quic_conn {
                if let Some(h_conn) = &mut inner.http_conn {
                    let path = &inner.args.as_ref().unwrap().dump_response_path;
                    h_conn.send_requests(&mut inner.conn, path);
                }

                // Generate outgoing QUIC packets and send them on DATAGRAM flow,
                // until quiche reports that there are no more
                // packets to be sent.
                loop {
                    let write = match inner.conn.send(&mut out) {
                        Ok(v) => v,

                        Err(quiche::Error::Done) => {
                            trace!("done writing");
                            break;
                        },

                        Err(e) => {
                            error!("send failed: {:?}", e);

                            inner.conn.close(false, 0x1, b"fail").ok();
                            break;
                        },
                    };

                    debug!(
                        "sending HTTP/3 DATAGRAM on flow_id={}",
                        context.flow_id.unwrap(),
                    );

                    match self.h3_conn.send_dgram(
                        conn,
                        context.flow_id.unwrap(),
                        &out[..write],
                    ) {
                        Ok(v) => v,

                        Err(e) => {
                            error!("failed to send dgram {:?}", e);
                            break;
                        },
                    }
                }
            }
        }
    }

    // The MASQUE client tunnelled response handler.
    //
    // Assess the MASQUE server responses in order to determine success. In the
    // happy path, CONNECT requests only complete after the inner tunnelled
    // requests do. So this method needs to determine what success looks like.
    // TODO: make this method's success detection more robust.
    fn handle_responses(
        &mut self, conn: &mut quiche::Connection, buf: &mut [u8],
        req_start: &std::time::Instant,
    ) {
        // TODO: avoid doing a lot of work if we know all has all been done.
        if self.is_complete() {
            return;
        }
        // TODO: checking internal QUIC timeouts here in order to make sure it
        // happens, probably some better way to do it.
        for (_target, context) in self.client_view.iter_mut() {
            if let Some(inner) = &mut context.inner_quic_conn {
                inner.conn.on_timeout();
            }
        }

        loop {
            match self.h3_conn.poll(conn) {
                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                    info!(
                        "{}, got response headers {:?} on stream id {}",
                        conn.trace_id(),
                        list,
                        stream_id
                    );

                    let mut status = None;

                    for hdr in list {
                        match hdr.name() {
                            ":status" => {
                                status =
                                    hdr.value().to_string().parse::<u32>().ok();
                            },

                            _ => (),
                        }
                    }

                    // TODO: this is a bit of a shortcut
                    match status {
                        Some(v) =>
                            if v != 200 {
                                self.reqs_failed += 1;
                            },

                        None => {
                            self.reqs_failed += 1;
                        },
                    }
                },

                Ok((stream_id, quiche::h3::Event::Data)) => {
                    if let Ok(read) = self.h3_conn.recv_body(conn, stream_id, buf)
                    {
                        debug!(
                            "got {} bytes of response data on stream {}",
                            read, stream_id
                        );

                        let entry = self
                            .client_view
                            .iter_mut()
                            .find(|(_k, v)| {
                                v.connect_reqs.first().unwrap().stream_id ==
                                    Some(stream_id)
                            })
                            .unwrap();

                        match &mut entry
                            .1
                            .connect_reqs
                            .first_mut()
                            .unwrap()
                            .response_writer
                        {
                            Some(rw) => {
                                rw.write_all(&buf[..read]).ok();
                            },

                            None => {
                                print!("{}", unsafe {
                                    std::str::from_utf8_unchecked(&buf[..read])
                                });
                            },
                        }
                    }
                },

                Ok((stream_id, quiche::h3::Event::Finished)) => {
                    debug!("got finished {}", stream_id);
                    // TODO: properly detect end of connect and tunneled requests.

                    self.reqs_complete += 1;
                    let reqs_count = self.client_view.len();

                    debug!(
                        "{}/{} CONNECT streams completed, {} failed",
                        self.reqs_complete, reqs_count, self.reqs_failed
                    );

                    if self.reqs_complete == reqs_count {
                        info!(
                            "{}/{} CONNECT streams completed {:?}, closing...",
                            self.reqs_complete,
                            reqs_count,
                            req_start.elapsed()
                        );

                        match conn.close(true, 0x00, b"kthxbye") {
                            // Already closed.
                            Ok(_) | Err(quiche::Error::Done) => (),

                            Err(e) => panic!("error closing conn: {:?}", e),
                        }

                        break;
                    }
                },

                Ok((_flow_id, quiche::h3::Event::Datagram)) => {
                    let (len, flow_id, flow_id_len) =
                        self.h3_conn.recv_dgram(conn, buf).unwrap();

                    trace!(
                        "received HTTP/3 DATAGRAM flow_id={} len={}",
                        flow_id,
                        len,
                    );

                    // Lookup inner QUIC connection, feed it received packets.
                    let entry = self
                        .client_view
                        .iter_mut()
                        .find(|(_k, v)| v.flow_id == Some(flow_id))
                        .unwrap();

                    if let Some(inner) = &mut entry.1.inner_quic_conn {
                        let read =
                            match inner.conn.recv(&mut buf[flow_id_len..len]) {
                                Ok(v) => v,

                                Err(e) => {
                                    error!("internal recv failed: {:?}", e);
                                    continue;
                                },
                            };

                        trace!("processed {} bytes", read);

                        // Create HTTP/3 connection once QUIC is established.
                        inner.make_app_proto();

                        // Check to see any thing happened in HTTP/3.
                        if let Some(h_conn) = inner.http_conn.as_mut() {
                            h_conn.handle_responses(
                                &mut inner.conn,
                                buf,
                                &inner.start_time,
                            );
                        }
                    }
                },

                Ok((_id, quiche::h3::Event::GoAway)) => (),

                Err(quiche::h3::Error::Done) => {
                    break;
                },

                Err(e) => {
                    error!("HTTP/3 processing failed: {:?}", e);

                    break;
                },
            }
        }

        if self.is_complete() {
            info!(
                "All inner connections complete their actions in {:?}, closing",
                req_start.elapsed()
            );
            match conn.close(true, 0x00, b"kthxbye") {
                // Already closed.
                Ok(_) | Err(quiche::Error::Done) => (),

                Err(e) => panic!("error closing conn: {:?}", e),
            }
        }
    }

    fn is_complete(&self) -> bool {
        // CONNECT requests have all been tidied up. Could be a failure case.
        if self.reqs_sent == self.reqs_complete {
            return true;
        }

        let mut inner_complete = true;

        for (_, client) in &self.client_view {
            match client.proxy_type {
                ProxyType::Http(_) => {
                    // TODO: it's hard to detect whether all the HTTP/1.1
                    // requests completed successfully, so just say they didn't
                    // for now.
                    return false;
                },

                ProxyType::Udp(_) | ProxyType::Quic(_) => {
                    // We have to have made an inner QUIC and HTTP/3 connection,
                    // and run them to completion before we declare things done.
                    if let Some(qc) = &client.inner_quic_conn {
                        if let Some(h_conn) = &qc.http_conn {
                            inner_complete =
                                inner_complete && h_conn.is_complete();
                        } else {
                            inner_complete = false;
                        }
                    }
                },

                _ => unreachable!(),
            }
        }

        // Did we send all the CONNECT requests that we wanted and have all the
        // inner connections make all the requests they wanted?
        self.reqs_sent == self.client_view.len() && inner_complete
    }

    fn report_incomplete(&self, start: &std::time::Instant) -> bool {
        if !self.is_complete() {
            error!(
                "MASQUE connection timed out after {:?} and sent {} connect requests",
                start.elapsed(),
                self.reqs_sent,
            );

            return true;
        }

        false
    }

    // The MASQUE server request handler.
    //
    // The prime purpose of this method is to handle new MASQUE client tunnel
    // requests, which happens in the `poll()` loop. New requests will be
    // validated and dispatched, forming new upstreams. Existing requests or
    // DATAGRAMS associated to an valid flow ID will just get forward on.
    //
    // However, because of how quiche-server uses the HttpConn trait, we also
    // piggyback all of the upstream checks at this stage.
    fn handle_requests(
        &mut self, conn: &mut std::pin::Pin<Box<quiche::Connection>>,
        partial_requests: &mut HashMap<u64, PartialRequest>,
        partial_responses: &mut HashMap<u64, PartialResponse>, _root: &str,
        _index: &str, buf: &mut [u8],
    ) -> quiche::h3::Result<()> {
        // Process HTTP events.
        loop {
            // check partial requests, flush as much pending data to socket as
            // possible
            for (stream_id, partial) in partial_requests.iter_mut() {
                trace!("There are {} bytes to send to target", partial.req.len());
                if partial.req.is_empty() {
                    continue;
                }

                if let Some(upstream) = self.upstreams.get_mut(stream_id) {
                    if let Some(tcp) = &mut upstream.tcp_stream {
                        match tcp.write(partial.req.as_slice()) {
                            Ok(written) => {
                                trace!("{} bytes sent to target", written);

                                partial.req.drain(..written);
                            },

                            Err(e) => {
                                if e.kind() == std::io::ErrorKind::WouldBlock {
                                    trace!("write() would block");
                                    // break;
                                    continue;
                                }

                                panic!("read() failed: {:?}", e);
                            },
                        }
                    }
                }
            }

            // Iterate over all the upstreams to see if there is any work to do.
            // Copy keys to appease the borrow checker.
            let keys = self.upstreams.keys().cloned().collect::<Vec<u64>>();
            for id in keys {
                self.handle_tcp_upstream(conn, id, false, buf, partial_responses);
                self.handle_udp_upstream(conn, id, buf);
            }

            for id in self.closed_upstreams.drain(..) {
                self.upstreams.remove(&id);
            }

            // Handle the MASQUE client requests to *this* proxy.
            match self.h3_conn.poll(conn) {
                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                    info!(
                        "{} got request {:?} on stream id {}",
                        conn.trace_id(),
                        &list,
                        stream_id
                    );

                    // Make the upstream connection based on request.
                    let (proxy_type, upstream_key) =
                        match validate_tunnel_request(&list, stream_id) {
                            Ok(v) => v,

                            Err(code) => {
                                let headers = Some(vec![
                                    quiche::h3::Header::new(
                                        ":status",
                                        &code.to_string(),
                                    ),
                                    quiche::h3::Header::new(
                                        "server",
                                        "quiche-masque",
                                    ),
                                ]);

                                let response = PartialResponse {
                                    headers,
                                    body: Vec::new(),
                                    written: 0,
                                    fin: true,
                                };

                                partial_responses.insert(stream_id, response);
                                continue;
                            },
                        };

                    let (headers, fin) =
                        self.make_upstream(&proxy_type, upstream_key, list)?;

                    let response = PartialResponse {
                        headers: Some(headers),
                        body: Vec::new(),
                        written: 0,
                        fin,
                    };

                    partial_responses.insert(stream_id, response);
                },

                Ok((stream_id, quiche::h3::Event::Data)) => {
                    info!(
                        "{} got data on stream id {}",
                        conn.trace_id(),
                        stream_id
                    );

                    if let Ok(read) = self.h3_conn.recv_body(conn, stream_id, buf)
                    {
                        debug!(
                            "got {} bytes of inner tunnel data on stream {}",
                            read, stream_id
                        );

                        debug!(
                            "got in inner tunnel was {:?}",
                            buf[..read].to_vec()
                        );

                        if let Some(partial) =
                            partial_requests.get_mut(&stream_id)
                        {
                            partial.req.extend_from_slice(&buf[..read]);
                        } else {
                            let request = PartialRequest {
                                req: buf[..read].to_vec(),
                            };

                            debug!("len req = {}", request.req.len());

                            partial_requests.insert(stream_id, request);
                        }
                    }
                },

                Ok((_stream_id, quiche::h3::Event::Finished)) => (),

                Ok((flow_id, quiche::h3::Event::Datagram)) => {
                    // Even though we got a Datagram event, we only read it if
                    // there is a related upstream.
                    if let Some(upstream) = self.upstreams.get_mut(&flow_id) {
                        if let Some(udp) = &mut upstream.udp_socket {
                            let (len, flow_id, flow_id_len) =
                                self.h3_conn.recv_dgram(conn, buf).unwrap();

                            trace!(
                                "received HTTP/3 DATAGRAM from client flow_id={} data={:?}",
                                flow_id,
                                &buf[flow_id_len..len].to_vec()
                            );

                            // If we're a relay, then send on the inner H3 conn.
                            if let Some(relay) = &mut upstream.masque_relay {
                                if let Some(relay_h3_conn) = &mut relay.h3_conn {
                                    match relay_h3_conn.send_dgram(
                                        &mut relay.conn,
                                        flow_id,
                                        &buf[flow_id_len..len],
                                    ) {
                                        Ok(v) => v,

                                        Err(e) => {
                                            error!("failed to send dgram to proxy chain {:?}", e);
                                            break;
                                        },
                                    }
                                }

                                // Generate outgoing QUIC packets and send them
                                // on the UDP socket, until quiche reports that
                                // there are no more packets to be sent.
                                loop {
                                    let write = match relay.conn.send(buf) {
                                        Ok(v) => v,

                                        Err(quiche::Error::Done) => {
                                            trace!("done writing");
                                            break;
                                        },

                                        Err(e) => {
                                            error!("send failed: {:?}", e);

                                            relay
                                                .conn
                                                .close(false, 0x1, b"fail")
                                                .ok();
                                            break;
                                        },
                                    };

                                    if let Err(e) = udp.send(&buf[..write]) {
                                        if e.kind() ==
                                            std::io::ErrorKind::WouldBlock
                                        {
                                            trace!("send() would block");
                                            break;
                                        }

                                        panic!("send() failed: {:?}", e);
                                    }

                                    trace!("written {}", write);
                                }
                                break;
                            }

                            match udp.send(&buf[flow_id_len..len]) {
                                Ok(written) => {
                                    trace!("{} bytes sent to target", written);
                                },

                                Err(e) => {
                                    if e.kind() == std::io::ErrorKind::WouldBlock
                                    {
                                        trace!("write() would block");
                                        continue;
                                    }

                                    panic!("read() failed: {:?}", e);
                                },
                            }
                        } else {
                            break;
                        }
                    }

                    break;
                },

                Ok((_id, quiche::h3::Event::GoAway)) => (),

                Err(quiche::h3::Error::Done) => {
                    break;
                },

                Err(e) => {
                    error!("{} HTTP/3 error {:?}", conn.trace_id(), e);

                    return Err(e);
                },
            }
        }

        Ok(())
    }

    // Mainly focused on shuffling CONNECT tunnel data back from the upstream.
    fn handle_writable(
        &mut self, conn: &mut std::pin::Pin<Box<quiche::Connection>>,
        partial_responses: &mut HashMap<u64, PartialResponse>, stream_id: u64,
    ) {
        // trace!("{} stream {} is writable", conn.trace_id(), stream_id);

        if !partial_responses.contains_key(&stream_id) {
            return;
        }

        let resp = partial_responses.get_mut(&stream_id).unwrap();

        if let Some(ref headers) = resp.headers {
            trace!("writing CONNECT response headers");
            match self
                .h3_conn
                .send_response(conn, stream_id, &headers, resp.fin)
            {
                Ok(_) => (),

                Err(quiche::h3::Error::StreamBlocked) => {
                    return;
                },

                Err(e) => {
                    error!("{} stream send failed {:?}", conn.trace_id(), e);
                    return;
                },
            }
        }

        resp.headers = None;

        // Once the CONNECT response has been sent, we move on to sending payload
        // received from the target as body data.
        if !resp.body.is_empty() {
            trace!(
                "ready to send {} bytes to stream {}",
                resp.body.len(),
                stream_id
            );

            let written = match self
                .h3_conn
                .send_body(conn, stream_id, &resp.body, resp.fin)
            {
                Ok(v) => v,

                Err(quiche::h3::Error::Done) => {
                    return;
                },

                Err(e) => {
                    error!("{} stream send failed {:?}", conn.trace_id(), e);
                    return;
                },
            };

            resp.body.drain(..written);
        }

        // TODO make an upstream bufer or write to partial directly?
        let mut buf = [0; 10240];

        self.handle_tcp_upstream(
            conn,
            stream_id,
            true,
            &mut buf,
            partial_responses,
        );

        for id in self.closed_upstreams.drain(..) {
            self.upstreams.remove(&id);
        }
    }
}
