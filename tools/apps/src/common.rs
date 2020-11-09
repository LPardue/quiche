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

//! Quiche application utilities.
//!
//! This module provides some utility functions that are common to quiche
//! applications.

use std::io::prelude::*;

use std::collections::HashMap;

use std::net;
use std::path;

use quiche::h3::NameValue;

use ring::rand::*;

use super::args::*;
use super::masque::*;

const MAX_JSON_DUMP_PAYLOAD: usize = 10000;

/// Returns a String containing a pretty printed version of the `buf` slice.
pub fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{:02x}", b)).collect();

    vec.join("")
}

/// ALPN helpers.
///
/// This module contains constants and functions for working with ALPN.
pub mod alpns {
    pub const HTTP_09: [&str; 4] = ["hq-29", "hq-28", "hq-27", "http/0.9"];
    pub const HTTP_3: [&str; 3] = ["h3-29", "h3-28", "h3-27"];
    pub const SIDUCK: [&str; 2] = ["siduck", "siduck-00"];

    pub fn length_prefixed(alpns: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();

        for s in alpns {
            out.push(s.len() as u8);
            out.extend_from_slice(s.as_bytes());
        }

        out
    }
}

pub struct PartialRequest {
    pub req: Vec<u8>,
}

pub struct PartialResponse {
    pub headers: Option<Vec<quiche::h3::Header>>,

    pub body: Vec<u8>,

    pub written: usize,

    pub fin: bool,
}

pub struct Client {
    pub conn: std::pin::Pin<Box<quiche::Connection>>,

    pub http_conn: Option<Box<dyn HttpConn>>,

    pub siduck_conn: Option<SiDuckConn>,

    pub app_proto_selected: bool,

    pub partial_requests: std::collections::HashMap<u64, PartialRequest>,

    pub partial_responses: std::collections::HashMap<u64, PartialResponse>,

    pub proxy_type: ProxyType,

    pub args: Option<ClientArgs>,

    pub conn_args: Option<CommonArgs>,

    pub start_time: std::time::Instant,
}

pub type ClientMap = HashMap<Vec<u8>, (net::SocketAddr, Client)>;

impl Client {
    pub fn with_url(
        url: &url::Url, client_args: ClientArgs, conn_args: CommonArgs,
        max_datagram_size: usize, proxy_type: ProxyType,
    ) -> (Self, Vec<u8>) {
        // Generate a random source connection ID for the connection.
        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        SystemRandom::new().fill(&mut scid[..]).unwrap();

        let mut config = quiche::Config::new(client_args.version).unwrap();

        config.verify_peer(!client_args.no_verify);

        config.set_application_protos(&conn_args.alpns).unwrap();

        config.set_max_idle_timeout(conn_args.idle_timeout);
        config.set_max_send_udp_payload_size(max_datagram_size);
        config.set_max_recv_udp_payload_size(max_datagram_size);
        config.set_initial_max_data(conn_args.max_data);
        config.set_initial_max_stream_data_bidi_local(conn_args.max_stream_data);
        config.set_initial_max_stream_data_bidi_remote(conn_args.max_stream_data);
        config.set_initial_max_stream_data_uni(conn_args.max_stream_data);
        config.set_initial_max_streams_bidi(conn_args.max_streams_bidi);
        config.set_initial_max_streams_uni(conn_args.max_streams_uni);
        config.set_disable_active_migration(true);

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

        if conn_args.no_grease {
            config.grease(false);
        }

        config
            .set_cc_algorithm_name(&conn_args.cc_algorithm)
            .unwrap();

        if conn_args.disable_hystart {
            config.enable_hystart(false);
        }

        let dgram_masque = matches!(&proxy_type,
                                ProxyType::Udp(_) | ProxyType::Quic(_));

        if conn_args.dgrams_enabled || dgram_masque {
            config.enable_dgram(true, 1000, 1000);
        }

        // Create a QUIC connection and initiate handshake.
        let mut conn = quiche::connect(url.domain(), &scid, &mut config).unwrap();

        if let Some(keylog) = &mut keylog {
            if let Ok(keylog) = keylog.try_clone() {
                conn.set_keylog(Box::new(keylog));
            }
        }

        // Only bother with qlog if the user specified it.
        #[cfg(feature = "qlog")]
        {
            if let Some(dir) = std::env::var_os("QLOGDIR") {
                let id = hex_dump(&scid);
                let writer = make_qlog_writer(&dir, "client", &id);

                conn.set_qlog(
                    Box::new(writer),
                    "quiche-client qlog".to_string(),
                    format!("{} id={}", "quiche-client qlog", id),
                );
            }
        }

        (
            Client {
                conn,
                http_conn: None,
                siduck_conn: None,
                app_proto_selected: false,
                partial_requests: HashMap::new(),
                partial_responses: HashMap::new(),
                proxy_type,
                args: Some(client_args),
                conn_args: Some(conn_args),
                start_time: std::time::Instant::now(),
            },
            scid.to_vec(),
        )
    }

    pub fn make_app_proto(&mut self) {
        if self.conn.is_established() && !self.app_proto_selected {
            // At this stage the ALPN negotiation succeeded and selected a
            // single application protocol name. We'll use this to construct
            // the correct type of HttpConn but `application_proto()`
            // returns a slice, so we have to convert it to a str in order
            // to compare to our lists of protocols. We `unwrap()` because
            // we need the value and if something fails at this stage, there
            // is not much anyone can do to recover.

            let app_proto = self.conn.application_proto();
            let app_proto = &std::str::from_utf8(&app_proto).unwrap();

            let masque = matches!(&self.proxy_type, ProxyType::Http(_) |
                    ProxyType::Udp(_) | ProxyType::Quic(_));

            if masque {
                match &self.args {
                    Some(args) => {
                        self.http_conn = Some(MasqueConn::with_urls(
                            &mut self.conn,
                            &args.urls,
                            args.reqs_cardinal,
                            &args.req_headers,
                            &args.body,
                            &args.method,
                            None,
                            &self.proxy_type,
                        ));
                        self.app_proto_selected = true;
                    },

                    None => panic!("No args to construct Application protocol"),
                }
            } else if alpns::HTTP_09.contains(app_proto) {
                match &self.args {
                    Some(args) => {
                        self.http_conn = Some(Http09Conn::with_urls(
                            &args.urls,
                            args.reqs_cardinal,
                        ));

                        self.app_proto_selected = true;
                    },

                    None => panic!("No args to construct Application protocol"),
                }
            } else if alpns::HTTP_3.contains(app_proto) {
                let dgram_sender = match &self.conn_args {
                    Some(conn_args) =>
                        if conn_args.dgrams_enabled {
                            Some(Http3DgramSender::new(
                                conn_args.dgram_count,
                                conn_args.dgram_data.clone(),
                                0,
                            ))
                        } else {
                            None
                        },

                    None => panic!("No args to construct Application protocol"),
                };

                match &self.args {
                    Some(args) => {
                        self.http_conn = Some(Http3Conn::with_urls(
                            &mut self.conn,
                            &args.urls,
                            args.reqs_cardinal,
                            &args.req_headers,
                            &args.body,
                            &args.method,
                            args.dump_json,
                            dgram_sender,
                        ));

                        self.app_proto_selected = true;
                    },

                    None => panic!("No args to construct Application protocol"),
                }
            } else if alpns::SIDUCK.contains(app_proto) {
                match &self.conn_args {
                    Some(conn_args) => {
                        self.siduck_conn = Some(SiDuckConn::new(
                            conn_args.dgram_count,
                            conn_args.dgram_data.clone(),
                        ));

                        self.app_proto_selected = true;
                    },

                    None => panic!("No args to construct Application protocol"),
                }
            }
        }
    }
}

/// Makes a buffered writer for a resource with a target URL.
///
/// The file will have the same name as the resource's last path segment value.
/// Multiple requests for the same URL are indicated by the value of `cardinal`,
/// any value "N" greater than 1, will cause ".N" to be appended to the
/// filename.
pub fn make_resource_writer(
    url: &url::Url, target_path: &Option<String>, cardinal: u64,
) -> Option<std::io::BufWriter<std::fs::File>> {
    if let Some(tp) = target_path {
        let resource =
            url.path_segments().map(|c| c.collect::<Vec<_>>()).unwrap();

        let mut path = format!("{}/{}", tp, resource.iter().last().unwrap());

        if cardinal > 1 {
            path = format!("{}.{}", path, cardinal);
        }

        match std::fs::File::create(&path) {
            Ok(f) => return Some(std::io::BufWriter::new(f)),

            Err(e) => panic!(
                "Error creating file for {}, attempted path was {}: {}",
                url, path, e
            ),
        }
    }

    None
}

fn autoindex(path: path::PathBuf, index: &str) -> path::PathBuf {
    if let Some(path_str) = path.to_str() {
        if path_str.ends_with('/') {
            let path_str = format!("{}{}", path_str, index);
            return path::PathBuf::from(&path_str);
        }
    }

    path
}

/// Makes a buffered writer for a qlog.
pub fn make_qlog_writer(
    dir: &std::ffi::OsStr, role: &str, id: &str,
) -> std::io::BufWriter<std::fs::File> {
    let mut path = std::path::PathBuf::from(dir);
    let filename = format!("{}-{}.qlog", role, id);
    path.push(filename);

    match std::fs::File::create(&path) {
        Ok(f) => std::io::BufWriter::new(f),

        Err(e) => panic!(
            "Error creating qlog file attempted path was {:?}: {}",
            path, e
        ),
    }
}

fn dump_json(reqs: &[Http3Request]) {
    println!("{{");
    println!("  \"entries\": [");
    let mut reqs = reqs.iter().peekable();

    while let Some(req) = reqs.next() {
        println!("  {{");
        println!("    \"request\":{{");
        println!("      \"headers\":[");

        let mut req_hdrs = req.hdrs.iter().peekable();
        while let Some(h) = req_hdrs.next() {
            println!("        {{");
            println!("          \"name\": \"{}\",", h.name());
            println!("          \"value\": \"{}\"", h.value());

            if req_hdrs.peek().is_some() {
                println!("        }},");
            } else {
                println!("        }}");
            }
        }
        println!("      ]}},");

        println!("    \"response\":{{");
        println!("      \"headers\":[");

        let mut response_hdrs = req.response_hdrs.iter().peekable();
        while let Some(h) = response_hdrs.next() {
            println!("        {{");
            println!("          \"name\": \"{}\",", h.name());
            println!(
                "          \"value\": \"{}\"",
                h.value().replace("\"", "\\\"")
            );

            if response_hdrs.peek().is_some() {
                println!("        }},");
            } else {
                println!("        }}");
            }
        }
        println!("      ],");
        println!("      \"body\": {:?}", req.response_body);
        println!("    }}");

        if reqs.peek().is_some() {
            println!("}},");
        } else {
            println!("}}");
        }
    }
    println!("]");
    println!("}}");
}

pub trait HttpConn {
    fn send_requests(
        &mut self, conn: &mut quiche::Connection, target_path: &Option<String>,
    );

    fn handle_responses(
        &mut self, conn: &mut quiche::Connection, buf: &mut [u8],
        req_start: &std::time::Instant,
    );

    fn is_complete(&self) -> bool;

    fn report_incomplete(&self, start: &std::time::Instant) -> bool;

    fn handle_requests(
        &mut self, conn: &mut std::pin::Pin<Box<quiche::Connection>>,
        partial_requests: &mut HashMap<u64, PartialRequest>,
        partial_responses: &mut HashMap<u64, PartialResponse>, root: &str,
        index: &str, buf: &mut [u8],
    ) -> quiche::h3::Result<()>;

    fn handle_writable(
        &mut self, conn: &mut std::pin::Pin<Box<quiche::Connection>>,
        partial_responses: &mut HashMap<u64, PartialResponse>, stream_id: u64,
    );
}

pub struct SiDuckConn {
    quacks_to_make: u64,
    quack_contents: String,
    quacks_sent: u64,
    quacks_acked: u64,
}

impl SiDuckConn {
    pub fn new(quacks_to_make: u64, quack_contents: String) -> Self {
        Self {
            quacks_to_make,
            quack_contents,
            quacks_sent: 0,
            quacks_acked: 0,
        }
    }

    pub fn send_quacks(&mut self, conn: &mut quiche::Connection) {
        trace!("sending quacks");
        let mut quacks_done = 0;

        for _ in self.quacks_sent..self.quacks_to_make {
            info!("sending QUIC DATAGRAM with data {:?}", self.quack_contents);

            match conn.dgram_send(self.quack_contents.as_bytes()) {
                Ok(v) => v,

                Err(e) => {
                    error!("failed to send dgram {:?}", e);

                    break;
                },
            }

            quacks_done += 1;
        }

        self.quacks_sent += quacks_done;
    }

    pub fn handle_quacks(
        &mut self, conn: &mut quiche::Connection, buf: &mut [u8],
    ) -> quiche::h3::Result<()> {
        loop {
            match conn.dgram_recv(buf) {
                Ok(len) => {
                    let data =
                        unsafe { std::str::from_utf8_unchecked(&buf[..len]) };
                    info!("Received DATAGRAM data {:?}", data);

                    // TODO
                    if data != "quack" {
                        match conn.close(true, 0x101, b"only quacks echo") {
                            // Already closed.
                            Ok(_) | Err(quiche::Error::Done) => (),

                            Err(e) => panic!("error closing conn: {:?}", e),
                        }

                        break;
                    }

                    match conn.dgram_send(format!("{}-ack", data).as_bytes()) {
                        Ok(v) => v,

                        Err(quiche::Error::Done) => (),

                        Err(e) => {
                            error!("failed to send quack ack {:?}", e);
                            return Err(From::from(e));
                        },
                    }
                },

                Err(quiche::Error::Done) => break,

                Err(e) => {
                    error!("failure receiving DATAGRAM failure {:?}", e);

                    return Err(From::from(e));
                },
            }
        }

        Ok(())
    }

    pub fn handle_quack_acks(
        &mut self, conn: &mut quiche::Connection, buf: &mut [u8],
        start: &std::time::Instant,
    ) {
        trace!("handle_quack_acks");

        loop {
            match conn.dgram_recv(buf) {
                Ok(len) => {
                    let data =
                        unsafe { std::str::from_utf8_unchecked(&buf[..len]) };

                    info!("Received DATAGRAM data {:?}", data);
                    self.quacks_acked += 1;

                    debug!(
                        "{}/{} quacks acked",
                        self.quacks_acked, self.quacks_to_make
                    );

                    if self.is_complete() {
                        info!(
                            "{}/{} dgrams(s) received in {:?}, closing...",
                            self.quacks_acked,
                            self.quacks_to_make,
                            start.elapsed()
                        );

                        match conn.close(true, 0x00, b"kthxbye") {
                            // Already closed.
                            Ok(_) | Err(quiche::Error::Done) => (),

                            Err(e) => panic!("error closing conn: {:?}", e),
                        }

                        break;
                    }
                },

                Err(quiche::Error::Done) => {
                    break;
                },

                Err(e) => {
                    error!("failure receiving DATAGRAM failure {:?}", e);

                    break;
                },
            }
        }
    }

    pub fn is_complete(&self) -> bool {
        self.quacks_acked == self.quacks_to_make
    }

    pub fn report_incomplete(&self, start: &std::time::Instant) -> bool {
        if !self.is_complete() {
            error!(
                "connection timed out after {:?} and only received {}/{} quack-acks",
                start.elapsed(),
                self.quacks_acked,
                self.quacks_to_make
            );

            return true;
        }

        false
    }
}

/// Represents an HTTP/0.9 formatted request.
pub struct Http09Request {
    url: url::Url,
    cardinal: u64,
    request_line: String,
    stream_id: Option<u64>,
    response_writer: Option<std::io::BufWriter<std::fs::File>>,
}

impl Http09Request {
    fn generate(urls: &[url::Url], reqs_cardinal: u64) -> Vec<Self> {
        let mut reqs = Vec::new();
        for url in urls {
            for i in 1..=reqs_cardinal {
                let request_line = format!("GET {}\r\n", url.path());
                reqs.push(Http09Request {
                    url: url.clone(),
                    cardinal: i,
                    request_line,
                    stream_id: None,
                    response_writer: None,
                });
            }
        }
        reqs
    }
}

#[derive(Debug)]
pub struct Http11Request {
    _url: url::Url,
    _cardinal: u64,
    pub request: String,
    _stream_id: Option<u64>,
    _response_writer: Option<std::io::BufWriter<std::fs::File>>,
}

impl Http11Request {
    pub fn generate(urls: &[url::Url], reqs_cardinal: u64) -> Vec<Self> {
        let mut reqs = Vec::new();
        for url in urls {
            for i in 1..=reqs_cardinal {
                let request = format!("GET {} HTTP/1.1\r\nhost: {}\r\nuser-agent: quiche-masque\r\n\r\n", url.path(), url.host_str().unwrap());
                reqs.push(Http11Request {
                    _url: url.clone(),
                    _cardinal: i,
                    request,
                    _stream_id: None,
                    _response_writer: None,
                });
            }
        }
        reqs
    }
}

/// Represents an HTTP/3 formatted request.
#[derive(Debug)]
pub struct Http3Request {
    pub url: url::Url,
    pub cardinal: u64,
    pub stream_id: Option<u64>,
    pub hdrs: Vec<quiche::h3::Header>,
    response_hdrs: Vec<quiche::h3::Header>,
    response_body: Vec<u8>,
    pub response_writer: Option<std::io::BufWriter<std::fs::File>>,
}

impl Http3Request {
    pub fn generate(
        urls: &[url::Url], reqs_cardinal: u64, method: &str,
        extra_headers: &[String], body_len: Option<usize>,
    ) -> Vec<Self> {
        let mut reqs = Vec::new();
        for url in urls {
            for i in 1..=reqs_cardinal {
                let authority = format!(
                    "{}:{}",
                    url.host_str().unwrap(),
                    url.port_or_known_default().unwrap()
                );

                let mut hdrs = match method {
                    "CONNECT" | "CONNECT-UDP" => vec![
                        quiche::h3::Header::new(":method", &method),
                        quiche::h3::Header::new(":authority", &authority),
                        quiche::h3::Header::new("user-agent", "quiche"),
                    ],

                    _ => vec![
                        quiche::h3::Header::new(":method", &method),
                        quiche::h3::Header::new(":scheme", url.scheme()),
                        quiche::h3::Header::new(":authority", &authority),
                        quiche::h3::Header::new(
                            ":path",
                            &url[url::Position::BeforePath..],
                        ),
                        quiche::h3::Header::new("user-agent", "quiche"),
                    ],
                };

                // Add custom headers to the request.
                for header in extra_headers {
                    let header_split: Vec<&str> =
                        header.splitn(2, ": ").collect();
                    if header_split.len() != 2 {
                        panic!("malformed header provided - \"{}\"", header);
                    }

                    hdrs.push(quiche::h3::Header::new(
                        header_split[0],
                        header_split[1],
                    ));
                }

                if let Some(l) = body_len {
                    hdrs.push(quiche::h3::Header::new(
                        "content-length",
                        &l.to_string(),
                    ));
                }

                reqs.push(Http3Request {
                    url: url.clone(),
                    cardinal: i,
                    stream_id: None,
                    hdrs,
                    response_hdrs: Vec::new(),
                    response_body: Vec::new(),
                    response_writer: None,
                });
            }
        }
        reqs
    }
}

#[derive(Default)]
pub struct Http09Conn {
    stream_id: u64,
    reqs_sent: usize,
    reqs_complete: usize,
    reqs: Vec<Http09Request>,
}

impl Http09Conn {
    pub fn with_urls(urls: &[url::Url], reqs_cardinal: u64) -> Box<dyn HttpConn> {
        let reqs = Http09Request::generate(urls, reqs_cardinal);

        let h_conn = Http09Conn {
            stream_id: 0,
            reqs_sent: 0,
            reqs_complete: 0,
            reqs,
        };

        Box::new(h_conn)
    }
}

impl HttpConn for Http09Conn {
    fn send_requests(
        &mut self, conn: &mut quiche::Connection, target_path: &Option<String>,
    ) {
        let mut reqs_done = 0;

        for req in self.reqs.iter_mut().skip(self.reqs_sent) {
            match conn.stream_send(
                self.stream_id,
                req.request_line.as_bytes(),
                true,
            ) {
                Ok(v) => v,

                Err(quiche::Error::StreamLimit) => {
                    debug!("not enough stream credits, retry later...");
                    break;
                },

                Err(e) => {
                    error!("failed to send request {:?}", e);
                    break;
                },
            };

            debug!("sending HTTP request {:?}", req.request_line);

            req.stream_id = Some(self.stream_id);
            req.response_writer =
                make_resource_writer(&req.url, target_path, req.cardinal);

            self.stream_id += 4;

            reqs_done += 1;
        }

        self.reqs_sent += reqs_done;
    }

    fn handle_responses(
        &mut self, conn: &mut quiche::Connection, buf: &mut [u8],
        req_start: &std::time::Instant,
    ) {
        // Process all readable streams.
        for s in conn.readable() {
            while let Ok((read, fin)) = conn.stream_recv(s, buf) {
                trace!("received {} bytes", read);

                let stream_buf = &buf[..read];

                trace!(
                    "stream {} has {} bytes (fin? {})",
                    s,
                    stream_buf.len(),
                    fin
                );

                let req = self
                    .reqs
                    .iter_mut()
                    .find(|r| r.stream_id == Some(s))
                    .unwrap();

                match &mut req.response_writer {
                    Some(rw) => {
                        rw.write_all(&buf[..read]).ok();
                    },

                    None => {
                        print!("{}", unsafe {
                            std::str::from_utf8_unchecked(&stream_buf)
                        });
                    },
                }

                // The server reported that it has no more data to send on
                // a client-initiated
                // bidirectional stream, which means
                // we got the full response. If all responses are received
                // then close the connection.
                if &s % 4 == 0 && fin {
                    self.reqs_complete += 1;
                    let reqs_count = self.reqs.len();

                    debug!(
                        "{}/{} responses received",
                        self.reqs_complete, reqs_count
                    );

                    if self.is_complete() {
                        info!(
                            "{}/{} response(s) received in {:?}, closing...",
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
                }
            }
        }
    }

    fn is_complete(&self) -> bool {
        self.reqs_complete == self.reqs.len()
    }

    fn report_incomplete(&self, start: &std::time::Instant) -> bool {
        if !self.is_complete() {
            error!(
                "connection timed out after {:?} and only completed {}/{} requests",
                start.elapsed(),
                self.reqs_complete,
                self.reqs.len()
            );

            return true;
        }

        false
    }

    fn handle_requests(
        &mut self, conn: &mut std::pin::Pin<Box<quiche::Connection>>,
        partial_requests: &mut HashMap<u64, PartialRequest>,
        partial_responses: &mut HashMap<u64, PartialResponse>, root: &str,
        index: &str, buf: &mut [u8],
    ) -> quiche::h3::Result<()> {
        // Process all readable streams.
        for s in conn.readable() {
            while let Ok((read, fin)) = conn.stream_recv(s, buf) {
                trace!("{} received {} bytes", conn.trace_id(), read);

                let stream_buf = &buf[..read];

                trace!(
                    "{} stream {} has {} bytes (fin? {})",
                    conn.trace_id(),
                    s,
                    stream_buf.len(),
                    fin
                );

                let stream_buf =
                    if let Some(partial) = partial_requests.get_mut(&s) {
                        partial.req.extend_from_slice(stream_buf);

                        if !partial.req.ends_with(b"\r\n") {
                            return Ok(());
                        }

                        &partial.req
                    } else {
                        if !stream_buf.ends_with(b"\r\n") {
                            let request = PartialRequest {
                                req: stream_buf.to_vec(),
                            };

                            partial_requests.insert(s, request);
                            return Ok(());
                        }

                        stream_buf
                    };

                if stream_buf.starts_with(b"GET ") {
                    let uri = &stream_buf[4..stream_buf.len() - 2];
                    let uri = String::from_utf8(uri.to_vec()).unwrap();
                    let uri = String::from(uri.lines().next().unwrap());
                    let uri = path::Path::new(&uri);
                    let mut path = path::PathBuf::from(root);

                    partial_requests.remove(&s);

                    for c in uri.components() {
                        if let path::Component::Normal(v) = c {
                            path.push(v)
                        }
                    }

                    path = autoindex(path, index);

                    info!(
                        "{} got GET request for {:?} on stream {}",
                        conn.trace_id(),
                        path,
                        s
                    );

                    let body = std::fs::read(path.as_path())
                        .unwrap_or_else(|_| b"Not Found!\r\n".to_vec());

                    info!(
                        "{} sending response of size {} on stream {}",
                        conn.trace_id(),
                        body.len(),
                        s
                    );

                    let written = match conn.stream_send(s, &body, true) {
                        Ok(v) => v,

                        Err(quiche::Error::Done) => 0,

                        Err(e) => {
                            error!(
                                "{} stream send failed {:?}",
                                conn.trace_id(),
                                e
                            );
                            return Err(From::from(e));
                        },
                    };

                    if written < body.len() {
                        let response = PartialResponse {
                            headers: None,
                            body,
                            written,
                            fin,
                        };

                        partial_responses.insert(s, response);
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_writable(
        &mut self, conn: &mut std::pin::Pin<Box<quiche::Connection>>,
        partial_responses: &mut HashMap<u64, PartialResponse>, stream_id: u64,
    ) {
        trace!("{} stream {} is writable", conn.trace_id(), stream_id);

        if !partial_responses.contains_key(&stream_id) {
            return;
        }

        let resp = partial_responses.get_mut(&stream_id).unwrap();
        let body = &resp.body[resp.written..];

        let written = match conn.stream_send(stream_id, &body, true) {
            Ok(v) => v,

            Err(quiche::Error::Done) => 0,

            Err(e) => {
                error!("{} stream send failed {:?}", conn.trace_id(), e);
                return;
            },
        };

        resp.written += written;

        if resp.written == resp.body.len() {
            partial_responses.remove(&stream_id);
        }
    }
}

pub struct Http3DgramSender {
    pub dgram_count: u64,
    pub dgram_content: String,
    pub flow_id: u64,
    pub dgrams_sent: u64,
}

impl Http3DgramSender {
    pub fn new(dgram_count: u64, dgram_content: String, flow_id: u64) -> Self {
        Self {
            dgram_count,
            dgram_content,
            flow_id,
            dgrams_sent: 0,
        }
    }
}

pub struct Http3Conn {
    h3_conn: quiche::h3::Connection,
    reqs_sent: usize,
    reqs_complete: usize,
    largest_processed_request: u64,
    reqs: Vec<Http3Request>,
    body: Option<Vec<u8>>,
    dump_json: bool,
    dgram_sender: Option<Http3DgramSender>,
}

impl Http3Conn {
    #[allow(clippy::too_many_arguments)]
    pub fn with_urls(
        conn: &mut quiche::Connection, urls: &[url::Url], reqs_cardinal: u64,
        req_headers: &[String], body: &Option<Vec<u8>>, method: &str,
        dump_json: bool, dgram_sender: Option<Http3DgramSender>,
    ) -> Box<dyn HttpConn> {
        // todo rustify this
        let body_len = match body {
            Some(b) => Some(b.len()),
            None => None,
        };

        let reqs = Http3Request::generate(
            urls,
            reqs_cardinal,
            method,
            req_headers,
            body_len,
        );

        let h_conn = Http3Conn {
            h3_conn: quiche::h3::Connection::with_transport(
                conn,
                &quiche::h3::Config::new().unwrap(),
            )
            .unwrap(),
            reqs_sent: 0,
            reqs_complete: 0,
            largest_processed_request: 0,
            reqs,
            body: body.as_ref().map(|b| b.to_vec()),
            dump_json,
            dgram_sender,
        };

        Box::new(h_conn)
    }

    pub fn with_conn(
        conn: &mut quiche::Connection, dgram_sender: Option<Http3DgramSender>,
    ) -> Box<dyn HttpConn> {
        let h_conn = Http3Conn {
            h3_conn: quiche::h3::Connection::with_transport(
                conn,
                &quiche::h3::Config::new().unwrap(),
            )
            .unwrap(),
            reqs_sent: 0,
            reqs_complete: 0,
            largest_processed_request: 0,
            reqs: Vec::new(),
            body: None,
            dump_json: false,
            dgram_sender,
        };

        Box::new(h_conn)
    }

    /// Builds an HTTP/3 response given a request.
    fn build_h3_response(
        root: &str, index: &str, request: &[quiche::h3::Header],
    ) -> (Vec<quiche::h3::Header>, Vec<u8>, String) {
        let mut file_path = path::PathBuf::from(root);
        let mut scheme = "";
        let mut host = "";
        let mut path = "";
        let mut method = "";
        let mut priority = "";

        // Parse some of the request headers.
        for hdr in request {
            match hdr.name() {
                ":scheme" => {
                    scheme = hdr.value();
                },

                ":authority" | "host" => {
                    host = hdr.value();
                },

                ":path" => {
                    path = hdr.value();
                },

                ":method" => {
                    method = hdr.value();
                },

                "priority" => {
                    priority = hdr.value();
                },

                _ => (),
            }
        }

        if scheme != "http" && scheme != "https" {
            let headers = vec![
                quiche::h3::Header::new(":status", &"400".to_string()),
                quiche::h3::Header::new("server", "quiche"),
            ];

            return (headers, b"Invalid scheme".to_vec(), priority.to_string());
        }

        let url = format!("{}://{}{}", scheme, host, path);
        let url = url::Url::parse(&url).unwrap();

        let pathbuf = path::PathBuf::from(url.path());
        let pathbuf = autoindex(pathbuf, index);

        // Priority query string takes precedence over the header.
        // So replace the header with one built here.
        let mut query_priority = "".to_string();
        for param in url.query_pairs() {
            if param.0 == "u" {
                query_priority.push_str(&format!("{}={},", param.0, param.1));
            }

            if param.0 == "i" && param.1 == "1" {
                query_priority.push_str("i,");
            }
        }

        if !query_priority.is_empty() {
            priority = &query_priority;
        }

        let (status, body) = match method {
            "GET" => {
                for c in pathbuf.components() {
                    if let path::Component::Normal(v) = c {
                        file_path.push(v)
                    }
                }

                match std::fs::read(file_path.as_path()) {
                    Ok(data) => (200, data),

                    Err(_) => (404, b"Not Found!".to_vec()),
                }
            },

            _ => (405, Vec::new()),
        };

        let headers = vec![
            quiche::h3::Header::new(":status", &status.to_string()),
            quiche::h3::Header::new("server", "quiche"),
            quiche::h3::Header::new("content-length", &body.len().to_string()),
            quiche::h3::Header::new("priority", &priority),
        ];

        (headers, body, priority.to_string())
    }
}

impl HttpConn for Http3Conn {
    fn send_requests(
        &mut self, conn: &mut quiche::Connection, target_path: &Option<String>,
    ) {
        let mut reqs_done = 0;

        for req in self.reqs.iter_mut().skip(self.reqs_sent) {
            let s = match self.h3_conn.send_request(
                conn,
                &req.hdrs,
                self.body.is_none(),
            ) {
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

            debug!("sending HTTP request {:?}", req.hdrs);

            req.stream_id = Some(s);
            req.response_writer =
                make_resource_writer(&req.url, target_path, req.cardinal);

            if let Some(body) = &self.body {
                if let Err(e) = self.h3_conn.send_body(conn, s, body, true) {
                    error!("failed to send request body {:?}", e);
                    break;
                }
            }

            reqs_done += 1;
        }

        self.reqs_sent += reqs_done;

        if let Some(ds) = self.dgram_sender.as_mut() {
            let mut dgrams_done = 0;

            for _ in ds.dgrams_sent..ds.dgram_count {
                info!(
                    "sending HTTP/3 DATAGRAM on flow_id={} with data {:?}",
                    ds.flow_id,
                    ds.dgram_content.as_bytes()
                );

                match self.h3_conn.send_dgram(
                    conn,
                    0,
                    ds.dgram_content.as_bytes(),
                ) {
                    Ok(v) => v,

                    Err(e) => {
                        error!("failed to send dgram {:?}", e);
                        break;
                    },
                }

                dgrams_done += 1;
            }

            ds.dgrams_sent += dgrams_done;
        }
    }

    fn handle_responses(
        &mut self, conn: &mut quiche::Connection, buf: &mut [u8],
        req_start: &std::time::Instant,
    ) {
        loop {
            match self.h3_conn.poll(conn) {
                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                    debug!(
                        "got response headers {:?} on stream id {}",
                        list, stream_id
                    );

                    let req = self
                        .reqs
                        .iter_mut()
                        .find(|r| r.stream_id == Some(stream_id))
                        .unwrap();

                    req.response_hdrs = list;
                },

                Ok((stream_id, quiche::h3::Event::Data)) => {
                    if let Ok(read) = self.h3_conn.recv_body(conn, stream_id, buf)
                    {
                        debug!(
                            "got {} bytes of response data on stream {}",
                            read, stream_id
                        );

                        let req = self
                            .reqs
                            .iter_mut()
                            .find(|r| r.stream_id == Some(stream_id))
                            .unwrap();

                        let len = std::cmp::min(
                            read,
                            MAX_JSON_DUMP_PAYLOAD - req.response_body.len(),
                        );
                        req.response_body.extend_from_slice(&buf[..len]);

                        match &mut req.response_writer {
                            Some(rw) => {
                                rw.write_all(&buf[..read]).ok();
                            },

                            None =>
                                if !self.dump_json {
                                    print!("{}", unsafe {
                                        std::str::from_utf8_unchecked(
                                            &buf[..read],
                                        )
                                    });
                                },
                        }
                    }
                },

                Ok((_stream_id, quiche::h3::Event::Finished)) => {
                    self.reqs_complete += 1;
                    let reqs_count = self.reqs.len();

                    debug!(
                        "{}/{} responses received",
                        self.reqs_complete, reqs_count
                    );

                    if self.is_complete() {
                        info!(
                            "{}/{} response(s) received in {:?}, closing...",
                            self.reqs_complete,
                            reqs_count,
                            req_start.elapsed()
                        );

                        if self.dump_json {
                            dump_json(&self.reqs);
                        }

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

                    info!(
                        "Received DATAGRAM flow_id={} len={} data={:?}",
                        flow_id,
                        len,
                        buf[flow_id_len..len].to_vec()
                    );
                },

                Ok((goaway_id, quiche::h3::Event::GoAway)) => {
                    info!(
                        "{} got GOAWAY with ID {} ",
                        conn.trace_id(),
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
    }

    fn is_complete(&self) -> bool {
        self.reqs_complete == self.reqs.len()
    }

    fn report_incomplete(&self, start: &std::time::Instant) -> bool {
        if !self.is_complete() {
            error!(
                "connection timed out after {:?} and only completed {}/{} requests",
                start.elapsed(),
                self.reqs_complete,
                self.reqs.len()
            );

            if self.dump_json {
                dump_json(&self.reqs);
            }

            return true;
        }

        false
    }

    fn handle_requests(
        &mut self, conn: &mut std::pin::Pin<Box<quiche::Connection>>,
        _partial_requests: &mut HashMap<u64, PartialRequest>,
        partial_responses: &mut HashMap<u64, PartialResponse>, root: &str,
        index: &str, buf: &mut [u8],
    ) -> quiche::h3::Result<()> {
        // Process HTTP events.
        loop {
            match self.h3_conn.poll(conn) {
                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                    info!(
                        "{} got request {:?} on stream id {}",
                        conn.trace_id(),
                        &list,
                        stream_id
                    );

                    self.largest_processed_request =
                        std::cmp::max(self.largest_processed_request, stream_id);

                    // We decide the response based on headers alone, so
                    // stop reading the request stream so that any body
                    // is ignored and pointless Data events are not
                    // generated.
                    conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0)
                        .unwrap();

                    let (headers, body, priority) =
                        Http3Conn::build_h3_response(root, index, &list);

                    match self.h3_conn.send_response_with_priority(
                        conn, stream_id, &headers, &priority, false,
                    ) {
                        Ok(v) => v,

                        Err(quiche::h3::Error::StreamBlocked) => {
                            let response = PartialResponse {
                                headers: Some(headers),
                                body,
                                written: 0,
                                fin: false,
                            };

                            partial_responses.insert(stream_id, response);
                            continue;
                        },

                        Err(e) => {
                            error!(
                                "{} stream send failed {:?}",
                                conn.trace_id(),
                                e
                            );

                            break;
                        },
                    }

                    let written = match self
                        .h3_conn
                        .send_body(conn, stream_id, &body, true)
                    {
                        Ok(v) => v,

                        Err(quiche::h3::Error::Done) => 0,

                        Err(e) => {
                            error!(
                                "{} stream send failed {:?}",
                                conn.trace_id(),
                                e
                            );

                            break;
                        },
                    };

                    if written < body.len() {
                        let response = PartialResponse {
                            headers: None,
                            body,
                            written,
                            fin: true,
                        };

                        partial_responses.insert(stream_id, response);
                    }
                },

                Ok((stream_id, quiche::h3::Event::Data)) => {
                    info!(
                        "{} got data on stream id {}",
                        conn.trace_id(),
                        stream_id
                    );
                },

                Ok((_stream_id, quiche::h3::Event::Finished)) => (),

                Ok((_, quiche::h3::Event::Datagram)) => {
                    let (len, flow_id, flow_id_len) =
                        self.h3_conn.recv_dgram(conn, buf).unwrap();

                    info!(
                        "Received DATAGRAM flow_id={} data={:?}",
                        flow_id,
                        &buf[flow_id_len..len].to_vec()
                    );
                },

                Ok((goaway_id, quiche::h3::Event::GoAway)) => {
                    trace!(
                        "{} got GOAWAY with ID {} ",
                        conn.trace_id(),
                        goaway_id
                    );
                    self.h3_conn
                        .send_goaway(conn, self.largest_processed_request)?;
                },

                Err(quiche::h3::Error::Done) => {
                    break;
                },

                Err(e) => {
                    error!("{} HTTP/3 error {:?}", conn.trace_id(), e);

                    return Err(e);
                },
            }
        }

        if let Some(ds) = self.dgram_sender.as_mut() {
            let mut dgrams_done = 0;

            for _ in ds.dgrams_sent..ds.dgram_count {
                info!(
                    "sending HTTP/3 DATAGRAM on flow_id={} with data {:?}",
                    ds.flow_id,
                    ds.dgram_content.as_bytes()
                );

                match self.h3_conn.send_dgram(
                    conn,
                    0,
                    ds.dgram_content.as_bytes(),
                ) {
                    Ok(v) => v,

                    Err(e) => {
                        error!("failed to send dgram {:?}", e);
                        break;
                    },
                }

                dgrams_done += 1;
            }

            ds.dgrams_sent += dgrams_done;
        }

        Ok(())
    }

    fn handle_writable(
        &mut self, conn: &mut std::pin::Pin<Box<quiche::Connection>>,
        partial_responses: &mut HashMap<u64, PartialResponse>, stream_id: u64,
    ) {
        debug!("{} stream {} is writable", conn.trace_id(), stream_id);

        if !partial_responses.contains_key(&stream_id) {
            return;
        }

        let resp = partial_responses.get_mut(&stream_id).unwrap();

        if let Some(ref headers) = resp.headers {
            match self.h3_conn.send_response(conn, stream_id, &headers, false) {
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

        let body = &resp.body[resp.written..];

        let written = match self.h3_conn.send_body(conn, stream_id, body, true) {
            Ok(v) => v,

            Err(quiche::h3::Error::Done) => {
                return;
            },

            Err(e) => {
                error!("{} stream send failed {:?}", conn.trace_id(), e);
                return;
            },
        };

        resp.written += written;

        if resp.written == resp.body.len() {
            partial_responses.remove(&stream_id);
        }
    }
}
