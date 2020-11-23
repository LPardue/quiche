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

use super::common::alpns;

pub trait Args {
    fn with_docopt(docopt: &docopt::Docopt) -> Self;
}

/// Contains commons arguments for creating a quiche QUIC connection.
pub struct CommonArgs {
    pub alpns: Vec<u8>,
    pub max_data: u64,
    pub max_stream_data: u64,
    pub max_streams_bidi: u64,
    pub max_streams_uni: u64,
    pub idle_timeout: u64,
    pub dump_packet_path: Option<String>,
    pub no_grease: bool,
    pub cc_algorithm: String,
    pub disable_hystart: bool,
    pub dgrams_enabled: bool,
    pub dgram_count: u64,
    pub dgram_data: String,
}

/// Creates a new `CommonArgs` structure using the provided [`Docopt`].
///
/// The `Docopt` usage String needs to include the following:
///
/// --http-version VERSION      HTTP version to use.
/// --max-data BYTES            Connection-wide flow control limit.
/// --max-stream-data BYTES     Per-stream flow control limit.
/// --max-streams-bidi STREAMS  Number of allowed concurrent streams.
/// --max-streams-uni STREAMS   Number of allowed concurrent streams.
/// --dump-packets PATH         Dump the incoming packets in PATH.
/// --no-grease                 Don't send GREASE.
/// --cc-algorithm NAME         Set a congestion control algorithm.
/// --disable-hystart           Disable HyStart++.
/// --dgram-proto PROTO         DATAGRAM application protocol.
/// --dgram-count COUNT         Number of DATAGRAMs to send.
///  --dgram-data DATA          DATAGRAM data to send.
///
/// [`Docopt`]: https://docs.rs/docopt/1.1.0/docopt/
impl Args for CommonArgs {
    fn with_docopt(docopt: &docopt::Docopt) -> Self {
        let args = docopt.parse().unwrap_or_else(|e| e.exit());

        let http_version = args.get_str("--http-version");
        let dgram_proto = args.get_str("--dgram-proto");
        let (alpns, dgrams_enabled) = match (http_version, dgram_proto) {
            ("HTTP/0.9", "none") =>
                (alpns::length_prefixed(&alpns::HTTP_09), false),

            ("HTTP/0.9", _) =>
                panic!("Unsupported HTTP version and DATAGRAM protocol."),

            ("HTTP/3", "none") => (alpns::length_prefixed(&alpns::HTTP_3), false),

            ("HTTP/3", "oneway") =>
                (alpns::length_prefixed(&alpns::HTTP_3), true),

            ("all", "none") => (
                [
                    alpns::length_prefixed(&alpns::HTTP_3),
                    alpns::length_prefixed(&alpns::HTTP_09),
                ]
                .concat(),
                false,
            ),

            // SiDuck is it's own application protocol.
            (_, "siduck") => (alpns::length_prefixed(&alpns::SIDUCK), true),

            (..) => panic!("Unsupported HTTP version and DATAGRAM protocol."),
        };

        let dgram_count = args.get_str("--dgram-count");
        let dgram_count = u64::from_str_radix(dgram_count, 10).unwrap();

        let dgram_data = args.get_str("--dgram-data").to_string();

        let max_data = args.get_str("--max-data");
        let max_data = u64::from_str_radix(max_data, 10).unwrap();

        let max_stream_data = args.get_str("--max-stream-data");
        let max_stream_data = u64::from_str_radix(max_stream_data, 10).unwrap();

        let max_streams_bidi = args.get_str("--max-streams-bidi");
        let max_streams_bidi = u64::from_str_radix(max_streams_bidi, 10).unwrap();

        let max_streams_uni = args.get_str("--max-streams-uni");
        let max_streams_uni = u64::from_str_radix(max_streams_uni, 10).unwrap();

        let idle_timeout = args.get_str("--idle-timeout");
        let idle_timeout = u64::from_str_radix(idle_timeout, 10).unwrap();

        let dump_packet_path = if args.get_str("--dump-packets") != "" {
            Some(args.get_str("--dump-packets").to_string())
        } else {
            None
        };

        let no_grease = args.get_bool("--no-grease");

        let cc_algorithm = args.get_str("--cc-algorithm");

        let disable_hystart = args.get_bool("--disable-hystart");

        CommonArgs {
            alpns,
            max_data,
            max_stream_data,
            max_streams_bidi,
            max_streams_uni,
            idle_timeout,
            dump_packet_path,
            no_grease,
            cc_algorithm: cc_algorithm.to_string(),
            disable_hystart,
            dgrams_enabled,
            dgram_count,
            dgram_data,
        }
    }
}

pub const CLIENT_USAGE: &str = "Usage:
  quiche-client [options] URL...
  quiche-client -h | --help

Options:
  --method METHOD          Use the given HTTP request method [default: GET].
  --body FILE              Send the given file as request body.
  --max-data BYTES         Connection-wide flow control limit [default: 10000000].
  --max-stream-data BYTES  Per-stream flow control limit [default: 1000000].
  --max-streams-bidi STREAMS  Number of allowed concurrent streams [default: 100].
  --max-streams-uni STREAMS   Number of allowed concurrent streams [default: 100].
  --idle-timeout TIMEOUT   Idle timeout in milliseconds [default: 30000].
  --wire-version VERSION   The version number to send to the server [default: babababa].
  --http-version VERSION   HTTP version to use [default: all].
  --dgram-proto PROTO      DATAGRAM application protocol to use [default: none].
  --dgram-count COUNT      Number of DATAGRAMs to send [default: 0].
  --dgram-data DATA        Data to send for certain types of DATAGRAM application protocol [default: quack].
  --dump-packets PATH      Dump the incoming packets as files in the given directory.
  --dump-responses PATH    Dump response payload as files in the given directory.
  --dump-json              Dump response headers and payload to stdout.
  --connect-to ADDRESS     Override ther server's address.
  --no-verify              Don't verify server's certificate.
  --no-grease              Don't send GREASE.
  --cc-algorithm NAME      Specify which congestion control algorithm to use [default: cubic].
  --disable-hystart        Disable HyStart++.
  -H --header HEADER ...   Add a request header.
  -n --requests REQUESTS   Send the given number of identical requests [default: 1].
  -h --help                Show this screen.
";

/// Application-specific arguments that compliment the `CommonArgs`.
pub struct ClientArgs {
    pub version: u32,
    pub dump_response_path: Option<String>,
    pub dump_json: bool,
    pub urls: Vec<url::Url>,
    pub reqs_cardinal: u64,
    pub req_headers: Vec<String>,
    pub no_verify: bool,
    pub body: Option<Vec<u8>>,
    pub method: String,
    pub connect_to: Option<String>,
}

impl Args for ClientArgs {
    fn with_docopt(docopt: &docopt::Docopt) -> Self {
        let args = docopt.parse().unwrap_or_else(|e| e.exit());

        let version = args.get_str("--wire-version");
        let version = u32::from_str_radix(version, 16).unwrap();

        let dump_response_path = if args.get_str("--dump-responses") != "" {
            Some(args.get_str("--dump-responses").to_string())
        } else {
            None
        };

        let dump_json = args.get_bool("--dump-json");

        // URLs (can be multiple).
        let urls: Vec<url::Url> = args
            .get_vec("URL")
            .into_iter()
            .map(|x| url::Url::parse(x).unwrap())
            .collect();

        // Request headers (can be multiple).
        let req_headers = args
            .get_vec("--header")
            .into_iter()
            .map(|x| x.to_string())
            .collect();

        let reqs_cardinal = args.get_str("--requests");
        let reqs_cardinal = u64::from_str_radix(reqs_cardinal, 10).unwrap();

        let no_verify = args.get_bool("--no-verify");

        let body = if args.get_bool("--body") {
            std::fs::read(args.get_str("--body")).ok()
        } else {
            None
        };

        let method = args.get_str("--method").to_string();

        let connect_to = if args.get_bool("--connect-to") {
            Some(args.get_str("--connect-to").to_string())
        } else {
            None
        };

        ClientArgs {
            version,
            dump_response_path,
            dump_json,
            urls,
            req_headers,
            reqs_cardinal,
            no_verify,
            body,
            method,
            connect_to,
        }
    }
}

pub const SERVER_USAGE: &str = "Usage:
  quiche-server [options]
  quiche-server -h | --help

Options:
  --listen <addr>             Listen on the given IP:port [default: 127.0.0.1:4433]
  --cert <file>               TLS certificate path [default: src/bin/cert.crt]
  --key <file>                TLS certificate key path [default: src/bin/cert.key]
  --root <dir>                Root directory [default: src/bin/root/]
  --index <name>              The file that will be used as index [default: index.html].
  --name <str>                Name of the server [default: quic.tech]
  --max-data BYTES            Connection-wide flow control limit [default: 10000000].
  --max-stream-data BYTES     Per-stream flow control limit [default: 1000000].
  --max-streams-bidi STREAMS  Number of allowed concurrent streams [default: 100].
  --max-streams-uni STREAMS   Number of allowed concurrent streams [default: 100].
  --idle-timeout TIMEOUT   Idle timeout in milliseconds [default: 30000].
  --dump-packets PATH         Dump the incoming packets as files in the given directory.
  --early-data                Enables receiving early data.
  --no-retry                  Disable stateless retry.
  --no-grease                 Don't send GREASE.
  --http-version VERSION      HTTP version to use [default: all].
  --dgram-proto PROTO         DATAGRAM application protocol to use [default: none].
  --dgram-count COUNT         Number of DATAGRAMs to send [default: 0].
  --dgram-data DATA           Data to send for certain types of DATAGRAM application protocol [default: brrr].
  --masque                    Enable MASQUE proxy mode.
  --masque-secret <str>       Secret required to be sent by MASQUE clients.
  --no-verify                 Don't verify server's certificate. (Only when connecting to proxy).
  --cc-algorithm NAME         Specify which congestion control algorithm to use [default: cubic].
  --disable-hystart           Disable HyStart++.
  -h --help                   Show this screen.
";

// Application-specific arguments that compliment the `CommonArgs`.
pub struct ServerArgs {
    pub listen: String,
    pub no_retry: bool,
    pub root: String,
    pub index: String,
    pub cert: String,
    pub key: String,
    pub early_data: bool,
    pub masque: bool,
    pub masque_secret: Option<String>,
    pub no_verify: bool,
}

impl Args for ServerArgs {
    fn with_docopt(docopt: &docopt::Docopt) -> Self {
        let args = docopt.parse().unwrap_or_else(|e| e.exit());

        let listen = args.get_str("--listen").to_string();
        let no_retry = args.get_bool("--no-retry");
        let early_data = args.get_bool("--early-data");
        let root = args.get_str("--root").to_string();
        let index = args.get_str("--index").to_string();
        let cert = args.get_str("--cert").to_string();
        let key = args.get_str("--key").to_string();
        let masque = args.get_bool("--masque");
        let masque_secret = if args.get_str("--masque-secret") != "" {
            Some(args.get_str("--masque-secret").to_string())
        } else {
            None
        };
        let no_verify = args.get_bool("--no-verify");

        ServerArgs {
            listen,
            no_retry,
            root,
            index,
            cert,
            key,
            early_data,
            masque,
            masque_secret,
            no_verify,
        }
    }
}
