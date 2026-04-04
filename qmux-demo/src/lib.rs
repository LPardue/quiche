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

//! QMux demo utilities.
//!
//! This crate provides utilities for running HTTP/3 over QMux (QUIC
//! multiplexing over TCP+TLS).

mod config;
mod error;
mod tls;
mod transport;

// Re-export the ALPN constant from quiche.
pub use quiche::H3_OVER_QMUX_ALPN;

/// ALPN for HTTP/0.9 (hq-interop) over QMux.
pub const HQ_INTEROP_QMUX_ALPN: &[u8] = b"hqx-01";

// Re-export error types.
pub use error::Error;
pub use error::Result;

// Re-export TLS utilities.
pub use tls::accept_tls;
pub use tls::accept_tls_stream;
pub use tls::connect_tls;
pub use tls::connect_tls_stream;
pub use tls::create_client_connector;
pub use tls::create_client_connector_with_alpn;
pub use tls::create_server_acceptor;
pub use tls::get_negotiated_protocol;
pub use tls::NegotiatedProtocol;

// Re-export transport.
pub use transport::QmuxOverTls;

// Re-export config helper.
pub use config::create_qmux_config;

/// Set up qlog on a connection if QLOGDIR env var is set.
///
/// Uses unix timestamp for unique filenames: `{role}-{timestamp}.sqlog`
/// Sets qlog level to Extra to capture FramesProcessed events (QMux frame-level
/// logging).
pub fn setup_qlog(conn: &mut quiche::Connection, role: &str) {
    if let Some(dir) = std::env::var_os("QLOGDIR") {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let filename = format!("{}-{}.sqlog", role, ts);
        let path = std::path::Path::new(&dir).join(&filename);
        let file =
            std::fs::File::create(&path).expect("failed to create qlog file");
        let writer = std::io::BufWriter::new(file);
        conn.set_qlog_with_level(
            Box::new(writer),
            format!("qmux-{} qlog", role),
            format!("qmux-{} {}", role, ts),
            quiche::QlogLevel::Extra,
        );
        log::info!("Writing qlog to {:?}", path);
    }
}
