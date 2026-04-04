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

//! Error types for QMux demo.

use std::io;

use tokio::net::TcpStream;

/// Error type for QMux demo operations.
#[derive(Debug)]
pub enum Error {
    /// TLS error.
    Tls(boring::ssl::Error),
    /// I/O error.
    Io(io::Error),
    /// QUIC/QMux error.
    Quiche(quiche::Error),
    /// H3 error.
    H3(quiche::h3::Error),
    /// Connection closed by peer.
    ConnectionClosed,
    /// ALPN negotiation failed.
    AlpnMismatch,
    /// Handshake error.
    Handshake(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Tls(e) => write!(f, "TLS error: {}", e),
            Error::Io(e) => write!(f, "I/O error: {}", e),
            Error::Quiche(e) => write!(f, "QUIC error: {:?}", e),
            Error::H3(e) => write!(f, "H3 error: {:?}", e),
            Error::ConnectionClosed => write!(f, "connection closed"),
            Error::AlpnMismatch => write!(f, "ALPN negotiation failed"),
            Error::Handshake(s) => write!(f, "handshake error: {}", s),
        }
    }
}

impl std::error::Error for Error {}

impl From<boring::ssl::Error> for Error {
    fn from(e: boring::ssl::Error) -> Self {
        Error::Tls(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<quiche::Error> for Error {
    fn from(e: quiche::Error) -> Self {
        Error::Quiche(e)
    }
}

impl From<quiche::h3::Error> for Error {
    fn from(e: quiche::h3::Error) -> Self {
        Error::H3(e)
    }
}

impl From<boring::error::ErrorStack> for Error {
    fn from(e: boring::error::ErrorStack) -> Self {
        Error::Handshake(e.to_string())
    }
}

impl From<tokio_boring::HandshakeError<TcpStream>> for Error {
    fn from(e: tokio_boring::HandshakeError<TcpStream>) -> Self {
        Error::Handshake(format!("{:?}", e))
    }
}

/// Result type for QMux demo operations.
pub type Result<T> = std::result::Result<T, Error>;
