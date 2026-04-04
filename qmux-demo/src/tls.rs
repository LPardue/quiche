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

//! TLS setup for QMux connections.

use boring::ssl::AlpnError;
use boring::ssl::SslAcceptor;
use boring::ssl::SslConnector;
use boring::ssl::SslFiletype;
use boring::ssl::SslMethod;
use boring::ssl::SslVerifyMode;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::net::TcpStream;
use tokio_boring::SslStream;

use crate::Error;
use crate::Result;
use crate::H3_OVER_QMUX_ALPN;
use crate::HQ_INTEROP_QMUX_ALPN;

/// Negotiated protocol after TLS handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiatedProtocol {
    /// HTTP/3 over QMux (h3qx-01)
    H3,
    /// HTTP/0.9 interop over QMux (hqx-01)
    HqInterop,
}

/// Create a TLS connector for QMux client connections with a specific ALPN.
///
/// The connector is configured with the specified ALPN and optionally a custom
/// CA certificate for server verification.
pub fn create_client_connector_with_alpn(
    alpn: &[u8], ca_cert: Option<&str>, verify: bool,
) -> std::result::Result<SslConnector, boring::error::ErrorStack> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;

    // Set ALPN protocols (wire format: length byte + protocol name).
    let mut alpn_wire = vec![alpn.len() as u8];
    alpn_wire.extend_from_slice(alpn);
    builder.set_alpn_protos(&alpn_wire)?;

    if !verify {
        builder.set_verify(SslVerifyMode::NONE);
    } else if let Some(ca) = ca_cert {
        builder.set_ca_file(ca)?;
    }

    Ok(builder.build())
}

/// Create a TLS connector for QMux client connections (HTTP/3).
///
/// The connector is configured with the h3qx-01 ALPN and optionally a custom
/// CA certificate for server verification.
pub fn create_client_connector(
    ca_cert: Option<&str>, verify: bool,
) -> std::result::Result<SslConnector, boring::error::ErrorStack> {
    create_client_connector_with_alpn(H3_OVER_QMUX_ALPN, ca_cert, verify)
}

/// Create a TLS acceptor for QMux server connections.
///
/// The acceptor is configured to accept both h3qx-01 and hqx-01
/// ALPNs, preferring h3qx-01.
pub fn create_server_acceptor(
    cert_path: &str, key_path: &str,
) -> std::result::Result<SslAcceptor, boring::error::ErrorStack> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;

    builder.set_certificate_chain_file(cert_path)?;
    builder.set_private_key_file(key_path, SslFiletype::PEM)?;

    // Set ALPN selection callback - accept both h3qx-01 and hqx-01.
    builder.set_alpn_select_callback(|_, client_protos| {
        // Prefer h3qx-01 if offered.
        if alpn_contains(client_protos, H3_OVER_QMUX_ALPN) {
            Ok(H3_OVER_QMUX_ALPN)
        } else if alpn_contains(client_protos, HQ_INTEROP_QMUX_ALPN) {
            Ok(HQ_INTEROP_QMUX_ALPN)
        } else {
            Err(AlpnError::NOACK)
        }
    });

    Ok(builder.build())
}

/// Check if ALPN protos list contains a specific protocol.
fn alpn_contains(protos: &[u8], target: &[u8]) -> bool {
    let mut i = 0;
    while i < protos.len() {
        let len = protos[i] as usize;
        if i + 1 + len > protos.len() {
            break;
        }
        if &protos[i + 1..i + 1 + len] == target {
            return true;
        }
        i += 1 + len;
    }
    false
}

/// Perform TLS client handshake on an existing stream.
///
/// Generic over the underlying stream type (TcpStream, UnixStream, etc.).
pub async fn connect_tls_stream<S>(
    stream: S, host: &str, connector: &SslConnector,
) -> Result<SslStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ssl = connector.configure()?.into_ssl(host)?;
    let stream = tokio_boring::SslStreamBuilder::new(ssl, stream)
        .connect()
        .await
        .map_err(|e| Error::Handshake(e.to_string()))?;

    // Verify an expected ALPN was negotiated.
    let alpn = stream.ssl().selected_alpn_protocol();
    if alpn != Some(H3_OVER_QMUX_ALPN) && alpn != Some(HQ_INTEROP_QMUX_ALPN) {
        return Err(Error::AlpnMismatch);
    }

    Ok(stream)
}

/// Connect to a server over TCP+TLS.
///
/// Returns the TLS stream. Use `get_negotiated_protocol()` to determine
/// which protocol was negotiated.
pub async fn connect_tls(
    addr: &str, host: &str, connector: &SslConnector,
) -> Result<SslStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    connect_tls_stream(tcp, host, connector).await
}

/// Perform TLS server handshake on an existing stream.
///
/// Generic over the underlying stream type (TcpStream, UnixStream, etc.).
pub async fn accept_tls_stream<S>(
    stream: S, acceptor: &SslAcceptor,
) -> Result<SslStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let stream = tokio_boring::accept(acceptor, stream)
        .await
        .map_err(|e| Error::Handshake(e.to_string()))?;
    Ok(stream)
}

/// Accept a TLS connection on an incoming TCP stream.
pub async fn accept_tls(
    tcp: TcpStream, acceptor: &SslAcceptor,
) -> Result<SslStream<TcpStream>> {
    accept_tls_stream(tcp, acceptor).await
}

/// Get the negotiated protocol from a TLS stream.
pub fn get_negotiated_protocol<S>(
    stream: &SslStream<S>,
) -> Option<NegotiatedProtocol> {
    match stream.ssl().selected_alpn_protocol() {
        Some(alpn) if alpn == H3_OVER_QMUX_ALPN => Some(NegotiatedProtocol::H3),
        Some(alpn) if alpn == HQ_INTEROP_QMUX_ALPN =>
            Some(NegotiatedProtocol::HqInterop),
        _ => None,
    }
}
