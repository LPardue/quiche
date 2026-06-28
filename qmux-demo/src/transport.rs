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

//! QMux transport over TLS streams.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;
use tokio_boring::SslStream;

use crate::Result;

/// Dummy address for QMux RecvInfo (addresses not used in QMux mode).
const DUMMY_ADDR: &str = "0.0.0.0:0";

/// QMux protocol over a TLS stream.
///
/// This handles buffering and I/O for the QMux protocol. Generic over the
/// underlying stream type (TcpStream, UnixStream, etc.).
pub struct QmuxOverTls<S> {
    stream: SslStream<S>,
    read_buf: Vec<u8>,
    read_len: usize,
    dummy_addr: SocketAddr,
    /// Maximum bytes per TLS write. 0 means unlimited (default).
    /// Setting this to a small value (e.g. 32) forces QMux records to span
    /// multiple TLS records, useful for testing desegmentation.
    max_tls_write: usize,
}

impl<S> QmuxOverTls<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Create a new carrier wrapping a TLS stream.
    pub fn new(stream: SslStream<S>) -> Self {
        Self {
            stream,
            read_buf: vec![0u8; 65536],
            read_len: 0,
            dummy_addr: DUMMY_ADDR.parse().unwrap(),
            max_tls_write: 0,
        }
    }

    /// Set the maximum bytes per TLS write.
    ///
    /// Setting this to a small value (e.g. 32) forces QMux records to be
    /// split across multiple TLS records, useful for testing Wireshark
    /// desegmentation.
    pub fn set_max_tls_write(&mut self, max: usize) {
        self.max_tls_write = max;
    }

    /// Read data from the TLS stream and feed it to the QMux connection.
    ///
    /// Returns `true` if data was read, `false` if the connection was closed.
    pub async fn recv(&mut self, conn: &mut quiche::Connection) -> Result<bool> {
        // Try to read more data from the stream.
        let n = match self.stream.read(&mut self.read_buf[self.read_len..]).await
        {
            Ok(0) => {
                log::trace!("TLS connection closed (read returned 0)");
                return Ok(false);
            },
            Ok(n) => n,
            Err(e) => {
                log::trace!("TLS read error: {:?}", e);
                return Err(e.into());
            },
        };
        log::trace!("TLS read {} bytes", n);
        self.read_len += n;

        // Process all complete QMux records in the buffer.
        self.process_records(conn)
    }

    /// Process all complete QMux records currently in the buffer.
    ///
    /// Each `conn.recv()` call processes one record. We loop until
    /// `Error::Done` indicates no more complete records are available.
    fn process_records(&mut self, conn: &mut quiche::Connection) -> Result<bool> {
        let recv_info = quiche::RecvInfo {
            from: self.dummy_addr,
            to: self.dummy_addr,
        };

        loop {
            if self.read_len == 0 {
                break;
            }

            match conn.recv(&mut self.read_buf[..self.read_len], recv_info) {
                Ok(consumed) => {
                    // Remove consumed data from buffer.
                    if consumed < self.read_len {
                        self.read_buf.copy_within(consumed..self.read_len, 0);
                    }
                    self.read_len -= consumed;
                },
                Err(quiche::Error::Done) => break,
                Err(e) => return Err(e.into()),
            }
        }

        Ok(true)
    }

    /// Write pending QMux output to the TLS stream.
    ///
    /// If `max_tls_write` is set, each QMux record is split into chunks
    /// of that size, each written as a separate TLS record. This is useful
    /// for testing Wireshark's QMux desegmentation.
    pub async fn send(&mut self, conn: &mut quiche::Connection) -> Result<()> {
        let mut out = [0u8; 65536];

        loop {
            let (written, _send_info) = match conn.send(&mut out) {
                Ok(v) => v,
                Err(quiche::Error::Done) => break,
                Err(e) => return Err(e.into()),
            };

            if self.max_tls_write > 0 {
                // Write in small chunks to force multiple TLS records.
                let mut pos = 0;
                while pos < written {
                    let end = std::cmp::min(pos + self.max_tls_write, written);
                    log::trace!("TLS write chunk {} bytes (of {})", end - pos, written);
                    self.stream.write_all(&out[pos..end]).await?;
                    self.stream.flush().await?;
                    pos = end;
                }
            } else {
                log::trace!("TLS write {} bytes", written);
                self.stream.write_all(&out[..written]).await?;
            }
        }

        self.stream.flush().await?;
        Ok(())
    }

    /// Drive I/O: send pending data and receive incoming data.
    ///
    /// Returns `false` if the connection was closed by the peer.
    pub async fn drive(&mut self, conn: &mut quiche::Connection) -> Result<bool> {
        // Send any pending output first.
        self.send(conn).await?;

        // Then try to receive.
        self.recv(conn).await
    }

    /// Try to receive data with a timeout.
    ///
    /// Returns:
    /// - `Ok(Some(true))` if data was read
    /// - `Ok(Some(false))` if the connection was closed
    /// - `Ok(None)` if timeout (no data available yet)
    pub async fn recv_timeout(
        &mut self, conn: &mut quiche::Connection, timeout: Duration,
    ) -> Result<Option<bool>> {
        match tokio::time::timeout(timeout, self.recv(conn)).await {
            Ok(result) => Ok(Some(result?)),
            Err(_) => Ok(None), // Timeout, no data
        }
    }

    /// Flush all pending output without waiting for input.
    pub async fn flush(&mut self, conn: &mut quiche::Connection) -> Result<()> {
        self.send(conn).await
    }
}
