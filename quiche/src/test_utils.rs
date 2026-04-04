// Copyright (C) 2025, Cloudflare, Inc.
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

use super::*;

use smallvec::smallvec;

use crate::recovery::Sent;

/// Trait for test pipe implementations that provide client/server connections.
///
/// This allows H3 tests to be generic over the underlying transport (QUIC or
/// QMux).
pub trait TestPipe {
    /// The buffer factory type used by connections in this pipe.
    type BufFactory: BufFactory;

    /// Returns mutable reference to the client connection.
    fn client(&mut self) -> &mut Connection<Self::BufFactory>;

    /// Returns mutable reference to the server connection.
    fn server(&mut self) -> &mut Connection<Self::BufFactory>;

    /// Advances the pipe, exchanging data between client and server.
    fn advance(&mut self) -> Result<()>;

    /// Performs any necessary handshake (QUIC TLS handshake, or no-op for
    /// QMux).
    fn handshake(&mut self) -> Result<()>;

    /// Sends frames from client to server.
    ///
    /// For QUIC, this wraps frames in a packet. For QMux, frames are sent
    /// directly. Returns the number of bytes consumed by the server.
    fn send_frames_to_server(
        &mut self, frames: &[frame::Frame], buf: &mut [u8],
    ) -> Result<usize>;
}

pub struct Pipe<F = DefaultBufFactory>
where
    F: BufFactory,
{
    pub client: Connection<F>,
    pub server: Connection<F>,
}

impl Pipe {
    pub fn default_config(cc_algorithm_name: &str) -> Result<Config> {
        let mut config = Config::new(PROTOCOL_VERSION)?;
        assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
        config.load_cert_chain_from_pem_file("examples/cert.crt")?;
        config.load_priv_key_from_pem_file("examples/cert.key")?;
        config.set_application_protos(&[b"proto1", b"proto2"])?;
        config.set_initial_max_data(30);
        config.set_initial_max_stream_data_bidi_local(15);
        config.set_initial_max_stream_data_bidi_remote(15);
        config.set_initial_max_stream_data_uni(10);
        config.set_initial_max_streams_bidi(3);
        config.set_initial_max_streams_uni(3);
        config.set_max_idle_timeout(180_000);
        config.verify_peer(false);
        config.set_ack_delay_exponent(8);
        Ok(config)
    }

    #[cfg(feature = "boringssl-boring-crate")]
    pub fn default_tls_ctx_builder() -> boring::ssl::SslContextBuilder {
        let mut ctx_builder =
            boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls())
                .unwrap();
        ctx_builder
            .set_certificate_chain_file("examples/cert.crt")
            .unwrap();
        ctx_builder
            .set_private_key_file(
                "examples/cert.key",
                boring::ssl::SslFiletype::PEM,
            )
            .unwrap();

        ctx_builder
    }

    pub fn client_addr() -> SocketAddr {
        "127.0.0.1:1234".parse().unwrap()
    }

    pub fn server_addr() -> SocketAddr {
        "127.0.0.1:4321".parse().unwrap()
    }

    pub fn new(cc_algorithm_name: &str) -> Result<Pipe> {
        let mut config = Self::default_config(cc_algorithm_name)?;
        Pipe::with_config(&mut config)
    }

    pub fn with_config(config: &mut Config) -> Result<Pipe> {
        Pipe::<DefaultBufFactory>::with_config_and_buf(config)
    }

    pub fn with_config_and_scid_lengths(
        config: &mut Config, client_scid_len: usize, server_scid_len: usize,
    ) -> Result<Pipe> {
        Pipe::<DefaultBufFactory>::with_config_and_scid_lengths_and_buf(
            config,
            client_scid_len,
            server_scid_len,
        )
    }

    pub fn with_client_config(client_config: &mut Config) -> Result<Pipe> {
        Pipe::<DefaultBufFactory>::with_client_config_and_buf(client_config)
    }

    pub fn with_server_config(server_config: &mut Config) -> Result<Pipe> {
        Pipe::<DefaultBufFactory>::with_server_config_and_buf(server_config)
    }

    pub fn with_client_and_server_config(
        client_config: &mut Config, server_config: &mut Config,
    ) -> Result<Pipe> {
        Pipe::<DefaultBufFactory>::with_client_and_server_config_and_buf(
            client_config,
            server_config,
        )
    }
}

impl<F: BufFactory> Pipe<F> {
    pub fn new_with_buf(cc_algorithm_name: &str) -> Result<Pipe<F>> {
        let mut config = Pipe::default_config(cc_algorithm_name)?;
        Pipe::with_config_and_buf(&mut config)
    }

    pub fn with_config_and_buf(config: &mut Config) -> Result<Pipe<F>> {
        let mut client_scid = [0; 16];
        rand::rand_bytes(&mut client_scid[..]);
        let client_scid = ConnectionId::from_ref(&client_scid);
        let client_addr = Pipe::client_addr();

        let mut server_scid = [0; 16];
        rand::rand_bytes(&mut server_scid[..]);
        let server_scid = ConnectionId::from_ref(&server_scid);
        let server_addr = Pipe::server_addr();

        Ok(Pipe {
            client: connect_with_buffer_factory(
                Some("quic.tech"),
                &client_scid,
                client_addr,
                server_addr,
                config,
            )?,
            server: accept_with_buf_factory(
                &server_scid,
                None,
                server_addr,
                client_addr,
                config,
            )?,
        })
    }

    pub fn with_config_and_scid_lengths_and_buf(
        config: &mut Config, client_scid_len: usize, server_scid_len: usize,
    ) -> Result<Pipe<F>> {
        let mut client_scid = vec![0; client_scid_len];
        rand::rand_bytes(&mut client_scid[..]);
        let client_scid = ConnectionId::from_ref(&client_scid);
        let client_addr = Pipe::client_addr();

        let mut server_scid = vec![0; server_scid_len];
        rand::rand_bytes(&mut server_scid[..]);
        let server_scid = ConnectionId::from_ref(&server_scid);
        let server_addr = Pipe::server_addr();

        Ok(Pipe {
            client: connect_with_buffer_factory(
                Some("quic.tech"),
                &client_scid,
                client_addr,
                server_addr,
                config,
            )?,
            server: accept_with_buf_factory(
                &server_scid,
                None,
                server_addr,
                client_addr,
                config,
            )?,
        })
    }

    pub fn with_client_config_and_buf(
        client_config: &mut Config,
    ) -> Result<Pipe<F>> {
        let mut client_scid = [0; 16];
        rand::rand_bytes(&mut client_scid[..]);
        let client_scid = ConnectionId::from_ref(&client_scid);
        let client_addr = Pipe::client_addr();

        let mut server_scid = [0; 16];
        rand::rand_bytes(&mut server_scid[..]);
        let server_scid = ConnectionId::from_ref(&server_scid);
        let server_addr = Pipe::server_addr();

        let mut config = Config::new(PROTOCOL_VERSION)?;
        config.load_cert_chain_from_pem_file("examples/cert.crt")?;
        config.load_priv_key_from_pem_file("examples/cert.key")?;
        config.set_application_protos(&[b"proto1", b"proto2"])?;
        config.set_initial_max_data(30);
        config.set_initial_max_stream_data_bidi_local(15);
        config.set_initial_max_stream_data_bidi_remote(15);
        config.set_initial_max_streams_bidi(3);
        config.set_initial_max_streams_uni(3);
        config.set_ack_delay_exponent(8);

        Ok(Pipe {
            client: connect_with_buffer_factory(
                Some("quic.tech"),
                &client_scid,
                client_addr,
                server_addr,
                client_config,
            )?,
            server: accept_with_buf_factory(
                &server_scid,
                None,
                server_addr,
                client_addr,
                &mut config,
            )?,
        })
    }

    pub fn with_server_config_and_buf(
        server_config: &mut Config,
    ) -> Result<Pipe<F>> {
        let mut client_scid = [0; 16];
        rand::rand_bytes(&mut client_scid[..]);
        let client_scid = ConnectionId::from_ref(&client_scid);
        let client_addr = Pipe::client_addr();

        let mut server_scid = [0; 16];
        rand::rand_bytes(&mut server_scid[..]);
        let server_scid = ConnectionId::from_ref(&server_scid);
        let server_addr = Pipe::server_addr();

        let mut config = Config::new(PROTOCOL_VERSION)?;
        config.set_application_protos(&[b"proto1", b"proto2"])?;
        config.set_initial_max_data(30);
        config.set_initial_max_stream_data_bidi_local(15);
        config.set_initial_max_stream_data_bidi_remote(15);
        config.set_initial_max_streams_bidi(3);
        config.set_initial_max_streams_uni(3);
        config.set_ack_delay_exponent(8);

        Ok(Pipe {
            client: connect_with_buffer_factory(
                Some("quic.tech"),
                &client_scid,
                client_addr,
                server_addr,
                &mut config,
            )?,
            server: accept_with_buf_factory(
                &server_scid,
                None,
                server_addr,
                client_addr,
                server_config,
            )?,
        })
    }

    pub fn with_client_and_server_config_and_buf(
        client_config: &mut Config, server_config: &mut Config,
    ) -> Result<Pipe<F>> {
        let mut client_scid = [0; 16];
        rand::rand_bytes(&mut client_scid[..]);
        let client_scid = ConnectionId::from_ref(&client_scid);
        let client_addr = Pipe::client_addr();

        let mut server_scid = [0; 16];
        rand::rand_bytes(&mut server_scid[..]);
        let server_scid = ConnectionId::from_ref(&server_scid);
        let server_addr = Pipe::server_addr();

        Ok(Pipe {
            client: connect_with_buffer_factory(
                Some("quic.tech"),
                &client_scid,
                client_addr,
                server_addr,
                client_config,
            )?,
            server: accept_with_buf_factory(
                &server_scid,
                None,
                server_addr,
                client_addr,
                server_config,
            )?,
        })
    }

    pub fn handshake(&mut self) -> Result<()> {
        while !self.client.is_established() || !self.server.is_established() {
            let flight = emit_flight(&mut self.client)?;
            process_flight(&mut self.server, flight)?;

            let flight = emit_flight(&mut self.server)?;
            process_flight(&mut self.client, flight)?;
        }

        Ok(())
    }

    pub fn advance(&mut self) -> Result<()> {
        let mut client_done = false;
        let mut server_done = false;

        while !client_done || !server_done {
            match emit_flight(&mut self.client) {
                Ok(flight) => process_flight(&mut self.server, flight)?,

                Err(Error::Done) => client_done = true,

                Err(e) => return Err(e),
            };

            match emit_flight(&mut self.server) {
                Ok(flight) => process_flight(&mut self.client, flight)?,

                Err(Error::Done) => server_done = true,

                Err(e) => return Err(e),
            };
        }

        Ok(())
    }

    pub fn client_recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let server_path = &self.server.paths.get_active().unwrap();
        let info = RecvInfo {
            to: server_path.peer_addr(),
            from: server_path.local_addr(),
        };

        self.client.recv(buf, info)
    }

    pub fn server_recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let client_path = &self.client.paths.get_active().unwrap();
        let info = RecvInfo {
            to: client_path.peer_addr(),
            from: client_path.local_addr(),
        };

        self.server.recv(buf, info)
    }

    pub fn send_pkt_to_server(
        &mut self, pkt_type: Type, frames: &[frame::Frame], buf: &mut [u8],
    ) -> Result<usize> {
        let written = encode_pkt(&mut self.client, pkt_type, frames, buf)?;
        recv_send(&mut self.server, buf, written)
    }

    pub fn client_update_key(&mut self) -> Result<()> {
        let crypto_ctx = &mut self.client.crypto_ctx[packet::Epoch::Application];

        let open_next = crypto_ctx
            .crypto_open
            .as_ref()
            .unwrap()
            .derive_next_packet_key()
            .unwrap();

        let seal_next = crypto_ctx
            .crypto_seal
            .as_ref()
            .unwrap()
            .derive_next_packet_key()?;

        let open_prev = crypto_ctx.crypto_open.replace(open_next);
        crypto_ctx.crypto_seal.replace(seal_next);

        crypto_ctx.key_update = Some(packet::KeyUpdate {
            crypto_open: open_prev.unwrap(),
            pn_on_update: self.client.next_pkt_num,
            update_acked: true,
            timer: Instant::now(),
        });

        self.client.key_phase = !self.client.key_phase;

        Ok(())
    }
}

impl<F: BufFactory> TestPipe for Pipe<F> {
    type BufFactory = F;

    fn client(&mut self) -> &mut Connection<Self::BufFactory> {
        &mut self.client
    }

    fn server(&mut self) -> &mut Connection<Self::BufFactory> {
        &mut self.server
    }

    fn advance(&mut self) -> Result<()> {
        Pipe::advance(self)
    }

    fn handshake(&mut self) -> Result<()> {
        Pipe::handshake(self)
    }

    fn send_frames_to_server(
        &mut self, frames: &[frame::Frame], buf: &mut [u8],
    ) -> Result<usize> {
        self.send_pkt_to_server(Type::Short, frames, buf)
    }
}

pub fn recv_send<F: BufFactory>(
    conn: &mut Connection<F>, buf: &mut [u8], len: usize,
) -> Result<usize> {
    let active_path = conn.paths.get_active()?;
    let info = RecvInfo {
        to: active_path.local_addr(),
        from: active_path.peer_addr(),
    };

    conn.recv(&mut buf[..len], info)?;

    let mut off = 0;

    match conn.send(&mut buf[off..]) {
        Ok((write, _)) => off += write,

        Err(Error::Done) => (),

        Err(e) => return Err(e),
    }

    Ok(off)
}

pub fn process_flight<F: BufFactory>(
    conn: &mut Connection<F>, flight: Vec<(Vec<u8>, SendInfo)>,
) -> Result<()> {
    for (mut pkt, si) in flight {
        let info = RecvInfo {
            to: si.to,
            from: si.from,
        };

        conn.recv(&mut pkt, info)?;
    }

    Ok(())
}

pub fn emit_flight_with_max_buffer<F: BufFactory>(
    conn: &mut Connection<F>, out_size: usize, from: Option<SocketAddr>,
    to: Option<SocketAddr>,
) -> Result<Vec<(Vec<u8>, SendInfo)>> {
    let mut flight = Vec::new();

    loop {
        let mut out = vec![0u8; out_size];

        let info = match conn.send_on_path(&mut out, from, to) {
            Ok((written, info)) => {
                out.truncate(written);
                info
            },

            Err(Error::Done) => break,

            Err(e) => return Err(e),
        };

        flight.push((out, info));
    }

    if flight.is_empty() {
        return Err(Error::Done);
    }

    Ok(flight)
}

pub fn emit_flight_on_path<F: BufFactory>(
    conn: &mut Connection<F>, from: Option<SocketAddr>, to: Option<SocketAddr>,
) -> Result<Vec<(Vec<u8>, SendInfo)>> {
    emit_flight_with_max_buffer(conn, 65535, from, to)
}

pub fn emit_flight<F: BufFactory>(
    conn: &mut Connection<F>,
) -> Result<Vec<(Vec<u8>, SendInfo)>> {
    emit_flight_on_path(conn, None, None)
}

pub fn encode_pkt<F: BufFactory>(
    conn: &mut Connection<F>, pkt_type: Type, frames: &[frame::Frame],
    buf: &mut [u8],
) -> Result<usize> {
    let mut b = octets::OctetsMut::with_slice(buf);

    let epoch = pkt_type.to_epoch()?;

    let crypto_ctx = &mut conn.crypto_ctx[epoch];

    let pn = conn.next_pkt_num;
    let pn_len = 4;

    let send_path = conn.paths.get_active()?;
    let active_dcid_seq = send_path
        .active_dcid_seq
        .as_ref()
        .ok_or(Error::InvalidState)?;
    let active_scid_seq = send_path
        .active_scid_seq
        .as_ref()
        .ok_or(Error::InvalidState)?;

    let hdr = Header {
        ty: pkt_type,
        version: conn.version,
        dcid: ConnectionId::from_ref(
            conn.ids.get_dcid(*active_dcid_seq)?.cid.as_ref(),
        ),
        scid: ConnectionId::from_ref(
            conn.ids.get_scid(*active_scid_seq)?.cid.as_ref(),
        ),
        pkt_num: pn,
        pkt_num_len: pn_len,
        token: conn.token.clone(),
        versions: None,
        key_phase: conn.key_phase,
    };

    hdr.to_bytes(&mut b)?;

    let payload_len = frames.iter().fold(0, |acc, x| acc + x.wire_len());

    if pkt_type != Type::Short {
        let len = pn_len + payload_len + crypto_ctx.crypto_overhead().unwrap();
        b.put_varint(len as u64)?;
    }

    // Always encode packet number in 4 bytes, to allow encoding packets
    // with empty payloads.
    b.put_u32(pn as u32)?;

    let payload_offset = b.off();

    for frame in frames {
        frame.to_bytes(&mut b)?;
    }

    let aead = match crypto_ctx.crypto_seal {
        Some(ref mut v) => v,
        None => return Err(Error::InvalidState),
    };

    let written = packet::encrypt_pkt(
        &mut b,
        pn,
        pn_len,
        payload_len,
        payload_offset,
        None,
        aead,
    )?;

    conn.next_pkt_num += 1;

    Ok(written)
}

pub fn decode_pkt<F: BufFactory>(
    conn: &mut Connection<F>, buf: &mut [u8],
) -> Result<Vec<frame::Frame>> {
    let mut b = octets::OctetsMut::with_slice(buf);

    let mut hdr = Header::from_bytes(&mut b, conn.source_id().len()).unwrap();

    let epoch = hdr.ty.to_epoch()?;

    let aead = conn.crypto_ctx[epoch].crypto_open.as_ref().unwrap();

    let payload_len = b.cap();

    packet::decrypt_hdr(&mut b, &mut hdr, aead).unwrap();

    let pn = packet::decode_pkt_num(
        conn.pkt_num_spaces[epoch].largest_rx_pkt_num,
        hdr.pkt_num,
        hdr.pkt_num_len,
    );

    let mut payload =
        packet::decrypt_pkt(&mut b, pn, hdr.pkt_num_len, payload_len, aead)
            .unwrap();

    let mut frames = Vec::new();

    while payload.cap() > 0 {
        let frame = frame::Frame::from_bytes(&mut payload, hdr.ty)?;
        frames.push(frame);
    }

    Ok(frames)
}

pub fn create_cid_and_reset_token(
    cid_len: usize,
) -> (ConnectionId<'static>, u128) {
    let mut cid = vec![0; cid_len];
    rand::rand_bytes(&mut cid[..]);
    let cid = ConnectionId::from(cid);

    let mut reset_token = [0; 16];
    rand::rand_bytes(&mut reset_token);
    let reset_token = u128::from_be_bytes(reset_token);

    (cid, reset_token)
}

pub fn helper_packet_sent(pkt_num: u64, now: Instant, size: usize) -> Sent {
    Sent {
        pkt_num,
        frames: smallvec![],
        time_sent: now,
        time_acked: None,
        time_lost: None,
        size,
        ack_eliciting: true,
        in_flight: true,
        delivered: 0,
        delivered_time: now,
        first_sent_time: now,
        is_app_limited: false,
        tx_in_flight: 0,
        lost: 0,
        has_data: true,
        is_pmtud_probe: false,
    }
}

// Helper function for testing either stream receive or discard.
pub fn stream_recv_discard<F: BufFactory>(
    conn: &mut Connection<F>, discard: bool, stream_id: u64,
) -> Result<(usize, bool)> {
    let mut buf = [0; 65535];
    if discard {
        conn.stream_discard(stream_id, 65535)
    } else {
        conn.stream_recv(stream_id, &mut buf)
    }
}

/// Triggers ACK-based loss detection for packets sent by `sender` before this
/// call.
///
/// This works by sending multiple PING packets from the sender and having the
/// receiver ACK them. Since loss detection uses a packet threshold, this
/// function sends as many packets as needed to ensure any previously
/// unacknowledged packets from the sender are detected as lost.
#[cfg(test)]
pub fn trigger_ack_based_loss<F: BufFactory>(
    sender: &mut Connection<F>, receiver: &mut Connection<F>,
) {
    let mut buf = [0; 65535];

    // Use the active path's packet loss threshold.
    let pkt_thresh = sender
        .paths
        .get_active()
        .unwrap()
        .recovery
        .pkt_thresh()
        .unwrap();

    for _ in 0..pkt_thresh {
        sender.send_ack_eliciting().unwrap();
        let (len, _) = sender.send(&mut buf).unwrap();

        let info = RecvInfo {
            to: receiver.paths.get_active().unwrap().local_addr(),
            from: receiver.paths.get_active().unwrap().peer_addr(),
        };
        receiver.recv(&mut buf[..len], info).unwrap();
    }

    // Receiver sends ACK for the new packets.
    let (ack_len, _) = receiver.send(&mut buf).unwrap();

    // Sender receives ACK, triggering loss detection.
    let info = RecvInfo {
        to: sender.paths.get_active().unwrap().local_addr(),
        from: sender.paths.get_active().unwrap().peer_addr(),
    };
    sender.recv(&mut buf[..ack_len], info).unwrap();
}

// ============================================================================
// QMux test utilities
// ============================================================================

/// Test utility for QMux connections.
///
/// QmuxPipe provides a pair of QMux connections (client and server) that
/// can exchange data via in-memory byte buffers. Unlike the regular QUIC
/// Pipe, QMux doesn't require packet encryption or TLS handshake.
#[cfg(feature = "qmux")]
pub struct QmuxPipe {
    pub client: Connection,
    pub server: Connection,
}

#[cfg(feature = "qmux")]
impl QmuxPipe {
    /// Creates a default QMux configuration.
    pub fn default_config() -> Result<Config> {
        let mut config = Config::new(PROTOCOL_VERSION)?;
        config.load_cert_chain_from_pem_file("examples/cert.crt")?;
        config.load_priv_key_from_pem_file("examples/cert.key")?;
        config.set_application_protos(&[H3_OVER_QMUX_ALPN])?;
        config.set_initial_max_data(1_000_000);
        config.set_initial_max_stream_data_bidi_local(100_000);
        config.set_initial_max_stream_data_bidi_remote(100_000);
        config.set_initial_max_stream_data_uni(100_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_max_idle_timeout(30_000);
        config.verify_peer(false);
        config.enable_dgram(true, 3, 3);
        config.enable_qmux(true);
        Ok(config)
    }

    /// Creates a new QmuxPipe with default configuration.
    pub fn new() -> Result<QmuxPipe> {
        let mut config = Self::default_config()?;
        Self::with_config(&mut config)
    }

    /// Creates a new QmuxPipe with custom configuration.
    pub fn with_config(config: &mut Config) -> Result<QmuxPipe> {
        let mut client_scid = [0; 16];
        rand::rand_bytes(&mut client_scid[..]);
        let client_scid = ConnectionId::from_ref(&client_scid);
        let client_addr = "127.0.0.1:1234".parse().unwrap();

        let mut server_scid = [0; 16];
        rand::rand_bytes(&mut server_scid[..]);
        let server_scid = ConnectionId::from_ref(&server_scid);
        let server_addr = "127.0.0.1:4321".parse().unwrap();

        let mut client = connect(
            Some("localhost"),
            &client_scid,
            client_addr,
            server_addr,
            config,
        )?;

        let mut server =
            accept(&server_scid, None, server_addr, client_addr, config)?;

        // Perform QMux handshake by exchanging QX_TRANSPORT_PARAMETERS.
        let mut buf = [0u8; 65536];

        // Client sends QX_TRANSPORT_PARAMETERS
        let (client_written, _) = client.send(&mut buf)?;

        // Server receives and sends its QX_TRANSPORT_PARAMETERS
        let recv_info = RecvInfo {
            from: client_addr,
            to: server_addr,
        };
        server.recv(&mut buf[..client_written], recv_info)?;

        let (server_written, _) = server.send(&mut buf)?;

        // Client receives server's QX_TRANSPORT_PARAMETERS
        let recv_info = RecvInfo {
            from: server_addr,
            to: client_addr,
        };
        client.recv(&mut buf[..server_written], recv_info)?;

        // Both should now be established
        assert!(client.is_established());
        assert!(server.is_established());

        Ok(QmuxPipe { client, server })
    }

    /// Sends data from client to server.
    ///
    /// Returns the number of bytes transferred.
    pub fn client_to_server(&mut self) -> Result<usize> {
        let mut buf = [0u8; 65536];

        // send() dispatches to send_qmux()
        let (written, _) = match self.client.send(&mut buf) {
            Ok(v) => v,
            Err(Error::Done) => return Ok(0),
            Err(e) => return Err(e),
        };

        if written == 0 {
            return Ok(0);
        }

        // recv() API dispatches to recv_qmux()
        // RecvInfo is ignored in QMux mode, so we use dummy addresses.
        let info = RecvInfo {
            from: "127.0.0.1:1234".parse().unwrap(),
            to: "127.0.0.1:4321".parse().unwrap(),
        };
        let consumed = self.server.recv(&mut buf[..written], info)?;
        Ok(consumed)
    }

    /// Sends data from server to client.
    ///
    /// Returns the number of bytes transferred.
    pub fn server_to_client(&mut self) -> Result<usize> {
        let mut buf = [0u8; 65536];

        // send() dispatches to send_qmux()
        let (written, _) = match self.server.send(&mut buf) {
            Ok(v) => v,
            Err(Error::Done) => return Ok(0),
            Err(e) => return Err(e),
        };

        if written == 0 {
            return Ok(0);
        }

        // recv() API dispatches to recv_qmux()
        // RecvInfo is ignored in QMux mode, so we use dummy addresses.
        let info = RecvInfo {
            from: "127.0.0.1:4321".parse().unwrap(),
            to: "127.0.0.1:1234".parse().unwrap(),
        };
        let consumed = self.client.recv(&mut buf[..written], info)?;
        Ok(consumed)
    }

    /// Advances the pipe, exchanging data in both directions until done.
    pub fn advance(&mut self) -> Result<()> {
        let mut client_done = false;
        let mut server_done = false;

        while !client_done || !server_done {
            match self.client_to_server() {
                Ok(0) => client_done = true,
                Ok(_) => (),
                Err(Error::Done) => client_done = true,
                Err(e) => return Err(e),
            }

            match self.server_to_client() {
                Ok(0) => server_done = true,
                Ok(_) => (),
                Err(Error::Done) => server_done = true,
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    /// Sends raw frames from client to server.
    ///
    /// This is the QMux equivalent of `Pipe::send_pkt_to_server()`. It encodes
    /// the frames directly and feeds them to the server's recv path.
    pub fn send_frames_to_server(
        &mut self, frames: &[frame::Frame], buf: &mut [u8],
    ) -> Result<usize> {
        // Write frames to a temp buffer first.
        let mut frames_buf = [0u8; 65536];
        let mut fb = octets::OctetsMut::with_slice(&mut frames_buf);

        for frame in frames {
            frame.to_bytes(&mut fb)?;
        }

        let frames_len = fb.off();
        if frames_len == 0 {
            return Ok(0);
        }

        // Wrap in a record: Size (varint) + Frames
        let mut b = octets::OctetsMut::with_slice(buf);
        b.put_varint(frames_len as u64)?;
        b.put_bytes(&frames_buf[..frames_len])?;
        let record_len = b.off();

        let info = RecvInfo {
            from: "127.0.0.1:1234".parse().unwrap(),
            to: "127.0.0.1:4321".parse().unwrap(),
        };
        self.server.recv(&mut buf[..record_len], info)
    }
}

#[cfg(feature = "qmux")]
impl TestPipe for QmuxPipe {
    type BufFactory = DefaultBufFactory;

    fn client(&mut self) -> &mut Connection<Self::BufFactory> {
        &mut self.client
    }

    fn server(&mut self) -> &mut Connection<Self::BufFactory> {
        &mut self.server
    }

    fn advance(&mut self) -> Result<()> {
        QmuxPipe::advance(self)
    }

    fn handshake(&mut self) -> Result<()> {
        // QMux doesn't need a handshake - connections are already established
        // when the QmuxPipe is created (TLS happens at transport layer).
        Ok(())
    }

    fn send_frames_to_server(
        &mut self, frames: &[frame::Frame], buf: &mut [u8],
    ) -> Result<usize> {
        QmuxPipe::send_frames_to_server(self, frames, buf)
    }
}
