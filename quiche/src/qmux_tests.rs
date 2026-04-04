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

//! QMux protocol tests.

use super::*;

use crate::h3::NameValue;
use crate::test_utils::QmuxPipe;

#[test]
fn qmux_pipe_creation() {
    let pipe = QmuxPipe::new().unwrap();

    assert!(pipe.client.is_established());
    assert!(pipe.server.is_established());
    assert!(pipe.client.qmux);
    assert!(pipe.server.qmux);
}

#[test]
fn qmux_client_stream_send() {
    let mut pipe = QmuxPipe::new().unwrap();

    // Client opens a bidi stream and sends data
    let stream_id = 0;
    let data = b"Hello, QMux!";

    let written = pipe.client.stream_send(stream_id, data, false).unwrap();
    assert_eq!(written, data.len());

    let transferred = pipe.client_to_server().unwrap();
    assert!(transferred > 0);

    // Server should be able to read
    assert!(pipe.server.readable().any(|id| id == stream_id));

    let mut buf = [0u8; 1024];
    let (read, fin) = pipe.server.stream_recv(stream_id, &mut buf).unwrap();
    assert_eq!(read, data.len());
    assert_eq!(&buf[..read], data);
    assert!(!fin);
}

#[test]
fn qmux_server_stream_send() {
    let mut pipe = QmuxPipe::new().unwrap();

    // Client opens a stream first
    let stream_id = 0;
    pipe.client.stream_send(stream_id, b"init", true).unwrap();
    pipe.client_to_server().unwrap();

    // Server responds on the same stream
    let response = b"Hello from server!";
    let written = pipe.server.stream_send(stream_id, response, true).unwrap();
    assert_eq!(written, response.len());

    let transferred = pipe.server_to_client().unwrap();
    assert!(transferred > 0);

    // Client should be able to read
    assert!(pipe.client.readable().any(|id| id == stream_id));

    let mut buf = [0u8; 1024];
    let (read, fin) = pipe.client.stream_recv(stream_id, &mut buf).unwrap();
    assert_eq!(read, response.len());
    assert_eq!(&buf[..read], response);
    assert!(fin);
    assert!(pipe.client.stream_finished(stream_id));
}

#[test]
fn qmux_bidirectional_exchange() {
    let mut pipe = QmuxPipe::new().unwrap();

    // Multiple streams with data in both directions
    for i in 0..3 {
        let stream_id = i * 4;

        // Client sends
        let client_data = format!("Client message {}", i);
        pipe.client
            .stream_send(stream_id, client_data.as_bytes(), false)
            .unwrap();
    }

    pipe.client_to_server().unwrap();

    // Server reads and responds
    for i in 0..3 {
        let stream_id = i * 4;

        let mut buf = [0u8; 1024];
        let (read, _fin) = pipe.server.stream_recv(stream_id, &mut buf).unwrap();
        assert!(read > 0);

        let server_data = format!("Server response {}", i);
        pipe.server
            .stream_send(stream_id, server_data.as_bytes(), true)
            .unwrap();
    }

    pipe.server_to_client().unwrap();

    for i in 0..3 {
        let stream_id = i * 4;

        let mut buf = [0u8; 1024];
        let (read, fin) = pipe.client.stream_recv(stream_id, &mut buf).unwrap();
        let expected = format!("Server response {}", i);
        assert_eq!(read, expected.len());
        assert_eq!(&buf[..read], expected.as_bytes());
        assert!(fin);
    }
}

#[test]
fn qmux_flow_control() {
    let mut config = QmuxPipe::default_config().unwrap();
    // Set small flow control limits
    config.set_initial_max_data(100);
    config.set_initial_max_stream_data_bidi_local(50);
    config.set_initial_max_stream_data_bidi_remote(50);

    let mut pipe = QmuxPipe::with_config(&mut config).unwrap();

    let stream_id = 0;
    let large_data = [0u8; 200];

    // Should only be able to send up to flow control limit
    let written = pipe
        .client
        .stream_send(stream_id, &large_data, false)
        .unwrap();
    assert!(written < large_data.len());
    assert!(written <= 50);

    pipe.client_to_server().unwrap();

    // Server receives
    let mut buf = [0u8; 1024];
    let (read, _fin) = pipe.server.stream_recv(stream_id, &mut buf).unwrap();
    assert_eq!(read, written);
}

#[test]
fn qmux_no_loss_detection_timer() {
    let pipe = QmuxPipe::new().unwrap();

    // QMux should not have loss detection timers
    // Only idle timer should be active
    let timeout = pipe.client.timeout();
    assert!(timeout.is_some()); // Idle timer

    // The timeout should be around max_idle_timeout (30 seconds in our config)
    // Not a short loss detection timer
    let timeout_ms = timeout.unwrap().as_millis();
    assert!(timeout_ms > 20000);
}

#[test]
fn qmux_idle_timeout() {
    let mut config = QmuxPipe::default_config().unwrap();
    config.set_max_idle_timeout(100); // 100ms

    let mut pipe = QmuxPipe::with_config(&mut config).unwrap();

    // Should have a timeout set (idle timer)
    let timeout = pipe.client.timeout();
    assert!(timeout.is_some());

    // Note: The actual timeout may be larger than max_idle_timeout due to
    // cmp::max(idle_timeout, 3 * path_pto) in idle_timeout(). For QMux this
    // is arguably wrong since there's no PTO, but we test the behavior as-is.

    // Force the idle timer to expire by setting it to the past
    pipe.client.idle_timer = Some(Instant::now() - Duration::from_millis(1));
    pipe.client.on_timeout();

    // Connection should be closed due to idle timeout
    assert!(pipe.client.is_closed());
    assert!(pipe.client.is_timed_out());
}

#[test]
fn qmux_connection_close() {
    let mut pipe = QmuxPipe::new().unwrap();

    // Client closes connection
    pipe.client.close(true, 0x100, b"goodbye").unwrap();

    pipe.client_to_server().unwrap();

    // Server should see the error
    assert!(pipe.server.peer_error().is_some());
    let error = pipe.server.peer_error().unwrap();
    assert!(error.is_app);
    assert_eq!(error.error_code, 0x100);
    assert_eq!(error.reason, b"goodbye");
}

#[test]
fn qmux_uni_stream() {
    let mut pipe = QmuxPipe::new().unwrap();

    // Client opens a unidirectional stream
    let stream_id = 2;
    let data = b"One-way message";

    let written = pipe.client.stream_send(stream_id, data, true).unwrap();
    assert_eq!(written, data.len());

    pipe.client_to_server().unwrap();

    // Server should be able to read
    let mut buf = [0u8; 1024];
    let (read, fin) = pipe.server.stream_recv(stream_id, &mut buf).unwrap();
    assert_eq!(read, data.len());
    assert_eq!(&buf[..read], data);
    assert!(fin);

    // Server cannot send on client-initiated uni stream
    assert!(pipe.server.stream_send(stream_id, b"reply", false).is_err());
}

// HTTP/3 over QMux tests
#[test]
fn qmux_h3_request_response() {
    let mut pipe = QmuxPipe::new().unwrap();

    // Create H3 connections on top of QMux
    let h3_config = h3::Config::new().unwrap();
    let mut h3_client =
        h3::Connection::with_transport(&mut pipe.client, &h3_config).unwrap();
    let mut h3_server =
        h3::Connection::with_transport(&mut pipe.server, &h3_config).unwrap();

    // Transfer H3 control streams (SETTINGS, QPACK)
    pipe.advance().unwrap();

    // Drain any H3 setup events
    while h3_client.poll(&mut pipe.client).is_ok() {}
    while h3_server.poll(&mut pipe.server).is_ok() {}

    // Client sends request
    let req = vec![
        h3::Header::new(b":method", b"GET"),
        h3::Header::new(b":scheme", b"https"),
        h3::Header::new(b":authority", b"localhost"),
        h3::Header::new(b":path", b"/"),
    ];
    let stream_id = h3_client
        .send_request(&mut pipe.client, &req, true)
        .unwrap();

    // Transfer to server
    pipe.client_to_server().unwrap();

    // Server receives request
    match h3_server.poll(&mut pipe.server) {
        Ok((sid, h3::Event::Headers { list, .. })) => {
            assert_eq!(sid, stream_id);
            // Verify we got the headers
            assert!(list.iter().any(|h| h.name() == b":method"));
        },
        other => panic!("Expected Headers event, got {:?}", other),
    }

    // Server should also get Finished event (client sent fin)
    match h3_server.poll(&mut pipe.server) {
        Ok((sid, h3::Event::Finished)) => {
            assert_eq!(sid, stream_id);
        },
        other => panic!("Expected Finished event, got {:?}", other),
    }

    // Server sends response
    let resp = vec![
        h3::Header::new(b":status", b"200"),
        h3::Header::new(b"content-length", b"5"),
    ];
    h3_server
        .send_response(&mut pipe.server, stream_id, &resp, false)
        .unwrap();
    h3_server
        .send_body(&mut pipe.server, stream_id, b"hello", true)
        .unwrap();

    // Transfer to client
    pipe.server_to_client().unwrap();

    // Client receives response headers
    match h3_client.poll(&mut pipe.client) {
        Ok((sid, h3::Event::Headers { list, .. })) => {
            assert_eq!(sid, stream_id);
            assert!(list.iter().any(|h| h.name() == b":status"));
        },
        other => panic!("Expected Headers event, got {:?}", other),
    }

    // Client receives body
    match h3_client.poll(&mut pipe.client) {
        Ok((sid, h3::Event::Data)) => {
            assert_eq!(sid, stream_id);
            let mut body = [0u8; 16];
            let len = h3_client
                .recv_body(&mut pipe.client, stream_id, &mut body)
                .unwrap();
            assert_eq!(&body[..len], b"hello");
        },
        other => panic!("Expected Data event, got {:?}", other),
    }

    // Client receives finished
    match h3_client.poll(&mut pipe.client) {
        Ok((sid, h3::Event::Finished)) => {
            assert_eq!(sid, stream_id);
        },
        other => panic!("Expected Finished event, got {:?}", other),
    }
}

// Frame encoding/decoding tests

#[test]
fn qmux_transport_parameters_frame() {
    let mut d = [42; 128];

    let params = vec![0x01, 0x02, 0x03, 0x04, 0x05];
    let frame = frame::Frame::QmuxTransportParameters {
        params: params.clone(),
    };

    let wire_len = {
        let mut b = octets::OctetsMut::with_slice(&mut d);
        frame.to_bytes(&mut b).unwrap()
    };

    // 8 bytes frame type + 1 byte length + 5 bytes params = 14 bytes
    assert_eq!(wire_len, 14);
    assert_eq!(frame.wire_len(), wire_len);

    // Verify frame type is correctly encoded (8-byte varint)
    assert_eq!(d[0] & 0xc0, 0xc0); // 8-byte varint marker

    let mut b = octets::Octets::with_slice(&d[..wire_len]);
    let parsed = frame::Frame::from_bytes(&mut b, packet::Type::Short).unwrap();

    match parsed {
        frame::Frame::QmuxTransportParameters { params: p } => {
            assert_eq!(p, params);
        },
        _ => panic!("expected QmuxTransportParameters frame"),
    }
}

#[test]
fn qmux_transport_parameters_frame_empty() {
    let mut d = [42; 128];

    let frame = frame::Frame::QmuxTransportParameters { params: vec![] };

    let wire_len = {
        let mut b = octets::OctetsMut::with_slice(&mut d);
        frame.to_bytes(&mut b).unwrap()
    };

    // 8 bytes frame type + 1 byte length (0) = 9 bytes
    assert_eq!(wire_len, 9);
    assert_eq!(frame.wire_len(), wire_len);

    let mut b = octets::Octets::with_slice(&d[..wire_len]);
    let parsed = frame::Frame::from_bytes(&mut b, packet::Type::Short).unwrap();

    match parsed {
        frame::Frame::QmuxTransportParameters { params } => {
            assert!(params.is_empty());
        },
        _ => panic!("expected QmuxTransportParameters frame"),
    }
}

#[test]
fn qmux_ping_request_frame() {
    let mut d = [42; 128];

    let frame = frame::Frame::QmuxPing {
        is_response: false,
        sequence_number: 12345,
    };

    let wire_len = {
        let mut b = octets::OctetsMut::with_slice(&mut d);
        frame.to_bytes(&mut b).unwrap()
    };

    // 8 bytes frame type + 2 bytes sequence number = 10 bytes
    assert_eq!(wire_len, 10);
    assert_eq!(frame.wire_len(), wire_len);

    let mut b = octets::Octets::with_slice(&d[..wire_len]);
    let parsed = frame::Frame::from_bytes(&mut b, packet::Type::Short).unwrap();

    match parsed {
        frame::Frame::QmuxPing {
            is_response,
            sequence_number,
        } => {
            assert!(!is_response);
            assert_eq!(sequence_number, 12345);
        },
        _ => panic!("expected QmuxPing frame"),
    }
}

#[test]
fn qmux_ping_response_frame() {
    let mut d = [42; 128];

    let frame = frame::Frame::QmuxPing {
        is_response: true,
        sequence_number: 0,
    };

    let wire_len = {
        let mut b = octets::OctetsMut::with_slice(&mut d);
        frame.to_bytes(&mut b).unwrap()
    };

    // 8 bytes frame type + 1 byte sequence number = 9 bytes
    assert_eq!(wire_len, 9);
    assert_eq!(frame.wire_len(), wire_len);

    let mut b = octets::Octets::with_slice(&d[..wire_len]);
    let parsed = frame::Frame::from_bytes(&mut b, packet::Type::Short).unwrap();

    match parsed {
        frame::Frame::QmuxPing {
            is_response,
            sequence_number,
        } => {
            assert!(is_response);
            assert_eq!(sequence_number, 0);
        },
        _ => panic!("expected QmuxPing frame"),
    }
}

#[test]
fn qmux_ping_large_sequence_frame() {
    let mut d = [42; 128];

    let frame = frame::Frame::QmuxPing {
        is_response: false,
        sequence_number: u64::MAX >> 2, // max varint value
    };

    let wire_len = {
        let mut b = octets::OctetsMut::with_slice(&mut d);
        frame.to_bytes(&mut b).unwrap()
    };

    // 8 bytes frame type + 8 bytes sequence number = 16 bytes
    assert_eq!(wire_len, 16);
    assert_eq!(frame.wire_len(), wire_len);

    let mut b = octets::Octets::with_slice(&d[..wire_len]);
    let parsed = frame::Frame::from_bytes(&mut b, packet::Type::Short).unwrap();

    match parsed {
        frame::Frame::QmuxPing {
            is_response,
            sequence_number,
        } => {
            assert!(!is_response);
            assert_eq!(sequence_number, u64::MAX >> 2);
        },
        _ => panic!("expected QmuxPing frame"),
    }
}
