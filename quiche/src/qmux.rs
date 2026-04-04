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

//! QMux protocol support.
//!
//! QMux provides QUIC's stream multiplexing API over reliable byte streams
//! (e.g., TLS over TCP). See draft-ietf-quic-qmux-01 for details.

use std::time::Instant;

#[cfg(feature = "qlog")]
use qlog::events::quic::FrameDirection;
#[cfg(feature = "qlog")]
use qlog::events::quic::FramesProcessed;
#[cfg(feature = "qlog")]
use qlog::events::quic::QuicEventType;
#[cfg(feature = "qlog")]
use qlog::events::EventData;
#[cfg(feature = "qlog")]
use qlog::events::EventImportance;
#[cfg(feature = "qlog")]
use qlog::events::EventType;

/// ALPN protocol identifier for HTTP/3 over QMux (draft-01).
pub const H3_OVER_QMUX_ALPN: &[u8] = b"h3qx-01";

use std::sync::Arc;

use crate::buffers::BufFactory;
use crate::frame;
use crate::packet;
use crate::stream;
use crate::Connection;
use crate::ConnectionId;
use crate::Error;
use crate::Header;
use crate::Result;
use crate::Type;

impl<F: BufFactory> Connection<F> {
    /// Processes incoming data from a QMux byte stream.
    ///
    /// In QMux mode, data arrives as records: `Size (varint) + Frames`.
    /// This method parses one complete record and processes its frames.
    ///
    /// Returns the number of bytes consumed from the input buffer.
    /// Returns `Error::Done` if the buffer doesn't contain a complete record.
    pub(crate) fn recv_qmux(&mut self, buf: &[u8]) -> Result<usize> {
        let now = Instant::now();

        if buf.is_empty() {
            trace!("{} qmux recv called with empty buffer", self.trace_id);
            return Err(Error::Done);
        }

        if self.is_closed() {
            trace!("{} qmux recv on closed connection", self.trace_id);
            return Err(Error::Done);
        }

        if self.is_draining() {
            trace!("{} qmux recv on draining connection", self.trace_id);
            return Err(Error::Done);
        }

        if self.local_error.is_some() {
            trace!("{} qmux recv while closing", self.trace_id);
            return Err(Error::Done);
        }

        trace!("{} qmux recv {} bytes", self.trace_id, buf.len());

        // Parse record header: Size (varint) indicating length of Frames field.
        let mut b = octets::Octets::with_slice(buf);

        let frames_len = match b.get_varint() {
            Ok(len) => len as usize,
            Err(octets::BufferTooShortError) => {
                trace!("{} qmux incomplete record header", self.trace_id);
                return Err(Error::Done);
            },
        };

        let size_len = b.off();

        // Validate record size against our advertised max.
        let our_max = self
            .local_transport_params
            .qmux_max_record_size
            .unwrap_or(crate::transport_params::QMUX_DEFAULT_MAX_RECORD_SIZE)
            as usize;
        if frames_len > our_max {
            error!(
                "{} qmux record too large: {} > {}",
                self.trace_id, frames_len, our_max
            );
            self.close(false, Error::InvalidFrame.to_wire(), b"record too large")
                .ok();
            return Err(Error::InvalidFrame);
        }

        // Check if we have the complete record.
        if b.cap() < frames_len {
            trace!(
                "{} qmux incomplete record: have {}, need {}",
                self.trace_id,
                b.cap(),
                frames_len
            );
            return Err(Error::Done);
        }

        // Extract the frames portion of the record.
        let frames_data = b.get_bytes(frames_len)?;
        let record_len = size_len + frames_len;

        trace!(
            "{} qmux recv record: size_len={} frames_len={}",
            self.trace_id,
            size_len,
            frames_len
        );

        // Parse frames within the record.
        let mut frames_buf = octets::Octets::with_slice(frames_data.as_ref());

        // Collect frames for qlog.
        #[cfg(feature = "qlog")]
        let mut qlog_frames = Vec::new();

        // Process frames within the record boundary.
        while frames_buf.cap() > 0 {
            let frame =
                match frame::Frame::from_bytes(&mut frames_buf, Type::Short) {
                    Ok(f) => f,

                    Err(Error::BufferTooShort) => {
                        // Incomplete frame within a complete record is an error.
                        error!(
                            "{} qmux truncated frame in record",
                            self.trace_id
                        );
                        self.close(
                            false,
                            Error::InvalidFrame.to_wire(),
                            b"truncated frame",
                        )
                        .ok();
                        return Err(Error::InvalidFrame);
                    },

                    Err(e) => {
                        error!(
                            "{} qmux frame parsing error: {:?}",
                            self.trace_id, e
                        );
                        self.close(false, e.to_wire(), b"").ok();
                        return Err(e);
                    },
                };

            trace!("{} qmux rx frm {:?}", self.trace_id, frame);

            #[cfg(feature = "qlog")]
            qlog_frames.push(frame.to_qlog());

            // The first frame MUST be QX_TRANSPORT_PARAMETERS.
            if !self.qmux_transport_params_received {
                match &frame {
                    frame::Frame::QmuxTransportParameters { params } => {
                        // Decode peer transport params, rejecting forbidden
                        // params per QMux Section 5.1.
                        let peer_params =
                            crate::TransportParams::decode_for_qmux(params)?;
                        self.process_peer_transport_params(peer_params)?;
                        self.qmux_transport_params_received = true;

                        // Initialize idle timer now that we have peer params.
                        if let Some(idle_timeout) = self.idle_timeout() {
                            self.idle_timer = Some(now + idle_timeout);
                        }

                        continue;
                    },
                    _ => {
                        error!(
                            "{} qmux first frame must be QX_TRANSPORT_PARAMETERS, got {:?}",
                            self.trace_id, frame
                        );
                        self.close(
                            false,
                            Error::InvalidTransportParam.to_wire(),
                            b"first frame must be QX_TRANSPORT_PARAMETERS",
                        )
                        .ok();
                        return Err(Error::InvalidTransportParam);
                    },
                }
            }

            // Reject QX_TRANSPORT_PARAMETERS after the first frame.
            if matches!(frame, frame::Frame::QmuxTransportParameters { .. }) {
                error!(
                    "{} qmux received duplicate QX_TRANSPORT_PARAMETERS",
                    self.trace_id
                );
                self.close(false, Error::InvalidFrame.to_wire(), b"").ok();
                return Err(Error::InvalidFrame);
            }

            // Reject frames that are forbidden in QMux mode.
            if is_forbidden_qmux_frame(&frame) {
                error!(
                    "{} qmux received forbidden frame: {:?}",
                    self.trace_id, frame
                );
                self.close(false, Error::InvalidFrame.to_wire(), b"").ok();
                return Err(Error::InvalidFrame);
            }

            // Handle QX_PING frames (QMux-specific, not handled by
            // process_frame).
            if let frame::Frame::QmuxPing {
                is_response,
                sequence_number,
            } = &frame
            {
                self.process_qmux_ping(*is_response, *sequence_number, now);
                continue; // Don't pass to process_frame
            }

            // Process the frame. We use a dummy header since QMux doesn't have
            // packet headers, and the frames that would use it are forbidden.
            let recv_path_id = self.paths.get_active_path_id()?;
            if let Err(e) = self.process_frame(
                frame,
                &qmux_dummy_header(),
                recv_path_id,
                packet::Epoch::Application,
                now,
            ) {
                error!("{} qmux frame processing error: {:?}", self.trace_id, e);
                self.close(false, e.to_wire(), b"").ok();
                return Err(e);
            }
        }

        // Update idle timer and byte counter.
        self.recv_bytes += record_len as u64;

        if let Some(idle_timeout) = self.idle_timeout() {
            self.idle_timer = Some(now + idle_timeout);
        }

        trace!(
            "{} qmux recv complete, consumed {} bytes",
            self.trace_id,
            record_len
        );

        // Emit qlog event for received frames.
        #[cfg(feature = "qlog")]
        if !qlog_frames.is_empty() {
            let ty = EventType::QuicEventType(QuicEventType::FramesProcessed);
            if EventImportance::from(ty).is_contained_in(&self.qlog.level) {
                if let Some(q) = &mut self.qlog.streamer {
                    let ev_data =
                        EventData::QuicFramesProcessed(FramesProcessed {
                            frames: qlog_frames,
                            packet_numbers: None,
                            direction: Some(FrameDirection::Parsed),
                        });

                    q.add_event_data_with_instant(ev_data, now).ok();
                }
            }
        }

        Ok(record_len)
    }

    /// Writes QMux frames to the output buffer.
    ///
    /// In QMux mode, frames are written directly without packet headers or
    /// encryption. This method generates frames for pending data and control
    /// information.
    ///
    /// Returns the number of bytes written to the output buffer.
    pub(crate) fn send_qmux(&mut self, out: &mut [u8]) -> Result<usize> {
        let now = Instant::now();

        if out.is_empty() {
            trace!("{} qmux send called with empty buffer", self.trace_id);
            return Err(Error::BufferTooShort);
        }

        if self.is_closed() {
            trace!("{} qmux send on closed connection", self.trace_id);
            return Err(Error::Done);
        }

        if self.is_draining() {
            trace!("{} qmux send on draining connection", self.trace_id);
            return Err(Error::Done);
        }

        trace!(
            "{} qmux send, buffer size {} bytes",
            self.trace_id,
            out.len()
        );

        // TODO: Optimize record layer to avoid temp buffer allocation.
        // Currently we write frames to a temp buffer, then copy to output
        // with Size prefix. Could instead reserve space for Size prefix
        // and write frames directly to output.

        // Allocate temp buffer for frames, respecting peer's max record size.
        let max_record_size = self.peer_max_record_size as usize;
        let mut frames_buf = vec![0u8; max_record_size];
        let mut b = octets::OctetsMut::with_slice(&mut frames_buf);

        // Collect frames for qlog.
        #[cfg(feature = "qlog")]
        let mut qlog_frames = Vec::new();

        // TODO: The QMux send path is simplified for MVP. It does not handle:
        // - Loss recovery retransmission (underlying transport handles this)
        // - Congestion control/pacing (underlying transport handles this)
        // - ACK frame generation (not used in QMux)
        //
        // TODO: Ensure records don't exceed peer's advertised max_record_size.
        // Currently we don't check this limit when generating records.

        // Send QX_TRANSPORT_PARAMETERS as the first frame if not sent yet.
        // Per the spec, this must be sent immediately when the transport
        // becomes available.
        if !self.qmux_transport_params_sent {
            // Encode only permitted params per QMux Section 5.1.
            let mut params_buf = [0u8; 256];
            let params = crate::TransportParams::encode_for_qmux(
                &self.local_transport_params,
                &mut params_buf,
            )?;

            let frame = frame::Frame::QmuxTransportParameters {
                params: params.to_vec(),
            };

            let frame_len = frame.wire_len();
            if b.cap() >= frame_len {
                trace!("{} qmux tx frm {:?}", self.trace_id, frame);
                #[cfg(feature = "qlog")]
                qlog_frames.push(frame.to_qlog());
                frame.to_bytes(&mut b)?;
                self.qmux_transport_params_sent = true;
            } else {
                return Err(Error::BufferTooShort);
            }
        }

        // Send QX_PING response if we have a pending request to respond to.
        if let Some(seq) = self.qmux_ping.pending_response.take() {
            let frame = frame::Frame::QmuxPing {
                is_response: true,
                sequence_number: seq,
            };

            let frame_len = frame.wire_len();
            if b.cap() >= frame_len {
                trace!("{} qmux tx frm {:?}", self.trace_id, frame);
                #[cfg(feature = "qlog")]
                qlog_frames.push(frame.to_qlog());
                frame.to_bytes(&mut b)?;
            } else {
                // Put it back if we couldn't send
                self.qmux_ping.pending_response = Some(seq);
            }
        }

        // Send QX_PING request if requested by the application.
        if self.qmux_ping.requested {
            let seq = self.qmux_ping.next_seq;
            let frame = frame::Frame::QmuxPing {
                is_response: false,
                sequence_number: seq,
            };

            let frame_len = frame.wire_len();
            if b.cap() >= frame_len {
                trace!("{} qmux tx frm {:?}", self.trace_id, frame);
                #[cfg(feature = "qlog")]
                qlog_frames.push(frame.to_qlog());
                frame.to_bytes(&mut b)?;
                self.qmux_ping.outstanding.insert(seq, now);
                self.qmux_ping.next_seq += 1;
                self.qmux_ping.requested = false;
            }
        }

        // Send CONNECTION_CLOSE if we have a local error.
        // After sending, we'll start draining (handled at end of function).
        if let Some(conn_err) = &self.local_error {
            let frame = if conn_err.is_app {
                frame::Frame::ApplicationClose {
                    error_code: conn_err.error_code,
                    reason: conn_err.reason.clone(),
                }
            } else {
                frame::Frame::ConnectionClose {
                    error_code: conn_err.error_code,
                    frame_type: 0,
                    reason: conn_err.reason.clone(),
                }
            };

            let frame_len = frame.wire_len();
            if b.cap() >= frame_len {
                trace!("{} qmux tx frm {:?}", self.trace_id, frame);
                #[cfg(feature = "qlog")]
                qlog_frames.push(frame.to_qlog());
                frame.to_bytes(&mut b)?;

                // Start draining after sending close
                if self.draining_timer.is_none() {
                    // Use a fixed drain timeout since we don't have RTT-based PTO
                    self.draining_timer =
                        Some(now + std::time::Duration::from_secs(3));
                }
            }
        }

        // Send MAX_DATA if needed.
        if self.should_send_max_data {
            let max = self.flow_control.max_data_next();
            let frame = frame::Frame::MaxData { max };

            let frame_len = frame.wire_len();
            if b.cap() >= frame_len {
                trace!("{} qmux tx frm {:?}", self.trace_id, frame);
                #[cfg(feature = "qlog")]
                qlog_frames.push(frame.to_qlog());
                frame.to_bytes(&mut b)?;
                self.flow_control.update_max_data(now);
                self.should_send_max_data = false;
            }
        }

        // Send MAX_STREAM_DATA for streams that need it.
        for stream_id in self.streams.almost_full().collect::<Vec<_>>() {
            if let Some(stream) = self.streams.get_mut(stream_id) {
                let max = stream.recv.max_data_next();
                let frame = frame::Frame::MaxStreamData { stream_id, max };

                let frame_len = frame.wire_len();
                if b.cap() >= frame_len {
                    trace!("{} qmux tx frm {:?}", self.trace_id, frame);
                    #[cfg(feature = "qlog")]
                    qlog_frames.push(frame.to_qlog());
                    frame.to_bytes(&mut b)?;
                    stream.recv.update_max_data(now);
                    self.streams.remove_almost_full(stream_id);
                } else {
                    break;
                }
            }
        }

        // Send MAX_STREAMS_BIDI if needed.
        if self.streams.should_update_max_streams_bidi() ||
            self.should_send_max_streams_bidi
        {
            let frame = frame::Frame::MaxStreamsBidi {
                max: self.streams.max_streams_bidi_next(),
            };

            let frame_len = frame.wire_len();
            if b.cap() >= frame_len {
                trace!("{} qmux tx frm {:?}", self.trace_id, frame);
                #[cfg(feature = "qlog")]
                qlog_frames.push(frame.to_qlog());
                frame.to_bytes(&mut b)?;
                self.streams.update_max_streams_bidi();
                self.should_send_max_streams_bidi = false;
            }
        }

        // Send MAX_STREAMS_UNI if needed.
        if self.streams.should_update_max_streams_uni() ||
            self.should_send_max_streams_uni
        {
            let frame = frame::Frame::MaxStreamsUni {
                max: self.streams.max_streams_uni_next(),
            };

            let frame_len = frame.wire_len();
            if b.cap() >= frame_len {
                trace!("{} qmux tx frm {:?}", self.trace_id, frame);
                #[cfg(feature = "qlog")]
                qlog_frames.push(frame.to_qlog());
                frame.to_bytes(&mut b)?;
                self.streams.update_max_streams_uni();
                self.should_send_max_streams_uni = false;
            }
        }

        // Send DATA_BLOCKED frame if needed.
        if let Some(limit) = self.blocked_limit {
            let frame = frame::Frame::DataBlocked { limit };

            let frame_len = frame.wire_len();
            if b.cap() >= frame_len {
                trace!("{} qmux tx frm {:?}", self.trace_id, frame);
                #[cfg(feature = "qlog")]
                qlog_frames.push(frame.to_qlog());
                frame.to_bytes(&mut b)?;
                self.blocked_limit = None;
                self.data_blocked_sent_count =
                    self.data_blocked_sent_count.saturating_add(1);
            }
        }

        // Send STREAMS_BLOCKED_BIDI frame if needed.
        if self
            .streams_blocked_bidi_state
            .has_pending_stream_blocked_frame()
        {
            if let Some(limit) = self.streams_blocked_bidi_state.blocked_at {
                let frame = frame::Frame::StreamsBlockedBidi { limit };

                let frame_len = frame.wire_len();
                if b.cap() >= frame_len {
                    trace!("{} qmux tx frm {:?}", self.trace_id, frame);
                    #[cfg(feature = "qlog")]
                    qlog_frames.push(frame.to_qlog());
                    frame.to_bytes(&mut b)?;
                    self.streams_blocked_bidi_state.blocked_sent = Some(limit);
                }
            }
        }

        // Send STREAMS_BLOCKED_UNI frame if needed.
        if self
            .streams_blocked_uni_state
            .has_pending_stream_blocked_frame()
        {
            if let Some(limit) = self.streams_blocked_uni_state.blocked_at {
                let frame = frame::Frame::StreamsBlockedUni { limit };

                let frame_len = frame.wire_len();
                if b.cap() >= frame_len {
                    trace!("{} qmux tx frm {:?}", self.trace_id, frame);
                    #[cfg(feature = "qlog")]
                    qlog_frames.push(frame.to_qlog());
                    frame.to_bytes(&mut b)?;
                    self.streams_blocked_uni_state.blocked_sent = Some(limit);
                }
            }
        }

        // Send STREAM_DATA_BLOCKED frames for blocked streams.
        for (stream_id, limit) in self
            .streams
            .blocked()
            .map(|(&k, &v)| (k, v))
            .collect::<Vec<(u64, u64)>>()
        {
            let frame = frame::Frame::StreamDataBlocked { stream_id, limit };

            let frame_len = frame.wire_len();
            if b.cap() >= frame_len {
                trace!("{} qmux tx frm {:?}", self.trace_id, frame);
                #[cfg(feature = "qlog")]
                qlog_frames.push(frame.to_qlog());
                frame.to_bytes(&mut b)?;
                self.streams.remove_blocked(stream_id);
                self.stream_data_blocked_sent_count =
                    self.stream_data_blocked_sent_count.saturating_add(1);
            } else {
                break;
            }
        }

        // Send RESET_STREAM frames.
        for (stream_id, error_code, final_size) in self
            .streams
            .reset()
            .map(|(&k, &v)| (k, v.0, v.1))
            .collect::<Vec<_>>()
        {
            let frame = frame::Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            };

            let frame_len = frame.wire_len();
            if b.cap() >= frame_len {
                trace!("{} qmux tx frm {:?}", self.trace_id, frame);
                #[cfg(feature = "qlog")]
                qlog_frames.push(frame.to_qlog());
                frame.to_bytes(&mut b)?;
                self.streams.remove_reset(stream_id);

                // In QMux, try to collect the stream after sending RESET_STREAM
                // (equivalent to when RESET_STREAM is ACKed in QUIC).
                if let Some(stream) = self.streams.get_mut(stream_id) {
                    let priority_key = Arc::clone(&stream.priority_key);

                    // Check if stream is in writable queue due to being stopped.
                    let is_writable = priority_key.writable.is_linked() &&
                        stream.send.is_stopped();

                    if stream.is_complete() &&
                        !stream.is_readable() &&
                        !is_writable
                    {
                        let local = stream.local;
                        self.streams.collect(stream_id, local);
                    }
                }
            } else {
                break;
            }
        }

        // Send STOP_SENDING frames.
        for (stream_id, error_code) in self
            .streams
            .stopped()
            .map(|(&k, &v)| (k, v))
            .collect::<Vec<_>>()
        {
            let frame = frame::Frame::StopSending {
                stream_id,
                error_code,
            };

            let frame_len = frame.wire_len();
            if b.cap() >= frame_len {
                trace!("{} qmux tx frm {:?}", self.trace_id, frame);
                #[cfg(feature = "qlog")]
                qlog_frames.push(frame.to_qlog());
                frame.to_bytes(&mut b)?;
                self.streams.remove_stopped(stream_id);
            } else {
                break;
            }
        }

        // Send STREAM and DATAGRAM frames.
        //
        // TODO: Alternate between STREAM and DATAGRAM frames for fairness,
        // similar to lib.rs which uses `emit_dgram` flag to toggle between
        // them each call. Currently we send all STREAM frames first, then
        // all DATAGRAMs, which could starve datagrams under high stream load.
        // See lib.rs: dgram_emitted, dgrams_to_emit, do_dgram, emit_dgram.

        // Send STREAM frames for all flushable streams.
        //
        // For the last frame in the record, we can omit the length field if
        // the stream data fills to the record boundary. This saves 2 bytes.
        // If length is omitted, we must stop - no more frames can follow.
        let mut record_full = false;
        while self.local_error.is_none() && !record_full {
            match emit_qmux_stream_frame(&mut self.streams, &mut b) {
                Ok((frame, len, length_included)) => {
                    trace!("{} qmux tx frm {:?}", self.trace_id, frame);
                    #[cfg(feature = "qlog")]
                    qlog_frames.push(frame.to_qlog());

                    // In QMux mode, the underlying reliable transport guarantees
                    // delivery, so we immediately mark stream data as acked.
                    // This allows streams to be collected when complete.
                    if let frame::Frame::StreamHeader {
                        stream_id, offset, ..
                    } = frame
                    {
                        if let Some(stream) = self.streams.get_mut(stream_id) {
                            stream.send.ack_and_drop(offset, len);

                            // Collect the stream if it's now complete.
                            if stream.is_complete() && !stream.is_readable() {
                                let local = stream.local;
                                self.streams.collect(stream_id, local);
                            }
                        }
                    }

                    // If length was omitted, frame extends to record boundary.
                    if !length_included {
                        record_full = true;
                    }
                },
                Err(Error::Done) => break,
                Err(_) => break,
            }
        }

        // Send DATAGRAM frames (only if record isn't already full).
        //
        // Similar to STREAM frames, we can omit the length field if the
        // datagram fills to the record boundary.
        while !record_full {
            let Some(dgram_len) = self.dgram_send_queue.peek_front_len() else {
                break;
            };

            let left = b.cap();

            // Header without length = 1 byte (type 0x30)
            // Header with length = 1 byte (type 0x31) + 2 bytes (length varint)
            let hdr_len_no_len = 1;
            let hdr_len_with_len = 1 + 2;

            // Check if we can fit this datagram.
            if left < hdr_len_no_len + dgram_len {
                break;
            }

            if let Some(data) = self.dgram_send_queue.pop() {
                // Check if datagram fills the remaining record space exactly.
                let fills_record = left == hdr_len_no_len + dgram_len;

                // Include length unless we fill the record exactly, or don't
                // have space for the length field.
                let include_length =
                    !fills_record && left >= hdr_len_with_len + dgram_len;

                frame::encode_dgram_header(
                    dgram_len as u64,
                    include_length,
                    &mut b,
                )?;
                b.put_bytes(data.as_ref())?;

                // If length was omitted, frame extends to record boundary.
                if !include_length {
                    record_full = true;
                }

                trace!(
                    "{} qmux tx frm datagram len={}",
                    self.trace_id,
                    dgram_len
                );
                #[cfg(feature = "qlog")]
                qlog_frames.push(qlog::events::quic::QuicFrame::Datagram {
                    raw: Some(Box::new(qlog::events::RawInfo {
                        length: None,
                        payload_length: Some(dgram_len as u64),
                        data: None,
                    })),
                });
                self.dgram_sent_count = self.dgram_sent_count.saturating_add(1);
            }
        }

        let frames_len = b.off();

        // No frames to send.
        if frames_len == 0 {
            return Err(Error::Done);
        }

        // Write record to output: Size (varint) + Frames
        let size_len = octets::varint_len(frames_len as u64);
        let record_len = size_len + frames_len;

        if out.len() < record_len {
            // Output buffer too small for the record.
            // TODO: Consider writing a smaller record with fewer frames.
            return Err(Error::BufferTooShort);
        }

        let mut out_buf = octets::OctetsMut::with_slice(out);
        out_buf.put_varint(frames_len as u64)?;
        out_buf.put_bytes(&frames_buf[..frames_len])?;

        trace!(
            "{} qmux send record: size={} frames_len={}",
            self.trace_id,
            size_len,
            frames_len
        );

        // Update idle timer and stats.
        self.sent_bytes += record_len as u64;

        if let Some(idle_timeout) = self.idle_timeout() {
            self.idle_timer = Some(now + idle_timeout);
        }

        // Emit qlog event for sent frames.
        #[cfg(feature = "qlog")]
        if !qlog_frames.is_empty() {
            let ty = EventType::QuicEventType(QuicEventType::FramesProcessed);
            if EventImportance::from(ty).is_contained_in(&self.qlog.level) {
                if let Some(q) = &mut self.qlog.streamer {
                    let ev_data =
                        EventData::QuicFramesProcessed(FramesProcessed {
                            frames: qlog_frames,
                            packet_numbers: None,
                            direction: Some(FrameDirection::Created),
                        });

                    q.add_event_data_with_instant(ev_data, now).ok();
                }
            }
        }

        Ok(record_len)
    }

    /// Processes a received QX_PING frame.
    ///
    /// For ping requests: tracks the largest sequence number for response.
    /// For ping responses: computes RTT and clears outstanding requests.
    fn process_qmux_ping(
        &mut self, is_response: bool, sequence_number: u64, now: Instant,
    ) {
        if is_response {
            // A response for seq N clears all outstanding requests with seq <= N.
            // split_off(N+1) returns everything > N, leaving <= N behind.
            let remaining =
                self.qmux_ping.outstanding.split_off(&(sequence_number + 1));

            // Get RTT from the matching request before discarding.
            if let Some(send_time) =
                self.qmux_ping.outstanding.get(&sequence_number)
            {
                self.qmux_ping.latest_rtt =
                    Some(now.saturating_duration_since(*send_time));
                trace!(
                    "{} qmux ping response seq={} rtt={:?}",
                    self.trace_id,
                    sequence_number,
                    self.qmux_ping.latest_rtt
                );
            } else {
                trace!(
                    "{} qmux ping response seq={} (no matching request)",
                    self.trace_id,
                    sequence_number
                );
            }

            // Keep only seq > N.
            self.qmux_ping.outstanding = remaining;
        } else {
            // Received a ping request - track largest seq for response.
            let pending = self.qmux_ping.pending_response.get_or_insert(0);
            if sequence_number > *pending {
                *pending = sequence_number;
            }
            trace!(
                "{} qmux ping request seq={}, pending_response={:?}",
                self.trace_id,
                sequence_number,
                self.qmux_ping.pending_response
            );
        }
    }
}

/// Emits a STREAM frame for QMux, optionally omitting the length field.
///
/// Returns `(frame, data_len, length_included)`:
/// - `frame`: The frame that was emitted
/// - `data_len`: The actual data length emitted
/// - `length_included`: Whether the length field was included. If false, the
///   frame extends to the record boundary and no more frames can follow.
fn emit_qmux_stream_frame<F: BufFactory>(
    streams: &mut stream::StreamMap<F>, b: &mut octets::OctetsMut,
) -> Result<(frame::Frame, usize, bool)> {
    let left = b.cap();

    while let Some(priority_key) = streams.peek_flushable() {
        let stream_id = priority_key.id;
        let stream = match streams.get_mut(stream_id) {
            Some(v) if !v.send.is_stopped() => v,
            _ => {
                streams.remove_flushable(&priority_key);
                continue;
            },
        };

        let stream_off = stream.send.off_front();
        let stream_data_len = stream.send.len() as usize;

        // Calculate header sizes.
        // Header without length = type (1) + stream_id (varint) + offset (varint)
        // Header with length = above + length (2 bytes, always 2-byte varint)
        let hdr_len_no_len =
            1 + octets::varint_len(stream_id) + octets::varint_len(stream_off);
        let hdr_len_with_len = hdr_len_no_len + 2;

        // Calculate max payload we can send.
        let max_payload_no_len = left.saturating_sub(hdr_len_no_len);
        let max_payload_with_len = left.saturating_sub(hdr_len_with_len);

        if max_payload_no_len == 0 {
            // Can't fit even header without length.
            let priority_key = Arc::clone(&stream.priority_key);
            streams.remove_flushable(&priority_key);
            continue;
        }

        // Decide whether to omit length field:
        // - If stream data >= max_payload_no_len, we can fill the record and omit
        //   the length field.
        // - Otherwise, include length field (if space permits).
        let omit_length = stream_data_len >= max_payload_no_len;

        let (hdr_len, max_payload) = if omit_length {
            (hdr_len_no_len, max_payload_no_len)
        } else if max_payload_with_len > 0 {
            (hdr_len_with_len, max_payload_with_len)
        } else {
            // Not enough space for header with length, but we can fit
            // without length. Use that.
            (hdr_len_no_len, max_payload_no_len)
        };

        // Reserve space and emit data.
        let hdr_off = b.off();
        let (mut stream_hdr, mut stream_payload) =
            b.split_at(hdr_off + hdr_len)?;

        let (len, fin) = stream
            .send
            .emit(&mut stream_payload.as_mut()[..max_payload])?;

        // Skip if no data and no FIN (nothing to send).
        if len == 0 && !fin {
            let priority_key = Arc::clone(&stream.priority_key);
            streams.remove_flushable(&priority_key);
            continue;
        }

        // Encode the header.
        stream_hdr.skip(hdr_off)?;

        // Determine if we actually filled the record (for omitting length).
        let include_length = !(omit_length && len == max_payload);

        frame::encode_stream_header(
            stream_id,
            stream_off,
            len as u64,
            fin,
            include_length,
            &mut stream_hdr,
        )?;

        // Advance buffer past the frame.
        b.skip(hdr_len + len)?;

        let frame = frame::Frame::StreamHeader {
            stream_id,
            offset: stream_off,
            length: len,
            fin,
        };

        // Update stream state.
        let priority_key = Arc::clone(&stream.priority_key);
        if !stream.is_flushable() {
            streams.remove_flushable(&priority_key);
        } else if stream.incremental {
            streams.remove_flushable(&priority_key);
            streams.insert_flushable(&priority_key);
        }

        return Ok((frame, len, include_length));
    }

    Err(Error::Done)
}

/// Returns true if the frame is forbidden in QMux mode.
///
/// QMux forbids frames that are related to packet-level concerns
/// (ACKs, connection IDs, path validation) or the QUIC handshake.
fn is_forbidden_qmux_frame(frame: &frame::Frame) -> bool {
    matches!(
        frame,
        frame::Frame::Ping { .. } |
            frame::Frame::ACK { .. } |
            frame::Frame::Crypto { .. } |
            frame::Frame::CryptoHeader { .. } |
            frame::Frame::NewToken { .. } |
            frame::Frame::NewConnectionId { .. } |
            frame::Frame::RetireConnectionId { .. } |
            frame::Frame::PathChallenge { .. } |
            frame::Frame::PathResponse { .. } |
            frame::Frame::HandshakeDone
    )
}

/// Returns a dummy header for QMux frame processing.
///
/// QMux doesn't have packet headers, but `process_frame` takes one.
/// The frames that actually use the header are forbidden in QMux mode,
/// so this is safe.
fn qmux_dummy_header() -> Header<'static> {
    Header {
        ty: Type::Short,
        version: 0,
        dcid: ConnectionId::default(),
        scid: ConnectionId::default(),
        pkt_num: 0,
        pkt_num_len: 0,
        token: None,
        versions: None,
        key_phase: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;
    use crate::PROTOCOL_VERSION;

    fn create_qmux_config() -> Result<Config> {
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
        config.enable_qmux(true);
        Ok(config)
    }

    /// Test that QMux handshake works: client and server exchange
    /// QX_TRANSPORT_PARAMETERS via send()/recv() and both become established.
    #[test]
    fn qmux_handshake_basic() {
        let mut config = create_qmux_config().unwrap();

        let client_scid = ConnectionId::from_ref(&[0xc1; 16]);
        let server_scid = ConnectionId::from_ref(&[0x51; 16]);
        let client_addr = "127.0.0.1:1234".parse().unwrap();
        let server_addr = "127.0.0.1:4321".parse().unwrap();

        let mut client = crate::connect(
            Some("localhost"),
            &client_scid,
            client_addr,
            server_addr,
            &mut config,
        )
        .unwrap();

        let mut server = crate::accept(
            &server_scid,
            None,
            server_addr,
            client_addr,
            &mut config,
        )
        .unwrap();

        // Neither should be established yet
        assert!(!client.is_established());
        assert!(!server.is_established());

        let mut buf = [0u8; 65535];

        // Client sends QX_TRANSPORT_PARAMETERS
        let (client_sent, _) = client.send(&mut buf).unwrap();
        assert!(client_sent > 0);

        // Server receives and processes
        let recv_info = crate::RecvInfo {
            from: client_addr,
            to: server_addr,
        };
        server.recv(&mut buf[..client_sent], recv_info).unwrap();

        // Server sends QX_TRANSPORT_PARAMETERS
        let (server_sent, _) = server.send(&mut buf).unwrap();
        assert!(server_sent > 0);

        // Client receives and processes
        let recv_info = crate::RecvInfo {
            from: server_addr,
            to: client_addr,
        };
        client.recv(&mut buf[..server_sent], recv_info).unwrap();

        // Both should now be established
        assert!(client.is_established());
        assert!(server.is_established());
    }

    /// Test that receiving a non-QX_TRANSPORT_PARAMETERS frame first is an
    /// error.
    #[test]
    fn qmux_first_frame_must_be_transport_params() {
        let mut config = create_qmux_config().unwrap();

        let server_scid = ConnectionId::from_ref(&[0x51; 16]);
        let client_addr = "127.0.0.1:1234".parse().unwrap();
        let server_addr = "127.0.0.1:4321".parse().unwrap();

        let mut server = crate::accept(
            &server_scid,
            None,
            server_addr,
            client_addr,
            &mut config,
        )
        .unwrap();

        // Craft a STREAM frame (not QX_TRANSPORT_PARAMETERS)
        let mut buf = [0u8; 256];
        let stream_frame = frame::Frame::Stream {
            stream_id: 0,
            data: crate::range_buf::RangeBuf::from(&b"hello"[..], 0, true),
        };
        let mut b = octets::OctetsMut::with_slice(&mut buf);
        stream_frame.to_bytes(&mut b).unwrap();
        let frame_len = b.off();

        // Server should reject this
        let recv_info = crate::RecvInfo {
            from: client_addr,
            to: server_addr,
        };
        let result = server.recv(&mut buf[..frame_len], recv_info);

        // Should fail with transport parameter error
        assert!(result.is_err());
    }

    /// Test that send() outputs QX_TRANSPORT_PARAMETERS as the first frame.
    #[test]
    fn qmux_transport_params_sent_first() {
        let mut config = create_qmux_config().unwrap();

        let client_scid = ConnectionId::from_ref(&[0xc1; 16]);
        let client_addr = "127.0.0.1:1234".parse().unwrap();
        let server_addr = "127.0.0.1:4321".parse().unwrap();

        let mut client = crate::connect(
            Some("localhost"),
            &client_scid,
            client_addr,
            server_addr,
            &mut config,
        )
        .unwrap();

        let mut buf = [0u8; 65535];

        // Client sends
        let (sent, _) = client.send(&mut buf).unwrap();
        assert!(sent > 0);

        // Parse the record: Size (varint) + Frames
        let mut b = octets::Octets::with_slice(&buf[..sent]);
        let frames_len = b.get_varint().unwrap() as usize;
        assert!(frames_len > 0);
        assert_eq!(b.cap(), frames_len);

        // Parse the first frame - should be QX_TRANSPORT_PARAMETERS
        let frame = frame::Frame::from_bytes(&mut b, Type::Short).unwrap();

        match frame {
            frame::Frame::QmuxTransportParameters { .. } => (),
            _ => panic!("expected QmuxTransportParameters, got {:?}", frame),
        }
    }

    /// Test that receiving a duplicate QX_TRANSPORT_PARAMETERS frame is an
    /// error.
    #[test]
    fn qmux_duplicate_transport_params_rejected() {
        let mut config = create_qmux_config().unwrap();

        let client_scid = ConnectionId::from_ref(&[0xc1; 16]);
        let server_scid = ConnectionId::from_ref(&[0x51; 16]);
        let client_addr = "127.0.0.1:1234".parse().unwrap();
        let server_addr = "127.0.0.1:4321".parse().unwrap();

        let mut client = crate::connect(
            Some("localhost"),
            &client_scid,
            client_addr,
            server_addr,
            &mut config,
        )
        .unwrap();

        let mut server = crate::accept(
            &server_scid,
            None,
            server_addr,
            client_addr,
            &mut config,
        )
        .unwrap();

        let mut buf = [0u8; 65535];

        // Client sends QX_TRANSPORT_PARAMETERS
        let (client_sent, _) = client.send(&mut buf).unwrap();

        // Server receives first QX_TRANSPORT_PARAMETERS - should succeed
        let recv_info = crate::RecvInfo {
            from: client_addr,
            to: server_addr,
        };
        server.recv(&mut buf[..client_sent], recv_info).unwrap();

        // Server should have received transport params
        assert!(server.qmux_transport_params_received);

        // Manually craft a second QX_TRANSPORT_PARAMETERS frame
        let tp_frame = frame::Frame::QmuxTransportParameters {
            params: vec![0x01, 0x02, 0x03],
        };
        let mut tp_buf = [0u8; 256];
        let mut b = octets::OctetsMut::with_slice(&mut tp_buf);
        tp_frame.to_bytes(&mut b).unwrap();
        let tp_len = b.off();

        let recv_info = crate::RecvInfo {
            from: client_addr,
            to: server_addr,
        };
        let result = server.recv(&mut tp_buf[..tp_len], recv_info);

        // Should fail with InvalidFrame
        assert!(result.is_err());
    }

    /// Test that forbidden transport params are rejected.
    #[test]
    fn qmux_forbidden_transport_params_rejected() {
        let mut config = create_qmux_config().unwrap();

        let server_scid = ConnectionId::from_ref(&[0x51; 16]);
        let client_addr = "127.0.0.1:1234".parse().unwrap();
        let server_addr = "127.0.0.1:4321".parse().unwrap();

        let mut server = crate::accept(
            &server_scid,
            None,
            server_addr,
            client_addr,
            &mut config,
        )
        .unwrap();

        // Craft a QX_TRANSPORT_PARAMETERS frame with a forbidden param
        // (ack_delay_exponent = 0x000a)
        let mut params_buf = [0u8; 64];
        let mut pb = octets::OctetsMut::with_slice(&mut params_buf);
        // max_idle_timeout (permitted)
        pb.put_varint(0x0001).unwrap(); // param id
        pb.put_varint(1).unwrap(); // length
        pb.put_varint(30).unwrap(); // value
                                    // ack_delay_exponent (FORBIDDEN)
        pb.put_varint(0x000a).unwrap(); // param id
        pb.put_varint(1).unwrap(); // length
        pb.put_varint(3).unwrap(); // value
        let params_len = pb.off();

        let tp_frame = frame::Frame::QmuxTransportParameters {
            params: params_buf[..params_len].to_vec(),
        };

        // Encode frame to temp buffer first.
        let mut frame_buf = [0u8; 128];
        let mut fb = octets::OctetsMut::with_slice(&mut frame_buf);
        tp_frame.to_bytes(&mut fb).unwrap();
        let frame_len = fb.off();

        // Wrap in a record: Size (varint) + Frames
        let mut record_buf = [0u8; 256];
        let mut rb = octets::OctetsMut::with_slice(&mut record_buf);
        rb.put_varint(frame_len as u64).unwrap();
        rb.put_bytes(&frame_buf[..frame_len]).unwrap();
        let record_len = rb.off();

        // Server should reject the forbidden param
        let recv_info = crate::RecvInfo {
            from: client_addr,
            to: server_addr,
        };
        let result = server.recv(&mut record_buf[..record_len], recv_info);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::InvalidTransportParam);
    }

    /// Test that only permitted params are encoded in QX_TRANSPORT_PARAMETERS.
    #[test]
    fn qmux_only_permitted_params_encoded() {
        let mut config = create_qmux_config().unwrap();

        let client_scid = ConnectionId::from_ref(&[0xc1; 16]);
        let client_addr = "127.0.0.1:1234".parse().unwrap();
        let server_addr = "127.0.0.1:4321".parse().unwrap();

        let mut client = crate::connect(
            Some("localhost"),
            &client_scid,
            client_addr,
            server_addr,
            &mut config,
        )
        .unwrap();

        let mut buf = [0u8; 65535];

        // Client sends QX_TRANSPORT_PARAMETERS
        let (sent, _) = client.send(&mut buf).unwrap();

        // Parse the record: Size (varint) + Frames
        let mut b = octets::Octets::with_slice(&buf[..sent]);
        let _frames_len = b.get_varint().unwrap();

        // Parse the frame
        let frame = frame::Frame::from_bytes(&mut b, Type::Short).unwrap();

        let params = match frame {
            frame::Frame::QmuxTransportParameters { params } => params,
            _ => panic!("expected QmuxTransportParameters"),
        };

        // Parse the params and check no forbidden ones are present
        let mut pb = octets::Octets::with_slice(&params);
        while pb.cap() > 0 {
            let id = pb.get_varint().unwrap();
            let len = pb.get_varint().unwrap() as usize;

            // Check this is a permitted param
            match id {
                0x0001 | // max_idle_timeout
                0x0004 | // initial_max_data
                0x0005 | // initial_max_stream_data_bidi_local
                0x0006 | // initial_max_stream_data_bidi_remote
                0x0007 | // initial_max_stream_data_uni
                0x0008 | // initial_max_streams_bidi
                0x0009 | // initial_max_streams_uni
                0x0020   // max_datagram_frame_size
                    => (),

                // qmux_max_record_size
                0x0571c59429cd0845 => (),

                _ => panic!("forbidden param id {:#x} found in encoded params", id),
            }

            pb.skip(len).unwrap();
        }
    }

    /// Test that qmux_max_record_size below default (16382) is rejected.
    #[test]
    fn qmux_max_record_size_below_minimum_rejected() {
        let mut config = create_qmux_config().unwrap();

        let server_scid = ConnectionId::from_ref(&[0xba; 16]);
        let client_addr = "127.0.0.1:1234".parse().unwrap();
        let server_addr = "127.0.0.1:4321".parse().unwrap();

        let mut server = crate::accept(
            &server_scid,
            None,
            server_addr,
            client_addr,
            &mut config,
        )
        .unwrap();

        // Craft a QX_TRANSPORT_PARAMETERS frame with qmux_max_record_size
        // below the minimum (16382).
        let mut params_buf = [0u8; 64];
        let mut pb = octets::OctetsMut::with_slice(&mut params_buf);
        // qmux_max_record_size with value 1000 (below 16382)
        pb.put_varint(crate::transport_params::QMUX_MAX_RECORD_SIZE_PARAM_ID)
            .unwrap();
        pb.put_varint(2).unwrap(); // length (2 bytes for varint 1000)
        pb.put_varint(1000).unwrap(); // value below minimum
        let params_len = pb.off();

        let tp_frame = frame::Frame::QmuxTransportParameters {
            params: params_buf[..params_len].to_vec(),
        };

        // Encode frame to temp buffer.
        let mut frame_buf = [0u8; 128];
        let mut fb = octets::OctetsMut::with_slice(&mut frame_buf);
        tp_frame.to_bytes(&mut fb).unwrap();
        let frame_len = fb.off();

        // Wrap in a record: Size (varint) + Frames
        let mut record_buf = [0u8; 256];
        let mut rb = octets::OctetsMut::with_slice(&mut record_buf);
        rb.put_varint(frame_len as u64).unwrap();
        rb.put_bytes(&frame_buf[..frame_len]).unwrap();
        let record_len = rb.off();

        // Server should reject the below-minimum value
        let recv_info = crate::RecvInfo {
            from: client_addr,
            to: server_addr,
        };
        let result = server.recv(&mut record_buf[..record_len], recv_info);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::InvalidTransportParam);
    }

    /// Test that qmux_max_record_size at or above default is accepted.
    #[test]
    fn qmux_max_record_size_at_minimum_accepted() {
        let mut config = create_qmux_config().unwrap();

        let server_scid = ConnectionId::from_ref(&[0xba; 16]);
        let client_addr = "127.0.0.1:1234".parse().unwrap();
        let server_addr = "127.0.0.1:4321".parse().unwrap();

        let mut server = crate::accept(
            &server_scid,
            None,
            server_addr,
            client_addr,
            &mut config,
        )
        .unwrap();

        // Craft a QX_TRANSPORT_PARAMETERS frame with qmux_max_record_size
        // at the minimum (16382).
        let mut params_buf = [0u8; 64];
        let mut pb = octets::OctetsMut::with_slice(&mut params_buf);
        // qmux_max_record_size with value 16382 (exactly the minimum)
        pb.put_varint(crate::transport_params::QMUX_MAX_RECORD_SIZE_PARAM_ID)
            .unwrap();
        pb.put_varint(2).unwrap(); // length
        pb.put_varint(16382).unwrap(); // value at minimum
        let params_len = pb.off();

        let tp_frame = frame::Frame::QmuxTransportParameters {
            params: params_buf[..params_len].to_vec(),
        };

        // Encode frame to temp buffer.
        let mut frame_buf = [0u8; 128];
        let mut fb = octets::OctetsMut::with_slice(&mut frame_buf);
        tp_frame.to_bytes(&mut fb).unwrap();
        let frame_len = fb.off();

        // Wrap in a record: Size (varint) + Frames
        let mut record_buf = [0u8; 256];
        let mut rb = octets::OctetsMut::with_slice(&mut record_buf);
        rb.put_varint(frame_len as u64).unwrap();
        rb.put_bytes(&frame_buf[..frame_len]).unwrap();
        let record_len = rb.off();

        // Server should accept the value
        let recv_info = crate::RecvInfo {
            from: client_addr,
            to: server_addr,
        };
        let result = server.recv(&mut record_buf[..record_len], recv_info);

        // Should succeed (return bytes consumed)
        assert!(result.is_ok());
    }

    /// Test that STREAM frames without Length field are correctly parsed
    /// within record boundaries.
    #[test]
    fn qmux_stream_frame_without_length() {
        use crate::test_utils::QmuxPipe;

        let mut pipe = QmuxPipe::new().unwrap();

        // Client sends stream data normally (with Length field).
        let stream_id = 0; // client-initiated bidi
        pipe.client.stream_send(stream_id, b"hello", false).unwrap();
        pipe.advance().unwrap();

        // Server should receive the data.
        let mut buf = [0u8; 100];
        let (len, fin) = pipe.server.stream_recv(stream_id, &mut buf).unwrap();
        assert_eq!(&buf[..len], b"hello");
        assert!(!fin);

        // Now craft a STREAM frame without Length field and send it in a record.
        // STREAM frame type bits: 0x08 + OFF(0x04) + LEN(0x02) + FIN(0x01)
        // Type 0x0d = STREAM with OFF, no LEN, FIN

        // Build the frame manually: type + stream_id + offset + data (no length)
        let mut frame_buf = [0u8; 64];
        let mut fb = octets::OctetsMut::with_slice(&mut frame_buf);
        fb.put_varint(0x0d).unwrap(); // STREAM type: OFF, no LEN, FIN
        fb.put_varint(stream_id).unwrap();
        fb.put_varint(5).unwrap(); // offset after "hello"
        fb.put_bytes(b"world").unwrap(); // data extends to end of record
        let frame_len = fb.off();

        // Wrap in a record.
        let mut record_buf = [0u8; 128];
        let mut rb = octets::OctetsMut::with_slice(&mut record_buf);
        rb.put_varint(frame_len as u64).unwrap();
        rb.put_bytes(&frame_buf[..frame_len]).unwrap();
        let record_len = rb.off();

        // Send to server.
        let info = crate::RecvInfo {
            from: "127.0.0.1:1234".parse().unwrap(),
            to: "127.0.0.1:4321".parse().unwrap(),
        };
        let consumed = pipe
            .server
            .recv(&mut record_buf[..record_len], info)
            .unwrap();
        assert_eq!(consumed, record_len);

        // Server should receive "world" with FIN.
        let (len, fin) = pipe.server.stream_recv(stream_id, &mut buf).unwrap();
        assert_eq!(&buf[..len], b"world");
        assert!(fin);
    }

    /// Test that DATAGRAM frames without Length field are correctly parsed
    /// within record boundaries.
    #[test]
    fn qmux_datagram_frame_without_length() {
        use crate::test_utils::QmuxPipe;

        let mut pipe = QmuxPipe::new().unwrap();

        // Build a DATAGRAM frame without Length field.
        // DATAGRAM type 0x30 = no LEN
        // DATAGRAM type 0x31 = LEN (what we normally send)
        let mut frame_buf = [0u8; 64];
        let mut fb = octets::OctetsMut::with_slice(&mut frame_buf);
        fb.put_varint(0x30).unwrap(); // DATAGRAM type: no LEN
        fb.put_bytes(b"datagram payload").unwrap(); // data extends to end of record
        let frame_len = fb.off();

        // Wrap in a record.
        let mut record_buf = [0u8; 128];
        let mut rb = octets::OctetsMut::with_slice(&mut record_buf);
        rb.put_varint(frame_len as u64).unwrap();
        rb.put_bytes(&frame_buf[..frame_len]).unwrap();
        let record_len = rb.off();

        // Send to server.
        let info = crate::RecvInfo {
            from: "127.0.0.1:1234".parse().unwrap(),
            to: "127.0.0.1:4321".parse().unwrap(),
        };
        let consumed = pipe
            .server
            .recv(&mut record_buf[..record_len], info)
            .unwrap();
        assert_eq!(consumed, record_len);

        // Server should receive the datagram.
        let mut buf = [0u8; 100];
        let len = pipe.server.dgram_recv(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"datagram payload");
    }

    /// Test that STREAM frames sent by send_qmux() omit the Length field when
    /// filling the record.
    #[test]
    fn qmux_stream_frame_sends_without_length() {
        use crate::test_utils::QmuxPipe;

        let mut pipe = QmuxPipe::new().unwrap();

        // Send transport params first.
        pipe.advance().unwrap();

        // Client sends enough stream data to fill the record.
        // Default max_record_size is 16382, so we need more than that.
        let stream_id = 0; // client-initiated bidi
        let large_data = vec![0x42u8; 20000];
        pipe.client
            .stream_send(stream_id, &large_data, false)
            .unwrap();

        // Get the raw bytes sent by the client.
        let mut buf = [0u8; 65536];
        let (sent, _) = pipe.client.send(&mut buf).unwrap();

        // Parse the record and verify the STREAM frame type.
        let mut b = octets::Octets::with_slice(&buf[..sent]);
        let frames_len = b.get_varint().unwrap() as usize;

        // The frame type should indicate no length field (type & 0x02 == 0).
        // STREAM type is 0x08 + flags: OFF(0x04), LEN(0x02), FIN(0x01)
        // With offset, no length: 0x08 | 0x04 = 0x0c
        let frame_type = b.get_varint().unwrap();

        // Check that LEN bit is NOT set (frame fills to record boundary).
        assert_eq!(
            frame_type & 0x02,
            0,
            "STREAM frame should omit length field when filling record, \
             got type {:#x}",
            frame_type
        );

        // Verify it's a STREAM frame.
        assert_eq!(frame_type & 0xf8, 0x08, "should be STREAM frame");

        // Parse stream_id and offset.
        let _stream_id = b.get_varint().unwrap();
        let _offset = b.get_varint().unwrap();

        // The remaining data should extend to the record boundary.
        let data_len = b.cap();

        // Verify the data fills to the record boundary.
        assert!(data_len > 0, "should have stream data");

        // The record should be full (frames_len should be close to max record
        // size). Default max is 16382.
        assert!(
            frames_len > 16000,
            "record should be nearly full, got {} bytes",
            frames_len
        );
    }

    /// Test that no frames are written after a STREAM frame without length.
    ///
    /// When a STREAM frame omits the length field, it extends to the record
    /// boundary, so no more frames can follow in that record.
    #[test]
    fn qmux_no_frames_after_stream_without_length() {
        use crate::test_utils::QmuxPipe;

        let mut pipe = QmuxPipe::new().unwrap();

        // Send transport params first.
        pipe.advance().unwrap();

        // Client sends data on two streams - enough to fill the record on
        // stream 0, plus some on stream 4.
        let stream0 = 0; // client-initiated bidi
        let stream4 = 4; // another client-initiated bidi

        // Send enough data on stream 0 to fill the record.
        let large_data = vec![0x42u8; 20000];
        pipe.client
            .stream_send(stream0, &large_data, false)
            .unwrap();

        // Also queue data on stream 4.
        pipe.client
            .stream_send(stream4, b"stream4 data", false)
            .unwrap();

        // Get the raw bytes sent by the client.
        let mut buf = [0u8; 65536];
        let (sent, _) = pipe.client.send(&mut buf).unwrap();

        // Parse the record.
        let mut b = octets::Octets::with_slice(&buf[..sent]);
        let frames_len = b.get_varint().unwrap() as usize;
        let size_len = sent - b.cap();

        // Verify record structure: Size + exactly frames_len bytes.
        assert_eq!(sent, size_len + frames_len);

        // Parse the STREAM frame.
        let frame_type = b.get_varint().unwrap();
        assert_eq!(frame_type & 0xf8, 0x08, "should be STREAM frame");

        // Check that LEN bit is NOT set.
        assert_eq!(
            frame_type & 0x02,
            0,
            "STREAM frame should omit length field"
        );

        let parsed_stream_id = b.get_varint().unwrap();
        assert_eq!(parsed_stream_id, stream0);

        let _offset = b.get_varint().unwrap();

        // The rest of the buffer should be stream data only - no more frames.
        // If another frame was incorrectly written, we'd have extra bytes that
        // don't belong to the stream data, which would corrupt parsing.
        let remaining = b.cap();

        // All remaining bytes should be stream 0 data.
        // The stream 4 data should NOT be in this record.
        assert!(
            remaining > 0,
            "should have stream data filling to record boundary"
        );

        // Verify that stream 4 data is still pending (not sent in this record).
        assert!(
            pipe.client.stream_writable(stream4, 1).unwrap_or(false),
            "stream 4 should still be writable (data not yet sent)"
        );

        // Send another record - this should contain the stream 4 data.
        let (sent2, _) = pipe.client.send(&mut buf).unwrap();
        assert!(sent2 > 0, "should have more data to send for stream 4");
    }

    /// Test that no frames are written after a DATAGRAM frame without length.
    #[test]
    fn qmux_no_frames_after_datagram_without_length() {
        use crate::test_utils::QmuxPipe;

        let mut pipe = QmuxPipe::new().unwrap();

        // Send transport params first.
        pipe.advance().unwrap();

        // To test that no frames follow a datagram without length, we need
        // to craft a situation where a datagram exactly fills the remaining
        // record space.
        //
        // Record max = 16382. We'll send stream data sized so that the
        // remaining space exactly fits: datagram header (1 byte, no length)
        // + datagram data.

        let stream_id = 0;

        // First, figure out the STREAM frame overhead for stream 0 at offset 0:
        // type (1) + stream_id varint (1 for 0) + offset varint (1 for 0) + len
        // (2) = 5 But we're using no-length, so it's: type (1) +
        // stream_id (1) + offset (1) = 3
        //
        // Actually for the test we want the STREAM frame to NOT fill the record,
        // then the DATAGRAM to fill it exactly.

        // Send small stream data first to not trigger stream filling record.
        let stream_data = vec![0x42u8; 100];
        pipe.client
            .stream_send(stream_id, &stream_data, false)
            .unwrap();

        // After STREAM frame, calculate remaining space and craft datagram to
        // fill it exactly. But we don't know the exact remaining space ahead
        // of time. Let's use a different approach:
        //
        // Send a datagram that's large enough to fill most of the record,
        // then queue another one that won't fit.

        // Queue a large datagram that will fill the record (leaving no room
        // for another).
        // Record max is 16382. STREAM frame is ~105 bytes (5 header + 100 data).
        // Remaining is ~16277. Datagram header without length is 1 byte.
        // So datagram data of 16276 bytes would fill exactly.
        let large_dgram = vec![0xDD; 16276];
        pipe.client.dgram_send(&large_dgram).unwrap();

        // Queue a small datagram that should NOT fit in this record.
        pipe.client.dgram_send(b"should be in next record").unwrap();

        // Send first record.
        let mut buf = [0u8; 65536];
        let (sent, _) = pipe.client.send(&mut buf).unwrap();

        // Parse frames and find the last one.
        let mut b = octets::Octets::with_slice(&buf[..sent]);
        let frames_len = b.get_varint().unwrap() as usize;

        let mut last_frame_had_length = true;
        let frames_start = b.off();

        while b.off() - frames_start < frames_len {
            let ty = b.get_varint().unwrap();

            if ty & 0xf8 == 0x08 {
                // STREAM frame
                let _sid = b.get_varint().unwrap();
                if ty & 0x04 != 0 {
                    let _off = b.get_varint().unwrap();
                }
                let has_len = ty & 0x02 != 0;
                let len = if has_len {
                    b.get_varint().unwrap() as usize
                } else {
                    b.cap()
                };
                b.skip(len).unwrap();
                last_frame_had_length = has_len;
            } else if ty == 0x30 || ty == 0x31 {
                // DATAGRAM frame
                let has_len = ty & 0x01 != 0;
                let len = if has_len {
                    b.get_varint().unwrap() as usize
                } else {
                    b.cap()
                };
                b.skip(len).unwrap();
                last_frame_had_length = has_len;
            } else {
                panic!("unexpected frame type {:#x}", ty);
            }
        }

        // If the last frame has no length, it means it filled to the record
        // boundary, and no more frames should follow.
        if !last_frame_had_length {
            // The record should be exactly full.
            assert_eq!(b.cap(), 0, "record should be exactly full");
        }

        // Verify second datagram is in a separate record.
        let (sent2, _) = pipe.client.send(&mut buf).unwrap();
        assert!(
            sent2 > 0,
            "second datagram should be sent in a separate record"
        );

        // Parse second record and verify it contains the small datagram.
        let mut b2 = octets::Octets::with_slice(&buf[..sent2]);
        let _frames_len2 = b2.get_varint().unwrap();
        let ty2 = b2.get_varint().unwrap();
        assert!(
            ty2 == 0x30 || ty2 == 0x31,
            "second record should start with DATAGRAM"
        );
    }

    /// Test QX_PING request/response round-trip and RTT measurement.
    #[test]
    fn qmux_ping_request_response() {
        use crate::test_utils::QmuxPipe;

        let mut pipe = QmuxPipe::new().unwrap();

        // Verify no RTT measured yet.
        assert!(pipe.client.qmux_ping_rtt().is_none());

        // Client requests a ping.
        pipe.client.qmux_ping();

        // Advance the pipe (client sends request, server receives and queues
        // response, server sends response, client receives and computes RTT).
        pipe.advance().unwrap();

        // Client should now have an RTT measurement.
        let rtt = pipe.client.qmux_ping_rtt();
        assert!(rtt.is_some(), "RTT should be measured after ping response");

        // RTT should be small (in-memory pipe).
        let rtt = rtt.unwrap();
        assert!(
            rtt < std::time::Duration::from_secs(1),
            "RTT {:?} seems too large for in-memory pipe",
            rtt
        );
    }

    /// Test that multiple QX_PING requests coalesce to a single response.
    #[test]
    fn qmux_ping_coalesce_responses() {
        use crate::test_utils::QmuxPipe;

        let mut pipe = QmuxPipe::new().unwrap();

        // Client requests 3 pings without advancing (all sent in one batch).
        pipe.client.qmux_ping();

        // Send client's ping request to server.
        let mut buf = [0u8; 65535];
        let (sent, _) = pipe.client.send(&mut buf).unwrap();
        let recv_info = crate::RecvInfo {
            from: "127.0.0.1:1234".parse().unwrap(),
            to: "127.0.0.1:4321".parse().unwrap(),
        };
        pipe.server.recv(&mut buf[..sent], recv_info).unwrap();

        // Server should have pending response for seq 0.
        // Send two more ping requests manually (seq 1 and 2) in one record.
        let ping1 = frame::Frame::QmuxPing {
            is_response: false,
            sequence_number: 1,
        };
        let ping2 = frame::Frame::QmuxPing {
            is_response: false,
            sequence_number: 2,
        };

        // Put both frames in one record.
        let mut frame_buf = [0u8; 64];
        let mut fb = octets::OctetsMut::with_slice(&mut frame_buf);
        ping1.to_bytes(&mut fb).unwrap();
        ping2.to_bytes(&mut fb).unwrap();
        let frames_len = fb.off();

        // Wrap in a single record and send to server.
        let mut record_buf = [0u8; 128];
        let mut rb = octets::OctetsMut::with_slice(&mut record_buf);
        rb.put_varint(frames_len as u64).unwrap();
        rb.put_bytes(&frame_buf[..frames_len]).unwrap();
        let record_len = rb.off();

        pipe.server
            .recv(&mut record_buf[..record_len], recv_info)
            .unwrap();

        // Server should respond with only seq 2 (largest).
        let (sent, _) = pipe.server.send(&mut buf).unwrap();

        // Parse the response to verify only one QX_PING response with seq 2.
        let mut b = octets::Octets::with_slice(&buf[..sent]);
        let _frames_len = b.get_varint().unwrap();

        let mut found_ping_response = false;
        while b.cap() > 0 {
            let frame = frame::Frame::from_bytes(&mut b, Type::Short).unwrap();
            if let frame::Frame::QmuxPing {
                is_response,
                sequence_number,
            } = frame
            {
                assert!(is_response, "should be a response");
                assert_eq!(sequence_number, 2, "should respond with largest seq");
                found_ping_response = true;
            }
        }
        assert!(found_ping_response, "should have sent a ping response");
    }
}
