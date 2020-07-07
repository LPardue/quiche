// Copyright (C) 2019, Cloudflare, Inc. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// A decoder for offline QPACK interop testing.
//
// qpack-decoder is quiche's tool for the decoding element of offline QPACK
// interop as described at
// https://github.com/quicwg/base-drafts/wiki/QPACK-Offline-Interop.
//
// The offline tests source files are plain text HTTP headers captured in the
// QIF (QPACK Interop Format) format. Several QPACK implementations have
// generated binary encodings from these source QIFs and uploaded them to
// https://github.com/qpackers/qifs/tree/master/encoded.

// qpack-decoder takes the binary encoded QPACK as input, decodes it, and
// generates QIF as output. The output can be compared to the original source in
// order to validate that the decoder is functioning properly.

#[macro_use]
extern crate log;

use std::collections::HashMap;

use std::fs::File;

use std::io::prelude::*;

use quiche::h3::qpack;

// Storage for blocked streams, keyed on stream ID and storing the Required
// Insert Count for the associated encoded field section bytes.
type BlockedStreamMap = HashMap<u64, (u64, Vec<u8>)>;

fn try_unblock(decoder: &mut qpack::Decoder, blocked_streams: &mut BlockedStreamMap) {
    let mut unblocked = Vec::new();

    for (k, v) in blocked_streams.iter() {

        // Early exit opportunity if the blocked stream's
        // Required Insert Count is greater than the Decoder's
        // insert count.
        if v.0 > decoder.total_insert_count() {
            continue;
        }

        match decoder.decode(&v.1, v.0, std::u64::MAX) {
            Ok(hdrs) => {
                for hdr in hdrs {
                    println!("{}\t{}", hdr.name(), hdr.value());
                }

                // Once the encoded field section is decoded,
                // we can mark is as unblocked.
                unblocked.push(k.clone());
            },

            Err(qpack::Error::BufferTooShort) => continue,

            Err(e) => panic!(e.to_string()),
        }

        println!();
    }

    for stream in unblocked {
        blocked_streams.remove(&stream);
    }
}

fn main() {
    env_logger::builder()
    .default_format_timestamp_nanos(true)
    .init();

    let mut args = std::env::args();

    let cmd = &args.next().unwrap();

    if args.len() != 1 {
        println!("Usage: {} FILE", cmd);
        return;
    }

    let path = &args.next().unwrap();

    let params: Vec<&str> = path.split('.').rev().collect();
    let max_dyn_table_capacity = u64::from_str_radix(params[2], 10).unwrap();
    let max_blocked_streams = u64::from_str_radix(params[1], 10).unwrap();
    let ack_mode = u64::from_str_radix(params[0], 10).unwrap();

    let mut file = File::open(&path).unwrap();

    let mut blocked_streams: BlockedStreamMap =
        std::collections::HashMap::new();

    debug!("Loaded {}, max_dynamic_table_capacity={} max_blocked_streams={} ack_mode={}",
        &path,
        max_dyn_table_capacity,
        max_blocked_streams,
        ack_mode);

    let mut dec = qpack::Decoder::new(max_dyn_table_capacity);

    loop {
        let mut stream_id: [u8; 8] = [0; 8];
        let mut len: [u8; 4] = [0; 4];

        let _ = file.read(&mut stream_id).unwrap();
        let stream_id = u64::from_be_bytes(stream_id);

        let _ = file.read(&mut len).unwrap();
        let len = u32::from_be_bytes(len) as usize;

        let mut data = vec![0; len as usize];

        let data_len = file.read(&mut data).unwrap();

        if data_len == 0 {
            break;
        }

        debug!("Got stream={} len={}", stream_id, len);

        // QPACK encoder instructions are sent on stream 0, try to consume these
        // first to update the Decoder state and dynamic table.
        if stream_id == 0 {
            debug!("read stream 0. len={}", len);
            let mut off = 0;
            while off < len {
                match dec.control(&mut data[off..len]) {
                    Ok((size, ev)) => {
                        debug!("Got {:?}, size={}", ev, size);
                        off += size;
                    },

                    Err(quiche::h3::qpack::Error::Done) => {
                        debug!("got done!");
                        break;
                    },

                    Err(e) => {
                        error!("got {}", e);
                        break;
                    },
                }
            }

            // After consuming instructions, the Decoder state might be
            // updated and allow us to unblock streams.
            try_unblock(&mut dec, &mut blocked_streams);
        } else {
            // All other streams carry HEADERS frames.

            // First decode the Required Insert Count, if the Decoder's
            // total inserts is too low, mark the stream as blocked and
            // move on to consuming the next piece of file data.
            let (size, decoded_insert_count) =
                dec.try_decode_req_insert_count(&data[..len]).unwrap();

            if decoded_insert_count > dec.total_insert_count() {
                debug!(
                    "Stream blocked: id={} decoded_ric={} total_inserts={}",
                    stream_id,
                    decoded_insert_count,
                    dec.total_insert_count()
                );

                blocked_streams.insert(
                    stream_id,
                    (decoded_insert_count, data[size..len].to_vec()),
                );
                continue;
            }

            match dec.decode(
                &data[size..len],
                decoded_insert_count,
                std::u64::MAX,
            ) {
                Ok(hdrs) =>
                    for hdr in hdrs {
                        println!("{}\t{}", hdr.name(), hdr.value());
                    },

                Err(qpack::Error::BufferTooShort) => continue,

                Err(e) => panic!(e.to_string()),
            }

            println!();
        }
    }

}
