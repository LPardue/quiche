// Copyright (C) 2019, Cloudflare, Inc.
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

#[macro_use]
extern crate log;

use std::fs::File;

use std::io::prelude::*;

use quiche::h3::qpack;

fn main() {
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

    debug!("Loaded {}, max_dynamic_table_capacity={} max_blocked_streams={} ack_mode={}",
        &path,
        max_dyn_table_capacity,
        max_blocked_streams,
        ack_mode);

    let mut dec = qpack::Decoder::new(max_dyn_table_capacity);

    env_logger::builder()
        .default_format_timestamp_nanos(true)
        .init();

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
        } else {
            for hdr in dec.decode(&data[..len], std::u64::MAX).unwrap() {
                println!("{}\t{}", hdr.name(), hdr.value());
            }

            println!();
        }
    }
}
