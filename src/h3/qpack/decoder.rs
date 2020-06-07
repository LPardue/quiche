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

use crate::octets;

use super::Error;
use super::Result;

use super::*;

/// A QPACK decoder.
pub struct Decoder {}

impl Default for Decoder {
    fn default() -> Decoder {
        Decoder {}
    }
}

impl Decoder {
    /// Creates a new QPACK decoder.
    pub fn new() -> Decoder {
        Decoder::default()
    }

    pub fn header_ack(&self, out: &mut [u8], stream_id: u64) -> Result<()> {
        let mut b = octets::OctetsMut::with_slice(out);
        encode_int(stream_id, start::HEADER_ACK, dec_prefix::HEADER_ACK, &mut b)?;
        Ok(())
    }

    /// Processes control instructions from the encoder.
    pub fn control(&mut self, buf: &mut [u8]) -> Result<(usize,Event)> {
        // TODO: process control instructions

        let mut b = octets::Octets::with_slice(buf);

        //while b.cap() > 0 {
            let first = b.peek_u8()?;

            match EncInstruction::from_byte(first) {
                EncInstruction::SetCapacity => {

                    let capacity = decode_int(&mut b, enc_prefix::SET_CAPACITY)?;

                    trace!("SetCapacity value={}", capacity);

                    Ok((b.off(),Event::Capacity{v:capacity}))
                },

                EncInstruction::InsertWithNameRef => {
                    const STATIC: u8 = 0b0100_0000;
                    let s = first & STATIC == STATIC;

                    let name_idx = decode_int(&mut b, enc_prefix::NAME_INDEX)?;
                    let value = decode_value_str(&mut b)?;

                    trace!(
                        "InsertWithNameRef name_idx={} static={} value={:?}",
                        name_idx,
                        s,
                        value
                    );

                    let (name, _) = lookup_static(name_idx)?;
                    let hdr = Header::new(name, &value);

                    Ok((b.off(),Event::Header{v:hdr}))
                },

                EncInstruction::InsertWithoutNameRef => {
                    let name = decode_name_str(&mut b, enc_prefix::NAME_LENGTH)?;
                    let value = decode_value_str(&mut b)?;

                    trace!(
                        "InsertWithoutNameRef name={:?} value={:?}",
                        name,
                        value
                    );

                    let hdr = Header::new(&name, &value);

                    Ok((b.off(),Event::Header{v:hdr}))
                },

                EncInstruction::Duplicate => {
                    let idx = decode_int(&mut b, enc_prefix::DUPLICATE_INDEX)?;

                    trace!("Duplicate index={}", idx);

                    Ok((b.off(),Event::Duplicate{v:idx}))
                }

                //_ => ()
            }
        //}

        //Err(Error::Done)
    }

    /// Decodes a QPACK header block into a list of headers.
    pub fn decode(&mut self, buf: &[u8], max_size: u64) -> Result<Vec<Header>> {
        let mut b = octets::Octets::with_slice(buf);

        let mut out = Vec::new();

        let mut left = max_size;

        let req_insert_count = decode_int(&mut b, rep_prefix::REQUIRED_INSERT_COUNT)?;
        let base = decode_int(&mut b, rep_prefix::BASE)?;

        trace!("Header count={} base={}", req_insert_count, base);

        while b.cap() > 0 {
            let first = b.peek_u8()?;

            match Representation::from_byte(first) {
                Representation::Indexed => {
                    const STATIC: u8 = 0b0100_0000;

                    let s = first & STATIC == STATIC;
                    let index = decode_int(&mut b, rep_prefix::FIELD_INDEX)?;

                    trace!("Indexed index={} static={}", index, s);

                    if !s {
                        // TODO: implement dynamic table
                        return Err(Error::InvalidHeaderValue);
                    }

                    let (name, value) = lookup_static(index)?;

                    left = left
                        .checked_sub((name.len() + value.len()) as u64)
                        .ok_or(Error::HeaderListTooLarge)?;

                    out.push(Header::new(&name, &value));
                },

                Representation::IndexedWithPostBase => {
                    let index = decode_int(&mut b, rep_prefix::NAME_INDEX_POST_BASE)?;

                    trace!("Indexed With Post Base index={}", index);

                    // TODO: implement dynamic table
                    return Err(Error::InvalidHeaderValue);
                },

                Representation::Literal => {
                    let name = decode_name_str(&mut b, rep_prefix::NAME_LENGTH)?;

                    let value = decode_value_str(&mut b)?;

                    trace!(
                        "Literal Without Name Reference name={:?} value={:?}",
                        name,
                        value
                    );

                    left = left
                        .checked_sub((name.len() + value.len()) as u64)
                        .ok_or(Error::HeaderListTooLarge)?;

                    out.push(Header::new(&name, &value));
                },

                Representation::LiteralWithNameRef => {
                    const STATIC: u8 = 0b0001_0000;

                    let s = first & STATIC == STATIC;
                    let name_idx = decode_int(&mut b, rep_prefix::NAME_INDEX)?;
                    let value = decode_value_str(&mut b)?;

                    trace!(
                        "Literal name_idx={} static={} value={:?}",
                        name_idx,
                        s,
                        value
                    );

                    if !s {
                        // TODO: implement dynamic table
                        return Err(Error::InvalidHeaderValue);
                    }

                    let (name, _) = lookup_static(name_idx)?;

                    left = left
                        .checked_sub((name.len() + value.len()) as u64)
                        .ok_or(Error::HeaderListTooLarge)?;

                    out.push(Header::new(name, &value));
                },

                Representation::LiteralWithPostBase => {
                    trace!("Literal With Post Base");

                    // TODO: implement dynamic table
                    return Err(Error::InvalidHeaderValue);
                },
            }
        }

        Ok(out)
    }
}

fn lookup_static(idx: u64) -> Result<(&'static str, &'static str)> {
    let hdr = match idx {
        0 => (":authority", ""),
        1 => (":path", "/"),
        2 => ("age", "0"),
        3 => ("content-disposition", ""),
        4 => ("content-length", "0"),
        5 => ("cookie", ""),
        6 => ("date", ""),
        7 => ("etag", ""),
        8 => ("if-modified-since", ""),
        9 => ("if-none-match", ""),
        10 => ("last-modified", ""),
        11 => ("link", ""),
        12 => ("location", ""),
        13 => ("referer", ""),
        14 => ("set-cookie", ""),
        15 => (":method", "CONNECT"),
        16 => (":method", "DELETE"),
        17 => (":method", "GET"),
        18 => (":method", "HEAD"),
        19 => (":method", "OPTIONS"),
        20 => (":method", "POST"),
        21 => (":method", "PUT"),
        22 => (":scheme", "http"),
        23 => (":scheme", "https"),
        24 => (":status", "103"),
        25 => (":status", "200"),
        26 => (":status", "304"),
        27 => (":status", "404"),
        28 => (":status", "503"),
        29 => ("accept", "*/*"),
        30 => ("accept", "application/dns-message"),
        31 => ("accept-encoding", "gzip, deflate, br"),
        32 => ("accept-ranges", "bytes"),
        33 => ("access-control-allow-headers", "cache-control"),
        34 => ("access-control-allow-headers", "content-type"),
        35 => ("access-control-allow-origin", "*"),
        36 => ("cache-control", "max-age=0"),
        37 => ("cache-control", "max-age=2592000"),
        38 => ("cache-control", "max-age=604800"),
        39 => ("cache-control", "no-cache"),
        40 => ("cache-control", "no-store"),
        41 => ("cache-control", "public, max-age=31536000"),
        42 => ("content-encoding", "br"),
        43 => ("content-encoding", "gzip"),
        44 => ("content-type", "application/dns-message"),
        45 => ("content-type", "application/javascript"),
        46 => ("content-type", "application/json"),
        47 => ("content-type", "application/x-www-form-urlencoded"),
        48 => ("content-type", "image/gif"),
        49 => ("content-type", "image/jpeg"),
        50 => ("content-type", "image/png"),
        51 => ("content-type", "text/css"),
        52 => ("content-type", "text/html; charset=utf-8"),
        53 => ("content-type", "text/plain"),
        54 => ("content-type", "text/plain;charset=utf-8"),
        55 => ("range", "bytes=0-"),
        56 => ("strict-transport-security", "max-age=31536000"),
        57 => (
            "strict-transport-security",
            "max-age=31536000; includesubdomains",
        ),
        58 => (
            "strict-transport-security",
            "max-age=31536000; includesubdomains; preload",
        ),
        59 => ("vary", "accept-encoding"),
        60 => ("vary", "origin"),
        61 => ("x-content-type-options", "nosniff"),
        62 => ("x-xss-protection", "1; mode=block"),
        63 => (":status", "100"),
        64 => (":status", "204"),
        65 => (":status", "206"),
        66 => (":status", "302"),
        67 => (":status", "400"),
        68 => (":status", "403"),
        69 => (":status", "421"),
        70 => (":status", "425"),
        71 => (":status", "500"),
        72 => ("accept-language", ""),
        73 => ("access-control-allow-credentials", "FALSE"),
        74 => ("access-control-allow-credentials", "TRUE"),
        75 => ("access-control-allow-headers", "*"),
        76 => ("access-control-allow-methods", "get"),
        77 => ("access-control-allow-methods", "get, post, options"),
        78 => ("access-control-allow-methods", "options"),
        79 => ("access-control-expose-headers", "content-length"),
        80 => ("access-control-request-headers", "content-type"),
        81 => ("access-control-request-method", "get"),
        82 => ("access-control-request-method", "post"),
        83 => ("alt-svc", "clear"),
        84 => ("authorization", ""),
        85 => (
            "content-security-policy",
            "script-src 'none'; object-src 'none'; base-uri 'none'",
        ),
        86 => ("early-data", "1"),
        87 => ("expect-ct", ""),
        88 => ("forwarded", ""),
        89 => ("if-range", ""),
        90 => ("origin", ""),
        91 => ("purpose", "prefetch"),
        92 => ("server", ""),
        93 => ("timing-allow-origin", "*"),
        94 => ("upgrade-insecure-requests", "1"),
        95 => ("user-agent", ""),
        96 => ("x-forwarded-for", ""),
        97 => ("x-frame-options", "deny"),
        98 => ("x-frame-options", "sameorigin"),

        _ => return Err(Error::InvalidStaticTableIndex),
    };

    Ok(hdr)
}

fn decode_name_str<'a>(b: &'a mut octets::Octets, prefix: usize) -> Result<String> {
    let first = b.peek_u8()?;

    let huff_mask = match prefix {
        rep_prefix::NAME_LENGTH => 0b0000_1000,

        enc_prefix::NAME_LENGTH => 0b0010_0000,

        _ => unreachable!()
    };

    let huff = first & huff_mask == huff_mask;

    let len = decode_int(b, prefix)? as usize;

    let mut val = b.get_bytes(len)?;

    let val = if huff {
        super::huffman::decode(&mut val)?
    } else {
        val.to_vec()
    };

    let val = String::from_utf8(val).map_err(|_| Error::InvalidHeaderValue)?;
    Ok(val)
}

fn decode_value_str<'a>(b: &'a mut octets::Octets) -> Result<String> {
    let first = b.peek_u8()?;

    let huff = first & 0b1000_0000 == 0b1000_0000;

    let len = decode_int(b, rep_prefix::VALUE_LENGTH)? as usize;

    let mut val = b.get_bytes(len)?;

    let val = if huff {
        super::huffman::decode(&mut val)?
    } else {
        val.to_vec()
    };

    let val = String::from_utf8(val).map_err(|_| Error::InvalidHeaderValue)?;
    Ok(val)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::octets;

    #[test]
    fn decode_int1() {
        let mut encoded = [0b01010, 0b00010];
        let mut b = octets::Octets::with_slice(&mut encoded);

        assert_eq!(decode_int(&mut b, 5), Ok(10));
    }

    #[test]
    fn decode_int2() {
        let mut encoded = [0b11111, 0b10011010, 0b00001010];
        let mut b = octets::Octets::with_slice(&mut encoded);

        assert_eq!(decode_int(&mut b, 5), Ok(1337));
    }

    #[test]
    fn decode_int3() {
        let mut encoded = [0b101010];
        let mut b = octets::Octets::with_slice(&mut encoded);

        assert_eq!(decode_int(&mut b, 8), Ok(42));
    }
}
