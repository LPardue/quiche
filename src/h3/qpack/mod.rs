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

//! HTTP/3 header compression (QPACK).

use crate::octets;

use crate::h3::Header;

mod start {
    // Encoder instructions
    pub const SET_CAPACITY: u8 = 0b0010_0000;
    pub const INSERT_WITH_NAME: u8 = 0b1000_0000;
    pub const INSERT_WITHOUT_NAME: u8 = 0b0100_0000;
    pub const DUPLICATE: u8 = 0b0000_0000;

    // Representations
    pub const INDEXED: u8 = 0b1000_0000;
    pub const INDEXED_WITH_POST_BASE: u8 = 0b0001_0000;
    pub const LITERAL: u8 = 0b0010_0000;
    pub const LITERAL_WITH_NAME_REF: u8 = 0b0100_0000;

    // Decoder instructions
    pub const HEADER_ACK: u8 = 0b1000_0000;
    pub const STREAM_CANCEL: u8 = 0b0100_0000;
    pub const INSERT_COUNT_INCREMENT: u8 = 0b0000_0000;
}

mod enc_prefix {
    pub const SET_CAPACITY: usize = 5;
    pub const NAME_INDEX: usize = 6;
    pub const NAME_LENGTH: usize = 5;
    pub const VALUE_LENGTH: usize = 7;
    pub const DUPLICATE_INDEX: usize = 5;
}

mod dec_prefix {
    pub const HEADER_ACK: usize = 7;
    pub const STREAM_CANCEL: usize = 6;
    pub const INSERT_COUNT_INCREMENT: usize = 6;
}

pub mod rep_prefix {
    pub const REQUIRED_INSERT_COUNT: usize = 8;
    pub const BASE: usize = 7;
    pub const FIELD_INDEX: usize = 6; // Field line index
    pub const FIELD_INDEX_POST_BASE: usize = 4; // Field line index
    pub const NAME_INDEX: usize = 4;
    pub const INDEXED_WITH_POST_BASE_NAME_INDEX: usize = 4;
    pub const LITERAL_WITH_POST_BASE_NAME_INDEX: usize = 3;
    pub const NAME_LENGTH: usize = 3;
    pub const VALUE_LENGTH: usize = 7;
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum EncInstruction {
    SetCapacity,
    InsertWithNameRef,
    InsertWithoutNameRef,
    Duplicate,
}

impl EncInstruction {
    pub fn from_byte(b: u8) -> Result<Self> {
        // order of checks is important in order to avoid aliasing instruction
        // types
        if b & start::INSERT_WITH_NAME == start::INSERT_WITH_NAME {
            return Ok(EncInstruction::InsertWithNameRef);
        }

        if b & start::INSERT_WITHOUT_NAME == start::INSERT_WITHOUT_NAME {
            return Ok(EncInstruction::InsertWithoutNameRef);
        }

        if b & start::SET_CAPACITY == start::SET_CAPACITY {
            return Ok(EncInstruction::SetCapacity);
        }

        Ok(EncInstruction::Duplicate)

        // if b & start::HEADER_ACK == start::HEADER_ACK {
        // return Ok(Instruction::HeaderAck);
        // }
        //
        // if b & start::STREAM_CANCEL == start::STREAM_CANCEL {
        // return Ok(Instruction::StreamCancellation);
        // }
        //
        // if b == 0 {
        // return Ok(Instruction::InsertCountIncrement);
        // }
    }
}

enum DecInstruction {
    HeaderAck,
    StreamCancellation,
    InsertCountIncrement,
}

impl DecInstruction {
    pub fn from_byte(b: u8) -> Result<Self> {
        if b == 0 {
            return Err(Error::Done);
        }

        if b & start::HEADER_ACK == start::HEADER_ACK {
            return Ok(DecInstruction::HeaderAck);
        }

        if b & start::STREAM_CANCEL == start::STREAM_CANCEL {
            return Ok(DecInstruction::StreamCancellation);
        }

        Ok(DecInstruction::InsertCountIncrement)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Representation {
    Indexed,
    IndexedWithPostBase,
    Literal,
    LiteralWithNameRef,
    LiteralWithPostBase,
}

impl Representation {
    pub fn from_byte(b: u8) -> Representation {
        if b & start::INDEXED == start::INDEXED {
            return Representation::Indexed;
        }

        if b & start::LITERAL_WITH_NAME_REF == start::LITERAL_WITH_NAME_REF {
            return Representation::LiteralWithNameRef;
        }

        if b & start::LITERAL == start::LITERAL {
            return Representation::Literal;
        }

        if b & start::INDEXED_WITH_POST_BASE == start::INDEXED_WITH_POST_BASE {
            return Representation::IndexedWithPostBase;
        }

        Representation::LiteralWithPostBase
    }
}
#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    Capacity { v: u64 },

    Header { v: Header },

    Duplicate { v: u64 },

    HeaderAck { v: u64 },

    StreamCancellation { v: u64 },

    InsertCountIncrement { v: u64 },
}

/// A specialized [`Result`] type for quiche QPACK operations.
///
/// This type is used throughout quiche's QPACK public API for any operation
/// that can produce an error.
///
/// [`Result`]: https://doc.rust-lang.org/std/result/enum.Result.html
pub type Result<T> = std::result::Result<T, Error>;

/// A QPACK error.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Error {
    /// There is no error or no work to do
    Done,

    /// The provided buffer is too short.
    BufferTooShort,

    /// The QPACK header block's huffman encoding is invalid.
    InvalidHuffmanEncoding,

    /// The QPACK static table index provided doesn't exist.
    InvalidStaticTableIndex,

    /// The decoded QPACK header name or value is not valid.
    InvalidHeaderValue,

    /// The decoded header list exceeded the size limit.
    HeaderListTooLarge,

    /// The decoder failed to interpret an encoder instruction received on the
    /// encoder stream.
    EncoderStreamError,

    /// The encoder failed to interpret a decoder instruction received on the
    /// decoder stream.
    DecoderStreamError,

    /// Decompression failed.
    DecompressionFailed,

    // Decoding was blocked.
    Blocked,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl std::convert::From<crate::octets::BufferTooShortError> for Error {
    fn from(_err: crate::octets::BufferTooShortError) -> Self {
        Error::BufferTooShort
    }
}

fn encode_int(
    mut v: u64, first: u8, prefix: usize, b: &mut octets::OctetsMut,
) -> Result<()> {
    let mask = 2u64.pow(prefix as u32) - 1;

    // Encode I on N bits.
    if v < mask {
        b.put_u8(first | v as u8)?;
        return Ok(());
    }

    // Encode (2^N - 1) on N bits.
    b.put_u8(first | mask as u8)?;

    v -= mask;

    while v >= 128 {
        // Encode (I % 128 + 128) on 8 bits.
        b.put_u8((v % 128 + 128) as u8)?;

        v >>= 7;
    }

    // Encode I on 8 bits.
    b.put_u8(v as u8)?;

    Ok(())
}

pub fn decode_int2(buf: &[u8], prefix: usize) -> Result<(usize, u64)> {
    let mask = 2u64.pow(prefix as u32) - 1;

    let mut offset = 0;

    let mut val =
        u64::from(*buf.get(offset).ok_or(Error::BufferTooShort)?);
    // error!("decode_int2 val={}", val);
    val &= mask;

    offset += 1;

    if val < mask {
        return Ok((offset, val));
    }

    let mut shift = 0;

    while let Some(byte) = buf.get(offset) {
        // error!("decode_int2 loop");
        offset += 1;

        let inc = u64::from(byte & 0b0111_1111)
            .checked_shl(shift)
            .ok_or(Error::BufferTooShort)?;

        val = val.checked_add(inc).ok_or(Error::BufferTooShort)?;

        shift += 7;

        if byte & 0b1000_0000 == 0 {
            return Ok((offset, val));
        }
    }

    Err(Error::BufferTooShort)
}

fn decode_int(b: &mut octets::Octets, prefix: usize) -> Result<u64> {
    let mask = 2u64.pow(prefix as u32) - 1;

    let mut val = u64::from(b.get_u8()?);
    // error!("decode_int val={}", val);
    val &= mask;

    if val < mask {
        return Ok(val);
    }

    let mut shift = 0;

    while b.cap() > 0 {
        // error!("decode_int loop");
        let byte = b.get_u8()?;

        let inc = u64::from(byte & 0b0111_1111)
            .checked_shl(shift)
            .ok_or(Error::BufferTooShort)?;

        val = val.checked_add(inc).ok_or(Error::BufferTooShort)?;

        shift += 7;

        if byte & 0b1000_0000 == 0 {
            return Ok(val);
        }
    }

    Err(Error::BufferTooShort)
}

#[cfg(test)]
mod tests {
    use crate::*;

    use super::*;

    #[test]
    fn static_encode_decode() {
        let mut encoded = [0u8; 240];

        let headers = vec![
            h3::Header::new(":path", "/rsrc.php/v3/yn/r/rIPZ9Qkrdd9.png"),
            h3::Header::new("accept-encoding", "gzip, deflate, br"),
            h3::Header::new("accept-language", "en-US,en;q=0.9"),
            h3::Header::new("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.70 Safari/537.36"),
            h3::Header::new("accept", "image/webp,image/apng,image/*,*/*;q=0.8"),
            h3::Header::new("referer", "https://static.xx.fbcdn.net/rsrc.php/v3/yT/l/0,cross/dzXGESIlGQQ.css"),
            h3::Header::new(":authority", "static.xx.fbcdn.net"),
            h3::Header::new(":scheme", "https"),
            h3::Header::new(":method", "GET"),
        ];

        let mut enc = Encoder::new();
        assert!(enc.encode(&headers, &mut encoded).is_ok());

        let mut dec = Decoder::new(256);
        let (size, decoded_insert_count) =
            dec.decode_req_insert_count2(&encoded).unwrap();
        assert_eq!(
            dec.decode(&mut encoded[size..], decoded_insert_count, std::u64::MAX),
            Ok(headers)
        );
    }

    #[test]
    fn encoder_capacity_instr() {
        let mut enc = Encoder::new();
        let mut dec = Decoder::new(256);
        let mut buf = [0u8; 24];

        enc.set_max_table_capacity(10);
        assert_eq!(enc.capacity_instruction(&mut buf), Ok(1));
        assert_eq!(dec.control(&mut buf), Ok((1, Event::Capacity { v: 10 })));

        // now send a bogus capacity
        let mut enc = Encoder::new();
        enc.set_max_table_capacity(1000);
        assert_eq!(enc.capacity_instruction(&mut buf), Ok(3));
        assert_eq!(
            dec.control(&mut buf),
            Err(h3::qpack::Error::EncoderStreamError)
        );
    }

    #[test]
    fn insert_with_name_instr() {
        let enc = Encoder::new();
        let mut dec = Decoder::new(256);
        let mut buf = [0u8; 24];

        let hdr = h3::Header::new(":method", "HELP");
        assert_eq!(enc.insert(&mut buf, &hdr, 15, true), Ok(6));
        assert_eq!(dec.control(&mut buf), Ok((6, Event::Header { v: hdr })));
    }

    #[test]
    fn insert_without_name_instr() {
        let enc = Encoder::new();
        let mut dec = Decoder::new(256);
        let mut buf = [0u8; 24];

        // insert without name (TODO the idx is weird here)
        let hdr = h3::Header::new(":path", "thewrongpath");
        assert_eq!(enc.insert(&mut buf, &hdr, 1, false), Ok(15));
        assert_eq!(dec.control(&mut buf), Ok((15, Event::Header { v: hdr })));
    }

    #[test]
    fn duplicate() {
        let enc = Encoder::new();
        let mut dec = Decoder::new(256);
        let mut buf = [0u8; 24];

        let hdr = h3::Header::new(":method", "HELP");
        assert_eq!(enc.insert(&mut buf, &hdr, 15, true), Ok(6));
        assert_eq!(dec.control(&mut buf), Ok((6, Event::Header { v: hdr })));

        assert_eq!(enc.duplicate(&mut buf, 0), Ok(1));
        assert_eq!(dec.control(&mut buf), Ok((1, Event::Duplicate { v: 0 })));

        // duplicating an entry that does not exist is an error
        assert_eq!(enc.duplicate(&mut buf, 5), Ok(1));
        assert_eq!(
            dec.control(&mut buf),
            Err(super::Error::DecompressionFailed)
        );
    }

    #[test]
    fn encoder_instructions_batched() {
        let enc = Encoder::new();
        let mut dec = Decoder::new(256);

        // combine several instructions into this single buffer
        const TOTAL_INSTRUCTION_SIZE: usize = 23;
        let mut buf = [0u8; TOTAL_INSTRUCTION_SIZE];

        let mut off = 0;

        off += enc.capacity_instruction(&mut buf[off..]).unwrap();

        let hdr = h3::Header::new(":method", "HELP");
        off += enc.insert(&mut buf[off..], &hdr, 15, true).unwrap();

        let hdr = h3::Header::new(":path", "thewrongpath");
        off += enc.insert(&mut buf[off..], &hdr, 1, false).unwrap();

        off += enc.duplicate(&mut buf[off..], 0).unwrap();

        off = 0;
        let (size, _) = dec.control(&mut buf[off..]).unwrap();

        off += size;
        let (size, _) = dec.control(&mut buf[off..]).unwrap();

        off += size;
        let (size, _) = dec.control(&mut buf[off..]).unwrap();

        off += size;
        let (size, _) = dec.control(&mut buf[off..]).unwrap();

        off += size;
        assert_eq!(off, TOTAL_INSTRUCTION_SIZE);
    }

    #[test]
    fn decoder_instructions() {
        let mut enc = Encoder::new();
        let dec = Decoder::new(256);
        let mut buf = [0u8; 24];

        // header ack
        assert_eq!(dec.header_ack(&mut buf, 123), Ok(1));
        assert_eq!(enc.control(&mut buf), Ok((1, Event::HeaderAck { v: 123 })));

        // stream cancellation
        assert_eq!(dec.stream_cancel(&mut buf, 456), Ok(3));
        assert_eq!(
            enc.control(&mut buf),
            Ok((3, Event::StreamCancellation { v: 456 }))
        );

        // insert count increment
        assert_eq!(dec.insert_count_increment(&mut buf, 789), Ok(3));
        assert_eq!(
            enc.control(&mut buf),
            Ok((3, Event::InsertCountIncrement { v: 789 }))
        );
    }

    #[test]
    fn decoder_instructions_batched() {
        let mut enc = Encoder::new();
        let dec = Decoder::new(256);

        // combine several instructions into this single buffer
        let mut buf = [0u8; 24];

        let mut off = 0;

        off += dec.header_ack(&mut buf[off..], 123).unwrap();
        off += dec.stream_cancel(&mut buf[off..], 456).unwrap();
        off += dec.insert_count_increment(&mut buf[off..], 789).unwrap();

        off = 0;
        let (size, _) = enc.control(&mut buf[off..]).unwrap();

        off += size;
        let (size, _) = enc.control(&mut buf[off..]).unwrap();

        off += size;
        let (size, _) = enc.control(&mut buf[off..]).unwrap();

        off += size;
        assert_eq!(enc.control(&mut buf[off..]), Err(h3::qpack::Error::Done));
    }
}

pub use decoder::Decoder;
pub use encoder::Encoder;

mod decoder;
mod encoder;
mod huffman;
