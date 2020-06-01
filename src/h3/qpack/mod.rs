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

mod start {
    // Encoder instructions
    pub const SET_CAPACITY: u8 = 0b0001_0000;
    pub const INSERT_WITH_NAME: u8 = 0b1000_0000;
    pub const INSERT_WITHOUT_NAME: u8 = 0b0100_0000;
    pub const DUPLICATE: u8 = 0b0000_0000;

    // Representations
    pub const INDEXED: u8 = 0b1000_0000;
    pub const INDEXED_WITH_POST_BASE: u8 = 0b0001_0000;
    pub const LITERAL: u8 = 0b0010_0000;
    pub const LITERAL_WITH_NAME_REF: u8 = 0b0100_0000;

    // Decoder instructions
    pub const ACK: u8 = 0b1000_0000;
    pub const STREAM_CANCEL: u8 = 0b0100_0000;
    pub const COUNT_INCREMENT: u8 = 0b0000_0000;
}

mod enc_prefix {
    pub const SET_CAPACITY: usize = 5;
    pub const NAME_INDEX: usize = 6;
    pub const NAME_LENGTH: usize = 5;
    pub const VALUE_LENGTH: usize = 7;
    pub const DUPLICATE_INDEX: usize = 5;
}

mod dec_prefix {
    pub const SET_CAPACITY: usize = 5;
    pub const NAME_INDEX: usize = 6;
    pub const NAME_LENGTH: usize = 5;
    pub const VALUE_LENGTH: usize = 7;
    pub const DUPLICATE_INDEX: usize = 5;
}

mod rep_prefix {
    pub const REQUIRED_INSERT_COUNT: usize = 8;
    pub const BASE: usize = 7;
    pub const FIELD_INDEX: usize = 6;// Field line index
    pub const FIELD_INDEX_POST_BASE: usize = 4;// Field line index
    pub const NAME_INDEX: usize = 4;
    pub const NAME_INDEX_POST_BASE: usize = 3;
    pub const NAME_LENGTH: usize = 3;
    pub const VALUE_LENGTH: usize = 7;

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

#[cfg(test)]
mod tests {
    use crate::*;

    use super::*;

    #[test]
    fn encode_decode() {
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

        let mut dec = Decoder::new();
        assert_eq!(dec.decode(&mut encoded, std::u64::MAX), Ok(headers));

        // capacity
        let mut foo = [0u8; 240];
        enc.set_max_table_capacity(1234);
        assert_eq!(enc.capacity_instruction(&mut foo), Ok(()));

        assert_eq!(dec.control(&mut foo), Ok(1234));
    }
}

pub use decoder::Decoder;
pub use encoder::Encoder;

mod decoder;
mod encoder;
mod huffman;
