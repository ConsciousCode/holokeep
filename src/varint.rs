//! Read and write DWARF's "Little Endian Base 128" (LEB128) variable length
//! integer encoding.
//!
//! The implementation is a direct translation of the psuedocode in the DWARF 4
//! standard's appendix C.
//!
//! Read and write signed integers:
//!
//! ```
//! use leb128;
//!
//! let mut buf = [0; 1024];
//!
//! // Write to anything that implements `std::io::Write`.
//! {
//!     let mut writable = &mut buf[..];
//!     leb128::write::signed(&mut writable, -12345).expect("Should write number");
//! }
//!
//! // Read from anything that implements `std::io::Read`.
//! let mut readable = &buf[..];
//! let val = leb128::read::signed(&mut readable).expect("Should read number");
//! assert_eq!(val, -12345);
//! ```
//!
//! Or read and write unsigned integers:
//!
//! ```
//! use leb128;
//!
//! let mut buf = [0; 1024];
//!
//! {
//!     let mut writable = &mut buf[..];
//!     leb128::write::unsigned(&mut writable, 98765).expect("Should write number");
//! }
//!
//! let mut readable = &buf[..];
//! let val = leb128::read(&mut readable).expect("Should read number");
//! assert_eq!(val, 98765);
//! ```

use bytes::BufMut;

const CONT_BIT: u8 = 1 << 7;
const PAYLOAD: u8 = CONT_BIT - 1;
const SIGN_BIT: u8 = 1 << 6;

/// An error type for reading LEB128-encoded values.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// There was an underlying IO error.
    #[error("bytes truncated")]
    Truncated,
    /// The number being read is larger than can be represented.
    #[error("leb128 overflow")]
    Overflow,
}

pub const fn size(value: u64) -> usize {
    if value <= 127 { 1 }
    else {
        ((value.ilog2() + 7)/7) as usize
    }
}

fn payload_u8(byte: u8) -> u64 {
    (byte & PAYLOAD) as u64
}
fn payload_u64(value: u64) -> u8 {
    value as u8 & PAYLOAD
}

/// Read an unsigned LEB128-encoded number from the `std::io::Read` stream
/// `r`.
///
/// On success, return the number.
pub fn read(buf: &mut &[u8]) -> Result<u64, Error> {
    let mut result = 0u64;
    let mut shift = 0u32;

    loop {
        let byte = buf
            .split_off_first()
            .copied()
            .ok_or(Error::Truncated)?;

        // Allow one last byte so long as it's just one bit
        if shift == 63 && byte > 1 {
            // Consume the rest of the varint so the next read is aligned
            let mut last = byte;
            while last & CONT_BIT != 0 {
                last = buf.split_off_first().copied().ok_or(Error::Truncated)?;
            }
            return Err(Error::Overflow);
        }

        result |= payload_u8(byte) << shift;

        if byte & CONT_BIT == 0 {
            return Ok(result);
        }

        shift += 7;
    }
}

/// Write `val` to the `std::io::Write` stream `w` as an unsigned LEB128 value.
///
/// On success, return the number of bytes written to `w`.
pub fn write(buf: &mut (impl ?Sized + BufMut), mut val: u64) {
    loop {
        let mut byte = payload_u64(val);
        val >>= 7;
        if val != 0 {
            // More bytes to come, so set the continuation bit.
            byte |= CONT_BIT;
        }

        buf.put_u8(byte);

        if val == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_u8() {
        for i in 0..127 {
            assert_eq!(i as u64, payload_u8(i));
            assert_eq!(i as u64, payload_u8(i | CONT_BIT));
        }
    }

    #[test]
    fn test_payload_u64() {
        for i in 0u64..127 {
            assert_eq!(i as u8, payload_u64(1 << 16 | i));
            assert_eq!(
                i as u8,
                payload_u64(i << 16 | i | (CONT_BIT as u64))
            );
        }
    }

    // Examples from the DWARF 4 standard, section 7.6, figure 22.
    #[test]
    fn test_read_unsigned() {
        let buf = [2u8];
        let mut readable = &buf[..];
        assert_eq!(
            2,
            read(&mut readable).expect("Should read number")
        );

        let buf = [127u8];
        let mut readable = &buf[..];
        assert_eq!(
            127,
            read(&mut readable).expect("Should read number")
        );

        let buf = [CONT_BIT, 1];
        let mut readable = &buf[..];
        assert_eq!(
            128,
            read(&mut readable).expect("Should read number")
        );

        let buf = [1u8 | CONT_BIT, 1];
        let mut readable = &buf[..];
        assert_eq!(
            129,
            read(&mut readable).expect("Should read number")
        );

        let buf = [2u8 | CONT_BIT, 1];
        let mut readable = &buf[..];
        assert_eq!(
            130,
            read(&mut readable).expect("Should read number")
        );

        let buf = [57u8 | CONT_BIT, 100];
        let mut readable = &buf[..];
        assert_eq!(
            12857,
            read(&mut readable).expect("Should read number")
        );
    }

    #[test]
    fn test_read_not_enough_data() {
        let buf = [CONT_BIT];
        let mut readable = &buf[..];
        match read(&mut readable) {
            Err(Error::Truncated) => (),
            otherwise => panic!("Unexpected: {:?}", otherwise),
        }
    }

    /*
    #[test]
    fn dogfood_unsigned() {
        for i in 0..1025 {
            let mut buf = [0u8; 1024];

            {
                let mut writable = &mut buf[..];
                write(&mut writable, i);
            }

            let mut readable = &buf[..];
            let result =
                read(&mut readable).expect("Should be able to read it back again");
            assert_eq!(i, result);
        }
    } */

    #[test]
    fn test_read_overflow() {
        let buf = [
            2u8 | CONT_BIT,
            2 | CONT_BIT,
            2 | CONT_BIT,
            2 | CONT_BIT,
            2 | CONT_BIT,
            2 | CONT_BIT,
            2 | CONT_BIT,
            2 | CONT_BIT,
            2 | CONT_BIT,
            2 | CONT_BIT,
            2 | CONT_BIT,
            2 | CONT_BIT,
            2 | CONT_BIT,
            2 | CONT_BIT,
            2 | CONT_BIT,
            2 | CONT_BIT,
            2 | CONT_BIT,
            2 | CONT_BIT,
            2 | CONT_BIT,
            2 | CONT_BIT,
            2 | CONT_BIT,
            2 | CONT_BIT,
            2 | CONT_BIT,
            2 | CONT_BIT,
            2 | CONT_BIT,
            2 | CONT_BIT,
            2 | CONT_BIT,
            2 | CONT_BIT,
            2 | CONT_BIT,
            2 | CONT_BIT,
            1,
        ];
        let mut readable = &buf[..];
        assert!(read(&mut readable).is_err());
    }

    #[test]
    fn test_read_multiple() {
        let buf = [2u8 | CONT_BIT, 1u8, 1u8];

        let mut readable = &buf[..];
        assert_eq!(
            read(&mut readable).expect("Should read first number"),
            130u64
        );
        assert_eq!(
            read(&mut readable).expect("Should read first number"),
            1u64
        );
    }

    #[test]
    fn test_read_multiple_with_overflow() {
        let buf = [
            0b1111_1111,
            0b1111_1111,
            0b1111_1111,
            0b1111_1111,
            0b1111_1111,
            0b1111_1111,
            0b1111_1111,
            0b1111_1111,
            0b1111_1111,
            0b1111_1111,
            0b0111_1111, // Overflow!
            0b1110_0100,
            0b1110_0000,
            0b0000_0010, // 45156
        ];
        let mut readable = &buf[..];

        assert!(if let Error::Overflow =
            read(&mut readable).expect_err("Should fail with Error::Overflow")
        {
            true
        } else {
            false
        });
        assert_eq!(
            read(&mut readable).expect("Should succeed with correct value"),
            45156
        );
    }

    #[test]
    fn test_write_size() {
        assert_eq!(size(0), 1);
        assert_eq!(size(64), 1);
        assert_eq!(size(127), 1);
        assert_eq!(size(128), 2);
        assert_eq!(size((1 << 42) - 1), 6);
        assert_eq!(size(u64::MAX), 10);
    }
}
