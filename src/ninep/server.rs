//! Answering 9P2000.L, one request at a time, for whatever a `Handler`
//! serves.
//!
//! The loop answers `Tversion` and `Tflush` itself, since nothing's ever
//! in flight while a request's being answered, and anything it can't
//! decode, or a handler doesn't serve, with `EOPNOTSUPP`.

use std::io::{self, Read, Write};

use super::client::libc_errno;
use super::{MSIZE, NOTAG, Rmsg, Tmsg, Unknown, VERSION, read_message, write_message};

/// What's served: an answer to each request, or an errno.
pub trait Handler {
    fn handle(&mut self, request: Tmsg) -> Result<Rmsg, i32>;
}

/// Answer requests read from `reader` until the stream ends.
pub fn serve(handler: &mut impl Handler, reader: &mut impl Read, writer: &mut impl Write) -> io::Result<()> {
    let mut msize = MSIZE;
    loop {
        let message = match read_message(reader, msize) {
            Ok(message) => message,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        let (tag, answer) = match Tmsg::decode(&message) {
            Ok((tag, Tmsg::Version { msize: theirs, version })) => {
                msize = theirs.min(MSIZE);
                let version = if version == VERSION { VERSION.to_vec() } else { b"unknown".to_vec() };
                (tag, Rmsg::Version { msize, version })
            },
            Ok((tag, Tmsg::Flush { .. })) => (tag, Rmsg::Flush),
            Ok((tag, request)) => (tag, handler.handle(request).unwrap_or_else(|errno| Rmsg::Lerror { ecode: u32::try_from(errno).unwrap_or(5) })),
            Err(e) => {
                let tag = e.get_ref().and_then(|e| e.downcast_ref::<Unknown>()).map_or(NOTAG, |unknown| unknown.1);
                let ecode = if tag == NOTAG { libc_errno::EPROTO } else { libc_errno::EOPNOTSUPP };
                (tag, Rmsg::Lerror { ecode: u32::try_from(ecode).unwrap_or(5) })
            },
        };
        write_message(writer, &answer.encode(tag)?)?;
    }
}
