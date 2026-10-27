use std::fmt;
use std::str::Utf8Error;

use bytes::TryGetError;

use crate::{cid, varint};

use super::dagpb::{PbLinkF, PbNodeF};
use super::pb::PbType;
use super::unixfsv1::{UFSv1F, UnixTimeF};

//----------------------//
//-[ Public interface ]-//
//----------------------//

/// Error while parsing dag-pb or unixfsv1.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct Error {
    #[from]
    detail: ErrorDetail
}

/// The kind of error which occurred.
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ErrorKind {
    /// Input was truncated.
    #[error("truncated input")]
    Truncated,
    /// Error while parsing protobuf wire format.
    #[error("parsing protobuf")]
    Protobuf,
    /// Error while parsing a dag-pb structure.
    #[error("parsing dag-pb")]
    Dagpb,
    /// Error while validating data.
    #[error("validating fields")]
    Validation,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum PrimitiveError {
    #[error("parsing varint")]
    Varint(#[from] varint::Error),

    #[error("truncated bytes")]
    Truncated,
}
impl From<TryGetError> for PrimitiveError {
    fn from(_: TryGetError) -> Self {
        Self::Truncated
    }
}

#[derive(Debug, thiserror::Error)]
pub(super) enum Utf8BytesError {
    /// Error while parsing UTF-8
    #[error("parsing utf-8")]
    Utf8,

    #[error("reading bytes")]
    Primitive(#[from] PrimitiveError),
}

impl From<Utf8Error> for Utf8BytesError {
    fn from(_: Utf8Error) -> Self {
        Self::Utf8
    }
}

/// Error while parsing a CID.
#[derive(Debug, thiserror::Error)]
pub enum CidError {
    /*
    #[error("truncated bytes")]
    Truncated,

    #[error("varint overflow")]
    Overflow,
    */
    #[error("primitive")]
    Primitive(#[from] PrimitiveError),

    /// Error while parsing CID.
    #[error("parsing CID")]
    Cid(#[from] cid::DecodeError),
}

#[derive(Debug, Copy, Clone)]
pub(super) enum Origin {
    Node,
    Link,
    Unixfsv1,
    UnixTime,
}

struct DisplaySource(Origin, u8);
impl fmt::Display for DisplaySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        macro_rules! fmt_field {
            ($field_ty:ty) => {
                match <$field_ty>::try_from(self.1) {
                    Ok(field) => write!(f, "{field:?}"),
                    Err(_) => write!(f, "unknown"),
                }
            };
        }

        match self.0 {
            Origin::Node => fmt_field!(PbNodeF),
            Origin::Link => fmt_field!(PbLinkF),
            Origin::Unixfsv1 => fmt_field!(UFSv1F),
            Origin::UnixTime => fmt_field!(UnixTimeF),
        }
    }
}

struct DisplayType(u8);
impl fmt::Display for DisplayType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let raw = self.0;
        match raw.try_into() {
            Ok(PbType::Varint) => write!(f, "int64({})", raw),
            Ok(PbType::Fixed64) => write!(f, "fixed64({})", raw),
            Ok(PbType::Length) => write!(f, "bytes({})", raw),
            Ok(PbType::Fixed32) => write!(f, "fixed32({})", raw),
            Err(_) => write!(f, "unknown({})", raw),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(super) enum InnerError {
    /// Input was truncated.
    #[error("truncated input")]
    Truncated,

    // Protobuf
    /// Invalid protobuf tag type.
    #[error("invalid tag type")]
    InvalidTag,
    /// Varint too big to fit in u64
    #[error("varint overflowed u64")]
    VarintOverflow,
    
    // Dagpb
    /// Message missing required field.
    #[error("missing required field")]
    Missing,
    /// Message has an unknown field.
    #[error("unknown field")]
    Unknown,
    /// Message has an unexpected duplicated field.
    #[error("duplicate field")]
    Duplicate,
    /// Field has the wrong type.
    #[error("field has the wrong type")]
    WrongType,
    /// Field appeared out of order.
    #[error("field out of order")]
    OutOfOrder,

    // Validation
    /// UTF-8 validation error.
    #[error("utf-8 validation")]
    Utf8,
    /// Error while reading CID.
    #[error("cid parsing")]
    Cid(#[from] cid::DecodeError),
    /// DataType field not recognized
    #[error("unknown DataType")]
    DataType,
}

impl InnerError {
    pub fn with_context(self, subsys: Origin, field: impl Into<u8>, ty: impl Into<u8>) -> Error {
        Error {
            detail: ErrorDetail {
                source: self,
                origin: subsys,
                field: field.into(),
                ty: ty.into(),
            }
        }
    }
}

impl From<TryGetError> for InnerError {
    fn from(_: TryGetError) -> Self {
        Self::Truncated
    }
}

impl From<varint::Error> for InnerError {
    fn from(value: varint::Error) -> Self {
        match value {
            varint::Error::Truncated => Self::Truncated,
            varint::Error::Overflow => Self::VarintOverflow,
        }
    }
}

impl From<PrimitiveError> for InnerError {
    fn from(value: PrimitiveError) -> Self {
        match value {
            PrimitiveError::Varint(e) => e.into(),
            PrimitiveError::Truncated => Self::Truncated,
        }
    }
}

impl From<Utf8BytesError> for InnerError {
    fn from(value: Utf8BytesError) -> Self {
        match value {
            Utf8BytesError::Utf8 => Self::Utf8,
            Utf8BytesError::Primitive(e) => e.into()
        }
    }
}

impl From<CidError> for InnerError {
    fn from(value: CidError) -> Self {
        match value {
            CidError::Primitive(e) => e.into(),
            CidError::Cid(e) => e.into()
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error(
    "parsing {origin:?}.{}: {} = {}",
    DisplaySource(self.origin, self.field),
    DisplayType(self.ty),
    self.field,
)]
struct ErrorDetail {
    source: InnerError,
    origin: Origin,
    field: u8,
    ty: u8,
}

impl Error {
    pub fn kind(&self) -> ErrorKind {
        match self.detail.source {
            InnerError::Truncated => ErrorKind::Truncated,

            // Protobuf
            InnerError::InvalidTag |
            InnerError::VarintOverflow => ErrorKind::Protobuf,
            
            // Dagpb
            InnerError::Missing |
            InnerError::Unknown |
            InnerError::Duplicate |
            InnerError::WrongType |
            InnerError::OutOfOrder => ErrorKind::Dagpb,

            // Validation
            InnerError::Utf8 |
            InnerError::Cid(..) |
            InnerError::DataType => ErrorKind::Validation,
        }
    }
}

pub(super) enum Scoped {
    Local(InnerError),
    Done(Error),
}
impl From<Error> for Scoped {
    fn from(value: Error) -> Self {
        Self::Done(value)
    }
}
// Generate explicit From traits, closed set, to help with coercion.
macro_rules! scoped_from {
    ($($t:ty),* $(,)?) => {$(
        impl From<$t> for Scoped {
            fn from(e: $t) -> Self { Self::Local(e.into()) }
        }
    )*};
}
scoped_from!(InnerError, PrimitiveError, Utf8BytesError, CidError, varint::Error, TryGetError);

#[must_use]
pub(super) fn try_context<T>(
    origin: Origin, field: impl Into<u8>, ty: impl Into<u8>,
    body: impl FnOnce() -> Result<T, Scoped>,
) -> Result<T, Error> {
    body().map_err(|e| match e {
        Scoped::Local(e) => e.with_context(origin, field, ty),
        Scoped::Done(e) => e,
    })
}