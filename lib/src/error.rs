// Model-output: Claude Fable 5.1
// Model-output: Claude Opus 5
// Model-output: Claude Mythos 5.1
use zstd_safe::{ErrorCode, get_error_name, zstd_sys::ZSTD_ErrorCode};

/// A `Result` alias where the `Err` case is `zeekstd::Error`.
pub type Result<T> = core::result::Result<T, Error>;

/// The errors that may occur when working with this crate.
#[derive(Debug)]
pub struct Error {
    kind: Kind,
}

impl Error {
    /// Returns true if the error origins from a failed number conversion.
    pub fn is_number_conversion_failed(&self) -> bool {
        matches!(self.kind, Kind::NumberConversionFailed(_))
    }

    pub(crate) fn offset_out_of_range() -> Self {
        Self {
            kind: Kind::OffsetOutOfRange,
        }
    }

    /// Returns true if the error origins from an out of range offset.
    pub fn is_offset_out_of_range(&self) -> bool {
        matches!(self.kind, Kind::OffsetOutOfRange)
    }

    pub(crate) fn frame_index_too_large() -> Self {
        Self {
            kind: Kind::FrameIndexTooLarge,
        }
    }

    /// Returns true if the error is related to a frame index that is too large.
    pub fn is_frame_index_too_large(&self) -> bool {
        matches!(self.kind, Kind::FrameIndexTooLarge)
    }

    pub(crate) fn invalid_frame_size_policy() -> Self {
        Self {
            kind: Kind::InvalidFrameSizePolicy,
        }
    }

    /// Returns true if the error is related to a frame size policy that is invalid.
    pub fn is_invalid_frame_size_policy(&self) -> bool {
        matches!(self.kind, Kind::InvalidFrameSizePolicy)
    }

    pub(crate) fn unexpected_eof() -> Self {
        Self {
            kind: Kind::UnexpectedEof,
        }
    }

    /// Returns true if the seekable source ended inside a frame.
    pub fn is_unexpected_eof(&self) -> bool {
        matches!(self.kind, Kind::UnexpectedEof)
    }

    pub(crate) fn frame_size_mismatch() -> Self {
        Self {
            kind: Kind::FrameSizeMismatch,
        }
    }

    /// Returns true if a frame's decompressed or compressed size differs from its seek table
    /// entry.
    pub fn is_frame_size_mismatch(&self) -> bool {
        matches!(self.kind, Kind::FrameSizeMismatch)
    }

    pub(crate) fn seek_table_position_mismatch() -> Self {
        Self {
            kind: Kind::SeekTablePositionMismatch,
        }
    }

    /// Returns true if the frames' compressed sizes do not add up to the position of the seek
    /// table that lists them.
    pub fn is_seek_table_position_mismatch(&self) -> bool {
        matches!(self.kind, Kind::SeekTablePositionMismatch)
    }

    pub(crate) fn zstd(code: ZSTD_ErrorCode) -> Self {
        let wrapped = 0_usize.wrapping_sub(code as usize);
        Self {
            kind: Kind::Zstd(wrapped),
        }
    }

    /// Returns true if the error origins from an IO error.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn is_io(&self) -> bool {
        matches!(self.kind, Kind::IO(_))
    }

    /// Returns true if the error origins from the zstd library.
    pub fn is_zstd(&self) -> bool {
        matches!(self.kind, Kind::Zstd(_))
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.kind {
            Kind::NumberConversionFailed(err) => write!(f, "number conversion failed: {err}"),
            Kind::OffsetOutOfRange => f.write_str("offset out of range"),
            Kind::FrameIndexTooLarge => f.write_str("frame index too large"),
            Kind::InvalidFrameSizePolicy => f.write_str("invalid frame size policy"),
            Kind::UnexpectedEof => f.write_str("seekable source ended inside a frame"),
            Kind::FrameSizeMismatch => {
                f.write_str("frame's size differs from its seek table entry")
            }
            Kind::SeekTablePositionMismatch => {
                f.write_str("frames' compressed sizes do not add up to the seek table's position")
            }
            #[cfg(feature = "std")]
            Kind::IO(err) => write!(f, "io error: {err}"),
            Kind::Zstd(code) => f.write_str(get_error_name(*code)),
        }
    }
}

impl core::error::Error for Error {}

impl From<core::num::TryFromIntError> for Error {
    fn from(value: core::num::TryFromIntError) -> Self {
        Self {
            kind: Kind::NumberConversionFailed(value),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self {
            kind: Kind::IO(value),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl From<Error> for std::io::Error {
    /// Hands back the original IO error, so that its kind can be acted on, and gives a truncated
    /// source the matching [`std::io::ErrorKind::UnexpectedEof`]. Any other error is wrapped as
    /// [`std::io::ErrorKind::Other`].
    fn from(value: Error) -> Self {
        match value.kind {
            Kind::IO(err) => err,
            Kind::UnexpectedEof => Self::new(std::io::ErrorKind::UnexpectedEof, value),
            _ => Self::other(value),
        }
    }
}

impl From<ErrorCode> for Error {
    fn from(value: ErrorCode) -> Self {
        Self {
            kind: Kind::Zstd(value),
        }
    }
}

enum Kind {
    /// Out of range integral type conversion attempted
    NumberConversionFailed(core::num::TryFromIntError),
    /// The desired offset is out of range.
    OffsetOutOfRange,
    /// The passed frame index is too large.
    FrameIndexTooLarge,
    /// The frame size policy is invalid.
    InvalidFrameSizePolicy,
    /// The seekable source ended inside a frame.
    UnexpectedEof,
    /// A frame's decompressed or compressed size differs from its seek table entry.
    FrameSizeMismatch,
    /// The frames' compressed sizes do not add up to the position of the seek table.
    SeekTablePositionMismatch,
    /// IO error.
    #[cfg(feature = "std")]
    IO(std::io::Error),
    /// An error from the zstd library.
    Zstd(ErrorCode),
}

impl core::fmt::Debug for Kind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NumberConversionFailed(arg0) => {
                f.debug_tuple("NumberConversionFailed").field(arg0).finish()
            }
            Self::OffsetOutOfRange => write!(f, "OffsetOutOfRange"),
            Self::FrameIndexTooLarge => write!(f, "FrameIndexTooLarge"),
            Self::InvalidFrameSizePolicy => write!(f, "InvalidFrameSizePolicy"),
            Self::UnexpectedEof => write!(f, "UnexpectedEof"),
            Self::FrameSizeMismatch => write!(f, "FrameSizeMismatch"),
            Self::SeekTablePositionMismatch => write!(f, "SeekTablePositionMismatch"),
            #[cfg(feature = "std")]
            Self::IO(arg0) => f.debug_tuple("IO").field(arg0).finish(),
            Self::Zstd(c) => write!(f, "{}; code {}", zstd_safe::get_error_name(*c), c),
        }
    }
}
