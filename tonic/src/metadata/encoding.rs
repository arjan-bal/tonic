use base64::Engine as _;
use bytes::Bytes;
use std::error::Error;
use std::fmt;
use std::hash::Hash;

use crate::metadata::value::UnencodedHeaderValue;

/// A possible error when converting a `MetadataValue` from a string or byte
/// slice.
#[derive(Debug, Hash)]
pub struct InvalidMetadataValue {
    _priv: (),
}

mod value_encoding {
    use crate::metadata::value::UnencodedHeaderValue;

    use super::InvalidMetadataValueBytes;
    use bytes::Bytes;
    use std::fmt;

    pub trait Sealed {
        #[doc(hidden)]
        fn is_empty(value: &[u8]) -> bool;

        #[doc(hidden)]
        fn from_bytes(value: &[u8]) -> Result<UnencodedHeaderValue, InvalidMetadataValueBytes>;

        #[doc(hidden)]
        fn from_shared(value: Bytes) -> Result<UnencodedHeaderValue, InvalidMetadataValueBytes>;

        #[doc(hidden)]
        fn from_static(value: &'static str) -> UnencodedHeaderValue;

        #[doc(hidden)]
        fn decode(value: &[u8]) -> Result<Bytes, InvalidMetadataValueBytes>;

        #[doc(hidden)]
        fn encode(value: Bytes) -> Bytes;

        #[doc(hidden)]
        fn equals(a: &UnencodedHeaderValue, b: &[u8]) -> bool;

        #[doc(hidden)]
        fn values_equal(a: &UnencodedHeaderValue, b: &UnencodedHeaderValue) -> bool;

        #[doc(hidden)]
        fn fmt(value: &UnencodedHeaderValue, f: &mut fmt::Formatter<'_>) -> fmt::Result;
    }
}

pub trait ValueEncoding: Clone + Eq + PartialEq + Hash + self::value_encoding::Sealed {
    /// Returns true if the provided key is valid for this ValueEncoding type.
    /// For example, `Ascii::is_valid_key("a") == true`,
    /// `Ascii::is_valid_key("a-bin") == false`.
    fn is_valid_key(key: &str) -> bool;
}

/// gRPC metadata values can be either ASCII strings or binary. Note that only
/// visible ASCII characters (32-127) are permitted.
/// This type should never be instantiated -- in fact, it's impossible
/// to, because there's no variants to instantiate. Instead, it's just used as
/// a type parameter for [`MetadataKey`] and [`MetadataValue`].
///
/// [`MetadataKey`]: struct.MetadataKey.html
/// [`MetadataValue`]: struct.MetadataValue.html
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum Ascii {}

impl Ascii {
    pub(crate) fn is_valid_value(key: impl AsRef<[u8]>) -> bool {
        // This array maps every byte (0-255) to a boolean (valid/invalid).
        static VALID_HEADER_VALUE_CHARS: [bool; 256] = {
            let mut table = [false; 256];

            let mut i = 0x20;
            while i <= 0x7E {
                table[i as usize] = true;
                i += 1;
            }
            table
        };
        let bytes = key.as_ref();

        for &b in bytes {
            if !VALID_HEADER_VALUE_CHARS[b as usize] {
                return false;
            }
        }
        true
    }
}

/// gRPC metadata values can be either ASCII strings or binary.
/// This type should never be instantiated -- in fact, it's impossible
/// to, because there's no variants to instantiate. Instead, it's just used as
/// a type parameter for [`MetadataKey`] and [`MetadataValue`].
///
/// [`MetadataKey`]: struct.MetadataKey.html
/// [`MetadataValue`]: struct.MetadataValue.html
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum Binary {}

// ===== impl ValueEncoding =====

impl self::value_encoding::Sealed for Ascii {
    fn is_empty(value: &[u8]) -> bool {
        value.is_empty()
    }

    fn from_bytes(value: &[u8]) -> Result<UnencodedHeaderValue, InvalidMetadataValueBytes> {
        let start = value
            .iter()
            .position(|b| !b.is_ascii_whitespace())
            .unwrap_or(value.len());
        let end = value
            .iter()
            .rposition(|b| !b.is_ascii_whitespace())
            .map(|p| p + 1)
            .unwrap_or(start);
        let value = &value[start..end];

        if !Ascii::is_valid_value(value) {
            return Err(InvalidMetadataValueBytes::new());
        }
        Ok(UnencodedHeaderValue::from_bytes(Bytes::copy_from_slice(
            value,
        )))
    }

    fn from_shared(value: Bytes) -> Result<UnencodedHeaderValue, InvalidMetadataValueBytes> {
        let start = value
            .iter()
            .position(|b| !b.is_ascii_whitespace())
            .unwrap_or(value.len());
        let end = value
            .iter()
            .rposition(|b| !b.is_ascii_whitespace())
            .map(|p| p + 1)
            .unwrap_or(start);
        let value = if end - start + 1 != value.len() {
            value.slice(start..end)
        } else {
            value
        };

        if !Ascii::is_valid_value(value.as_ref()) {
            return Err(InvalidMetadataValueBytes::new());
        }
        Ok(UnencodedHeaderValue::from_bytes(value))
    }

    fn from_static(value: &'static str) -> UnencodedHeaderValue {
        let value = value.trim();
        if !Ascii::is_valid_value(value) {
            panic!("Invalid ASCII header value: {}", value)
        }
        UnencodedHeaderValue::from_bytes(Bytes::from_static(value.as_bytes()))
    }

    fn decode(value: &[u8]) -> Result<Bytes, InvalidMetadataValueBytes> {
        let start = value
            .iter()
            .position(|b| !b.is_ascii_whitespace())
            .unwrap_or(value.len());
        let end = value
            .iter()
            .rposition(|b| !b.is_ascii_whitespace())
            .map(|p| p + 1)
            .unwrap_or(start);
        let value = &value[start..end];
        if !Ascii::is_valid_value(value.as_ref()) {
            return Err(InvalidMetadataValueBytes::new());
        }
        Ok(Bytes::copy_from_slice(value))
    }

    fn equals(a: &UnencodedHeaderValue, b: &[u8]) -> bool {
        a.data.as_ref() == b
    }

    fn values_equal(a: &UnencodedHeaderValue, b: &UnencodedHeaderValue) -> bool {
        a == b
    }

    fn fmt(value: &UnencodedHeaderValue, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(value, f)
    }

    fn encode(value: Bytes) -> Bytes {
        value
    }
}

fn is_valid_key(key: impl AsRef<[u8]>) -> bool {
    // This array maps every byte (0-255) to a boolean (valid/invalid).
    static VALID_HEADER_KEY_CHARS: [bool; 256] = {
        let mut table = [false; 256];

        // Valid: 0-9
        let mut i = b'0';
        while i <= b'9' {
            table[i as usize] = true;
            i += 1;
        }

        // Valid: a-z
        let mut i = b'a';
        while i <= b'z' {
            table[i as usize] = true;
            i += 1;
        }

        // Valid: special chars
        table[b'_' as usize] = true;
        table[b'-' as usize] = true;
        table[b'.' as usize] = true;

        table
    };
    let bytes = key.as_ref();
    if bytes.is_empty() {
        return false;
    }

    for &b in bytes {
        if !VALID_HEADER_KEY_CHARS[b as usize] {
            return false;
        }
    }
    true
}

impl ValueEncoding for Ascii {
    fn is_valid_key(key: &str) -> bool {
        is_valid_key(key) && !Binary::is_valid_key(key)
    }
}

impl self::value_encoding::Sealed for Binary {
    fn is_empty(value: &[u8]) -> bool {
        for c in value {
            if *c != b'=' {
                return false;
            }
        }
        true
    }

    fn from_bytes(value: &[u8]) -> Result<UnencodedHeaderValue, InvalidMetadataValueBytes> {
        Ok(UnencodedHeaderValue::from_bytes(Bytes::copy_from_slice(
            value,
        )))
    }

    fn from_shared(value: Bytes) -> Result<UnencodedHeaderValue, InvalidMetadataValueBytes> {
        Ok(UnencodedHeaderValue::from_bytes(value))
    }

    fn from_static(value: &'static str) -> UnencodedHeaderValue {
        let decoded = crate::util::base64::STANDARD.decode(value).unwrap();
        UnencodedHeaderValue::from_bytes(Bytes::from(decoded))
    }

    fn decode(value: &[u8]) -> Result<Bytes, InvalidMetadataValueBytes> {
        crate::util::base64::STANDARD
            .decode(value)
            .map(|bytes_vec| bytes_vec.into())
            .map_err(|_| InvalidMetadataValueBytes::new())
    }

    fn equals(a: &UnencodedHeaderValue, b: &[u8]) -> bool {
        a.data.as_ref() == b
    }

    fn values_equal(a: &UnencodedHeaderValue, b: &UnencodedHeaderValue) -> bool {
        a.data == b.data
    }

    fn fmt(value: &UnencodedHeaderValue, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", value.data)
    }

    fn encode(value: Bytes) -> Bytes {
        let encoded_value: String = crate::util::base64::STANDARD_NO_PAD.encode(value);
        Bytes::from(encoded_value)
    }
}

impl ValueEncoding for Binary {
    fn is_valid_key(key: &str) -> bool {
        key.ends_with("-bin") && is_valid_key(key)
    }
}

// ===== impl InvalidMetadataValue =====

impl InvalidMetadataValue {
    pub(crate) fn new() -> Self {
        InvalidMetadataValue { _priv: () }
    }
}

impl fmt::Display for InvalidMetadataValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("failed to parse metadata value")
    }
}

impl Error for InvalidMetadataValue {}

/// A possible error when converting a `MetadataValue` from a string or byte
/// slice.
#[derive(Debug, Hash)]
pub struct InvalidMetadataValueBytes(InvalidMetadataValue);

// ===== impl InvalidMetadataValueBytes =====

impl InvalidMetadataValueBytes {
    pub(crate) fn new() -> Self {
        InvalidMetadataValueBytes(InvalidMetadataValue::new())
    }
}

impl fmt::Display for InvalidMetadataValueBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Error for InvalidMetadataValueBytes {}
