//! dag-json serde implementation.
//!
//! DAG-JSON is JSON with two reserved forms for the IPLD kinds JSON lacks,
//! and a canonical form for content addressing:
//! - Links are `{"/": "<CID string>"}`, CIDv0 in base58btc and CIDv1 in
//!   base32.
//! - Bytes are `{"/": {"bytes": "<base64, standard alphabet, unpadded>"}}`.
//! - Map keys are sorted bytewise and must be unique.
//! - No whitespace.
//! - Floats are written the way JavaScript's `Number#toString` would, but
//!   always with a `.` or an exponent so they don't read back as integers.
//! - Strings are escaped as `JSON.stringify` would.
//!
//! <https://ipld.io/specs/codecs/dag-json/spec/>

use crate::canon::Canon;
use crate::serde::{self as harness, Error};

mod ser;
mod de;

pub use de::Deserializer;
pub use ser::Serializer;

/// Encode a value as DAG-JSON.
pub fn to_vec<T: ?Sized + serde::Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    Ok(harness::serialize(Serializer::new(), value)?.into_bytes())
}

/// Decode a whole DAG-JSON block.
pub fn from_slice<'de, T: serde::Deserialize<'de>>(input: &'de [u8]) -> Result<T, Error> {
    harness::deserialize(Deserializer::new(input))
}

/// Decode a whole DAG-JSON block, noting whether it was canonical.
pub fn from_slice_canon<'de, T: serde::Deserialize<'de>>(input: &'de [u8]) -> Result<Canon<T>, Error> {
    harness::deserialize_canon(Deserializer::new(input))
}

/// Format a finite float like JavaScript's `Number#toString`, except that
/// integral values get a `.0` so they stay floats.
fn format_float(value: f64) -> String {
    // Rust's `{:e}` gives the shortest digits which round-trip, which is
    // also what JavaScript uses; only the layout differs
    let sci = format!("{:e}", value.abs());
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i64 = exp.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let k = i64::try_from(digits.len()).unwrap_or(i64::MAX);
    // Where the decimal point goes, relative to the digits
    let n = exp.saturating_add(1);
    let zeros = |count: i64| "0".repeat(usize::try_from(count).unwrap_or(0));

    let mut out = String::new();
    if value < 0.0 {
        out.push('-');
    }
    if value == 0.0 {
        out.push_str("0.0");
    }
    else if k <= n && n <= 21 {
        out.push_str(&digits);
        out.push_str(&zeros(n.saturating_sub(k)));
        out.push_str(".0");
    }
    else if 0 < n && n <= 21 {
        let (int, frac) = digits.split_at(usize::try_from(n).unwrap_or(0));
        out.push_str(int);
        out.push('.');
        out.push_str(frac);
    }
    else if -6 < n && n <= 0 {
        out.push_str("0.");
        out.push_str(&zeros(n.saturating_neg()));
        out.push_str(&digits);
    }
    else {
        let (first, rest) = digits.split_at(1);
        out.push_str(first);
        if !rest.is_empty() {
            out.push('.');
            out.push_str(rest);
        }
        let exp = n.saturating_sub(1);
        out.push('e');
        out.push(if exp < 0 { '-' } else { '+' });
        out.push_str(&exp.unsigned_abs().to_string());
    }
    out
}

/// Write a string escaped as `JSON.stringify` would.
fn write_string(out: &mut Vec<u8>, value: &str) {
    out.push(b'"');
    let mut rest = value;
    while let Some(at) = rest.find(|c: char| c == '"' || c == '\\' || c < ' ') {
        let (plain, tail) = rest.split_at(at);
        out.extend_from_slice(plain.as_bytes());
        let mut chars = tail.chars();
        let Some(c) = chars.next() else { break };
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c => out.extend_from_slice(format!("\\u{:04x}", u32::from(c)).as_bytes()),
        }
        rest = chars.as_str();
    }
    out.extend_from_slice(rest.as_bytes());
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use serde_bytes::ByteBuf;

    use super::*;
    use crate::cid::{Cidv0, Cidv1, Cidv1Spec};
    use crate::model::Ipld;

    #[test]
    fn links_with_long_digests() {
        use crate::model::Link;
        use crate::multihash::{DigestBuf, Multihash};
        // Up to IPIP-0512's 128 bytes, spilling past what's kept inline
        for len in [0, 32, 33, 64, 65, 128] {
            let digest = crate::multihash::DefaultDigest::decode(&vec![0xab; len]).expect("digest");
            let link: Link = crate::cid::AnyCid::V1(Cidv1::new(0x55, Multihash::new(0x00, digest)));
            let value = Ipld::List(vec![Ipld::Link(link)]);
            let bytes = to_vec(&value).expect("encode");
            assert_eq!(from_slice::<Ipld>(&bytes).expect("decode"), value, "{len}");
        }
    }

    #[test]
    fn limits_nesting() {
        use crate::serde::MAX_DEPTH;
        let nested = |depth: usize| format!("{}null{}", "[".repeat(depth), "]".repeat(depth));
        assert!(from_slice::<Ipld>(nested(MAX_DEPTH).as_bytes()).is_ok());
        assert!(from_slice::<Ipld>(nested(MAX_DEPTH + 1).as_bytes()).is_err());
        assert!(from_slice::<Ipld>(nested(100_000).as_bytes()).is_err());
    }

    #[test]
    fn floats_like_javascript() {
        for (value, expected) in [
            (0.5, "0.5"),
            (-1.1, "-1.1"),
            (1e-323, "1e-323"),
            (8.940_696_716_308_594e-8, "8.940696716308594e-8"),
            (82_497.637_120_861_87, "82497.63712086187"),
            (0.000_001, "0.000001"),
            (1e-7, "1e-7"),
            (1e21, "1e+21"),
            (1.5e300, "1.5e+300"),
            // Integral floats keep a decimal point
            (1.0, "1.0"),
            (-0.0, "0.0"),
            (1e20, "100000000000000000000.0"),
        ] {
            assert_eq!(format_float(value), expected, "{value:e}");
            let parsed: f64 = from_slice(expected.as_bytes()).expect(expected);
            assert_eq!(parsed.to_bits(), if value == 0.0 { 0.0f64.to_bits() } else { value.to_bits() });
        }
    }

    #[test]
    fn strings_like_json_stringify() {
        let mut out = Vec::new();
        write_string(&mut out, "a\"b\\c\n\t\r\u{08}\u{0c}\u{01}\u{1f}/☺\u{7f}");
        assert_eq!(out, b"\"a\\\"b\\\\c\\n\\t\\r\\b\\f\\u0001\\u001f/\xe2\x98\xba\x7f\"");
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    enum Variant {
        Unit,
        Newtype(u8),
        Tuple(u8, bool),
        Struct { x: i8 },
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Thing {
        zzz: u32,
        a: String,
        link: Cidv1,
        v0: Cidv0,
        bytes: ByteBuf,
        none: Option<i8>,
        list: Vec<i64>,
        variants: Vec<Variant>,
        float: f64,
        big: i128,
    }

    fn thing() -> Thing {
        Thing {
            zzz: 70000,
            a: "hello \"world\"\n".into(),
            link: Cidv1Spec::default().hash(b"hello world"),
            v0: "QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn".parse().expect("v0"),
            bytes: ByteBuf::from(vec![0xa1]),
            none: None,
            list: vec![i64::MIN, -1, 0, i64::MAX],
            variants: vec![Variant::Unit, Variant::Newtype(1), Variant::Tuple(2, true), Variant::Struct { x: -3 }],
            float: 2.0,
            big: -(1 << 64),
        }
    }

    #[test]
    fn typed_round_trip() {
        let bytes = to_vec(&thing()).expect("encode");
        let decoded = from_slice_canon::<Thing>(&bytes).expect("decode");
        assert!(decoded.is_canon(), "{}", String::from_utf8_lossy(&bytes));
        assert_eq!(decoded.into_inner(), thing());

        let ipld: Ipld = from_slice(&bytes).expect("as ipld");
        assert_eq!(to_vec(&ipld).expect("re-encode"), bytes);
    }

    #[test]
    fn encodings() {
        let link: Cidv1 = Cidv1Spec::default().hash(b"hello world");
        let cases = [
            (Ipld::Null, "null"),
            (Ipld::Bool(false), "false"),
            (Ipld::Integer(-(1 << 64)), "-18446744073709551616"),
            (Ipld::Float(1.5), "1.5"),
            (Ipld::String("a".into()), "\"a\""),
            (Ipld::Bytes(vec![0xa1]), "{\"/\":{\"bytes\":\"oQ\"}}"),
            (Ipld::Link(link.into()), "{\"/\":\"bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e\"}"),
            (Ipld::List(vec![Ipld::Integer(1), Ipld::List(vec![])]), "[1,[]]"),
            (from_slice(b"{\"b\":1,\"aa\":2}").expect("map"), "{\"aa\":2,\"b\":1}"),
        ];
        for (value, expected) in cases {
            assert_eq!(String::from_utf8(to_vec(&value).expect("encode")).expect("utf-8"), expected);
            assert_eq!(from_slice::<Ipld>(expected.as_bytes()).expect(expected), value);
        }
    }

    #[test]
    fn struct_keys_sorted_bytewise() {
        #[derive(Serialize)]
        struct S { bb: u8, a: u8, c: u8 }
        assert_eq!(to_vec(&S { bb: 1, a: 2, c: 3 }).expect("encode"), b"{\"a\":2,\"bb\":1,\"c\":3}");
    }

    #[test]
    fn noncanonical_forms_decode() {
        for (label, input, value) in [
            ("whitespace", " [ 1 , 2 ] ", Ipld::List(vec![Ipld::Integer(1), Ipld::Integer(2)])),
            ("unsorted keys", "{\"b\":1,\"a\":2}", from_slice::<Ipld>(b"{\"a\":2,\"b\":1}").expect("map")),
            ("negative zero", "-0", Ipld::Integer(0)),
            ("float exponent", "1.5e0", Ipld::Float(1.5)),
            ("unnecessary escape", "\"\\u0061\\/\"", Ipld::String("a/".into())),
            ("base36 CID", "{\"/\":\"k2cwued9o1pvrt3q271rrqbo49x30tbxwpoeaq75z14e5ui2rzygpbe1\"}",
                from_slice::<Ipld>(b"{\"/\":\"bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e\"}").expect("link")),
        ] {
            let decoded = from_slice_canon::<Ipld>(input.as_bytes()).expect(label);
            assert!(!decoded.is_canon(), "{label} should be non-canonical");
            assert_eq!(decoded.into_inner(), value, "{label}");
        }
        // A surrogate pair escape
        assert_eq!(from_slice::<String>(b"\"\\ud800\\udd51\"").expect("pair"), "\u{10151}");
    }

    #[test]
    fn reserved_slash_key() {
        // Straight from the spec: a "/" value that isn't a string is an
        // ordinary map, as is one where a key sorts before "/"
        for valid in [
            "{\"/\":true,\"bar\":\"baz\"}",
            "{\"/\":null}",
            "{\"/\":{\"bytes\":1}}",
            "{\"/\":{\"bytes\":\"oQ\",\"x\":1}}",
            "{\"!\":1,\"/\":\"not a cid\"}",
        ] {
            let decoded = from_slice_canon::<Ipld>(valid.as_bytes()).expect(valid);
            assert!(decoded.is_canon(), "{valid}");
            assert!(matches!(decoded.inner(), Ipld::Map(_)), "{valid} is a map");
            assert_eq!(to_vec(decoded.inner()).expect(valid), valid.as_bytes());
        }
        // ...but a first key of "/" with a string or bytes form is a link
        // or bytes, which can't have other keys
        for invalid in [
            "{\"/\":\"bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e\",\"a\":1}",
            "{\"/\":{\"bytes\":\"oQ\"},\"a\":1}",
            "{\"/\":\"\"}",
        ] {
            assert!(from_slice::<Ipld>(invalid.as_bytes()).is_err(), "{invalid} should fail");
        }
        // and encoders mustn't produce those
        let link_shaped = |rest: Vec<(&str, Ipld)>| {
            let mut map: std::collections::BTreeMap<String, Ipld> =
                rest.into_iter().map(|(k, v)| (k.to_owned(), v)).collect();
            map.insert("/".into(), Ipld::String("x".into()));
            Ipld::Map(map)
        };
        assert!(to_vec(&link_shaped(vec![])).is_err());
        assert!(to_vec(&link_shaped(vec![("a", Ipld::Null)])).is_err());
        assert!(to_vec(&link_shaped(vec![("!", Ipld::Null)])).is_ok());
    }

    #[test]
    fn strict_errors() {
        for input in [
            "", "nul", "[1,]", "[1 2]", "{\"a\":1,}", "{\"a\" 1}", "{\"a\":1,\"a\":2}",
            "01", "1.", ".5", "1e", "+1", "1e999", "NaN", "\"\\x\"", "\"\x01\"", "\"\\ud800\"",
            "{\"/\":\"not a cid\"}", "{\"/\":{\"bytes\":\"!\"}}", "{\"/\":\"bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e\",\"a\":1}",
            "1 2", "\"unterminated",
        ] {
            assert!(from_slice::<Ipld>(input.as_bytes()).is_err(), "{input:?} should fail");
        }
        assert!(to_vec(&f64::NAN).is_err());
    }
}
