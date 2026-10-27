//! Differential fuzzing against the ecosystem's implementations,
//! `serde_ipld_dagcbor` and `serde_ipld_dagjson` over `ipld-core`.
//!
//! Random `Ipld` values are encoded by both and must give identical bytes,
//! each must decode the other's output, and on mutated encodings the two
//! decoders must agree on what's valid and what it means. The other side
//! is fed its own `ipld_core::ipld::Ipld`, converted independently, so the
//! two paths share nothing but the value.
//!
//! More cases: `PROPTEST_CASES=100000 cargo test differential`.

use std::collections::BTreeMap;

use ipld_core::cid::Cid as CoreCid;
use ipld_core::ipld::Ipld as CoreIpld;
use proptest::collection::{btree_map, vec};
use proptest::prelude::*;

use crate::cid::{AnyCid, CidRef, Cidv0, Cidv1};
use crate::multihash::{DigestBuf, Inline, Multihash};
use crate::model::{Ipld, Link};
use crate::{dagcbor, dagjson};

//-----------------//
//-[ Generators ]-//
//-----------------//

fn digest(len: std::ops::RangeInclusive<usize>) -> impl Strategy<Value = Inline<64>> {
    vec(any::<u8>(), len).prop_map(|d| Inline::decode(&d).expect("at most 64 bytes"))
}

fn link() -> impl Strategy<Value = Link> {
    // Multiformats varints stop at 2^63 - 1
    let code = || 0..=i64::MAX.unsigned_abs();
    let codec = prop_oneof![
        Just(0x55u64), Just(0x70), Just(0x71), Just(0x0129),
        code(),
    ];
    let hash = prop_oneof![Just(0x12u64), Just(0x00), code()];
    prop_oneof![
        vec(any::<u8>(), 32).prop_map(|d| AnyCid::V0(Cidv0::new(Inline::decode(&d).expect("32 bytes")))),
        (codec, hash, digest(0..=64))
            .prop_map(|(codec, hash, digest)| AnyCid::V1(Cidv1::new(codec, Multihash::new(hash, digest)))),
    ]
}

/// Integers, around the encoding boundaries. `wide` adds those outside i64.
fn integer(wide: bool) -> BoxedStrategy<i128> {
    let mut edges: Vec<i128> = [0, 1, 23, 24, 255, 256, 65535, 65536, (1 << 32) - 1, 1 << 32]
        .into_iter()
        .flat_map(|n: i128| [n, n.saturating_neg(), n.saturating_neg().saturating_sub(1)])
        .chain([i64::MAX.into(), i64::MIN.into()])
        .collect();
    let narrow = prop_oneof![
        (-1000i128..1000),
        any::<i64>().prop_map(i128::from),
    ];
    if wide {
        edges.extend([i128::from(i64::MAX).saturating_add(1), i128::from(i64::MIN).saturating_sub(1), u64::MAX.into(), -(1 << 64)]);
        prop_oneof![proptest::sample::select(edges), narrow, (-(1i128 << 64)..(1i128 << 64))].boxed()
    }
    else {
        prop_oneof![proptest::sample::select(edges), narrow].boxed()
    }
}

fn float() -> impl Strategy<Value = f64> {
    prop_oneof![
        any::<f64>().prop_filter("finite", |f| f.is_finite()),
        proptest::sample::select(vec![
            0.0, 1.0, -1.0, 0.5, 1e21, 1e-7, 1e-6, 1e20, 5e-324, f64::MAX, f64::MIN_POSITIVE,
        ]),
        (-1e6f64..1e6),
    ]
}

/// Which values the other side handles faithfully.
#[derive(Clone, Copy)]
struct Gen {
    /// Floats, left out where formatting is a known divergence.
    floats: bool,
    /// Integers outside i64, which `serde_ipld_dagjson` turns into floats.
    wide_ints: bool,
    /// Map keys of "/", see `has_slash_key`.
    slash_keys: bool,
}

const CBOR: Gen = Gen { floats: true, wide_ints: true, slash_keys: true };
const JSON: Gen = Gen { floats: true, wide_ints: false, slash_keys: false };
const JSON_NO_FLOATS: Gen = Gen { floats: false, wide_ints: false, slash_keys: false };

/// A random IPLD value.
fn ipld(kinds: Gen) -> impl Strategy<Value = Ipld> {
    let float = if kinds.floats { float().prop_map(Ipld::Float).boxed() } else { Just(Ipld::Null).boxed() };

    let leaf = prop_oneof![
        Just(Ipld::Null),
        any::<bool>().prop_map(Ipld::Bool),
        integer(kinds.wide_ints).prop_map(Ipld::Integer),
        float,
        any::<String>().prop_map(Ipld::String),
        vec(any::<u8>(), 0..48).prop_map(Ipld::Bytes),
        link().prop_map(Ipld::Link),
    ];
    leaf.prop_recursive(4, 64, 8, move |inner| {
        let list = vec(inner.clone(), 0..8).prop_map(Ipld::List);
        if kinds.slash_keys {
            prop_oneof![
                list,
                btree_map(prop_oneof![any::<String>(), "[a-c/]{0,3}"], inner.clone(), 0..8).prop_map(Ipld::Map),
                // Maps keyed "/" which mustn't be mistaken for links or bytes
                inner.prop_map(|v| Ipld::Map([("/".to_owned(), v)].into())),
            ].boxed()
        }
        else {
            let key = prop_oneof![any::<String>(), "[a-c]{0,3}"].prop_filter("no /", |k| k != "/");
            prop_oneof![list, btree_map(key, inner, 0..8).prop_map(Ipld::Map)].boxed()
        }
    })
}

//-----------------//
//-[ Conversion ]-//
//-----------------//

fn to_core(value: &Ipld) -> CoreIpld {
    match value {
        Ipld::Null => CoreIpld::Null,
        Ipld::Bool(b) => CoreIpld::Bool(*b),
        Ipld::Integer(i) => CoreIpld::Integer(*i),
        Ipld::Float(f) => CoreIpld::Float(*f),
        Ipld::String(s) => CoreIpld::String(s.clone()),
        Ipld::Bytes(b) => CoreIpld::Bytes(b.clone()),
        Ipld::List(list) => CoreIpld::List(list.iter().map(to_core).collect()),
        Ipld::Map(map) => CoreIpld::Map(map.iter().map(|(k, v)| (k.clone(), to_core(v))).collect::<BTreeMap<_, _>>()),
        Ipld::Link(link) => CoreIpld::Link(CoreCid::try_from(link.to_bytes().as_slice()).expect("valid CID")),
    }
}

/// Does any part of a value match?
fn any_part(value: &Ipld, f: &impl Fn(&Ipld) -> bool) -> bool {
    f(value) || match value {
        Ipld::List(list) => list.iter().any(|v| any_part(v, f)),
        Ipld::Map(map) => map.values().any(|v| any_part(v, f)),
        _ => false,
    }
}

fn has_float(value: &Ipld) -> bool {
    any_part(value, &|v| matches!(v, Ipld::Float(_)))
}

/// Integers outside i64, which `serde_ipld_dagjson` reads as floats.
fn has_wide_int(value: &Ipld) -> bool {
    any_part(value, &|v| matches!(v, Ipld::Integer(i) if i64::try_from(*i).is_err()))
}

/// Maps keyed "/", which `serde_ipld_dagjson` mishandles: it writes
/// `{"/":""}`, which can't be read back, and rejects `{"/":null}`, which
/// the spec says is an ordinary map.
fn has_slash_key(value: &Ipld) -> bool {
    any_part(value, &|v| matches!(v, Ipld::Map(map) if map.contains_key("/")))
}

/// Summarize an outcome for comparison, keeping errors opaque.
fn outcome<T, E: std::fmt::Display>(result: &Result<T, E>) -> Result<&T, String> {
    result.as_ref().map_err(ToString::to_string)
}

fn config() -> ProptestConfig {
    // Honour PROPTEST_CASES, defaulting to something quick. Mutations
    // that land on known divergences are discarded, so allow for plenty.
    let cases = ProptestConfig::default().cases.max(512);
    ProptestConfig { cases, max_global_rejects: cases, ..ProptestConfig::default() }
}

//--------------//
//-[ dag-cbor ]-//
//--------------//

proptest! {
    #![proptest_config(config())]

    #[test]
    fn dagcbor_encodes_identically(value in ipld(CBOR)) {
        let ours = dagcbor::to_vec(&value);
        let theirs = serde_ipld_dagcbor::to_vec(&to_core(&value));
        match (&ours, &theirs) {
            (Ok(a), Ok(b)) => prop_assert_eq!(a, b),
            _ => prop_assert!(false, "ours {:?}, theirs {:?}", outcome(&ours), outcome(&theirs)),
        }
    }

    #[test]
    fn dagcbor_decodes_each_other(value in ipld(CBOR)) {
        let ours = dagcbor::to_vec(&value).expect("encode");
        let theirs = serde_ipld_dagcbor::to_vec(&to_core(&value)).expect("encode");

        let decoded = dagcbor::from_slice_canon::<Ipld>(&theirs).expect("we decode theirs");
        prop_assert!(decoded.is_canon());
        prop_assert_eq!(decoded.inner(), &value);

        let decoded: CoreIpld = serde_ipld_dagcbor::from_slice(&ours).expect("they decode ours");
        prop_assert_eq!(decoded, to_core(&value));
    }

    /// Corrupt a valid encoding and make sure both decoders agree on it.
    #[test]
    fn dagcbor_decoders_agree(value in ipld(CBOR), at in any::<prop::sample::Index>(), byte in any::<u8>()) {
        let mut bytes = dagcbor::to_vec(&value).expect("encode");
        let at = at.index(bytes.len());
        bytes[at] = byte;

        let ours = dagcbor::from_slice_canon::<Ipld>(&bytes);
        let theirs = serde_ipld_dagcbor::from_slice::<CoreIpld>(&bytes);
        match (&ours, &theirs) {
            // They may disagree on what input means only if neither
            // thinks it's canonical, eg dag-json's -0 (an integer, by spec)
            (Ok(a), Ok(b)) => prop_assert!(
                &to_core(a.inner()) == b
                    || (!a.is_canon() && serde_ipld_dagcbor::to_vec(b).ok().as_ref() != Some(&bytes)),
                "ours {:?}, theirs {:?}: {:02x?}", a.inner(), b, bytes
            ),
            (Err(_), Err(_)) => (),
            (Ok(a), Err(e)) => prop_assert!(!a.is_canon(), "we accept as canonical what they reject ({}): {:02x?}", e, bytes),
            // We may reject what they accept only if they can't faithfully
            // re-encode it, eg the cid crate ignores bytes after a CID
            (Err(e), Ok(b)) => prop_assert!(
                serde_ipld_dagcbor::to_vec(b).ok().as_ref() != Some(&bytes),
                "we reject ({}) what they accept canonically: {:02x?}", e, bytes
            ),
        }
    }
}

//--------------//
//-[ dag-json ]-//
//--------------//

proptest! {
    #![proptest_config(config())]

    #[test]
    fn dagjson_encodes_identically(value in ipld(JSON_NO_FLOATS)) {
        let ours = dagjson::to_vec(&value);
        let theirs = serde_ipld_dagjson::to_vec(&to_core(&value));
        match (&ours, &theirs) {
            (Ok(a), Ok(b)) => prop_assert_eq!(String::from_utf8_lossy(a), String::from_utf8_lossy(b)),
            (Err(_), Err(_)) => (),
            _ => prop_assert!(false, "ours {:?}, theirs {:?}", outcome(&ours), outcome(&theirs)),
        }
    }

    #[test]
    fn dagjson_decodes_each_other(value in ipld(JSON)) {
        let Ok(ours) = dagjson::to_vec(&value) else { return Ok(()) };
        let Ok(theirs) = serde_ipld_dagjson::to_vec(&to_core(&value)) else { return Ok(()) };

        let decoded = dagjson::from_slice_canon::<Ipld>(&theirs).expect("we decode theirs");
        prop_assert_eq!(decoded.inner(), &value);
        if !has_float(&value) {
            prop_assert!(decoded.is_canon());
        }

        let decoded: CoreIpld = serde_ipld_dagjson::from_slice(&ours).expect("they decode ours");
        prop_assert_eq!(decoded, to_core(&value));
    }

    #[test]
    fn dagjson_decoders_agree(value in ipld(JSON_NO_FLOATS), at in any::<prop::sample::Index>(), byte in any::<u8>()) {
        let Ok(mut bytes) = dagjson::to_vec(&value) else { return Ok(()) };
        let at = at.index(bytes.len());
        bytes[at] = byte;

        let ours = dagjson::from_slice_canon::<Ipld>(&bytes);
        // Mutation can make what serde_ipld_dagjson mishandles
        prop_assume!(!ours.as_ref().is_ok_and(|v| has_slash_key(v.inner()) || has_wide_int(v.inner())));
        let theirs = serde_ipld_dagjson::from_slice::<CoreIpld>(&bytes);
        let text = String::from_utf8_lossy(&bytes);
        match (&ours, &theirs) {
            // They may disagree on what input means only if neither
            // thinks it's canonical, eg dag-json's -0 (an integer, by spec)
            (Ok(a), Ok(b)) => prop_assert!(
                &to_core(a.inner()) == b
                    || (!a.is_canon() && serde_ipld_dagjson::to_vec(b).ok().as_ref() != Some(&bytes)),
                "ours {:?}, theirs {:?}: {}", a.inner(), b, text
            ),
            (Err(_), Err(_)) => (),
            (Ok(a), Err(e)) => prop_assert!(!a.is_canon(), "we accept as canonical what they reject ({}): {}", e, text),
            (Err(e), Ok(b)) => prop_assert!(
                serde_ipld_dagjson::to_vec(b).ok().as_ref() != Some(&bytes),
                "we reject ({}) what they accept canonically: {}", e, text
            ),
        }
    }
}
