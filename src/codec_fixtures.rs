//! Tests against <https://github.com/ipld/codec-fixtures>, the git
//! submodule at `fixtures/codec-fixtures`.
//!
//! Every fixture is a directory of `<CID>.<codec>` blocks, the same data in
//! each codec. Without dag-cbor or dag-json codecs (yet) those blocks only
//! exercise CIDs, multihashes and block verification; dag-pb blocks also
//! round-trip through `pb` and are cross-checked against their dag-json.

use std::fs;
use std::path::{Path, PathBuf};

use multibase::Base;
use serde_json::{Map, Value};

use crate::block::Block;
use crate::{dagcbor, dagjson};
use crate::model::Ipld;
use crate::cid::{AnyCid, BaseCid, Cid, CidRef, Cidv1, Cidv1Spec, DAG_CBOR_CODEC, DAG_JSON_CODEC, DAG_PB_CODEC};
use crate::multihash::{Inline, MultihashFunc};
use crate::pb::{PbLink, PbNode};

fn root() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/codec-fixtures");
    assert!(
        root.join("fixtures").is_dir(),
        "codec-fixtures missing, run `git submodule update --init`"
    );
    root
}

struct Fixture {
    /// The fixture's directory name.
    name: String,
    cid: String,
    codec: String,
    bytes: Vec<u8>,
}

impl Fixture {
    fn label(&self) -> String {
        format!("{}/{}.{}", self.name, self.cid, self.codec)
    }
}

fn fixture_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = fs::read_dir(root().join("fixtures"))
        .expect("fixtures dir")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    dirs
}

fn fixtures() -> Vec<Fixture> {
    let mut out = Vec::new();
    for dir in fixture_dirs() {
        let name = dir.file_name().and_then(|n| n.to_str()).expect("utf-8 name").to_owned();
        for file in fs::read_dir(&dir).expect("fixture dir") {
            let path = file.expect("entry").path();
            let file_name = path.file_name().and_then(|n| n.to_str()).expect("utf-8 name");
            let (cid, codec) = file_name.split_once('.').expect("<CID>.<codec>");
            out.push(Fixture {
                name: name.clone(),
                cid: cid.to_owned(),
                codec: codec.to_owned(),
                bytes: fs::read(&path).expect("read fixture"),
            });
        }
    }
    out.sort_by(|a, b| (&a.name, &a.codec).cmp(&(&b.name, &b.codec)));
    out
}

fn codec_code(codec: &str) -> u64 {
    match codec {
        "dag-pb" => DAG_PB_CODEC,
        "dag-cbor" => DAG_CBOR_CODEC,
        "dag-json" => DAG_JSON_CODEC,
        other => panic!("unknown codec {other}"),
    }
}

fn negative(path: &str) -> Vec<Value> {
    let path = root().join("negative-fixtures").join(path);
    let json = fs::read_to_string(&path).expect("negative fixture");
    serde_json::from_str::<Value>(&json)
        .expect("json")
        .as_array()
        .expect("list of cases")
        .clone()
}

fn case_name(case: &Value) -> &str {
    case["name"].as_str().expect("name")
}

//------------------------------//
//-[ CIDs, hashes and blocks ]-//
//------------------------------//

#[test]
fn every_block_verifies() {
    let fixtures = fixtures();
    assert!(fixtures.len() > 250, "only found {} fixtures", fixtures.len());

    for f in &fixtures {
        let label = f.label();
        let cid: Cidv1 = f.cid.parse().expect(&label);
        assert_eq!(cid.to_string(), f.cid, "{label}");
        assert_eq!(cid.codec(), codec_code(&f.codec), "{label}");
        assert_eq!(cid.hashcode(), u64::from(MultihashFunc::Sha2_256), "{label}");
        assert_eq!(Cidv1::<Inline<64>>::decode(&cid.to_bytes()).expect(&label), cid);

        let block = Block::verify(cid.clone(), f.bytes.clone().into()).expect(&label);
        let spec = Cidv1Spec::from_cid(&cid).expect(&label);
        assert_eq!(Block::hash(spec, f.bytes.clone().into()), block, "{label}");

        // ...and a single flipped bit doesn't
        let mut corrupt = f.bytes.clone();
        if let Some(byte) = corrupt.last_mut() {
            *byte ^= 1;
            assert!(Block::verify(cid, corrupt.into()).is_err(), "{label}");
        }
    }
}

#[test]
fn cid_strings() {
    // `cid-<CID>` fixtures are named after a CID in some base and version
    let mut seen = 0;
    for dir in fixture_dirs() {
        let name = dir.file_name().and_then(|n| n.to_str()).expect("utf-8 name");
        let Some(s) = name.strip_prefix("cid-") else { continue };
        if s == "arrayof" || s == "mapof" {
            continue;
        }
        seen += 1;

        let cid: AnyCid<Inline<64>> = s.parse().expect(s);
        let (expected, canonical) = if s.starts_with("Qm") {
            (Base::Base58Btc.decode(s).expect(s), true)
        }
        else {
            let (base, bytes) = multibase::decode(s).expect(s);
            (bytes, base == Base::Base32Lower)
        };
        assert_eq!(cid.to_bytes(), expected, "{s}");
        assert_eq!(cid.size(), expected.len(), "{s}");
        if canonical {
            assert_eq!(cid.to_string(), s);
        }
        let back = AnyCid::<Inline<64>>::decode(&expected).expect(s);
        assert_eq!(back.version(), cid.version(), "{s}");
    }
    assert!(seen > 10, "only found {seen} CID fixtures");
}

//------------//
//-[ dag-pb ]-//
//------------//

/// A dag-json map, as opposed to a link `{"/": "..."}` or bytes
/// `{"/": {"bytes": "..."}}`.
fn as_map(value: &Value) -> Option<&Map<String, Value>> {
    value.as_object().filter(|map| !map.contains_key("/"))
}

fn as_bytes(value: &Value) -> Option<Vec<u8>> {
    let map = value.as_object().filter(|map| map.len() == 1)?;
    let inner = map.get("/")?.as_object().filter(|inner| inner.len() == 1)?;
    // dag-json bytes are unpadded standard base64, multibase "m"
    multibase::decode(format!("m{}", inner.get("bytes")?.as_str()?)).ok().map(|(_, bytes)| bytes)
}

fn as_cid(value: &Value) -> Option<Vec<u8>> {
    let map = value.as_object().filter(|map| map.len() == 1)?;
    let cid: AnyCid<Inline<64>> = map.get("/")?.as_str()?.parse().ok()?;
    Some(cid.to_bytes())
}

/// Encode the dag-pb data model form of a node given as dag-json,
/// checking it the way the spec's encoders must.
fn encode_dag_json(value: &Value) -> Result<Vec<u8>, String> {
    let node = as_map(value).ok_or("not a map")?;
    if node.keys().any(|k| k != "Data" && k != "Links") {
        return Err("extraneous properties".into());
    }
    let data = match node.get("Data") {
        None => None,
        Some(data) => Some(as_bytes(data).ok_or("Data must be bytes")?),
    };
    let links = node.get("Links").and_then(Value::as_array).ok_or("Links must be a list")?;

    let mut parsed = Vec::new();
    for link in links {
        let link = as_map(link).ok_or("bad link")?;
        if link.keys().any(|k| !["Hash", "Name", "Tsize"].contains(&k.as_str())) {
            return Err("extraneous properties on link".into());
        }
        let hash = link.get("Hash").ok_or("link must have a Hash")?;
        let hash = as_cid(hash).ok_or("link Hash must be a CID")?;
        let name = match link.get("Name") {
            None => None,
            Some(name) => Some(name.as_str().ok_or("link Name must be a string")?),
        };
        let tsize = match link.get("Tsize") {
            None => None,
            Some(tsize) if tsize.as_i64().is_some_and(i64::is_negative) => {
                return Err("link Tsize cannot be negative".into());
            }
            Some(tsize) => Some(tsize.as_u64().ok_or("link Tsize must be an integer")?),
        };
        parsed.push((hash, name, tsize));
    }

    let node = PbNode {
        links: parsed
            .iter()
            .map(|(hash, name, tsize)| PbLink {
                hash: hash.as_slice().into(),
                name: name.map(str::as_bytes),
                tsize: *tsize,
            })
            .collect(),
        data: data.as_deref(),
    };
    node.validate().map_err(|e| e.to_string())?;
    Ok(node.encode())
}

#[test]
fn dagpb_round_trip() {
    let fixtures = fixtures();
    let dagpb: Vec<&Fixture> = fixtures.iter().filter(|f| f.codec == "dag-pb").collect();
    assert!(dagpb.len() >= 17, "only found {} dag-pb fixtures", dagpb.len());

    for f in dagpb {
        let label = f.label();
        let node = PbNode::decode(&f.bytes).expect(&label);
        node.validate().expect(&label);
        assert_eq!(node.encode(), f.bytes, "{label} re-encodes");
        for link in &node.links {
            link.cid().expect(&label);
        }

        // The dag-json form of the same node encodes to the same block
        let json = fixtures
            .iter()
            .find(|j| j.name == f.name && j.codec == "dag-json")
            .expect("dag-json sibling");
        let value: Value = serde_json::from_slice(&json.bytes)
            .unwrap_or_else(|e| panic!("{}: {e}", json.label()));
        assert_eq!(encode_dag_json(&value).expect(&label), f.bytes, "{label} from dag-json");
    }
}

#[test]
fn dagpb_decode_negative() {
    let cases = negative("dag-pb/decode/edges.json");
    assert!(!cases.is_empty());
    for case in &cases {
        let hex = case["hex"].as_str().expect("hex");
        let (_, bytes) = multibase::decode(format!("f{hex}")).expect("hex");
        assert!(
            PbNode::decode(&bytes).is_err(),
            "{} should fail: {}",
            case_name(case),
            case["error"]
        );
    }
}

#[test]
fn dagpb_encode_negative() {
    // Most of these are type errors which PbNode can't even represent, so
    // they're caught converting from dag-json. Sorting is checked by
    // PbNode::validate.
    for file in ["dag-pb/encode/invalid-forms.json", "dag-pb/encode/basic-datamodel-kinds.json"] {
        let cases = negative(file);
        assert!(!cases.is_empty());
        for case in &cases {
            let error = case["error"].as_str().expect("error");
            let result = encode_dag_json(&case["dag-json"]);
            let got = result.expect_err(&format!("{} should fail: {error}", case_name(case)));
            // The spec's error messages look like "Invalid DAG-PB form (...)"
            if let Some(reason) = error.strip_prefix("Invalid DAG-PB form (").and_then(|e| e.strip_suffix(')')) {
                assert_eq!(got, reason, "{}", case_name(case));
            }
        }
    }
}

//--------------//
//-[ dag-cbor ]-//
//--------------//

#[test]
fn dagcbor_round_trip() {
    let fixtures = fixtures();
    let cbor: Vec<&Fixture> = fixtures.iter().filter(|f| f.codec == "dag-cbor").collect();
    assert!(cbor.len() >= 128, "only found {} dag-cbor fixtures", cbor.len());

    let mut failures = Vec::new();
    for f in cbor {
        let label = f.label();
        let decoded = match dagcbor::from_slice_canon::<Ipld>(&f.bytes) {
            Ok(decoded) => decoded,
            Err(e) => {
                failures.push(format!("{label}: decode: {e}"));
                continue;
            },
        };
        if !decoded.is_canon() {
            failures.push(format!("{label}: decoded as non-canonical"));
        }
        match dagcbor::to_vec(decoded.inner()) {
            Ok(bytes) if bytes == f.bytes => (),
            Ok(_) => failures.push(format!("{label}: re-encodes differently")),
            Err(e) => failures.push(format!("{label}: encode: {e}")),
        }
    }
    assert!(failures.is_empty(), "{} failures:\n{}", failures.len(), failures.join("\n"));
}

#[test]
fn dagcbor_decode_negative() {
    let cases = negative("dag-cbor/decode/duplicate-keys.json");
    assert!(!cases.is_empty());
    for case in &cases {
        let hex = case["hex"].as_str().expect("hex");
        let (_, bytes) = multibase::decode(format!("f{hex}")).expect("hex");
        assert!(
            dagcbor::from_slice::<Ipld>(&bytes).is_err(),
            "{} should fail: {}",
            case_name(case),
            case["error"]
        );
    }
}

//--------------//
//-[ dag-json ]-//
//--------------//

#[test]
fn dagjson_round_trip() {
    let fixtures = fixtures();
    let json: Vec<&Fixture> = fixtures.iter().filter(|f| f.codec == "dag-json").collect();
    assert!(json.len() >= 128, "only found {} dag-json fixtures", json.len());

    let mut failures = Vec::new();
    for f in json {
        let label = f.label();
        let decoded = match dagjson::from_slice_canon::<Ipld>(&f.bytes) {
            Ok(decoded) => decoded,
            Err(e) => {
                failures.push(format!("{label}: decode: {e}"));
                continue;
            },
        };
        if !decoded.is_canon() {
            failures.push(format!("{label}: decoded as non-canonical"));
        }
        match dagjson::to_vec(decoded.inner()) {
            Ok(bytes) if bytes == f.bytes => (),
            Ok(bytes) => failures.push(format!("{label}: re-encodes as {}", String::from_utf8_lossy(&bytes))),
            Err(e) => failures.push(format!("{label}: encode: {e}")),
        }
    }
    assert!(failures.is_empty(), "{} failures:\n{}", failures.len(), failures.join("\n"));
}

#[test]
fn cross_codec() {
    // The same data in dag-cbor and dag-json transcodes to the other exactly
    let fixtures = fixtures();
    let mut failures = Vec::new();
    let mut pairs = 0;
    for cbor in fixtures.iter().filter(|f| f.codec == "dag-cbor") {
        let Some(json) = fixtures.iter().find(|j| j.name == cbor.name && j.codec == "dag-json") else {
            continue;
        };
        pairs += 1;
        let from_cbor: Ipld = dagcbor::from_slice(&cbor.bytes)
            .unwrap_or_else(|e| panic!("{}: {e}", cbor.label()));
        let from_json: Ipld = dagjson::from_slice(&json.bytes)
            .unwrap_or_else(|e| panic!("{}: {e}", json.label()));
        if from_cbor != from_json {
            failures.push(format!("{}: decodes differently from cbor and json", cbor.name));
        }
        if dagjson::to_vec(&from_cbor).ok().as_ref() != Some(&json.bytes) {
            failures.push(format!("{}: cbor -> json differs", cbor.name));
        }
        if dagcbor::to_vec(&from_json).ok().as_ref() != Some(&cbor.bytes) {
            failures.push(format!("{}: json -> cbor differs", cbor.name));
        }
    }
    assert!(pairs >= 128, "only found {pairs} cbor/json pairs");
    assert!(failures.is_empty(), "{} failures:\n{}", failures.len(), failures.join("\n"));
}

#[test]
fn dagjson_decode_negative() {
    let cases = negative("dag-json/decode/duplicate-keys.json");
    assert!(!cases.is_empty());
    for case in &cases {
        let hex = case["hex"].as_str().expect("hex");
        let (_, bytes) = multibase::decode(format!("f{hex}")).expect("hex");
        assert!(
            dagjson::from_slice::<Ipld>(&bytes).is_err(),
            "{} should fail: {}",
            case_name(case),
            case["error"]
        );
    }
}

//-----------//
//-[ Store ]-//
//-----------//

#[test]
fn every_block_stores_and_retrieves() {
    use crate::cid::CidVersion;
    use crate::store::{Db, Catalog};

    let router = Catalog::standard(Db::memory().expect("db")).expect("router");
    let mut placed = std::collections::BTreeMap::<(String, String), usize>::new();
    for f in fixtures() {
        let label = f.label();
        let cid: Cidv1 = f.cid.parse().expect(&label);
        let block = Block::verify(cid.clone(), f.bytes.clone().into()).expect(&label);
        let store = router.put_block(&block, CidVersion::V1).expect(&label);
        *placed.entry((f.codec.clone(), store)).or_default() += 1;

        let back = router.get_block(&AnyCid::V1(cid)).expect(&label).expect(&label);
        assert_eq!(back.data(), f.bytes, "{label}");
    }
    // Every fixture is canonical, and dag-pb is UnixFS only in Kubo's form
    let expected = [
        (("dag-cbor", "ipld"), 128),
        (("dag-json", "ipld"), 128),
        (("dag-pb", "raw"), 15),
        (("dag-pb", "unixfs"), 2),
    ];
    let expected: std::collections::BTreeMap<_, _> =
        expected.into_iter().map(|((codec, store), n)| ((codec.to_owned(), store.to_owned()), n)).collect();
    assert_eq!(placed, expected);
}

//---------//
//-[ CAR ]-//
//---------//

/// The fixtures' own CAR holds every fixture block, and they verify.
#[test]
fn fixtures_car_imports() {
    use crate::store::{Db, Catalog};

    let mut router = Catalog::standard(Db::memory().expect("db")).expect("router");
    let car = fs::File::open(root().join("fixtures.car")).expect("fixtures.car");
    let (roots, blocks) = crate::car::import(std::io::BufReader::new(car), &mut router).expect("import");
    assert!(roots.is_empty());
    assert!(blocks > 0);
    for f in fixtures() {
        let label = f.label();
        let cid: crate::model::Link = f.cid.parse().expect(&label);
        let back = router.get_block(&cid).expect(&label).expect(&label);
        assert_eq!(back.data(), f.bytes, "{label}");
    }
}

/// Every link in every fixture is a backref, whichever store took it.
#[test]
fn every_link_is_a_backref() {
    use crate::cid::CidVersion;
    use crate::store::{Db, RefIndex, Catalog};

    let router = Catalog::standard(Db::memory().expect("db")).expect("router");
    let mut checked = 0;
    for f in fixtures() {
        let label = f.label();
        let cid: Cidv1 = f.cid.parse().expect(&label);
        let block = Block::verify(cid.clone(), f.bytes.clone().into()).expect(&label);
        router.put_block(&block, CidVersion::V1).expect(&label);
        let source = crate::multihash::Multihash::from(cid.clone());
        for link in crate::links::links(cid.codec(), &f.bytes).expect(&label) {
            assert!(router.backrefs(link.multihash()).expect(&label).contains(&source), "{label} -> {link}");
            checked += 1;
        }
    }
    assert!(checked > 50, "only {checked} links");
}
