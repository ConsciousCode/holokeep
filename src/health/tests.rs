use super::*;
use crate::block::Block;
use crate::cid::{CidVersion, Cidv1Spec};
use crate::store::Db;

fn replica(label: u8, risks: &[&str]) -> Replica {
    Replica { label: vec![label], risks: risks.iter().map(|&risk| risk.to_owned()).collect() }
}

fn elsewhere(peer: &str, replica: Replica) -> Elsewhere {
    Elsewhere { peer: peer.to_owned(), replica, seen: 0 }
}

#[test]
fn a_blocks_tolerance_counts_copies_here_and_elsewhere_by_what_they_share() {
    let catalog = Catalog::standard(Db::memory().expect("db")).expect("catalog");
    let block = Block::hash(Cidv1Spec::default(), b"leaf".to_vec().into());
    catalog.put_block(&block, CidVersion::V1).expect("put");
    let cid = Link::V1(block.cid().clone());
    let here = catalog.replicas(block.cid().multihash()).expect("replicas");
    assert_eq!(here.len(), 1);
    let disk = here[0].risks.iter().find(|risk| risk.starts_with("volume:")).expect("volume").clone();
    let mut known = Known::default();
    // Alone, any of its risks loses it
    let alone = Health::of(&catalog, &cid, Some(4), &known, true, 2).expect("health");
    assert_eq!((alone.tolerance, alone.target, alone.kept), (1, 2, false));
    assert!(alone.short() && alone.shared.contains(&disk));
    // A client's copies don't count
    assert_eq!(Health::of(&catalog, &cid, None, &known, false, 2).expect("health").tolerance, 0);
    // A copy on another disk makes two
    let key = block.cid().multihash().to_bytes();
    known.elsewhere.insert(key.clone(), vec![elsewhere("b", replica(9, &["volume:09", "disk:y"]))]);
    let two = Health::of(&catalog, &cid, None, &known, true, 2).expect("health");
    assert_eq!(two.tolerance, 2);
    assert!(!two.short() && two.shared.is_empty());
    // Two copies elsewhere sharing a building are one failure from gone
    known.elsewhere.insert(key, vec![elsewhere("b", replica(8, &["volume:08", "home"])), elsewhere("c", replica(9, &["volume:09", "home"]))]);
    let one = Health::of(&catalog, &cid, None, &known, false, 2).expect("health");
    assert_eq!((one.tolerance, one.shared.as_slice()), (1, ["home".to_owned()].as_slice()));
    // So many blocks' health sums
    let mut summary = Summary::default();
    summary.add(&alone, true);
    summary.add(&two, true);
    summary.add(&one, false);
    assert_eq!((summary.blocks, summary.bytes, summary.least, summary.most), (3, 4, Some(1), Some(2)));
    assert_eq!((summary.short.0, summary.short.1), (2, 4));
    assert_eq!(summary.one_risk.get(&vec!["home".to_owned()]), Some(&(1, 0)));
    assert_eq!(summary.none.0, 0);
}

#[test]
fn sizes_ages_and_labels_read_as_people_and_the_socket_want() {
    assert_eq!(bytes(0), "0 B");
    assert_eq!(bytes(1023), "1023 B");
    assert_eq!(bytes(1024), "1.0 KiB");
    assert_eq!(bytes(1536), "1.5 KiB");
    assert_eq!(bytes(21 << 30), "21.0 GiB");
    assert_eq!(bytes((1 << 20) - 1), "1.0 MiB", "not 1024.0 KiB");
    assert_eq!(bytes(3 << 40), "3.0 TiB");
    assert_eq!(bytes(5 << 50), "5.0 PiB");
    assert_eq!(bytes(u64::MAX), "16.0 EiB");
    assert_eq!(ago(100, 130), "just now");
    assert_eq!(ago(0, 7200), "2h ago");
    assert_eq!(ago(0, 3 * 86_400), "3d ago");
    assert_eq!(unhex(&hex(&[0, 0xab, 0x7f])), Some(vec![0, 0xab, 0x7f]));
    assert_eq!(unhex("abc"), None);
}
