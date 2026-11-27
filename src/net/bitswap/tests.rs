use super::*;
use crate::cid::Cidv1Spec;

fn raw(data: &[u8]) -> Link {
    AnyCid::V1(Cidv1Spec::default().hash(data))
}

#[test]
fn a_message_round_trips() {
    let (a, b) = (raw(b"a"), raw(b"b"));
    let message = Message {
        wants: vec![
            Entry { cid: a.clone(), priority: 7, cancel: false, want: WantType::Have, send_dont_have: true },
            Entry { cid: b.clone(), priority: -1, cancel: true, want: WantType::Block, send_dont_have: false },
        ],
        full: true,
        blocks: vec![(a.clone(), b"a".to_vec())],
        presences: vec![(a, Presence::Have), (b, Presence::DontHave)],
        pending_bytes: 12,
    };
    assert_eq!(Message::decode(&message.encode()).expect("decode"), message);
    assert_eq!(Message::decode(&[]).expect("empty"), Message::default());
}

/// Field numbers and wire types as Kubo's protobuf has them, byte for byte.
#[test]
fn a_message_is_as_the_protobuf_says() {
    let cid = raw(b"x");
    let bytes = cid.to_bytes();
    let want = Message { wants: vec![Entry { cid: cid.clone(), priority: 1, cancel: false, want: WantType::Have, send_dont_have: true }], ..Message::default() };
    let len = u8::try_from(bytes.len()).expect("short");
    // Entry: block (1, bytes), priority (2), wantType (4), sendDontHave (5)
    let entry = [&[0x0a, len][..], &bytes, &[0x10, 1, 0x20, 1, 0x28, 1]].concat();
    let list = [&[0x0a, u8::try_from(entry.len()).expect("short")][..], &entry].concat();
    assert_eq!(want.encode(), [&[0x0a, u8::try_from(list.len()).expect("short")][..], &list].concat());

    // A block in the payload, its prefix CIDv1, raw, sha2-256, 32 bytes
    let block = Message { blocks: vec![(cid.clone(), b"x".to_vec())], ..Message::default() };
    let payload = [&[0x0a, 4, 1, 0x55, 0x12, 0x20][..], &[0x12, 1, b'x']].concat();
    assert_eq!(block.encode(), [&[0x1a, u8::try_from(payload.len()).expect("short")][..], &payload].concat());

    // Don't have: the cid (1), and type 1 (2)
    let dont = Message { presences: vec![(cid, Presence::DontHave)], ..Message::default() };
    let presence = [&[0x0a, len][..], &bytes, &[0x10, 1]].concat();
    assert_eq!(dont.encode(), [&[0x22, u8::try_from(presence.len()).expect("short")][..], &presence].concat());
}

#[test]
fn a_block_received_is_what_its_prefix_hashes_it_as() {
    // A payload claiming a CID by prefix alone: what's named is the hash
    // of the data, whatever the sender meant
    let payload = [&[0x0a, 4, 1, 0x55, 0x12, 0x20][..], &[0x12, 3, b'a', b'b', b'c']].concat();
    let message = Message::decode(&[&[0x1a, u8::try_from(payload.len()).expect("short")][..], &payload].concat()).expect("decode");
    assert_eq!(message.blocks, vec![(raw(b"abc"), b"abc".to_vec())]);
    // 1.0.0's blocks are CIDv0's
    let old = Message::decode(&[0x12, 3, b'a', b'b', b'c']).expect("decode");
    assert!(matches!(old.blocks.first(), Some((AnyCid::V0(_), _))));
    // What's cut short, or hashed by what isn't known, is no message
    assert!(Message::decode(&[0x1a, 9, 0x0a]).is_err());
    assert!(Message::decode(&[0x1a, 6, 0x0a, 4, 1, 0x55, 0x7f, 0x20]).is_err());
}

#[tokio::test]
async fn messages_are_framed_by_their_length() {
    let message = Message { presences: vec![(raw(b"x"), Presence::Have)], ..Message::default() };
    let mut wire = futures::io::Cursor::new(Vec::new());
    write(&mut wire, &message).await.expect("write");
    write(&mut wire, &Message::default()).await.expect("write");
    let mut reading = futures::io::Cursor::new(wire.into_inner());
    assert_eq!(read(&mut reading).await.expect("read"), Some(message));
    assert_eq!(read(&mut reading).await.expect("read"), Some(Message::default()));
    assert_eq!(read(&mut reading).await.expect("read"), None, "the end");
    // A length past the most is refused before anything's read
    let mut huge = Vec::new();
    crate::varint::write(&mut huge, u64::try_from(MESSAGE).expect("fits") + 1);
    assert!(read(&mut futures::io::Cursor::new(huge)).await.is_err());
}
