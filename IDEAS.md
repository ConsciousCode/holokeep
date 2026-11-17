- OrbitDB integration
  - Likely just a NodeJS wrapper proxying holokeep as an IPFS node
- Trustless gateway support
- Opaque inner block representations
  - eg internally a structure representing edits to a file where CIDs can point into the structure to share common data that can't be represented by blobs and unixfs
- Auto-importing with some kind of adapter
  - "Consume the universe", some kind of archival of mutable clearnet data
  - Connect it to RSS, ATproto, ActivityPub, APIs, on a timer, 
- Dedicated filesystem for holokeep's particular needs
  - ie you give it a raw disk and it stores data that way rather than through sharding on a host filesystem

- A well-known root anchor
  - Every user's root anchor one anchor with a well-known nonce, each user's root being their view of it, so applications can name and index "the root", or other well-known anchors ("inbox", "settings"), without knowing whose
  - Sound now views are per owner and sets say whose view they're for; needs a migration (a set carrying each user's current root, stored `/anchors/<old-root>` links), and rethinking the device-to-user change on making a mesh

TODO:
- Flood underreplicated blocks on peer join, intuitively the fluid finding its level