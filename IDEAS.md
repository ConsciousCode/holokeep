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

TODO:
- Flood underreplicated blocks on peer join, intuitively the fluid finding its level