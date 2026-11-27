//! Delegated routing: who provides a CID, asked of a router over HTTP.
//!
//! The Routing V1 HTTP API, as `delegated-ipfs.dev` serves it, which knows
//! many providers the DHT doesn't, from IPNI's indexers (`cid.contact`)
//! and its own DHT walks.
//!
//! The router learns what's sought, as a DNS resolver learns what's
//! visited, so it's asked only of a fetch that's had nothing for a
//! moment from whoever else it's found; what it finds is joined to the
//! DHT, and the more of Amino that's known, the less it's asked.

use std::time::Duration;

use libp2p::{Multiaddr, PeerId};
use serde::Deserialize;

/// The routers asked by default: Kubo's.
pub const ROUTERS: &[&str] = &["https://delegated-ipfs.dev"];

/// How long a router's answer is waited for.
const TIMEOUT: Duration = Duration::from_secs(10);

/// The most of an answer that's read.
const LIMIT: u64 = 1 << 20;

/// A router's answer, as much of it as is read.
#[derive(Deserialize)]
struct Answer {
    #[serde(rename = "Providers", default)]
    providers: Option<Vec<Provider>>,
}

#[derive(Deserialize)]
struct Provider {
    #[serde(rename = "Schema", default)]
    schema: String,
    #[serde(rename = "ID", default)]
    id: Option<String>,
    #[serde(rename = "Addrs", default)]
    addrs: Option<Vec<String>>,
    #[serde(rename = "Protocols", default)]
    protocols: Option<Vec<String>>,
}

/// The providers in a router's answer that Bitswap may reach, each with
/// the addresses it may be dialled at: none with none.
pub fn providers(json: &str) -> Vec<(PeerId, Vec<Multiaddr>)> {
    let Ok(answer) = serde_json::from_str::<Answer>(json) else {
        return Vec::new();
    };
    let mut found: Vec<(PeerId, Vec<Multiaddr>)> = Vec::new();
    for provider in answer.providers.unwrap_or_default() {
        // "bitswap" is the schema before "peer", which says its protocols
        let bitswap = provider.schema == "bitswap" || (provider.schema == "peer" && provider.protocols.as_ref().is_none_or(|protocols| protocols.iter().any(|protocol| protocol == "transport-bitswap")));
        let Some(peer) = provider.id.and_then(|id| id.parse::<PeerId>().ok()).filter(|_| bitswap) else {
            continue;
        };
        let addrs: Vec<Multiaddr> = provider.addrs.unwrap_or_default().iter().filter_map(|addr| addr.parse().ok()).filter(dialable).collect();
        if addrs.is_empty() {
            continue;
        }
        match found.iter_mut().find(|(known, _)| *known == peer) {
            Some((_, known)) => known.extend(addrs),
            None => found.push((peer, addrs)),
        }
    }
    found
}

/// Ask a router who provides a CID: blocking, so in a thread of its own.
/// Nothing if it can't be asked, or doesn't know.
pub fn ask(router: &str, cid: &str) -> Vec<(PeerId, Vec<Multiaddr>)> {
    let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(TIMEOUT)).user_agent(concat!("holokeep/", env!("CARGO_PKG_VERSION"))).build().into();
    // Only what may be dialled over TCP, of routers that heed it (IPIP-484)
    let url = format!("{}/routing/v1/providers/{cid}?filter-protocols=transport-bitswap,unknown&filter-addrs=tcp,!p2p-circuit", router.trim_end_matches('/'));
    let Ok(mut answer) = agent.get(&url).header("Accept", "application/json").call() else {
        return Vec::new();
    };
    answer.body_mut().with_config().limit(LIMIT).read_to_string().map(|json| providers(&json)).unwrap_or_default()
}

/// Whether an address may reach a peer from elsewhere: not one of its
/// own network's, which reaches someone else, or no one, from here.
pub fn dialable(addr: &Multiaddr) -> bool {
    use libp2p::multiaddr::Protocol;
    addr.iter().all(|protocol| match protocol {
        Protocol::Ip4(ip) => {
            let [a, b, ..] = ip.octets();
            !(ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() || ip.is_broadcast() || ip.is_documentation() || (a == 100 && (64..128).contains(&b)))
        },
        Protocol::Ip6(ip) => {
            let first = ip.segments().first().copied().unwrap_or_default();
            !(ip.is_loopback() || ip.is_unspecified() || (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80)
        },
        _ => true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_routers_answer_gives_the_bitswap_providers_dialable_from_here() {
        let json = r#"{"Providers":[
            {"Schema":"peer","ID":"12D3KooWKV5mPCRKSM2SNDLB1rMW1hbeUQdX7sE4HtiGjkNaNTBh","Addrs":["/ip4/1.2.3.4/tcp/4001","/ip4/192.168.1.2/tcp/4001","/ip6/::1/tcp/4001","/ip4/1.2.3.4/udp/4001/quic-v1"],"Protocols":["transport-bitswap"]},
            {"Schema":"peer","ID":"12D3KooWQLwPmXwT1oUCMzDqTKkDGnzyV7ewyWHxV5uXDNoCSVXJ","Addrs":["/ip4/5.6.7.8/tcp/4001"],"Protocols":["transport-ipfs-gateway-http"]},
            {"Schema":"peer","ID":"12D3KooWQLwPmXwT1oUCMzDqTKkDGnzyV7ewyWHxV5uXDNoCSVXJ","Addrs":["/ip4/10.0.0.1/tcp/4001"]},
            {"Schema":"bitswap","ID":"QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ","Addrs":["/dnsaddr/mars.example/tcp/4001"]},
            {"Schema":"peer","ID":"not a peer","Addrs":["/ip4/1.2.3.4/tcp/4001"]}
        ]}"#;
        let found = providers(json);
        let ids: Vec<String> = found.iter().map(|(peer, _)| peer.to_string()).collect();
        assert_eq!(ids, ["12D3KooWKV5mPCRKSM2SNDLB1rMW1hbeUQdX7sE4HtiGjkNaNTBh", "QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ"], "not one serving HTTP alone, nor one at private addresses alone");
        let addrs: Vec<String> = found.iter().flat_map(|(_, addrs)| addrs.iter().map(ToString::to_string)).collect();
        assert_eq!(addrs, ["/ip4/1.2.3.4/tcp/4001", "/ip4/1.2.3.4/udp/4001/quic-v1", "/dnsaddr/mars.example/tcp/4001"]);
        assert!(providers("{}").is_empty() && providers("not json").is_empty() && providers(r#"{"Providers":null}"#).is_empty());
    }
}
