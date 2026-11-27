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
//!
//! Some providers are trustless gateways, reached over HTTP rather than
//! Bitswap (`/dns/…/tcp/443/https`), as storage providers often are:
//! each block's had of them as `/ipfs/<cid>?format=raw`, and checked
//! against its CID as a block from Bitswap is.

use std::time::Duration;

use libp2p::{Multiaddr, PeerId};
use serde::Deserialize;

/// The routers asked by default: Kubo's.
pub const ROUTERS: &[&str] = &["https://delegated-ipfs.dev"];

/// How long a router's answer is waited for.
const TIMEOUT: Duration = Duration::from_secs(10);

/// The most of an answer that's read.
const LIMIT: u64 = 1 << 20;

/// How long a block's waited for of a gateway.
const BLOCK_TIMEOUT: Duration = Duration::from_secs(30);

/// The most of a block that's read: Bitswap's peers send none over 2 MiB.
const BLOCK_LIMIT: u64 = 4 << 20;

/// What a router found: who provides it over Bitswap, and where each's
/// dialled, and the gateways that do over HTTP, by base URL.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Found {
    pub peers: Vec<(PeerId, Vec<Multiaddr>)>,
    pub gateways: Vec<String>,
}

impl Found {
    /// What both found.
    pub fn extend(&mut self, other: Self) {
        for (peer, addrs) in other.peers {
            match self.peers.iter_mut().find(|(known, _)| *known == peer) {
                Some((_, known)) => known.extend(addrs),
                None => self.peers.push((peer, addrs)),
            }
        }
        for gateway in other.gateways {
            if !self.gateways.contains(&gateway) {
                self.gateways.push(gateway);
            }
        }
    }
}

/// One agent for every ask, so each router's and gateway's connections
/// are kept for the next.
fn agent() -> &'static ureq::Agent {
    static AGENT: std::sync::OnceLock<ureq::Agent> = std::sync::OnceLock::new();
    AGENT.get_or_init(|| ureq::Agent::config_builder().user_agent(concat!("holokeep/", env!("CARGO_PKG_VERSION"))).build().into())
}

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

/// The providers in a router's answer that may be reached from here:
/// over Bitswap, each with the addresses it may be dialled at, and over
/// HTTP, each gateway as its base URL.
pub fn providers(json: &str) -> Found {
    let mut found = Found::default();
    let Ok(answer) = serde_json::from_str::<Answer>(json) else {
        return found;
    };
    for provider in answer.providers.unwrap_or_default() {
        let says = |protocol: &str| provider.protocols.as_ref().is_none_or(|protocols| protocols.iter().any(|said| said == protocol));
        // "bitswap" is the schema before "peer", which says its protocols
        let bitswap = provider.schema == "bitswap" || (provider.schema == "peer" && says("transport-bitswap"));
        let http = provider.schema == "peer" && says("transport-ipfs-gateway-http");
        let (gateways, dialled): (Vec<Multiaddr>, Vec<Multiaddr>) = provider.addrs.iter().flatten().filter_map(|addr| addr.parse().ok()).filter(dialable).partition(|addr| gateway(addr).is_some());
        let mut one = Found::default();
        if http {
            one.gateways = gateways.iter().filter_map(gateway).collect();
        }
        if let Some(peer) = provider.id.as_deref().and_then(|id| id.parse::<PeerId>().ok()).filter(|_| bitswap && !dialled.is_empty()) {
            one.peers.push((peer, dialled));
        }
        found.extend(one);
    }
    found
}

/// The base URL of a gateway reached at an address, if it's one reached
/// over HTTP: `/dns/host/tcp/443/https`, `…/tls/http`, or `…/http`.
pub fn gateway(addr: &Multiaddr) -> Option<String> {
    use libp2p::multiaddr::Protocol;
    let mut protocols = addr.iter().filter(|protocol| !matches!(protocol, Protocol::P2p(_) | Protocol::Sni(_)));
    let host = match protocols.next()? {
        Protocol::Ip4(ip) => ip.to_string(),
        Protocol::Ip6(ip) => format!("[{ip}]"),
        Protocol::Dns(host) | Protocol::Dns4(host) | Protocol::Dns6(host) => host.into_owned(),
        _ => return None,
    };
    let Protocol::Tcp(port) = protocols.next()? else {
        return None;
    };
    let scheme = match (protocols.next()?, protocols.next()) {
        (Protocol::Https, None) | (Protocol::Tls, Some(Protocol::Http)) => "https",
        (Protocol::Http, None) => "http",
        _ => return None,
    };
    protocols.next().is_none().then(|| format!("{scheme}://{host}:{port}"))
}

/// A block of a gateway, as it says it is: blocking, so in a thread of
/// its own. Nothing if it hasn't it, or can't be asked.
pub fn block(gateway: &str, cid: &str) -> Option<Vec<u8>> {
    let mut answer = agent().get(format!("{gateway}/ipfs/{cid}?format=raw")).config().timeout_global(Some(BLOCK_TIMEOUT)).build().header("Accept", "application/vnd.ipld.raw").call().ok()?;
    answer.body_mut().with_config().limit(BLOCK_LIMIT).read_to_vec().ok()
}

/// Ask a router who provides a CID: blocking, so in a thread of its own.
/// Nothing if it can't be asked, or doesn't know.
pub fn ask(router: &str, cid: &str) -> Found {
    // Only what may be reached over TCP or QUIC, directly or through a
    // relay, of routers that heed it (IPIP-484)
    let url = format!("{}/routing/v1/providers/{cid}?filter-protocols=transport-bitswap,transport-ipfs-gateway-http,unknown&filter-addrs=tcp,quic-v1", router.trim_end_matches('/'));
    let Ok(mut answer) = agent().get(&url).config().timeout_global(Some(TIMEOUT)).build().header("Accept", "application/json").call() else {
        return Found::default();
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
            {"Schema":"peer","ID":"not a peer","Addrs":["/ip4/1.2.3.4/tcp/4001"]},
            {"Schema":"peer","ID":"12D3KooWP9jPCTRwpRk7J7CknwqC3h14ujuvtBoN518YuiJ5MSFR","Addrs":["/dns/a-fil-http.example/tcp/443/https","/ip4/10.0.0.2/tcp/80/http"],"Protocols":["transport-ipfs-gateway-http"]},
            {"Schema":"peer","ID":"12D3KooWK2zFzpv4B1ww3NsZUnhwp2JJWGuDeHX73edcM9HAK8Bj","Addrs":["/dns4/gw.example/tcp/4001/tls/sni/gw.example/http","/dns4/gw.example/tcp/4001/tls/ws"],"Protocols":["transport-ipfs-gateway-http"]}
        ]}"#;
        let Found { peers: found, gateways } = providers(json);
        assert_eq!(gateways, ["https://a-fil-http.example:443", "https://gw.example:4001"], "not a gateway at a private address, nor a WebSocket");
        let ids: Vec<String> = found.iter().map(|(peer, _)| peer.to_string()).collect();
        assert_eq!(ids, ["12D3KooWKV5mPCRKSM2SNDLB1rMW1hbeUQdX7sE4HtiGjkNaNTBh", "QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ"], "not one serving HTTP alone, nor one at private addresses alone");
        let addrs: Vec<String> = found.iter().flat_map(|(_, addrs)| addrs.iter().map(ToString::to_string)).collect();
        assert_eq!(addrs, ["/ip4/1.2.3.4/tcp/4001", "/ip4/1.2.3.4/udp/4001/quic-v1", "/dnsaddr/mars.example/tcp/4001"]);
        assert!([providers("{}"), providers("not json"), providers(r#"{"Providers":null}"#)].iter().all(|found| *found == Found::default()));
    }
}
