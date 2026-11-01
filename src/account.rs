//! What one of the host's users may ask of a repo another user owns,
//! through its running node.
//!
//! It says and sees things as its own account, which the repo signs for
//! with a key of the account's own. Its keeps hold blocks here like
//! anyone's, and what it says stays its own.
//!
//! A command is words separated by tabs, so a tag's name may have
//! spaces; it's answered by lines, an error by a line starting "error: ".

use crate::cid::CidRef as _;
use crate::claim;
use crate::model::Link;
use crate::store::{Catalog, Error};

/// Answer a command for the account the catalog acts for.
pub fn answer(catalog: &mut Catalog, command: &str) -> Vec<String> {
    let words: Vec<&str> = command.split('\t').collect();
    respond(catalog, &words).unwrap_or_else(|e| vec![format!("error: {e}")])
}

fn cids(words: &[&str]) -> Result<Vec<Link>, String> {
    if words.is_empty() {
        return Err("no CIDs".into());
    }
    words.iter().map(|word| word.parse().map_err(|_| format!("not a CID: {word}"))).collect()
}

fn tag(name: &str) -> Result<Link, String> {
    claim::tag(name)
        .filter(|_| name.len() <= claim::MAX_NAME)
        .ok_or_else(|| format!("a tag's name is 1 to {} bytes", claim::MAX_NAME))
}

fn respond(catalog: &mut Catalog, words: &[&str]) -> Result<Vec<String>, String> {
    let failed = |e: Error| e.to_string();
    let mut out = Vec::new();
    match words {
        ["whoami"] => {
            let account = catalog.account().map_err(failed)?;
            out.push(format!("uid\t{}", catalog.uid()));
            let device = account.as_ref().and_then(|account| account.device.as_ref());
            out.push(format!("device\t{}", device.map_or_else(|| "-".to_owned(), crate::keys::peer_id)));
            let user = account.as_ref().and_then(|account| account.user.as_ref());
            out.push(format!("user\t{}", user.map_or_else(|| "-".to_owned(), crate::keys::peer_id)));
        },
        ["keep", "add", rest @ ..] => {
            let (shallow, rest) = match rest {
                ["--shallow", rest @ ..] => (true, rest),
                rest => (false, rest),
            };
            let cids = cids(rest)?;
            let mut frontiers = Vec::new();
            for cid in &cids {
                let missing = catalog.missing_under(cid).map_err(failed)?;
                if missing.contains(cid) || (!shallow && !missing.is_empty()) {
                    return Err(format!("{} blocks under {cid} aren't here; a keep needs all of what it keeps (or keep it --shallow)", missing.len()));
                }
                frontiers.push(missing);
            }
            catalog.batch(|catalog| {
                for (cid, beyond) in cids.iter().zip(&frontiers) {
                    out.push(catalog.keep_short_of(cid, beyond)?.to_string());
                }
                Ok::<_, Error>(())
            }).map_err(failed)?;
        },
        ["keep", "rm", rest @ ..] => {
            let cids = cids(rest)?;
            catalog.batch(|catalog| {
                for cid in &cids {
                    out.extend(catalog.unkeep(cid)?.iter().map(ToString::to_string));
                }
                Ok::<_, Error>(())
            }).map_err(failed)?;
        },
        ["keep", "ls"] => out.extend(catalog.claims().ok_or("this repo keeps no claims")?.keeps().map_err(failed)?.iter().map(ToString::to_string)),
        ["tag", "add", name, rest @ ..] => {
            let (tag, cids) = (tag(name)?, cids(rest)?);
            catalog.batch(|catalog| {
                for cid in &cids {
                    out.push(catalog.tag(cid, &tag)?.to_string());
                }
                Ok::<_, Error>(())
            }).map_err(failed)?;
        },
        ["tag", "rm", name, rest @ ..] => {
            let (tag, cids) = (tag(name)?, cids(rest)?);
            catalog.batch(|catalog| {
                for cid in &cids {
                    out.extend(catalog.untag(cid, &tag)?.iter().map(ToString::to_string));
                }
                Ok::<_, Error>(())
            }).map_err(failed)?;
        },
        ["tag", "ls", cid] => {
            let cid: Link = cid.parse().map_err(|_| format!("not a CID: {cid}"))?;
            let claims = catalog.claims().ok_or("this repo keeps no claims")?;
            for tag in claims.tags(cid.multihash()).map_err(failed)? {
                out.push(claim::tag_name(&tag).map_or_else(|| tag.to_string(), str::to_owned));
            }
        },
        ["tag", "find", name] => {
            let claims = catalog.claims().ok_or("this repo keeps no claims")?;
            out.extend(claims.tagged(tag(name)?.multihash()).map_err(failed)?.iter().map(ToString::to_string));
        },
        _ => return Err(format!("not something an account can ask: {}", words.join(" "))),
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::Block;
    use crate::cid::{AnyCid, CidVersion, Cidv1Spec};
    use crate::testutil::Scratch;

    #[test]
    fn an_account_says_and_sees_its_own() {
        let scratch = Scratch::new("account");
        let mut repo = Catalog::open_repo(scratch.path()).expect("open");
        let block = Block::hash(Cidv1Spec::default(), b"shared"[..].into());
        repo.put_block(&block, CidVersion::V1).expect("put");
        let cid = AnyCid::V1(block.cid().clone()).to_string();
        let owner = (repo.uid(), repo.signer().expect("signer").clone());
        let other = crate::keys::Key::generate().expect("key");
        repo.act_for(owner.0.wrapping_add(1), other.clone()).expect("act");

        assert_eq!(answer(&mut repo, &format!("tag\tadd\ttwo words\t{cid}")).len(), 1);
        assert_eq!(answer(&mut repo, &format!("tag\tls\t{cid}")), ["two words"]);
        assert_eq!(answer(&mut repo, &format!("keep\tadd\t{cid}")).len(), 1);
        assert_eq!(answer(&mut repo, "keep\tls"), std::slice::from_ref(&cid));
        let me = answer(&mut repo, "whoami");
        assert_eq!(me.get(1), Some(&format!("device\t{}", crate::keys::peer_id(&other.id()))));
        assert!(answer(&mut repo, "keep\tadd\tnot a cid").first().is_some_and(|line| line.starts_with("error: ")));
        assert!(answer(&mut repo, "collect").first().is_some_and(|line| line.starts_with("error: ")));

        repo.act_for(owner.0, owner.1).expect("act");
        assert!(answer(&mut repo, &format!("tag\tls\t{cid}")).is_empty());
        assert!(answer(&mut repo, "keep\tls").is_empty());
    }
}
