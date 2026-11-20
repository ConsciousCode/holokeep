//! What clients ask a member to say or tell them, as their account (see
//! `crate::net::thin`).

use std::collections::HashSet;

use libp2p::PeerId;
use libp2p::request_response::{self, ResponseChannel};

use super::{FetchId, Node};
use crate::cid::CidRef as _;
use crate::claim::covers;
use crate::grants::WRITE;
use crate::net::durability::{self, Kept, Push};
use crate::model::Link;
use crate::net::mesh::Result;
use crate::net::thin::{Answer, Ask};

/// What a client asked, waiting on fetches of what it needs here.
pub struct Asked {
    fetches: HashSet<FetchId>,
    uid: u32,
    words: Vec<String>,
    channel: ResponseChannel<Answer>,
}

/// What a command needs here before it's answered: DAGs, whole, and
/// blocks, alone.
fn needs(words: &[String]) -> (Vec<Link>, Vec<Link>) {
    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    let parse = |words: &[&str]| words.iter().filter_map(|word| word.parse().ok()).collect::<Vec<Link>>();
    match words.as_slice() {
        ["keep", "add", "--shallow", rest @ ..] => (Vec::new(), parse(rest)),
        ["keep", "add", rest @ ..] => (parse(rest), Vec::new()),
        ["anchor", "set", "--lazy", ..] => (Vec::new(), Vec::new()),
        ["anchor", "set", _, cid] => (parse(&[cid]), Vec::new()),
        _ => (Vec::new(), Vec::new()),
    }
}

fn parse(cid: &str) -> Result<Link> {
    cid.parse().map_err(|_| crate::net::mesh::Error::Invalid(format!("not a CID: {cid}")))
}

fn error(message: &str) -> Answer {
    Answer { lines: vec![format!("error: {message}")] }
}

impl Node {
    pub(super) fn on_ask(&mut self, event: request_response::Event<Ask, Answer>) -> Result<()> {
        let request_response::Event::Message { peer, message: request_response::Message::Request { request, channel, .. }, .. } = event else {
            return Ok(());
        };
        if let Some(key) = self.visitors.get(&peer).cloned() {
            let answer = self.answer_visitor(&peer, &key, &request.words).unwrap_or_else(|e| error(&e.to_string()));
            let _ = self.swarm.behaviour_mut().asks.send_response(channel, answer);
            return Ok(());
        }
        let Some(&uid) = self.clients.get(&peer) else {
            let _ = self.swarm.behaviour_mut().asks.send_response(channel, error("only clients ask"));
            return Ok(());
        };
        if request.words.iter().any(|word| word.contains(['\t', '\n'])) {
            let _ = self.swarm.behaviour_mut().asks.send_response(channel, error("what's asked can't have tabs or newlines in it"));
            return Ok(());
        }
        // What isn't here of what it's to keep is fetched from the user's
        // other machines first, as `hk keep` fetches through the node
        let (dags, blocks) = needs(&request.words);
        let mut fetches = HashSet::new();
        for root in dags {
            if !self.catalog.viewing(uid, |catalog| catalog.missing_under(&root))??.is_empty() {
                fetches.insert(self.fetch_for(uid, root)?);
            }
        }
        let absent: Vec<Link> = blocks.into_iter().filter(|cid| !matches!(self.catalog.viewing(uid, |catalog| catalog.visible(cid.multihash())), Ok(Ok(true)))).collect();
        if !absent.is_empty() {
            fetches.insert(self.fetch_blocks_for(uid, absent)?);
        }
        if fetches.is_empty() {
            return self.answer_ask(uid, &request.words, channel);
        }
        self.asked.push(Asked { fetches, uid, words: request.words, channel });
        Ok(())
    }

    /// Answer a visitor, which may ask only about what's shared with it:
    /// which views, what each is now, as it may read them, and what a set
    /// of its own would follow.
    fn answer_visitor(&mut self, peer: &PeerId, key: &Link, words: &[String]) -> Result<Answer> {
        let words: Vec<&str> = words.iter().map(String::as_str).collect();
        let mut lines = Vec::new();
        match words.as_slice() {
            ["whoami"] => lines.push(format!("visitor\t{peer}")),
            ["shared"] => {
                let Some((_, state)) = &self.granted else {
                    return Ok(Answer::default());
                };
                for share in state.shares().into_iter().filter(|share| share.user == *key && !share.held.is_empty()) {
                    if let Some(view) = crate::claim::view(&share.anchor, &share.owner) {
                        lines.push(format!("{view}\t{}\t{}", crate::keys::peer_id(&share.owner), share.held.join(" ")));
                    }
                }
            },
            ["anchor", "show", view] => {
                let view = parse(view)?;
                let value = self.catalog.as_guest(key, |catalog| catalog.anchor_value(&view))??;
                lines.push(value.map_or_else(|| "unset".to_owned(), |value| value.to_string()));
            },
            // What a set of its own would follow: the view's heads, and
            // when each was set
            ["anchor", "heads", view] => {
                let view = parse(view)?;
                for (set, _, at) in self.catalog.as_guest(key, |catalog| catalog.anchor_heads(&view))?? {
                    lines.push(format!("{set}\t{at}"));
                }
            },
            // What a sign of its own would follow: its last here
            ["signed"] => {
                if let Some(sign) = self.catalog.claims().map(|claims| claims.head(key)).transpose()?.flatten() {
                    lines.push(sign.to_string());
                }
            },
            _ => return Ok(error("a visitor may only read and write what's shared with it: whoami, shared, anchor show, anchor heads, signed, blocks, and pushes")),
        }
        Ok(Answer { lines })
    }

    /// Hold what a visitor pushed, for the user it's pushed for, if this
    /// serves them and the visitor may write a view of theirs: what it
    /// sets, and what that reaches. What a set of its reaches that isn't
    /// here is fetched, as it is for a guest's.
    pub(super) fn on_visitor_push(&mut self, key: &Link, push: Push, channel: ResponseChannel<Kept>) -> Result<()> {
        let local = match (&self.granted, push.user()) {
            (Some((_, state)), Some(user)) => self.locals()?.into_iter().find(|local| {
                local.rooted
                    && local.user_bytes().as_deref() == Some(user)
                    && local.user.as_ref().is_some_and(|owner| state.shares().iter().any(|share| share.owner == *owner && share.user == *key && share.held.iter().any(|held| covers(held, WRITE))))
            }),
            _ => None,
        };
        let Some(local) = local.filter(|local| self.recognizes(local)) else {
            let _ = self.swarm.behaviour_mut().push.send_response(channel, Kept::default());
            return Ok(());
        };
        let (kept, sets) = self.catalog.viewing(local.uid, |catalog| durability::answer_visitor_push(catalog, push))??;
        let _ = self.swarm.behaviour_mut().push.send_response(channel, kept);
        self.took_guest_claims(&local, &sets)
    }

    /// A fetch finished: answer what a client asked, if that's what it
    /// waited on. Whether it was a client's.
    pub(super) fn fetched_for_ask(&mut self, id: FetchId) -> Result<bool> {
        let Some(i) = self.asked.iter().position(|asked| asked.fetches.contains(&id)) else {
            return Ok(false);
        };
        let waiting = self.asked.get_mut(i).is_some_and(|asked| {
            asked.fetches.remove(&id);
            !asked.fetches.is_empty()
        });
        if !waiting {
            let asked = self.asked.swap_remove(i);
            self.answer_ask(asked.uid, &asked.words, asked.channel)?;
        }
        Ok(true)
    }

    /// Answer as a client's account, signing with its key here.
    fn answer_ask(&mut self, uid: u32, words: &[String], channel: ResponseChannel<Answer>) -> Result<()> {
        let command = words.join("\t");
        let home = self.catalog.uid();
        let lines = if uid == home {
            crate::account::answer(&mut self.catalog, &command)
        } else {
            let key = self.others.iter().find(|(other, _)| *other == uid).map(|(_, key)| key.clone());
            match (key, self.catalog.signer().cloned()) {
                (Some(key), Some(back)) => {
                    self.catalog.act_for(uid, key)?;
                    let lines = crate::account::answer(&mut self.catalog, &command);
                    self.catalog.act_for(home, back)?;
                    lines
                },
                _ => vec!["error: the account has no key here to sign with".to_owned()],
            }
        };
        let _ = self.swarm.behaviour_mut().asks.send_response(channel, Answer { lines });
        Ok(())
    }
}
