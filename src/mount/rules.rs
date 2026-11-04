//! Rules for what's made through the mount: `.souprules` files, a line to
//! a rule, as a pattern and what's made by that name is.
//!
//! ```text
//! # pattern    settings
//! .obsidian/   detach
//! *.db         pace=30s
//! cache/       app=obsidian inline
//! ```
//!
//! A pattern without a slash but at its end matches a name anywhere
//! below the rules' directory; one with a slash, a path from it. A
//! trailing slash matches directories alone. `*` matches any run of a
//! name's bytes, `?` any one.

use std::path::Path;
use std::time::Duration;

/// What the built-in rules say, before any file's: what applications
/// keep their state in, made anchors of their own.
const DEFAULTS: &str = ".obsidian/ detach\n.git/ detach\n.vscode/ detach\n.idea/ detach\n";

/// The name of a directory's rules file.
pub const FILE: &str = ".souprules";

/// The most of a rules file that's read.
pub const MOST: usize = 64 * 1024;

/// What the rules say of something made.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Settings {
    /// Whether a directory is made an anchor of its own, mounted where
    /// it's made, rather than part of the anchor it's in.
    pub detach: Option<bool>,
    /// The least time between an anchor's commits, for an anchor mounted
    /// by this name.
    pub pace: Option<Duration>,
}

impl Settings {
    /// These, with what `over` says over them.
    fn and(self, over: Self) -> Self {
        Self { detach: over.detach.or(self.detach), pace: over.pace.or(self.pace) }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Rule {
    pattern: Vec<u8>,
    /// Whether the pattern's a path from the rules' directory, not a name.
    path: bool,
    dir_only: bool,
    /// The application it's for, if not any.
    app: Option<String>,
    settings: Settings,
}

/// A rules file's rules, in order: a later one says over an earlier.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rules(Vec<Rule>);

impl Rules {
    /// The rules of a file's text, and what of it isn't a rule, by line.
    pub fn parse(text: &str) -> (Self, Vec<String>) {
        let mut rules = Vec::new();
        let mut errors = Vec::new();
        for (number, line) in text.lines().enumerate() {
            let line = line.split_once('#').map_or(line, |(rule, _)| rule).trim();
            let mut words = line.split_whitespace();
            let Some(pattern) = words.next() else {
                continue;
            };
            match Rule::parse(pattern, words) {
                Ok(rule) => rules.push(rule),
                Err(e) => errors.push(format!("line {}: {e}", number.saturating_add(1))),
            }
        }
        (Self(rules), errors)
    }

    /// The built-in rules.
    pub fn defaults() -> Self {
        Self::parse(DEFAULTS).0
    }

    /// What these say of what's made at `rel` from their directory, a
    /// directory if `dir`, by `app` if it's known, over `settings`.
    pub fn apply(&self, settings: Settings, rel: &Path, dir: bool, app: Option<&str>) -> Settings {
        use std::os::unix::ffi::OsStrExt as _;
        let rel = rel.as_os_str().as_bytes();
        let name = rel.rsplit(|&byte| byte == b'/').next().unwrap_or(rel);
        self.0.iter().fold(settings, |settings, rule| {
            let applies = (dir || !rule.dir_only)
                && rule.app.as_deref().is_none_or(|wanted| app == Some(wanted))
                && glob(&rule.pattern, if rule.path { rel } else { name });
            if applies { settings.and(rule.settings) } else { settings }
        })
    }
}

impl Rule {
    fn parse<'a>(pattern: &str, words: impl Iterator<Item = &'a str>) -> Result<Self, String> {
        let dir_only = pattern.ends_with('/');
        let trimmed = pattern.trim_end_matches('/');
        let path = trimmed.contains('/');
        let trimmed = trimmed.trim_start_matches('/');
        if trimmed.is_empty() {
            return Err(format!("{pattern:?} matches nothing"));
        }
        let mut rule = Self { pattern: trimmed.as_bytes().to_vec(), path, dir_only, app: None, settings: Settings::default() };
        for word in words {
            match word.split_once('=') {
                None if word == "detach" => rule.settings.detach = Some(true),
                None if word == "inline" => rule.settings.detach = Some(false),
                Some(("pace", pace)) => rule.settings.pace = Some(duration(pace).ok_or_else(|| format!("{pace:?} isn't a time, as 30s, 5m or 1h"))?),
                Some(("app", app)) if !app.is_empty() => rule.app = Some(app.to_owned()),
                _ => return Err(format!("{word:?} isn't a setting: detach, inline, pace=<time> or app=<name>")),
            }
        }
        Ok(rule)
    }
}

/// A time, as `30s`, `5m`, `1h` or `0`.
fn duration(text: &str) -> Option<Duration> {
    if text == "0" {
        return Some(Duration::ZERO);
    }
    let unit = text.len().checked_sub(1).and_then(|at| text.get(at..))?;
    let n: u64 = text.get(..text.len().saturating_sub(1))?.parse().ok()?;
    match unit {
        "s" => Some(Duration::from_secs(n)),
        "m" => Some(Duration::from_secs(n.checked_mul(60)?)),
        "h" => Some(Duration::from_secs(n.checked_mul(3600)?)),
        _ => None,
    }
}

/// Whether `text` matches `pattern`: `*` for any run of bytes but `/`,
/// `?` for any one.
fn glob(pattern: &[u8], text: &[u8]) -> bool {
    match pattern.split_first() {
        None => text.is_empty(),
        Some((b'*', rest)) => {
            let mut at = text;
            loop {
                if glob(rest, at) {
                    return true;
                }
                match at.split_first() {
                    Some((&byte, tail)) if byte != b'/' => at = tail,
                    _ => return false,
                }
            }
        },
        Some((&wanted, rest)) => match text.split_first() {
            Some((&byte, tail)) if byte == wanted || (wanted == b'?' && byte != b'/') => glob(rest, tail),
            _ => false,
        },
    }
}

/// What the app making a request is called: its process's name, as
/// `/proc/<pid>/comm` says.
pub fn app_of(pid: u32) -> Option<String> {
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    Some(comm.trim_end().to_owned()).filter(|comm| !comm.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn said(text: &str, rel: &str, dir: bool, app: Option<&str>) -> Settings {
        let (rules, errors) = Rules::parse(text);
        assert!(errors.is_empty(), "{errors:?}");
        rules.apply(Settings::default(), Path::new(rel), dir, app)
    }

    #[test]
    fn rules_say_what_matching_names_are() {
        let detach = Settings { detach: Some(true), pace: None };
        assert_eq!(Rules::defaults().apply(Settings::default(), Path::new("notes/.obsidian"), true, None), detach);
        assert_eq!(Rules::defaults().apply(Settings::default(), Path::new(".obsidian"), false, None), Settings::default(), "a directory's rule");
        assert_eq!(said("*.db pace=30s", "app/state.db", false, None).pace, Some(Duration::from_secs(30)));
        assert_eq!(said("*.db pace=30s", "app/state.db-journal", false, None).pace, None);
        assert_eq!(said("cache/ detach # comment", "a/b/cache", true, None), detach, "a name anywhere below");
        assert_eq!(said("a/cache/ detach", "a/cache", true, None), detach, "a path from the rules'");
        assert_eq!(said("a/cache/ detach", "b/a/cache", true, None), Settings::default());
        assert_eq!(said("/top detach", "top", true, None), detach);
        assert_eq!(said("c?che detach", "cache", true, None), detach);
        assert_eq!(said("*/x detach", "a/b/x", true, None), Settings::default(), "* is within a name");
        // Later says over earlier, and only for its app
        let text = ".git/ detach\n.git/ inline app=git\n";
        assert_eq!(said(text, ".git", true, Some("git")).detach, Some(false));
        assert_eq!(said(text, ".git", true, Some("bash")).detach, Some(true));
        assert_eq!(said(text, ".git", true, None).detach, Some(true));
        assert_eq!(said("x pace=1h\nx detach", "x", true, None), Settings { detach: Some(true), pace: Some(Duration::from_hours(1)) }, "settings say over only what they say");
    }

    #[test]
    fn what_isnt_a_rule_is_said_by_line() {
        let (rules, errors) = Rules::parse("ok detach\n\n  # nothing\nbad sideways\nslow pace=soon\n/ detach\nfine pace=0\n");
        assert_eq!(rules.0.len(), 2);
        assert_eq!(errors.len(), 3, "{errors:?}");
        assert!(errors.first().is_some_and(|e| e.starts_with("line 4:")), "{errors:?}");
    }
}
