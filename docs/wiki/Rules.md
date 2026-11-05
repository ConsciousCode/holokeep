Rules say what [[Mount|hk mount]] makes of what applications make
through it. An application's state (`.obsidian/`, `.git/`) changes far
more often than what it's about, and inside an anchor it would change
that anchor with it; a rule makes it an anchor of its own instead.
Rules apply as something's made, so nothing has to scan for them.

## Rules files

A **rules file** is a file named `.souprules` in any directory: its
rules apply to what's made in that directory and anywhere below it,
through [[Anchors and Names#Mount points|mount points]] too. The one at
the top of the account's root anchor, `~/soup/.souprules`, applies
everywhere, including to anchors reached through `anchors/`.

Rules are applied in order: the built-in ones, then the root's top's,
then each directory's from the top down, so a nearer rules file says
over a farther one, and within a file a later line over an earlier. A
rule says over only the settings it names.

A rules file is read again as soon as it's another file (another CID,
or another size, mtime or inode in a work directory). What isn't a rule
is said in the mount's output, with its line, and skipped.

## Syntax

One rule to a line: a pattern, then settings, separated by whitespace.
`#` starts a comment.

```
# pattern      settings
.obsidian/     detach
cache/         detach app=obsidian
notes/.git/    inline
*.db           pace=5m
__pycache__/   copies=1
```

- A pattern with no slash but at its end matches a **name**, anywhere
  below the rules file's directory. One with a slash elsewhere (a
  leading one included) matches a **path** from that directory, through
  mount points by their names.
- A trailing `/` matches directories alone.
- `*` matches any run of bytes within a name, `?` any one byte; neither
  matches `/`.
- Names with whitespace can't be matched yet.

| Setting | Meaning |
|---|---|
| `detach` | A directory made by this name is a new anchor, an empty directory, mounted where it's made. |
| `inline` | A directory made by this name is an ordinary directory of the anchor it's in. |
| `copies=<n>` | A directory made by this name is an anchor of its own (unless the rules say `inline`), kept by a keep asking for `n` failures to lose what's in it, at least 1 (see [[Replication and Retention#Durability]]). |
| `pace=<time>` | An anchor mounted by this name is committed at most this often, as well as by its own pace (see [[Mount#Committing]]). Times are `30s`, `5m`, `1h` or `0`. |
| `app=<name>` | The rule applies only to what the application by this name makes: the process making the request, by `/proc/<pid>/comm`. |

## Built-in rules

```
.obsidian/ detach
.git/      detach
.vscode/   detach
.idea/     detach
```

## When rules apply

- `detach` and `inline` apply when a directory is made (`mkdir`).
  Directories already there stay as they are; to detach one, make it
  again: `mv .obsidian .obsidian.old && mkdir .obsidian && cp -a
  .obsidian.old/. .obsidian/ && rm -r .obsidian.old`, with the
  application closed.
- `pace` applies whenever the mount point is looked up, so it follows
  edits to the rules. An anchor reached only through `anchors/` has no
  floor.
- `copies` applies when the directory is made, as its anchor's keep;
  changing the rule later doesn't change keeps already made.

Not yet implemented: detaching files, so far only directories; and
`copies=0`, a cache the mesh may drop entirely under pressure, which
needs whole anchors dropped at once so nothing's left half there.

Source: `src/mount/rules.rs`, `src/mount.rs` (`settings_for`, `rules_at`), `src/mount/write.rs` (`mkdir_by`, `anchor_at`).
