How the pages of this wiki are written. It's read mostly in Obsidian,
straight from `~/soup/wiki`, so its conventions come first.

## What belongs here

- **Reference, not rationale.** A page says what Holokeep does, exactly
  enough to reimplement or interoperate with it: formats, encodings,
  algorithms, constants. Why it's designed that way belongs in the
  README; link to it, or say it in one sentence.
- **What exists.** Describe what the code does now. Anything planned is
  marked plainly as "not yet implemented" or listed under a heading
  saying so, never described as if it worked.
- **One topic per page.** If a section is linked to from several pages,
  or grows past a screen or two, it's probably a page of its own.

## Pages

- **Titles are file names**, in Title Case with spaces, and short words
  (and, of, the) lower case: `Anchors and Names.md`. Obsidian shows the
  file name as the title, so a page has no `#` heading of its own.
- Sections are `##`, subsections `###`; go no deeper.
- [[Data Soup]] is the index: every page is listed there with a one-line
  summary, and new terms join its vocabulary table.
- A page that describes code ends with a `Source:` line naming the files
  it was checked against, so it can be checked again when they change.
- `aliases` in front matter are welcome where a page has another obvious
  name (`aliases: [CIDs]`); nothing else goes in front matter yet.

## Links

- Between pages, wiki links: `[[Claims]]`, `[[Mesh#Protocols]]`, or with
  other text, `[[Claims|a keep]]`.
- Link a concept the first time a page mentions it, not every time.
- Links outside the wiki are ordinary Markdown links.
- A path in the holokeep repository is code, not a link: `src/claim.rs`.

## Precision

- **Formats as tables or layouts.** Fields of a map are a table of key,
  type and meaning; byte layouts are a code block with offsets. Say
  which encoding: dag-cbor (canonical) for blocks and tickets, serde CBOR
  for wire messages.
- **Exact constants.** Sizes, limits and intervals are given with their
  units (1 MiB, 64 KiB, 300 s, 2G). Byte strings are quoted with escapes
  (`"hkbats\x00\x01"`), and literal bytes in hex (`0x81 0x58 0x20`).
- **Real examples.** A CID in an example is one that was actually
  computed, or is elided (`bafybei…`). Never make one up.
- Formulas are written once, in a code block, in plain notation
  (`sha256(a || b)`, `u32_be(x)`, `[0..16]` for a byte range).

## Wording

- Plain English, present tense, active voice: "the node fetches", not
  "blocks will be fetched".
- Use the vocabulary on [[Data Soup]] consistently: a *block* is not a
  file, a *node* is not a device, *dissolved* and *precipitated* mean
  exactly what's defined there.
- Code identifiers, commands, protocol names, table names and field names
  go in backticks: `hk mount`, `/holokeep/blocks/1.0.0`, `claim_targets`.
- Name things the code names. When the code's name is odd, use it and
  explain it once, rather than inventing a second name.

## Keeping it current

A change to a format, protocol or constant isn't done until the page
describing it says so. `scripts/snapshot-wiki.sh` copies the wiki into
`docs/wiki` in the holokeep repository from time to time, as a fallback;
edit the pages here, never the snapshot.
