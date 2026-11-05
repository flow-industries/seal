import { expect, spyOn, test } from "bun:test";
import { linkRanges } from "../vault/links.ts";
import { markdownParser } from "../vault/table-syntax.ts";
import {
  completeNoteLinks,
  createLinkIndex,
  describeUnresolvedLink,
  type LinkNote,
  noteReferences,
  resolvedLinks,
  resolveNoteEmbed,
  resolveNoteLink,
} from "./index.ts";
import { rebaseOutgoingLinks, repairMovedNoteLinks } from "./rename.ts";

const note = (id: string, path: string, source = ""): LinkNote => ({
  id,
  path,
  source,
  kind: "md",
});

test("syntax ranges preserve Markdown destinations and omit code, comments, YAML and escapes", () => {
  const source =
    '---\naliases: ["[[fake]]"]\n---\n`[[inline]]`\n\n    [[indented]]\n\n~~~\n[[fenced]]\n~~~\n<!-- [[comment]] -->\n%% [[hidden]] %%\n\\[[escaped]]\n[[real#Heading|label]] [name](<folder/a b.md#Part> "title") [paren](a\\(b\\).md)\n\n[ref]: reference.md\n\n```\n[[unclosed]]';
  expect(linkRanges(source).map((link) => link.target)).toEqual([
    "real#Heading",
    "folder/a b.md#Part",
    "a\\(b\\).md",
    "reference.md",
  ]);
});

test("resolves relative and root wiki links, aliases, heading slugs, repeated headings and blocks", () => {
  const notes = [
    note("from", "folder/From.md"),
    note(
      "target",
      "other/Target.md",
      "---\naliases: [Alternate]\n---\n# First Heading\nBody\n\n## Child\nText\n\n# First Heading\nSecond\n\nBlock text\ncontinues ^block-1\n",
    ),
    note("nested", "folder/Nested.md"),
  ];
  const index = createLinkIndex(notes);
  expect(resolveNoteLink(index, "other/Target", "from")?.id).toBe("target");
  expect(
    resolveNoteLink(
      index,
      "../other/Target.md#first-heading-1",
      "from",
      "markdown",
    )?.line,
  ).toBe(10);
  expect(resolveNoteLink(index, "Alternate#First Heading", "from")?.line).toBe(
    4,
  );
  expect(resolveNoteLink(index, "/other/Target#^block-1", "from")?.line).toBe(
    13,
  );
  expect(resolveNoteLink(index, "Nested.md", "from", "markdown")?.id).toBe(
    "nested",
  );
  expect(resolveNoteLink(index, "Target.md", "from", "markdown")).toBeNull();
  expect(resolveNoteLink(index, "https://example.com", "from")).toBeNull();
  expect(resolveNoteLink(index, "Target#missing", "from")).toBeNull();
  expect(completeNoteLinks(index, "Alternate#Fi", "from")).toHaveLength(2);
  expect(completeNoteLinks(index, "Target#^blo", "from")[0]?.target).toBe(
    "/other/Target#^block-1",
  );
  expect(resolveNoteEmbed(index, "Target#First Heading", "from")?.source).toBe(
    "# First Heading\nBody\n\n## Child\nText\n\n",
  );
  expect(
    resolveNoteEmbed(index, "/other/Target#^block-1", "from")?.source,
  ).toBe("Block text\ncontinues");
  expect(
    resolveNoteEmbed(index, "Target", "from", { ancestors: ["target"] }),
  ).toBeNull();
  expect(resolveNoteEmbed(index, "Target", "from", { maxDepth: 1 })).toBeNull();
});

test("duplicate basenames and aliases remain ambiguous; nearest relative path wins", () => {
  const index = createLinkIndex([
    note("from", "From.md"),
    note("a", "a/Same.md", "---\naliases: [Twin]\n---"),
    note("b", "b/Same.md", "---\naliases: [Twin]\n---"),
    note("near", "a/From.md"),
  ]);
  expect(resolveNoteLink(index, "Same", "from")).toBeNull();
  expect(resolveNoteLink(index, "Twin", "from")).toBeNull();
  expect(resolveNoteLink(index, "Same", "near")?.id).toBe("a");
});

test("aliases and heading keys preserve Unicode normalization and contextual casing", () => {
  const index = createLinkIndex([
    note("from", "From.md"),
    note("target", "Target.md", "---\naliases: [Cafe\u0301, İ]\n---\n# ΟΔΟΣ\n"),
  ]);
  for (const target of ["Café#ΟΔΟΣ", "i\u0307#ΟΔΟΣ"])
    expect(resolveNoteLink(index, target, "from")).toMatchObject({
      id: "target",
      line: 4,
    });
});

test("references include outgoing, backlinks and bounded-word unlinked mentions", () => {
  const index = createLinkIndex([
    note("a", "Alpha.md", "[[Beta]] [[Missing]]"),
    note(
      "b",
      "Beta.md",
      "Alpha here\nAlphabet\n`Alpha`\n[[Alpha]]\n%% Alpha %%",
    ),
  ]);
  const refs = noteReferences(index, "a");
  expect(refs.outgoing.map((row) => row.target)).toEqual(["Beta", "Missing"]);
  expect(refs.backlinks.map((row) => row.line)).toEqual([4]);
  expect(refs.unlinked.map((row) => row.line)).toEqual([1]);
});

test("mention patterns keep longest literal aliases on every note and query", () => {
  const index = createLinkIndex([
    note("a", "Alpha.md", '---\naliases: ["Long Alpha", "C++"]\n---'),
    note("b", "Beta.md", "Long Alpha and Alpha\nC++ and CCC"),
    note("c", "Gamma.md", "Long Alpha and Alpha\nC++ and CCC"),
  ]);
  for (let attempt = 0; attempt < 2; attempt++)
    expect(
      noteReferences(index, "a").unlinked.map((row) => [
        row.noteId,
        row.line,
        index.byId.get(row.noteId)?.source.slice(row.start, row.end),
      ]),
    ).toEqual([
      ["b", 1, "Long Alpha"],
      ["b", 2, "C++"],
      ["c", 1, "Long Alpha"],
      ["c", 2, "C++"],
    ]);
});

test("moves repair inbound links and relative outbound assets while preserving labels and fragments", () => {
  const before = [
    note(
      "a",
      "folder/Old.md",
      '[other](../Other.md#part "title") ![asset](../media/pic.png) [[Other]]',
    ),
    note(
      "b",
      "Other.md",
      '\ufeff---\r\ncustom: true\r\n---\r\n[[folder/Old#Heading|keep]] [old](folder/Old.md#heading "title") `[[folder/Old]]`',
    ),
  ];
  const after = [
    note("a", "deeper/place/New.md", before[0]!.source),
    before[1]!,
  ];
  const repairs = repairMovedNoteLinks(before, after, [
    { id: "asset", path: "media/pic.png" },
  ]);
  expect(repairs.get("a")).toBe(
    '[other](../../Other.md#part "title") ![asset](../../media/pic.png) [[Other]]',
  );
  expect(repairs.get("b")).toBe(
    '\ufeff---\r\ncustom: true\r\n---\r\n[[/deeper/place/New#Heading|keep]] [old](deeper/place/New.md#heading "title") `[[folder/Old]]`',
  );
});

test("ambiguous links are not rewritten and URL-escaped destinations retain their meaning", () => {
  const before = [
    note(
      "from",
      "From.md",
      "[[Same]] [target](a/Same.md) [space](a/Space%20Name.md)",
    ),
    note("a", "a/Same.md"),
    note("b", "b/Same.md"),
    note("space", "a/Space Name.md"),
  ];
  const after = before.map((n) =>
    n.id === "a"
      ? { ...n, path: "a/New.md" }
      : n.id === "space"
        ? { ...n, path: "new/Space (Name).md" }
        : n,
  );
  expect(repairMovedNoteLinks(before, after).get("from")).toBe(
    "[[Same]] [target](a/New.md) [space](new/Space%20%28Name%29.md)",
  );
});

test("incremental indexes reuse unchanged notes and refresh edited anchors, aliases and references", () => {
  const first = note("first", "First.md", "[[Second#Before]]");
  const second = note(
    "second",
    "Second.md",
    "---\naliases: [Old alias]\n---\n# Before\nText ^old-block",
  );
  const initial = createLinkIndex([first, second]);
  const edited = {
    ...second,
    source: "---\naliases: [New alias]\n---\n# After\nText ^new-block",
  };
  const next = createLinkIndex([{ ...first }, edited], initial);
  expect(next.byId.get("first")).toBe(initial.byId.get("first"));
  expect(next.byId.get("second")).not.toBe(initial.byId.get("second"));
  expect(resolveNoteLink(next, "Second#Before", "first")).toBeNull();
  expect(resolveNoteLink(next, "Old alias", "first")).toBeNull();
  expect(resolveNoteLink(next, "New alias#After", "first")?.line).toBe(4);
  expect(
    completeNoteLinks(next, "Second#^", "first").map((item) => item.label),
  ).toEqual(["^new-block"]);
  expect(noteReferences(next, "second").backlinks).toHaveLength(1);
  expect(resolveNoteLink(initial, "Old alias#Before", "first")?.line).toBe(4);
});

test("incremental indexes invalidate path and format changes and follow additions, removals and ordering", () => {
  const first = note("first", "First.md", "[[Second]]");
  const second = note("second", "Second.md", "# Heading");
  const initial = createLinkIndex([first, second]);
  const moved = { ...second, path: "Moved.md" };
  const withMove = createLinkIndex([moved, first], initial);
  expect(withMove.notes.map((item) => item.id)).toEqual(["second", "first"]);
  expect(withMove.byId.get("second")).not.toBe(initial.byId.get("second"));
  expect(withMove.byId.get("first")).toBe(initial.byId.get("first"));
  expect(resolveNoteLink(withMove, "Second", "first")).toBeNull();
  expect(resolveNoteLink(withMove, "Moved", "first")?.id).toBe("second");
  const mdx = { ...moved, kind: "mdx" as const };
  const withFormat = createLinkIndex([first, mdx], withMove);
  expect(withFormat.byId.get("second")).not.toBe(withMove.byId.get("second"));
  expect(withFormat.byId.get("second")?.kind).toBe("mdx");
  const added = note("added", "Added.md");
  const withRemoval = createLinkIndex([first, added], withFormat);
  expect(withRemoval.byId.has("second")).toBe(false);
  expect(withRemoval.notes.map((item) => item.id)).toEqual(["first", "added"]);
  expect(withRemoval.byId.get("first")).toBe(initial.byId.get("first"));
  expect(createLinkIndex([], withRemoval).byId.size).toBe(0);
  expect(createLinkIndex([first]).byId.get("first")).not.toBe(
    initial.byId.get("first"),
  );
});

test("missing-note actions propose validated paths relative to the source and preserve explicit wiki roots", () => {
  const index = createLinkIndex([note("from", "folder/From.md")]);
  expect(describeUnresolvedLink(index, "New note", "from")).toEqual({
    kind: "missing-note",
    path: "folder/New note.md",
  });
  expect(
    describeUnresolvedLink(index, "../New%20note.mdx#Start", "from"),
  ).toEqual({ kind: "missing-note", path: "New note.mdx" });
  expect(describeUnresolvedLink(index, "projects/New", "from")).toEqual({
    kind: "missing-note",
    path: "projects/New.md",
  });
  expect(describeUnresolvedLink(index, "/Root", "from")).toEqual({
    kind: "missing-note",
    path: "Root.md",
  });
  expect(describeUnresolvedLink(index, "./Sibling", "from")).toEqual({
    kind: "missing-note",
    path: "folder/Sibling.md",
  });
});

test("unresolved classification distinguishes ambiguous titles and aliases from missing anchors", () => {
  const index = createLinkIndex([
    note("from", "From.md"),
    note("b", "b/Same.md", "---\naliases: [Twin]\n---\n# Present"),
    note("a", "a/Same.md", "---\naliases: [Twin]\n---"),
    note("alias", "Other.md", "---\naliases: [Same]\n---"),
  ]);
  const ambiguous = {
    kind: "ambiguous" as const,
    candidates: [
      { id: "a", path: "a/Same.md" },
      { id: "b", path: "b/Same.md" },
    ],
  };
  expect(describeUnresolvedLink(index, "Same", "from")).toEqual(ambiguous);
  expect(describeUnresolvedLink(index, "Twin#Missing", "from")).toEqual(
    ambiguous,
  );
  expect(resolveNoteLink(index, "Same", "from")).toBeNull();
  expect(describeUnresolvedLink(index, "b/Same#Missing", "from")).toEqual({
    kind: "missing-fragment",
  });
  expect(describeUnresolvedLink(index, "#Missing", "from")).toEqual({
    kind: "missing-fragment",
  });
  expect(describeUnresolvedLink(index, "b/Same#Present", "from")).toEqual({
    kind: "invalid",
  });
});

test("missing-note actions reject unsafe paths and note-folder collisions", () => {
  const index = createLinkIndex([
    note("from", "From.md"),
    note("file", "Existing.md"),
    note("child", "folder.md/Child.md"),
  ]);
  for (const target of [
    "",
    "../Outside",
    "a/../../Outside",
    "https://example.com",
    "//host/path",
    "bad%ZZ",
    "Name#bad%ZZ",
    "bad%00",
    "bad\\path",
    "CON",
    "bad?name",
    "trailing ",
    "trailing.",
    "double//slash",
    "folder/",
    "Existing.md/Child",
    "folder.md",
    "a".repeat(256),
    `${"a/".repeat(64)}Child`,
  ]) {
    expect(describeUnresolvedLink(index, target, "from")).toEqual({
      kind: "invalid",
    });
  }
  expect(describeUnresolvedLink(index, "New", "unknown")).toEqual({
    kind: "invalid",
  });
});

test("renames preserve destination identity across root shadowing, percent names and extension collisions", () => {
  for (const destination of [
    "New.md",
    "100%.md",
    "100%20literal.md",
    "New (copy).md",
  ]) {
    const before = [
      note("from", "folder/From.md", "[[Old#Heading|label]]"),
      note("moving", "Old.md", "# Heading"),
      note("shadow", `folder/${destination}`),
      note("extension", destination.replace(/\.md$/u, ".mdx")),
    ];
    const after = before.map((item) =>
      item.id === "moving" ? { ...item, path: destination } : item,
    );
    const repaired = repairMovedNoteLinks(before, after).get("from");
    expect(repaired).toBeDefined();
    const target = linkRanges(repaired ?? "")[0]?.target ?? "";
    expect(resolveNoteLink(createLinkIndex(after), target, "from")?.id).toBe(
      "moving",
    );
    expect(repaired?.endsWith("|label]]")).toBe(true);
    expect(target.startsWith("/")).toBe(true);
  }
});

test("standalone block identifiers select the preceding complete block and inline list IDs select one item", () => {
  const source =
    "- one\n- two\n\n^list-id\n\n> Quote one\n> Quote two\n\n^quote-id\n\n- first ^first-id\n- second ^second-id";
  const index = createLinkIndex([
    note("from", "From.md"),
    note("blocks", "Blocks.md", source),
  ]);
  expect(resolveNoteEmbed(index, "Blocks#^list-id", "from")?.source).toBe(
    "- one\n- two",
  );
  expect(resolveNoteEmbed(index, "Blocks#^quote-id", "from")?.source).toBe(
    "> Quote one\n> Quote two",
  );
  expect(resolveNoteEmbed(index, "Blocks#^first-id", "from")?.source).toBe(
    "- first",
  );
  expect(resolveNoteEmbed(index, "Blocks#^second-id", "from")?.source).toBe(
    "- second",
  );
});

test("nested headings resolve within their parent and global completion preserves duplicate heading identity", () => {
  const index = createLinkIndex([
    note("from", "folder/From.md"),
    note("a", "A.md", "# Parent\n## Child\nFirst\n# Other\n## Child\nSecond"),
    note("b", "B.md", "# Child"),
  ]);
  expect(resolveNoteLink(index, "A#Parent#Child", "from")?.line).toBe(2);
  expect(resolveNoteLink(index, "A#Other#Child", "from")?.line).toBe(5);
  expect(resolveNoteLink(index, "A#Child#Other", "from")).toBeNull();
  expect(resolveNoteEmbed(index, "A#Other#Child", "from")?.source).toBe(
    "## Child\nSecond",
  );
  const global = completeNoteLinks(index, "##Child", "from");
  expect(global).toHaveLength(3);
  expect(
    global.map((item) => resolveNoteLink(index, item.target, "from")),
  ).toEqual([
    { id: "a", path: "A.md", line: 2, fragment: "child" },
    { id: "a", path: "A.md", line: 5, fragment: "child-1" },
    { id: "b", path: "B.md", line: 1, fragment: "Child" },
  ]);
  const nested = completeNoteLinks(index, "A#Other#Ch", "from");
  expect(nested).toHaveLength(1);
  expect(resolveNoteLink(index, nested[0]?.target ?? "", "from")?.line).toBe(5);
});

test("Markdown completions, unresolved creation and embeds preserve relative and root path semantics", () => {
  const index = createLinkIndex([
    note("from", "folder/From.md"),
    note("root", "sub/Target.md", "Root"),
    note("relative", "folder/sub/Target.md", "Relative"),
    note("percent", "100%.md", "# 100%"),
  ]);
  expect(
    resolveNoteEmbed(index, "sub/Target.md", "from", "markdown")?.source,
  ).toBe("Relative");
  expect(resolveNoteEmbed(index, "sub/Target.md", "from", "wiki")?.source).toBe(
    "Root",
  );
  expect(describeUnresolvedLink(index, "sub/New", "from", "markdown")).toEqual({
    kind: "missing-note",
    path: "folder/sub/New.md",
  });
  expect(describeUnresolvedLink(index, "sub/New", "from", "wiki")).toEqual({
    kind: "missing-note",
    path: "sub/New.md",
  });
  for (const syntax of ["wiki", "markdown"] as const) {
    for (const candidate of completeNoteLinks(index, "", "from", syntax)) {
      expect(
        resolveNoteLink(index, candidate.target, "from", syntax)?.path,
      ).toBe(candidate.detail);
    }
    const percent = completeNoteLinks(index, "##100", "from", syntax)[0];
    expect(
      resolveNoteLink(index, percent?.target ?? "", "from", syntax)?.id,
    ).toBe("percent");
  }
});

test("outgoing rebasing preserves copied text destinations, local fragments and encrypted asset references", () => {
  const notes = [
    note("from", "folder/From.md", "# Local"),
    note("target", "Target.md", "# Heading"),
    note("shadow", "new/Target.md"),
  ];
  const source =
    '[[../Target#Heading|label]] [target](../Target.md#Heading "title") [[#Local]] ![pic](../media/pic.png) `[[Target]]`';
  const rebased = rebaseOutgoingLinks(
    source,
    "from",
    "new/deep/Excerpt.md",
    notes,
    [{ id: "asset", path: "media/pic.png" }],
  );
  expect(rebased).toBe(
    '[[/Target#Heading|label]] [target](../../Target.md#Heading "title") [[/folder/From#Local]] ![pic](../../media/pic.png) `[[Target]]`',
  );
  const context = createLinkIndex([
    ...notes,
    note("excerpt", "new/deep/Excerpt.md", rebased),
  ]);
  const links = linkRanges(rebased);
  expect(resolveNoteLink(context, links[0]?.target ?? "", "excerpt")?.id).toBe(
    "target",
  );
  expect(resolveNoteLink(context, links[2]?.target ?? "", "excerpt")?.id).toBe(
    "from",
  );
});

test("rebasing accounts for the newly created destination shadowing an existing basename", () => {
  const notes = [
    note("from", "From.md"),
    note("original", "Target.md", "# Heading"),
  ];
  const rebased = rebaseOutgoingLinks(
    "[[Target#Heading]]",
    "from",
    "new/Target.md",
    notes,
  );
  const after = createLinkIndex([
    ...notes,
    note("copy", "new/Target.md", rebased),
  ]);
  expect(
    resolveNoteLink(after, linkRanges(rebased)[0]?.target ?? "", "copy")?.id,
  ).toBe("original");
});

test("editing a note performs one Markdown parse while unchanged note analysis is reused", () => {
  const initial = createLinkIndex([
    note(
      "edited",
      "Edited.md",
      "---\naliases: [Alias]\n---\n# Heading\n[[Target]]\nText ^block",
    ),
    note("target", "Target.md", "# Target"),
  ]);
  const parse = spyOn(markdownParser, "parse");
  try {
    const changed = initial.notes.map((item) =>
      item.id === "edited"
        ? { ...item, source: item.source + "\n[also](Target.md)" }
        : { ...item },
    );
    const next = createLinkIndex(changed, initial);
    expect(parse).toHaveBeenCalledTimes(1);
    expect(next.byId.get("target")).toBe(initial.byId.get("target"));
    expect(next.byId.get("edited")?.aliases).toEqual(["Alias"]);
    expect(next.byId.get("edited")?.links.map((link) => link.target)).toEqual([
      "Target",
      "Target.md",
    ]);
    expect(resolveNoteLink(next, "Alias#Heading", "target")?.line).toBe(4);
    parse.mockClear();
    createLinkIndex(changed, next);
    expect(parse).not.toHaveBeenCalled();
  } finally {
    parse.mockRestore();
  }
});

test("resolution follows renames and alias edits when an index inherits its lookup", () => {
  const first = createLinkIndex([
    note("from", "From.md", "[[Target]] [[Nickname]]"),
    note("target", "Target.md", "---\naliases: [Nickname]\n---\n# Target"),
  ]);
  expect(resolveNoteLink(first, "Target", "from")?.id).toBe("target");
  expect(resolveNoteLink(first, "Nickname", "from")?.id).toBe("target");
  const renamed = createLinkIndex(
    [
      note("from", "From.md", "[[Target]] [[Nickname]]"),
      note("target", "Moved.md", "---\naliases: [Other]\n---\n# Target"),
    ],
    first,
  );
  expect(resolveNoteLink(renamed, "Target", "from")).toBeNull();
  expect(resolveNoteLink(renamed, "Moved", "from")?.id).toBe("target");
  expect(resolveNoteLink(renamed, "Nickname", "from")).toBeNull();
  expect(resolveNoteLink(renamed, "Other", "from")?.id).toBe("target");
  expect(
    noteReferences(renamed, "target").backlinks.map((item) => item.target),
  ).toEqual([]);
  expect(
    noteReferences(first, "target").backlinks.map((item) => item.target),
  ).toEqual(["Target", "Nickname"]);
});

test("alias-only edits revalidate fallback misses, additions and collisions across snapshots", () => {
  const first = createLinkIndex([
    note("from", "From.md", "[[Later]] [plain](Later) [[Café]]"),
    note("target", "Target.md"),
    note("other", "Other.md", "---\naliases: [Unrelated]\n---"),
  ]);
  const origin = first.byId.get("from");
  if (!origin) throw new Error("Missing origin");
  const before = resolvedLinks(first, origin);
  expect(before.map((item) => item.id)).toEqual([
    undefined,
    undefined,
    undefined,
  ]);
  const unrelated = createLinkIndex(
    first.notes.map((item) =>
      item.id === "other"
        ? { ...item, source: "---\naliases: [Different]\n---" }
        : item,
    ),
    first,
  );
  expect(resolvedLinks(unrelated, origin)).toBe(before);
  const added = createLinkIndex(
    unrelated.notes.map((item) =>
      item.id === "target"
        ? { ...item, source: "---\naliases: [Later, Cafe\u0301]\n---" }
        : item,
    ),
    unrelated,
  );
  expect(resolvedLinks(added, origin).map((item) => item.id)).toEqual([
    "target",
    undefined,
    "target",
  ]);
  const collision = createLinkIndex(
    added.notes.map((item) =>
      item.id === "other"
        ? { ...item, source: "---\naliases: [Later]\n---" }
        : item,
    ),
    added,
  );
  expect(resolvedLinks(collision, origin).map((item) => item.id)).toEqual([
    undefined,
    undefined,
    "target",
  ]);
  const removed = createLinkIndex(
    collision.notes.map((item) =>
      item.id === "target" ? { ...item, source: "" } : item,
    ),
    collision,
  );
  expect(resolvedLinks(removed, origin).map((item) => item.id)).toEqual([
    "other",
    undefined,
    undefined,
  ]);
  expect(resolvedLinks(first, origin).map((item) => item.id)).toEqual([
    undefined,
    undefined,
    undefined,
  ]);
  expect(resolvedLinks(added, origin).map((item) => item.id)).toEqual([
    "target",
    undefined,
    "target",
  ]);
});

test("bare wiki misses across folders follow alias additions, collisions and removals", () => {
  const origins = [
    note("first", "first/From.md", "[[Later]] [[LATER]] [plain](Later)"),
    note("second", "second/From.md", "[[Later]] [[LATER]] [plain](Later)"),
  ];
  const initial = createLinkIndex([
    ...origins,
    note("target", "Target.md"),
    note("other", "Other.md"),
  ]);
  let index = initial;
  for (const [targetAlias, otherAlias, expected] of [
    ["", "", undefined],
    ["Later", "", "target"],
    ["Later", "LATER", undefined],
    ["", "LATER", "other"],
    ["", "", undefined],
  ] as const) {
    index = createLinkIndex(
      [
        ...origins,
        note("target", "Target.md", `---\naliases: [${targetAlias}]\n---`),
        note("other", "Other.md", `---\naliases: [${otherAlias}]\n---`),
      ],
      index,
    );
    for (const origin of origins) {
      const indexed = index.byId.get(origin.id);
      if (!indexed) throw new Error("Missing origin");
      expect(initial.byId.get(origin.id)).toBe(indexed);
      expect(resolvedLinks(index, indexed).map(({ id }) => id)).toEqual([
        expected,
        expected,
        undefined,
      ]);
    }
  }
});

test("cached references preserve path precedence, fragment fallback, ordering and fresh public rows", () => {
  const first = createLinkIndex([
    note("from", "folder/From.md", "[[Twin#Heading]] [plain](Twin.md)"),
    note("second", "folder/Second.md", "[[Twin]]"),
    note("near", "folder/Twin.md", "# Heading"),
    note("far", "elsewhere/Twin.md"),
    note("alias", "Alias.md", "---\naliases: [Twin]\n---"),
  ]);
  const origin = first.byId.get("from");
  if (!origin) throw new Error("Missing origin");
  const before = resolvedLinks(first, origin);
  expect(before.map((item) => item.id)).toEqual(["near", "near"]);
  const edited = createLinkIndex(
    first.notes.map((item) =>
      item.id === "near" ? { ...item, source: "Body" } : item,
    ),
    first,
  );
  expect(resolvedLinks(edited, origin)).toBe(before);
  expect(resolveNoteLink(edited, "Twin#Heading", "from")).toBeNull();
  const publicRows = noteReferences(edited, "near");
  expect(publicRows.backlinks.map((row) => row.noteId)).toEqual([
    "from",
    "from",
    "second",
  ]);
  const firstRow = publicRows.backlinks[0];
  if (!firstRow) throw new Error("Missing backlink");
  firstRow.text = "mutated caller result";
  expect(noteReferences(edited, "near").backlinks[0]?.text).toBe(
    "[[Twin#Heading]] [plain](Twin.md)",
  );
  const reordered = createLinkIndex([...edited.notes].reverse(), edited);
  expect(
    noteReferences(reordered, "near").backlinks.map((row) => row.noteId),
  ).toEqual(["second", "from", "from"]);
  const moved = createLinkIndex(
    reordered.notes.map((item) =>
      item.id === "near" ? { ...item, path: "folder/Moved.md" } : item,
    ),
    reordered,
  );
  expect(resolvedLinks(moved, origin).map((item) => item.id)).toEqual([
    "far",
    undefined,
  ]);
  const ambiguous = createLinkIndex(
    [...moved.notes, note("another", "another/Twin.md")],
    moved,
  );
  expect(resolvedLinks(ambiguous, origin).map((item) => item.id)).toEqual([
    undefined,
    undefined,
  ]);
  expect(resolvedLinks(first, origin).map((item) => item.id)).toEqual([
    "near",
    "near",
  ]);
});
