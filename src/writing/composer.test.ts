import { expect, test } from "bun:test";
import {
  createLinkIndex,
  type LinkNote,
  resolveNoteLink,
} from "../links/index.ts";
import { linkRanges } from "../vault/links.ts";
import { extractNote, mergeNotes } from "./composer.ts";

function note(id: string, path: string, source: string): LinkNote {
  return { id, path, source, kind: "md" };
}

test("extract preserves untouched BOM, frontmatter, CRLF and unknown syntax while rebasing assets", () => {
  const selected =
    "# Move\r\n[local](#Move) ![pic](../pic.png) [other](Other.md) <Widget />";
  const source =
    "\uFEFF---\r\ncustom: [a, b]\r\n---\r\n# Keep\r\n" + selected + "\r\nTail";
  const from = source.indexOf(selected);
  const result = extractNote(
    {
      kind: "extract",
      originId: "origin",
      expectedSource: source,
      from,
      to: from + selected.length,
      path: "deep/new/Extract.md",
    },
    [
      note("origin", "folder/Origin.md", source),
      note("other", "folder/Other.md", ""),
    ],
    [{ id: "pic", path: "pic.png" }],
  );
  expect(result.origin).toBe(
    source.slice(0, from) + "[Extract](../deep/new/Extract.md)" + "\r\nTail",
  );
  expect(result.extracted).toBe(
    "# Move\r\n[local](/deep/new/Extract.md#Move) ![pic](../../pic.png) [other](../../folder/Other.md) <Widget />",
  );
});

test("extract leaves references to anchors remaining in the origin pointing to the origin", () => {
  const source = "# Keep\n\nSelected [keep](#Keep)";
  const result = extractNote(
    {
      kind: "extract",
      originId: "o",
      expectedSource: source,
      from: source.indexOf("Selected"),
      to: source.length,
      path: "New.md",
    },
    [note("o", "Old.md", source)],
    [],
  );
  expect(result.extracted).toBe("Selected [keep](Old.md#Keep)");
});

test("extract repairs the remaining origin's references to moved headings", () => {
  const source = "[moved](#Moved)\n\n# Moved\nBody";
  const result = extractNote(
    {
      kind: "extract",
      originId: "o",
      expectedSource: source,
      from: source.indexOf("# Moved"),
      to: source.length,
      path: "New.md",
    },
    [note("o", "Old.md", source)],
    [],
  );
  expect(result.origin).toBe("[moved](/New.md#Moved)\n\n[New](New.md)");
});

test("extraction rejects stale text, frontmatter selection, split Unicode and unsafe paths", () => {
  const source = "---\ncustom: true\n---\nA🙂B";
  const notes = [note("o", "Old.md", source)];
  const request = {
    kind: "extract" as const,
    originId: "o",
    expectedSource: source,
    from: source.indexOf("A"),
    to: source.length,
    path: "New.md",
  };
  for (const change of [
    { expectedSource: "stale" },
    { from: 0 },
    { from: source.indexOf("🙂") + 1 },
    { path: "../bad.md" },
    { path: "bad\uD800.md" },
  ])
    expect(() => extractNote({ ...request, ...change }, notes, [])).toThrow();
});

test("merge repairs aliases, embeds, fragments and self links, retaining destination frontmatter and unknown source", () => {
  const source =
    "---\naliases: [Nickname]\ncustom: keep\n---\n# Part\n[[#Part|self]] [block](#^id) ![pic](pic.png)\nText ^id\n<Component />";
  const destination =
    "---\ncustom: target\n---\n# Part\n[[folder/Origin#Part]]";
  const reference =
    '[[Nickname#Part|alias]] ![[folder/Origin#^id]] [jump](folder/Origin.md#Part "title") `[[Nickname]]` <!-- [[Nickname]] -->';
  const notes = [
    note("o", "folder/Origin.md", source),
    note("t", "Target.md", destination),
    note("r", "Ref.md", reference),
  ];
  const result = mergeNotes(
    { kind: "merge", originId: "o", targetId: "t", expectedSource: source },
    notes,
    [{ id: "pic", path: "folder/pic.png" }],
  );
  expect(result.get("t")).toBe(
    "---\ncustom: target\n---\n# Part\n[[/Target.md#part-1]]\n\n# Part\n[[/Target.md#part-1|self]] [block](/Target.md#^id) ![pic](folder/pic.png)\nText ^id\n<Component />",
  );
  expect(result.get("r")).toBe(
    '[[/Target.md#part-1|alias]] ![[/Target.md#^id]] [jump](/Target.md#part-1 "title") `[[Nickname]]` <!-- [[Nickname]] -->',
  );
  expect(result.has("o")).toBe(false);
});

test("merge keeps unresolved fragments and rejects stale targets or duplicate block identities", () => {
  const source = "Body ^same";
  const notes = [
    note("o", "Old.md", source),
    note("t", "New.md", "Target"),
    note("r", "Ref.md", "[[Old#Missing|label]]"),
  ];
  const request = {
    kind: "merge" as const,
    originId: "o",
    targetId: "t",
    expectedSource: source,
  };
  expect(mergeNotes(request, notes, []).get("r")).toBe(
    "[[/New.md#Missing|label]]",
  );
  expect(() =>
    mergeNotes({ ...request, expectedTargetSource: "stale" }, notes, []),
  ).toThrow("changed");
  expect(() =>
    mergeNotes(request, [notes[0]!, note("t", "New.md", "Other ^same")], []),
  ).toThrow("duplicate block");
});

test("merge preserves heading link identity when literal suffixes collide with generated IDs", () => {
  const notes = [
    note("t", "T.md", "# foo\n# foo"),
    note("o", "O.md", "# foo-1\nBody"),
    note("r", "R.md", "[[O#foo-1]]"),
  ];
  const updates = mergeNotes(
    {
      kind: "merge",
      originId: "o",
      targetId: "t",
      expectedSource: "# foo-1\nBody",
    },
    notes,
    [],
  );
  const after = createLinkIndex(
    notes
      .filter((item) => item.id !== "o")
      .map((item) => ({
        ...item,
        source: updates.get(item.id) ?? item.source,
      })),
  );
  expect(after.byId.get("t")?.headings.map((heading) => heading.id)).toEqual([
    "foo",
    "foo-1",
    "foo-1-1",
  ]);
  const repaired = linkRanges(updates.get("r") ?? "")[0];
  expect(repaired?.target).toBe("/T.md#foo-1-1");
  expect(resolveNoteLink(after, repaired?.target ?? "", "r")).toEqual({
    id: "t",
    path: "T.md",
    fragment: "foo-1-1",
    line: 4,
  });
  expect(resolveNoteLink(after, "/T.md#foo-1", "r")?.line).toBe(2);
});
