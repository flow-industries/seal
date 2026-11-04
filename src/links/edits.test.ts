import { expect, test } from "bun:test";
import {
  applyGuardedEdit,
  mentionLinkEdit,
  mentionLinkText,
  planNoteEdit,
  wikiLink,
  wikiLinkPath,
} from "./edits.ts";
import {
  createLinkIndex,
  type LinkNote,
  noteReferences,
  resolveNoteLink,
} from "./index.ts";

const note = (id: string, path: string, source = ""): LinkNote => ({
  id,
  path,
  source,
  kind: "md",
});

test("copied links use the shortest path that resolves from every note", () => {
  const index = createLinkIndex([
    note("plan", "Projects/Plan.md"),
    note("same-a", "a/Same.md"),
    note("same-b", "b/Same.md"),
    note("root", "Same.md"),
    note("twin-md", "x/Twin.md"),
    note("twin-mdx", "x/Twin.mdx"),
    note("odd", "Odd #1 | [draft] 100%.md"),
    note("from", "deep/folder/From.md"),
  ]);
  const path = (id: string) =>
    wikiLinkPath(index, index.byId.get(id) ?? { id, path: "" });
  expect(path("plan")).toBe("Plan");
  expect(path("same-a")).toBe("a/Same");
  expect(path("root")).toBe("/Same");
  expect(path("twin-md")).toBe("x/Twin.md");
  expect(path("odd")).toBe("Odd %231 %7C %5Bdraft%5D 100%25");
  for (const id of ["plan", "same-a", "root", "twin-md", "twin-mdx", "odd"])
    for (const from of ["from", "same-b", "root"])
      expect(resolveNoteLink(index, path(id), from)?.id).toBe(id);
  expect(wikiLink("Plan", "Next steps")).toBe("[[Plan#Next steps]]");
  expect(wikiLink("Plan", "C# | tips")).toBe("[[Plan#C%23 %7C tips]]");
  expect(wikiLink("Plan", "^abc123")).toBe("[[Plan#^abc123]]");
});

test("mention links keep the visible text: exact, alias and case differences", () => {
  expect(mentionLinkText("Plan", "Plan")).toBe("[[Plan]]");
  expect(mentionLinkText("Plan", "Launch plan")).toBe("[[Plan|Launch plan]]");
  expect(mentionLinkText("Plan", "plan")).toBe("[[Plan|plan]]");
  expect(mentionLinkText("a/Plan", "Plan")).toBe("[[a/Plan|Plan]]");
  expect(mentionLinkText("Plan", "Plan]")).toBeNull();
});

test("linking an unlinked mention edits only the matched text and refuses stale offsets", () => {
  const plan = note(
    "plan",
    "Projects/Plan.md",
    "---\naliases: [Launch plan]\n---\n",
  );
  const index = createLinkIndex([
    plan,
    note("journal", "Journal.md", "Today: the launch plan.\n\nAlso Plan."),
  ]);
  const [alias, exact] = noteReferences(index, "plan").unlinked;
  if (!alias || !exact) throw new Error("Missing mentions");
  const aliasEdit = mentionLinkEdit(index, "plan", alias);
  expect(aliasEdit).toEqual({
    from: 11,
    to: 22,
    insert: "[[Plan|launch plan]]",
    guard: { from: 11, to: 22, text: "launch plan" },
  });
  const exactEdit = mentionLinkEdit(index, "plan", exact);
  if (!aliasEdit || !exactEdit) throw new Error("Missing edits");
  const source = index.byId.get("journal")?.source ?? "";
  const linked = applyGuardedEdit(source, exactEdit);
  expect(linked).toBe("Today: the launch plan.\n\nAlso [[Plan]].");
  expect(applyGuardedEdit(`Edited. ${source}`, aliasEdit)).toBeNull();
  const after = createLinkIndex([
    plan,
    note("journal", "Journal.md", linked ?? ""),
  ]);
  const refs = noteReferences(after, "plan");
  expect(refs.backlinks.map((row) => row.line)).toEqual([3]);
  expect(refs.unlinked.map((row) => row.line)).toEqual([1]);
  const both = applyGuardedEdit(linked ?? "", aliasEdit);
  expect(both).toBe("Today: the [[Plan|launch plan]].\n\nAlso [[Plan]].");
  const done = noteReferences(
    createLinkIndex([plan, note("journal", "Journal.md", both ?? "")]),
    "plan",
  );
  expect(done.backlinks.map((row) => row.line)).toEqual([1, 3]);
  expect(done.unlinked).toEqual([]);
  const labelled = createLinkIndex([
    plan,
    note(
      "md",
      "Md.md",
      "[the launch plan](Projects/Plan.md) ![Plan](Plan.png)",
    ),
  ]);
  expect(noteReferences(labelled, "plan").unlinked).toEqual([]);
});

function mentionsOf(source: string) {
  const index = createLinkIndex([
    note("plan", "Plan.md", "---\naliases: [Launch plan]\n---\n"),
    note("other", "Other.md", source),
  ]);
  return {
    index,
    mentions: noteReferences(index, "plan").unlinked,
  };
}

test("only plain prose counts as a mention: URLs, tags, IDs, definitions, emails and math don't", () => {
  for (const source of [
    "See https://example.com/plan",
    "See <https://example.com/plan>",
    "Tagged #plan",
    "Tagged #project/plan",
    "Block ^plan",
    "Note[^plan] here\n\n[^plan]: the note",
    "[plan]: https://example.com",
    "Mail plan@example.com or @plan",
    "Inline $plan$ math",
    "$$\nplan\n$$",
    "Code `plan` and\n\n```\nplan\n```",
    "Linked [[Plan|launch plan]] and [the plan](Plan.md) and ![plan](plan.png)",
    "%% plan %% <!-- plan -->",
    "Tagged #launch-plan here",
    "#launch-plan at the start",
    "Block text ^launch-plan",
    "Handle @launch-plan",
    "Path notes/launch-plan.md and docs/launch-plan",
    "File plan.md",
  ]) {
    const { mentions } = mentionsOf(source);
    expect({ source, mentions }).toEqual({ source, mentions: [] });
  }
  const bracketed = mentionsOf("[about the plan] and ==the plan==\n\nA plan.");
  expect(bracketed.mentions.map((row) => [row.line, row.start])).toEqual([
    [1, 11],
    [3, 37],
  ]);
});

test("mentions in headings are listed but never rewritten, so links to the heading keep resolving", () => {
  const { index, mentions } = mentionsOf("# Launch plan\n\nBody");
  expect(mentions).toHaveLength(1);
  expect(mentions[0]?.start).toBeUndefined();
  const [heading] = mentions;
  if (!heading) throw new Error("Missing mention");
  expect(
    mentionLinkEdit(index, "plan", { ...heading, start: 2, end: 13 }),
  ).toBeNull();
  const setext = mentionsOf("Launch plan\n===").mentions;
  expect(setext[0]?.start).toBeUndefined();
});

test("a table cell takes an exact link, or a labelled one with its pipe escaped", () => {
  const linked = (source: string) => {
    const { index, mentions } = mentionsOf(source);
    const [cell] = mentions;
    if (cell?.start === undefined) throw new Error("Missing linkable mention");
    const edit = mentionLinkEdit(index, "plan", cell);
    if (!edit) throw new Error("Missing edit");
    return applyGuardedEdit(index.byId.get("other")?.source ?? "", edit);
  };
  expect(linked("| a | b |\n| - | - |\n| x | the Plan |")).toBe(
    "| a | b |\n| - | - |\n| x | the [[Plan]] |",
  );
  expect(linked("| a | b |\n| - | - |\n| x | the plan |")).toBe(
    "| a | b |\n| - | - |\n| x | the [[Plan\\|plan]] |",
  );
  expect(linked("| a | b |\r\n| - | - |\r\n| x | the plan |\r\n")).toBe(
    "| a | b |\r\n| - | - |\r\n| x | the [[Plan\\|plan]] |\r\n",
  );
  expect(mentionLinkText("Plan", "plan", true)).toBe("[[Plan\\|plan]]");
  expect(mentionLinkText("Plan", "Plan", true)).toBe("[[Plan]]");
  expect(mentionLinkText("Plan", "pl|an", true)).toBeNull();
});

test("a cross-note write is refused while blocked or when the note moved, and names the note", () => {
  const target = { path: "Journal/Day.md", source: "Before plan after" };
  const edit = {
    from: 7,
    to: 11,
    insert: "[[Plan]]",
    guard: { from: 7, to: 11, text: "plan" },
  };
  expect(planNoteEdit(target, edit, false)).toEqual({
    source: "Before [[Plan]] after",
  });
  expect(planNoteEdit(target, edit, true)).toEqual({
    error:
      "Save your pending edits before changing Journal/Day.md. Nothing was changed.",
  });
  expect(
    planNoteEdit({ ...target, source: "Before the plan after" }, edit, false),
  ).toEqual({
    error: "Journal/Day.md changed, so nothing was changed there. Try again.",
  });
});

test("hyphenated words and sentence ends still count as mentions", () => {
  const { mentions } = mentionsOf("A pre-plan.\n\nC#-plan rocks.\n\nThe plan.");
  expect(mentions.map((row) => row.line)).toEqual([1, 3, 5]);
});

test("Link on a labelled cell mention moves the row from unlinked mentions to backlinks", () => {
  const notes = [
    note("a", "a/Plan.md"),
    note("b", "b/Plan.md"),
    note("other", "Other.md", "| a | b |\n| - | - |\n| x | the Plan |"),
  ];
  const index = createLinkIndex(notes);
  expect(wikiLinkPath(index, { id: "a", path: "a/Plan.md" })).toBe("a/Plan");
  const [cell] = noteReferences(index, "a").unlinked;
  if (cell?.start === undefined) throw new Error("Missing linkable mention");
  const edit = mentionLinkEdit(index, "a", cell);
  if (!edit) throw new Error("Missing edit");
  const source = applyGuardedEdit(notes[2]?.source ?? "", edit);
  expect(source).toBe("| a | b |\n| - | - |\n| x | the [[a/Plan\\|Plan]] |");
  const linked = createLinkIndex([
    ...notes.slice(0, 2),
    note("other", "Other.md", source ?? ""),
  ]);
  const references = noteReferences(linked, "a");
  expect(references.unlinked).toEqual([]);
  expect(references.backlinks.map((row) => row.noteId)).toEqual(["other"]);
});

test("mention classification is cached per indexed note and refreshed when its source changes", () => {
  const plan = note("plan", "Plan.md");
  const coded = note("other", "Other.md", "`the plan` here");
  const first = createLinkIndex([plan, coded]);
  expect(noteReferences(first, "plan").unlinked).toEqual([]);
  const same = createLinkIndex([plan, { ...coded }], first);
  expect(same.byId.get("other")).toBe(first.byId.get("other"));
  expect(noteReferences(same, "plan").unlinked).toEqual([]);
  const edited = createLinkIndex(
    [plan, { ...coded, source: "*the plan* here" }],
    same,
  );
  expect(
    noteReferences(edited, "plan").unlinked.map((row) => row.start),
  ).toEqual([5]);
});
