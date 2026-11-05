import { expect, spyOn, test } from "bun:test";
import { createPathLookup, type PathLookup } from "../vault/links.ts";
import { createLinkIndex, type LinkNote, noteReferences } from "./index.ts";

/** Each note links to 8 notes that exist and 8 that don't, as real vaults do. */
function vault(count: number, alias = (index: number) => `Alias ${index}`) {
  return Array.from(
    { length: count },
    (_, index): LinkNote => ({
      id: `id-${index}`,
      path: `area-${index % 12}/Note ${index}.md`,
      kind: "md",
      source: `---\naliases: [${alias(index)}]\n---\n# Note ${index}\n\n${Array.from(
        { length: 8 },
        (_, link) =>
          `[[Note ${(index * 7 + link * 13) % count}]] [[Missing ${index}-${link}]]`,
      ).join(" ")}\n`,
    }),
  );
}
/** Every link a pass resolves goes through `pathResolution`, so its calls measure the work without a wall clock. */
function resolutions(run: () => void): number {
  const lookup: PathLookup = Object.getPrototypeOf(createPathLookup([]));
  const resolve = spyOn(lookup, "pathResolution");
  try {
    run();
    return resolve.mock.calls.length;
  } finally {
    resolve.mockRestore();
  }
}

test("a keystroke over 10,000 notes with resolved and unresolved links re-resolves only the edited note", () => {
  const notes = vault(10_000);
  let index = createLinkIndex(notes);
  const cold = noteReferences(index, "id-7");
  expect(cold.backlinks.length).toBeGreaterThan(0);
  const keystrokes = [1, 2, 3].map((length) => {
    const edited = notes.map((note, position) =>
      position === 3
        ? { ...note, source: note.source + "x".repeat(length) }
        : note,
    );
    index = createLinkIndex(edited, index);
    return resolutions(() => noteReferences(index, "id-7"));
  });
  // Only the edited note's 16 links; before the per-note cache, every pass cleared the memo and resolved all 160,000 again.
  expect(keystrokes).toEqual([16, 16, 16]);
  expect(noteReferences(index, "id-7")).toEqual(cold);
});

test("an alias edit keeps the path maps, so it costs a fraction of a cold pass", () => {
  const notes = vault(5_000);
  let index = createLinkIndex(notes);
  const cold = resolutions(() => noteReferences(index, "id-7"));
  const aliasEdits = ["N", "Ni", "Nic"].map((nickname) => {
    const edited = notes.map((note, position) =>
      position === 7
        ? { ...note, source: note.source.replace("Alias 7", nickname) }
        : note,
    );
    index = createLinkIndex(edited, index);
    return resolutions(() => noteReferences(index, "id-7"));
  });
  expect(cold).toBe(notes.length * 16);
  expect(aliasEdits).toEqual([16, 16, 16]);
  expect(noteReferences(index, "id-7").backlinks.length).toBeGreaterThan(0);
});
