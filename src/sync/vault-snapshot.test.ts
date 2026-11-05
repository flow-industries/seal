import { expect, test } from "bun:test";
import {
  applyJournal,
  decodeJournal,
  encodeJournal,
  encodeSnapshot,
  entryStamps,
  journalFootprint,
  journalSince,
  type SnapshotEntry,
} from "./vault-snapshot.ts";

interface EncodedJournal {
  version: number;
  entries: SnapshotEntry[];
  removed?: string[];
  extra?: boolean;
}
const bytes = (value: EncodedJournal) =>
  new TextEncoder().encode(JSON.stringify(value));
function entry(
  id: string,
  revision: string,
  nonce = `nonce-${revision}`,
): SnapshotEntry {
  return {
    id,
    revision,
    recordType: "game.flow.note.item",
    envelope: { version: 1, nonce, ciphertext: `ciphertext-${revision}` },
    chunkHashes: [],
    encryptedBlobs: [],
  };
}

test("a journal holds exactly the upserts and removals since its base", () => {
  const base = [entry("a", "1"), entry("b", "1"), entry("c", "1")];
  const next = [entry("a", "1"), entry("b", "2"), entry("d", "1")];
  const journal = journalSince(entryStamps(base), next);
  expect(journal).toEqual({
    entries: [entry("b", "2"), entry("d", "1")],
    removed: ["c"],
  });
  expect(applyJournal(base, decodeJournal(encodeJournal(journal)))).toEqual(
    next,
  );
  expect(journalSince(entryStamps(next), next)).toEqual({
    entries: [],
    removed: [],
  });
});

test("ciphertext replaced under the same revision is still journaled", () => {
  const base = [entry("a", "1")];
  const reencrypted = entry("a", "1", "another-nonce");
  expect(journalSince(entryStamps(base), [reencrypted]).entries).toEqual([
    reencrypted,
  ]);
});

test("a journal without removals encodes exactly as the snapshot of its entries", () => {
  const entries = [entry("a", "1")];
  expect(encodeJournal({ entries, removed: [] })).toEqual(
    encodeSnapshot(entries),
  );
  expect(decodeJournal(encodeSnapshot(entries))).toEqual({
    entries,
    removed: [],
  });
});

test("malformed or inconsistent journals are rejected", () => {
  for (const journal of [
    { version: 2, entries: [entry("a", "1")], removed: ["a"] },
    { version: 2, entries: [entry("a", "1"), entry("a", "2")] },
    { version: 2, entries: [], removed: [] },
    { version: 2, entries: [], removed: ["a", "a"] },
    { version: 2, entries: [], extra: true },
    { version: 3, entries: [] },
  ])
    expect(() => decodeJournal(bytes(journal))).toThrow();
  expect(() =>
    applyJournal([entry("a", "1")], { entries: [], removed: ["missing"] }),
  ).toThrow("Journal removes a missing entry");
  expect(() =>
    applyJournal(
      Array.from({ length: 10_000 }, (_, index) => entry(`${index}`, "1")),
      { entries: [entry("extra", "1")], removed: [] },
    ),
  ).toThrow("Snapshot exceeds item bounds");
});

test("journal footprints match the encoded result over random histories", () => {
  const ids = Array.from({ length: 12 }, (_, index) => `id-${index}`);
  const random = (values: string[]) => values.filter(() => Math.random() < 0.6);
  for (let round = 0; round < 2_000; round++) {
    const base = random(ids).map((id) =>
      entry(id, `r${Math.floor(Math.random() * 3)}`),
    );
    const previous = new Map(base.map((value) => [value.id, value]));
    const next = random(ids).map((id) => {
      const kept = previous.get(id);
      return kept && Math.random() < 0.5
        ? structuredClone(kept)
        : entry(id, `s${Math.floor(Math.random() * 3)}é`);
    });
    const stamps = entryStamps(base);
    const journal = journalSince(stamps, next);
    expect(
      new Map(
        applyJournal(base, decodeJournal(encodeJournal(journal))).map(
          (value) => [value.id, value],
        ),
      ),
    ).toEqual(new Map(next.map((value) => [value.id, value])));
    const { superseded, snapshotBytes } = journalFootprint(stamps, journal);
    expect(snapshotBytes).toBe(
      encodeSnapshot(applyJournal(base, journal)).length,
    );
    const encoded = (value: SnapshotEntry) =>
      encodeSnapshot([value]).length - 26;
    const replacements = new Map(
      journal.entries.map((value) => [value.id, encoded(value)]),
    );
    const removed = new Set(journal.removed);
    expect(superseded).toBe(
      base.reduce((sum, value) => {
        const replacement = replacements.get(value.id);
        if (removed.has(value.id)) return sum + encoded(value);
        return replacement === undefined
          ? sum
          : sum + Math.max(encoded(value) - replacement, 0);
      }, 0),
    );
  }
});

test("a journal counts only what it shrank or removed, and flags a deleted entry with blobs", () => {
  const held = (id: string, revision: string, blob = "b".repeat(1_000)) => ({
    ...entry(id, revision),
    chunkHashes: ["a".repeat(64)],
    encryptedBlobs: [blob],
  });
  const tombstone = (value: SnapshotEntry): SnapshotEntry => ({
    ...value,
    revision: `${value.revision}-gone`,
    recordType: "game.flow.note.tombstone",
  });
  const stamps = entryStamps([held("blobs", "1"), entry("text", "1")]);
  const footprint = (entries: SnapshotEntry[], removed: string[] = []) =>
    journalFootprint(stamps, { entries, removed });
  expect(footprint([held("blobs", "2")])).toMatchObject({
    superseded: 0,
    erasesBlobs: false,
  });
  expect(footprint([held("blobs", "2", "b")]).superseded).toBe(999);
  expect(footprint([entry("text", "2")])).toMatchObject({
    superseded: 0,
    erasesBlobs: false,
  });
  expect(footprint([tombstone(entry("text", "2"))]).erasesBlobs).toBe(false);
  expect(footprint([], ["text"]).erasesBlobs).toBe(false);
  expect(footprint([tombstone(held("blobs", "2", ""))]).erasesBlobs).toBe(true);
  expect(footprint([], ["blobs"])).toMatchObject({
    erasesBlobs: true,
    superseded: stamps.get("blobs")?.bytes,
  });
  expect(footprint([tombstone(held("new", "1"))]).erasesBlobs).toBe(false);
  const buried = entryStamps([tombstone(held("gone", "1"))]);
  expect(
    journalFootprint(buried, {
      entries: [tombstone(held("gone", "2"))],
      removed: [],
    }).erasesBlobs,
  ).toBe(false);
  expect(
    journalFootprint(buried, { entries: [], removed: ["gone"] }),
  ).toMatchObject({ erasesBlobs: false });
});
