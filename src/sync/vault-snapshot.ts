import { z } from "zod";
import type { RootMetadata } from "../crypto/access-v3.ts";
import { entryAuthorSchema } from "../crypto/authorship.ts";
import type { VaultDatabase } from "../vault/storage.ts";
import type { RemoteRecord } from "./records.ts";

const opaque = z.string().min(1).max(512);
const MAX_ENTRIES = 10_000;
/** The largest snapshot any reader decodes; writers refuse anything larger before uploading. */
export const MAX_SNAPSHOT_BYTES = 512_000_000;
const entrySchema = z
  .object({
    id: opaque,
    revision: opaque,
    recordType: z.enum(["game.flow.note.item", "game.flow.note.tombstone"]),
    envelope: z
      .object({
        version: z.literal(1),
        nonce: z.string().max(128),
        ciphertext: z.string().max(900_000),
      })
      .strict(),
    chunkHashes: z.array(z.string().regex(/^[a-f0-9]{64}$/u)).max(128),
    encryptedBlobs: z.array(z.string().max(540_000)).max(128),
    author: entryAuthorSchema.optional(),
  })
  .strict();
const snapshotSchema = z
  .object({
    version: z.literal(2),
    entries: z.array(entrySchema).max(MAX_ENTRIES),
  })
  .strict();
const journalSchema = snapshotSchema.extend({
  removed: z.array(opaque).min(1).max(MAX_ENTRIES).optional(),
});
export type SnapshotEntry = z.infer<typeof entrySchema>;
/** Entries upserted over a base snapshot and ids the base no longer holds. */
export interface SnapshotJournal {
  entries: SnapshotEntry[];
  removed: string[];
}
export class VaultAccessError extends Error {}

export interface VaultSnapshot {
  cid: string;
  entries: SnapshotEntry[];
  /** The verified access the entries' signatures are checked against. */
  access?: RootMetadata;
}
export interface VaultSnapshotTransport {
  readonly version: 2;
  stop?(): void;
  readSnapshot(): Promise<VaultSnapshot | null>;
  writeSnapshot(
    entries: SnapshotEntry[],
    expectedCid: string | null,
  ): Promise<{ cid: string }>;
}
export function encodeBlob(bytes: Uint8Array): string {
  let binary = "";
  for (let start = 0; start < bytes.length; start += 8192)
    binary += String.fromCharCode(...bytes.subarray(start, start + 8192));
  return btoa(binary);
}
export function decodeBlob(value: string): Uint8Array {
  const binary = atob(value);
  if (binary.length > 400_000) throw new Error("Snapshot chunk exceeds bounds");
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}
export function snapshotRemote(entry: SnapshotEntry) {
  const blobs = entry.encryptedBlobs.map(decodeBlob);
  if (blobs.length !== entry.chunkHashes.length)
    throw new Error("Incomplete snapshot item");
  const remote: RemoteRecord = {
    cid: entry.revision,
    record: {
      $type: entry.recordType,
      id: entry.id,
      revision: entry.revision,
      envelope: entry.envelope,
      chunkHashes: entry.chunkHashes,
      blobs: blobs.map((bytes, index) => ({
        $type: "blob",
        ref: { $link: entry.chunkHashes[index] ?? "" },
        mimeType: "application/octet-stream",
        size: bytes.length,
      })),
    },
  };
  if (entry.author) remote.record.author = entry.author;
  return { remote, blobs };
}
export function encodeSnapshot(entries: SnapshotEntry[]): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({ version: 2, entries }));
}
export function decodeSnapshot(bytes: Uint8Array): SnapshotEntry[] {
  if (bytes.length > MAX_SNAPSHOT_BYTES)
    throw new Error("Snapshot exceeds bounds");
  const snapshot = snapshotSchema.parse(
    JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)),
  );
  if (
    new Set(snapshot.entries.map((entry) => entry.id)).size !==
    snapshot.entries.length
  )
    throw new Error("Duplicate snapshot identity");
  return snapshot.entries;
}
/** A journal without removals encodes exactly as the snapshot of its entries, so either fits the other's chunk. */
export function encodeJournal({ entries, removed }: SnapshotJournal) {
  return removed.length
    ? new TextEncoder().encode(JSON.stringify({ version: 2, entries, removed }))
    : encodeSnapshot(entries);
}
export function decodeJournal(bytes: Uint8Array): SnapshotJournal {
  const journal = journalSchema.parse(
    JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)),
  );
  const removed = journal.removed ?? [];
  const ids = [...journal.entries.map((entry) => entry.id), ...removed];
  if (new Set(ids).size !== ids.length)
    throw new Error("Duplicate journal identity");
  return { entries: journal.entries, removed };
}
/** What a journal write needs to know about one base entry without retaining it. */
export interface EntryStamp {
  /** The revision, plus the nonce and chunk hashes that change whenever the ciphertext does, and its signature. */
  version: string;
  /** The entry's encoded length inside a snapshot. */
  bytes: number;
  /** A live entry with blobs: any attachment, or a note too long to inline. */
  holdsBlobs: boolean;
}
function entryVersion(entry: SnapshotEntry): string {
  return JSON.stringify([
    entry.revision,
    entry.recordType,
    entry.envelope.nonce,
    entry.chunkHashes,
    entry.author?.signature ?? null,
  ]);
}
const ITEM = "game.flow.note.item";
const encoder = new TextEncoder();
function entryBytes(entry: SnapshotEntry): number {
  return encoder.encode(JSON.stringify(entry)).length;
}
export function entryStamps(
  entries: SnapshotEntry[],
): ReadonlyMap<string, EntryStamp> {
  return new Map(
    entries.map((entry) => [
      entry.id,
      {
        version: entryVersion(entry),
        bytes: entryBytes(entry),
        holdsBlobs:
          entry.recordType === ITEM && entry.encryptedBlobs.length > 0,
      },
    ]),
  );
}
/** The journal that turns the base stamped as `base` into exactly `entries`. */
export function journalSince(
  base: ReadonlyMap<string, EntryStamp>,
  entries: SnapshotEntry[],
): SnapshotJournal {
  const live = new Set(entries.map((entry) => entry.id));
  return {
    entries: entries.filter(
      (entry) => base.get(entry.id)?.version !== entryVersion(entry),
    ),
    removed: [...base.keys()].filter((id) => !live.has(id)),
  };
}
const SNAPSHOT_FRAME_BYTES = encodeSnapshot([]).length;
export interface JournalFootprint {
  /**
   * Base bytes that stay published until a compaction but no longer count
   * toward the vault: what removed entries held, and what replaced entries
   * shrank by. The rest of a replaced entry is matched by its replacement in
   * the journal, so the base's dead bytes never exceed this plus the journal.
   */
  superseded: number;
  /** Whether the journal deletes a base entry that holds blobs. */
  erasesBlobs: boolean;
  /** The exact length of the snapshot that base plus journal produce. */
  snapshotBytes: number;
}
/** Measures `journal` applied over the base stamped as `base` without encoding the result. */
export function journalFootprint(
  base: ReadonlyMap<string, EntryStamp>,
  journal: SnapshotJournal,
): JournalFootprint {
  let superseded = 0;
  let erasesBlobs = false;
  let replaced = 0;
  let liveBytes = 0;
  for (const stamp of base.values()) liveBytes += stamp.bytes;
  for (const entry of journal.entries) {
    const bytes = entryBytes(entry);
    liveBytes += bytes;
    const stamp = base.get(entry.id);
    if (!stamp) continue;
    liveBytes -= stamp.bytes;
    replaced++;
    superseded += Math.max(stamp.bytes - bytes, 0);
    if (entry.recordType !== ITEM && stamp.holdsBlobs) erasesBlobs = true;
  }
  for (const id of journal.removed) {
    const stamp = base.get(id);
    if (!stamp) continue;
    liveBytes -= stamp.bytes;
    replaced++;
    superseded += stamp.bytes;
    if (stamp.holdsBlobs) erasesBlobs = true;
  }
  const liveCount = base.size - replaced + journal.entries.length;
  return {
    superseded,
    erasesBlobs,
    snapshotBytes:
      SNAPSHOT_FRAME_BYTES + liveBytes + Math.max(liveCount - 1, 0),
  };
}
export function applyJournal(
  base: SnapshotEntry[],
  journal: SnapshotJournal,
): SnapshotEntry[] {
  const merged = new Map(base.map((entry) => [entry.id, entry]));
  for (const id of journal.removed)
    if (!merged.delete(id)) throw new Error("Journal removes a missing entry");
  for (const entry of journal.entries) merged.set(entry.id, entry);
  if (merged.size > MAX_ENTRIES)
    throw new Error("Snapshot exceeds item bounds");
  return [...merged.values()];
}
export async function captureSnapshot(database: VaultDatabase): Promise<{
  entries: SnapshotEntry[];
  pending: { id: string; revision: string }[];
}> {
  return database.transaction(
    "r",
    database.items,
    database.outbox,
    async () => {
      const items = await database.items.toArray();
      if (items.length > MAX_ENTRIES)
        throw new Error("Snapshot exceeds item bounds");
      const entries = items
        .sort((a, b) => a.id.localeCompare(b.id))
        .map((item) => {
          if (
            (item.encryptedBlobs?.length ?? 0) !==
            (item.chunkHashes?.length ?? 0)
          )
            throw new Error("Missing local attachment chunks");
          const entry: SnapshotEntry = {
            id: item.id,
            revision: item.revision,
            recordType: item.recordType ?? "game.flow.note.item",
            envelope: item.envelope,
            chunkHashes: item.chunkHashes ?? [],
            encryptedBlobs: (item.encryptedBlobs ?? []).map(encodeBlob),
          };
          if (item.author) entry.author = item.author;
          return entry;
        });
      return {
        entries,
        pending: (await database.outbox.toArray()).map(({ id, revision }) => ({
          id,
          revision,
        })),
      };
    },
  );
}
