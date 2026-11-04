import { expect, test } from "bun:test";
import Dexie from "dexie";
import { IDBKeyRange, indexedDB } from "fake-indexeddb";
import { createVaultKey, decrypt, encrypt } from "../crypto/index.ts";
import { createSession } from "../vault/session.ts";
import { rekeySnapshot } from "./rekey.ts";
import {
  captureSnapshot,
  decodeBlob,
  encodeBlob,
  type SnapshotEntry,
  snapshotRemote,
} from "./vault-snapshot.ts";

Dexie.dependencies.indexedDB = indexedDB;
Dexie.dependencies.IDBKeyRange = IDBKeyRange;
const did = "did:plc:rekey";

async function populated() {
  const vault = crypto.randomUUID();
  const key = await createVaultKey();
  const session = createSession({ owner: did, vault, key });
  const attachment = crypto.getRandomValues(new Uint8Array(65_536));
  const big = crypto.getRandomValues(new Uint8Array(600_000));
  await session.import([
    { path: "plan.md", bytes: new TextEncoder().encode("# Secret plan") },
    { path: "photo.bin", bytes: attachment },
    { path: "archive.bin", bytes: big },
  ]);
  const plan = (await session.readView()).notes.find(
    (note) => note.path === "plan.md",
  );
  if (!plan) throw new Error("Missing plan");
  await session.permanentRemove(plan.id);
  await session.import([
    { path: "kept.md", bytes: new TextEncoder().encode("# Kept") },
  ]);
  const { entries } = await captureSnapshot(session.database);
  session.lock();
  return { vault, key, entries, attachment, big };
}
const hex = async (bytes: Uint8Array) =>
  Array.from(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new Uint8Array(bytes)),
    ),
    (value) => value.toString(16).padStart(2, "0"),
  ).join("");
/** Rewrites an entry's first chunk as `chunk` and re-seals the item envelope over the new hash, as any key holder can. */
async function withChunk(
  key: Uint8Array,
  vault: string,
  entry: SnapshotEntry,
  chunk: Uint8Array,
): Promise<SnapshotEntry> {
  const chunkHashes = [await hex(chunk), ...entry.chunkHashes.slice(1)];
  const context = {
    did,
    vault,
    item: entry.id,
    revision: entry.revision,
    epoch: 1,
  };
  const item = await decrypt(entry.envelope, key, {
    ...context,
    assets: entry.chunkHashes,
  });
  return {
    ...entry,
    envelope: await encrypt(item, key, { ...context, assets: chunkHashes }),
    chunkHashes,
    encryptedBlobs: [encodeBlob(chunk), ...entry.encryptedBlobs.slice(1)],
  };
}
/** Variants of a chunked entry that a lenient parser would read but the shared strict one refuses. */
async function planted(key: Uint8Array, vault: string, entry: SnapshotEntry) {
  const text = new TextDecoder().decode(
    decodeBlob(entry.encryptedBlobs[0] ?? ""),
  );
  const head = new TextEncoder().encode(`${text.slice(0, -1)},"pad":"`);
  const invalidUtf8 = new Uint8Array(head.length + 3);
  invalidUtf8.set(head);
  invalidUtf8.set([0xff, 0x22, 0x7d], head.length);
  return Promise.all([
    withChunk(key, vault, entry, invalidUtf8),
    withChunk(
      key,
      vault,
      entry,
      new TextEncoder().encode(`${text.slice(0, -1)},"pad":"x"}`),
    ),
  ]);
}

test("re-keyed entries open only under the new key and epoch, with identical plaintext", async () => {
  const { vault, key, entries, attachment, big } = await populated();
  const next = await createVaultKey();
  const { entries: rekeyed, failed } = await rekeySnapshot(
    entries,
    { did, vault },
    { key, epoch: 1 },
    { key: next, epoch: 2 },
  );
  expect(failed).toEqual([]);
  expect(
    rekeyed.map(({ id, revision, recordType }) => [id, revision, recordType]),
  ).toEqual(
    entries.map(({ id, revision, recordType }) => [id, revision, recordType]),
  );
  expect(rekeyed.some((entry) => entry.chunkHashes.length > 1)).toBe(true);
  for (const [index, entry] of rekeyed.entries()) {
    const before = entries[index];
    expect(entry.envelope.ciphertext).not.toBe(before?.envelope.ciphertext);
    if (entry.chunkHashes.length)
      expect(entry.chunkHashes).not.toEqual(before?.chunkHashes);
  }
  const reader = createSession({ owner: did, vault, key: next, epoch: 2 });
  for (const entry of rekeyed) {
    const { remote, blobs } = snapshotRemote(entry);
    await reader.applyRemote(remote, blobs);
  }
  const files = new Map(
    (await reader.export()).map((file) => [file.path, file.bytes]),
  );
  expect(new TextDecoder().decode(files.get("kept.md"))).toBe("# Kept");
  expect(files.get("photo.bin")).toEqual(attachment);
  expect(files.get("archive.bin")).toEqual(big);
  expect(files.has("plan.md")).toBe(false);
  reader.lock();

  const stale = createSession({ owner: did, vault, key, epoch: 2 });
  const [first] = rekeyed;
  if (!first) throw new Error("Missing entry");
  const { remote, blobs } = snapshotRemote(first);
  await expect(stale.validateRemote(remote, blobs)).rejects.toThrow();
  stale.lock();
  const again = await rekeySnapshot(
    rekeyed,
    { did, vault },
    { key, epoch: 1 },
    { key, epoch: 3 },
  );
  expect(again.failed).toHaveLength(rekeyed.length);
});

test("a re-keyed entry carries no old signature; `sign` attaches only a signature", async () => {
  const { vault, key, entries } = await populated();
  const next = await createVaultKey();
  const [first] = entries;
  if (!first) throw new Error("Missing entry");
  const signed: SnapshotEntry = {
    ...first,
    author: { recipientId: "A".repeat(43), signature: "A".repeat(86) },
  };
  const unsigned = await rekeySnapshot(
    [signed],
    { did, vault },
    { key, epoch: 1 },
    { key: next, epoch: 2 },
  );
  expect(Object.keys(unsigned.entries[0] ?? {}).sort()).toEqual(
    [
      "chunkHashes",
      "encryptedBlobs",
      "envelope",
      "id",
      "recordType",
      "revision",
    ].sort(),
  );
  const seen: [string, string][] = [];
  const author = { recipientId: "B".repeat(43), signature: "B".repeat(86) };
  const endorsed = await rekeySnapshot(
    entries,
    { did, vault },
    { key, epoch: 1 },
    { key: next, epoch: 2 },
    async (original, rekeyed) => {
      seen.push([original.envelope.nonce, rekeyed.envelope.nonce]);
      return original.id === first.id ? author : undefined;
    },
  );
  expect(seen).toHaveLength(entries.length);
  expect(seen.every(([before, after]) => before !== after)).toBe(true);
  expect(endorsed.entries[0]).toEqual({
    ...unsigned.entries[0],
    envelope: endorsed.entries[0]?.envelope ?? first.envelope,
    chunkHashes: endorsed.entries[0]?.chunkHashes ?? [],
    encryptedBlobs: endorsed.entries[0]?.encryptedBlobs ?? [],
    author,
  });
  expect(endorsed.entries.slice(1).every((entry) => !entry.author)).toBe(true);
});

test("an entry that won't re-seal is reported by name instead of vetoing the others", async () => {
  const { vault, key, entries } = await populated();
  const chunked = entries.findIndex((entry) => entry.chunkHashes.length > 0);
  const target = entries[chunked];
  if (!target) throw new Error("Missing chunked entry");
  const bytes = decodeBlob(target.encryptedBlobs[0] ?? "");
  bytes[bytes.length - 3] ^= 1;
  const tampered = entries.map((entry, index) =>
    index === chunked
      ? {
          ...entry,
          encryptedBlobs: [encodeBlob(bytes), ...entry.encryptedBlobs.slice(1)],
        }
      : entry,
  );
  const next = await createVaultKey();
  const result = await rekeySnapshot(
    tampered,
    { did, vault },
    { key, epoch: 1 },
    { key: next, epoch: 2 },
  );
  expect(result.failed).toEqual([
    { id: target.id, digest: expect.any(String), name: expect.any(String) },
  ]);
  expect(result.entries.map((entry) => entry.id)).toEqual(
    entries.filter((entry) => entry.id !== target.id).map((entry) => entry.id),
  );
  const [a, b] = entries;
  if (!a || !b) throw new Error("Missing entries");
  const swapped = await rekeySnapshot(
    [{ ...a, envelope: b.envelope }],
    { did, vault },
    { key, epoch: 1 },
    { key: next, epoch: 2 },
  );
  expect(swapped.failed).toEqual([{ id: a.id, digest: expect.any(String) }]);
});

test("every entry a reader accepts re-keys, and a chunk the strict parser refuses is refused by readers too", async () => {
  const { vault, key, entries } = await populated();
  const reader = createSession({ owner: did, vault, key });
  const candidates = [...entries];
  for (const entry of entries)
    if (entry.chunkHashes.length)
      candidates.push(...(await planted(key, vault, entry)));
  let refused = 0;
  for (const entry of candidates) {
    const { remote, blobs } = snapshotRemote(entry);
    const accepted = await reader.validateRemote(remote, blobs).then(
      () => true,
      () => false,
    );
    const { failed } = await rekeySnapshot(
      [entry],
      { did, vault },
      { key, epoch: 1 },
      { key: await createVaultKey(), epoch: 2 },
    );
    expect(failed.length === 0).toBe(accepted);
    if (!accepted) refused++;
  }
  expect(refused).toBe(candidates.length - entries.length);
  reader.lock();
});
