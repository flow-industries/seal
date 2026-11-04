import Dexie, { RangeSet } from "dexie";
import { IDBKeyRange, indexedDB } from "fake-indexeddb";

Dexie.dependencies.indexedDB = indexedDB;
Dexie.dependencies.IDBKeyRange = IDBKeyRange;

import { expect, spyOn, test } from "bun:test";
import { createVaultKey } from "../crypto/index.ts";
import type { VaultItem } from "./model.ts";
import { createSession, VaultSession } from "./session.ts";
import type { StoredRevision } from "./storage.ts";

test("same-path edits and preview refreshes reuse unrelated encrypted payloads", async () => {
  const session = createSession({
    owner: "did:plc:payload-reuse",
    vault: crypto.randomUUID(),
    key: await createVaultKey(),
  });
  try {
    const source = "# Before\n![[image.png]]";
    const image = new Uint8Array(100_000);
    image.set([137, 80, 78, 71, 13, 10, 26, 10]);
    await session.import([
      { path: "note.md", bytes: new TextEncoder().encode(source) },
      { path: "image.png", bytes: image },
    ]);
    const [note] = (await session.readView()).notes;
    if (!note) throw new Error("Missing note");
    await session.assetsForNote(note.id);
    const scan = spyOn(session.database.items, "toArray");
    const payloads = spyOn(session.database.items, "bulkGet");
    await session.saveNote(note.id, note.path, `${source}\nEdited`);
    expect((await session.readView()).notes[0]?.source).toBe(
      `${source}\nEdited`,
    );
    expect((await session.assetsForNote(note.id))[0]?.bytes).toEqual(image);
    expect(scan).not.toHaveBeenCalled();
    expect(payloads.mock.calls.flatMap(([ids]) => ids)).toEqual([note.id]);
    expect(await session.database.history.count()).toBe(1);
    expect((await session.database.outbox.get(note.id))?.revision).toBe(
      (await session.database.items.get(note.id))?.revision,
    );
    scan.mockRestore();
    payloads.mockRestore();
  } finally {
    session.lock();
    await session.database.delete();
  }
});

/** Records every item the session decrypts, and whether it decrypted the item's bytes or only its metadata. */
function countReads(session: VaultSession) {
  const reads: { id: string; bytes: Uint8Array | null }[] = [];
  const read = Object.getOwnPropertyDescriptor(
    VaultSession.prototype,
    "read",
  )?.value;
  if (!(read instanceof Function)) throw new Error("Missing read");
  // SAFETY: The wrapper only records each decrypted item and forwards the call and its result unchanged.
  Object.defineProperty(session, "read", {
    value: async (stored: StoredRevision, includeBytes = true) => {
      const item: VaultItem = await read.call(session, stored, includeBytes);
      reads.push({ id: stored.id, bytes: includeBytes ? item.bytes : null });
      return item;
    },
  });
  return reads;
}

test("encrypted saves, outbox, local history, reload and locking", async () => {
  const key = await createVaultKey();
  const options = { owner: "did:plc:test", vault: crypto.randomUUID(), key };
  const session = createSession(options);
  const id = await session.create("secret-name.md");
  await session.save(id, "very-secret-source");
  const raw = JSON.stringify(await session.database.items.toArray());
  expect(raw).not.toContain("secret-name");
  expect(raw).not.toContain("very-secret-source");
  expect(await session.database.outbox.count()).toBe(1);
  expect(await session.open(id)).toBe("very-secret-source");
  expect(await session.history(id)).toHaveLength(1);
  session.lock();
  expect(key.some((value) => value !== 0)).toBe(true);
  const reopened = createSession(options);
  expect(await reopened.open(id)).toBe("very-secret-source");
  const prior = await reopened.database.items.get(id);
  await reopened.save(id, "other");
  await expect(reopened.database.save(prior!, prior!.sequence)).rejects.toThrow(
    "Concurrent",
  );
  reopened.lock();
});
test("editing unchanged imported BOM source preserves exact bytes", async () => {
  const key = await createVaultKey();
  const session = createSession({
    owner: "did:plc:bom",
    vault: crypto.randomUUID(),
    key,
  });
  const bytes = new TextEncoder().encode(
    "\ufeff---\r\nunknown: true\r\n---\r\n",
  );
  await session.import([{ path: "BOM.md", bytes }]);
  const [note] = await session.listNotes();
  expect(note).toBeDefined();
  await session.save(note!.id, await session.open(note!.id));
  expect((await session.export())[0]!.bytes).toEqual(bytes);
  session.lock();
});
test("large asset chunk encryption and authenticated ordered mapping", async () => {
  const session = createSession({
    owner: "did:plc:assets",
    vault: crypto.randomUUID(),
    key: await createVaultKey(),
  });
  const bytes = crypto.getRandomValues(new Uint8Array(60_000));
  await session.import([{ path: "media.bin", bytes }]);
  const stored = (await session.database.items.toArray())[0]!;
  expect(stored.encryptedBlobs).toHaveLength(1);
  expect(JSON.stringify(stored.envelope).length).toBeLessThan(2000);
  expect((await session.export())[0]!.bytes).toEqual(bytes);
  stored.chunkHashes = ["wrong"];
  await session.database.items.put(stored);
  await expect(session.export()).rejects.toThrow();
  session.lock();
});
test("remote conflict application rejects interleaved acknowledged local save", async () => {
  const key = await createVaultKey();
  const vault = crypto.randomUUID();
  const session = createSession({ owner: "did:plc:race", vault, key });
  const id = await session.create("race.md");
  await session.save(id, "old");
  const prior = (await session.database.items.get(id))!;
  const original = session.database.transaction.bind(session.database);
  // SAFETY: The test intercepts the generic transaction overload to inject a write before remote commit.
  session.database.transaction = (async (
    ...args: Parameters<typeof original>
  ) => {
    session.database.transaction = original;
    await session.save(id, "new acknowledged edit");
    return original(...args);
  }) as typeof session.database.transaction;
  await expect(
    session.applyRemote({
      cid: "remote",
      record: {
        $type: "game.flow.note.item",
        id,
        revision: prior.revision,
        envelope: prior.envelope,
        blobs: [],
      },
    }),
  ).rejects.toThrow("Concurrent");
  expect(await session.open(id)).toBe("new acknowledged edit");
  expect(await session.database.outbox.count()).toBe(1);
  session.lock();
});
test("authenticated older revisions never roll back acknowledged source", async () => {
  const session = createSession({
    owner: "did:plc:replay",
    vault: crypto.randomUUID(),
    key: await createVaultKey(),
  });
  const id = await session.create("replay.md");
  await session.save(id, "first");
  const old = (await session.database.items.get(id))!;
  await session.database.acknowledge(id, old.revision, "old-cid");
  await session.save(id, "newer");
  const current = (await session.database.items.get(id))!;
  await session.database.acknowledge(id, current.revision, "new-cid");
  await expect(
    session.applyRemote({
      cid: "old-cid",
      record: {
        $type: "game.flow.note.item",
        id,
        revision: old.revision,
        envelope: old.envelope,
        blobs: [],
        chunkHashes: old.chunkHashes,
      },
    }),
  ).rejects.toThrow("stale");
  expect(await session.open(id)).toBe("newer");
  session.lock();
});
test("empty folders and reused trashed names remain usable", async () => {
  const session = createSession({
    owner: "did:plc:folders",
    vault: crypto.randomUUID(),
    key: await createVaultKey(),
  });
  await session.createFolder("empty/child");
  expect(await session.listFolders()).toContain("empty/child");
  const id = await session.create("old.md");
  await session.remove(id);
  await session.create("old.md");
  expect(await session.listTrash()).toHaveLength(1);
  expect(await session.listNotes()).toHaveLength(1);
  session.lock();
});
test("equal-counter tombstone fork preserves synced source as recovery draft", async () => {
  const key = await createVaultKey();
  const vault = crypto.randomUUID();
  const session = createSession({
    owner: "did:plc:fork",
    vault,
    key,
  });
  const id = await session.create("fork.md");
  await session.save(id, "synced source");
  const original = (await session.database.items.get(id))!;
  await session.database.acknowledge(id, original.revision, "synced");
  const context = {
    did: "did:plc:fork",
    vault,
    item: id,
    revision: "fork",
    epoch: 1,
    assets: [],
  };
  const { encrypt } = await import("../crypto/index.ts");
  const envelope = await encrypt(
    new TextEncoder().encode(
      JSON.stringify({
        id,
        kind: "note",
        name: "fork.md",
        parent: null,
        format: "md",
        bytes: [],
        trashed: true,
        permanent: true,
        revisionCounter: 2,
      }),
    ),
    key,
    context,
  );
  await session.applyRemote({
    cid: "fork",
    record: {
      $type: "game.flow.note.tombstone",
      id,
      revision: "fork",
      envelope,
      blobs: [],
    },
  });
  expect(
    (await session.export()).map((file) =>
      new TextDecoder().decode(file.bytes),
    ),
  ).toContain("synced source");
  session.lock();
});
test("restore creates new identity and atomically consumes original trash", async () => {
  const session = createSession({
    owner: "did:plc:restore",
    vault: crypto.randomUUID(),
    key: await createVaultKey(),
  });
  const id = await session.create("restored.md");
  await session.save(id, "restored source");
  await session.remove(id);
  const restored = await session.restore(id);
  expect(restored).not.toBe(id);
  expect(await session.open(restored)).toBe("restored source");
  expect(await session.listTrash()).toHaveLength(0);
  await expect(session.restore(id)).rejects.toThrow("recoverable");
  session.lock();
});
test("preview capability includes only referenced tokenized current-note media", async () => {
  const session = createSession({
    owner: "did:plc:media",
    vault: crypto.randomUUID(),
    key: await createVaultKey(),
  });
  const png = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]);
  await session.import([
    {
      path: "notes/current.md",
      bytes: new TextEncoder().encode(
        "![ok](../assets/selected.png)\n`![hidden](../assets/other.png)`\n![web](https://example.com/x)",
      ),
    },
    { path: "assets/selected.png", bytes: png },
    { path: "assets/other.png", bytes: png },
  ]);
  const [note] = await session.listNotes();
  if (!note) throw new Error("Missing fixture");
  const assets = await session.assetsForNote(note.id);
  expect(assets).toHaveLength(1);
  expect(assets[0]?.path).toBe("../assets/selected.png");
  expect(assets[0]?.mime).toBe("image/png");
  session.lock();
});
test("encrypted remote graph repairs persist source and outbox without plaintext metadata", async () => {
  const key = await createVaultKey();
  const vault = crypto.randomUUID();
  const owner = "did:plc:graph";
  const session = createSession({ owner, vault, key });
  const { encrypt } = await import("../crypto/index.ts");
  for (const [id, name, parent] of [
    ["a", "same.md", null],
    ["b", "SAME.md", null],
    ["c", "lost.md", "missing"],
  ] as const) {
    const revision = `remote-${id}`;
    const value = {
      id,
      name,
      parent,
      kind: "note",
      format: "md",
      createdAt: "now",
      updatedAt: "now",
      bytes: Array.from(new TextEncoder().encode(`source-${id}`)),
      revisionCounter: 1,
    };
    const envelope = await encrypt(
      new TextEncoder().encode(JSON.stringify(value)),
      key,
      { did: owner, vault, item: id, revision, epoch: 1, assets: [] },
    );
    await session.applyRemote({
      cid: `cid-${id}`,
      record: {
        $type: "game.flow.note.item",
        id,
        revision,
        envelope,
        blobs: [],
      },
    });
  }
  expect((await session.repairGraph()).length).toBe(2);
  expect(await session.listNotes()).toHaveLength(3);
  expect(await session.open("b")).toBe("source-b");
  expect(await session.open("c")).toBe("source-c");
  expect(await session.database.outbox.count()).toBe(2);
  expect(JSON.stringify(await session.database.items.toArray())).not.toContain(
    "same.md",
  );
  expect(await session.repairGraph()).toHaveLength(0);
  session.lock();
});
test("note assets decrypt only referenced attachments, once per revision, and wipe them on lock", async () => {
  const session = createSession({
    owner: "did:plc:asset-reads",
    vault: crypto.randomUUID(),
    key: await createVaultKey(),
  });
  const png = (seed: number) =>
    new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10, seed]);
  const source = "![one](../assets/one.png) ![[two.png]] [[other]]";
  await session.import([
    { path: "notes/current.md", bytes: new TextEncoder().encode(source) },
    { path: "notes/other.md", bytes: new TextEncoder().encode("![[one.png]]") },
    ...Array.from({ length: 20 }, (_, index) => ({
      path: `assets/unused-${index}.png`,
      bytes: png(index),
    })),
    { path: "assets/one.png", bytes: png(100) },
    { path: "assets/two.png", bytes: png(200) },
  ]);
  const note = (await session.listNotes()).find(
    (item) => item.path === "notes/current.md",
  );
  if (!note) throw new Error("Missing fixture");
  const reads = countReads(session);
  const first = await session.assetsForNote(note.id);
  const attachmentIds = first.map((asset) => asset.id).sort();
  expect(first.map((asset) => asset.path)).toEqual([
    "../assets/one.png",
    "two.png",
  ]);
  expect(
    reads
      .filter((read) => read.bytes)
      .map((read) => read.id)
      .sort(),
  ).toEqual([note.id, ...attachmentIds].sort());
  const decrypted = reads.flatMap((read) =>
    read.bytes && attachmentIds.includes(read.id) ? [read.bytes] : [],
  );
  expect(decrypted).toHaveLength(2);

  for (const asset of first) asset.bytes.fill(0);
  reads.length = 0;
  const again = await session.assetsForNote(note.id, `${source} ![[two.png]]`);
  expect(reads).toEqual([]);
  expect(again.map((asset) => Array.from(asset.bytes))).toEqual([
    Array.from(png(100)),
    Array.from(png(200)),
  ]);

  session.lock();
  expect(decrypted.every((bytes) => bytes.every((byte) => byte === 0))).toBe(
    true,
  );
  await expect(session.assetsForNote(note.id, source)).rejects.toThrow();
});
test("cached attachment plaintext is wiped once the store trashes, removes or supersedes it", async () => {
  const session = createSession({
    owner: "did:plc:asset-prune",
    vault: crypto.randomUUID(),
    key: await createVaultKey(),
  });
  const png = (seed: number) =>
    new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10, seed]);
  await session.import([
    {
      path: "current.md",
      bytes: new TextEncoder().encode("![[trashed.png]] ![[removed.png]]"),
    },
    { path: "moved.md", bytes: new TextEncoder().encode("![[moved.png]]") },
    { path: "trashed.png", bytes: png(1) },
    { path: "removed.png", bytes: png(2) },
    { path: "folder/moved.png", bytes: png(3) },
  ]);
  const notes = await session.listNotes();
  const current = notes.find((note) => note.path === "current.md");
  const moved = notes.find((note) => note.path === "moved.md");
  if (!current || !moved) throw new Error("Missing fixture");
  const reads = countReads(session);
  const [trashed, removed] = await session.assetsForNote(current.id);
  const [relocated] = await session.assetsForNote(moved.id);
  if (!trashed || !removed || !relocated) throw new Error("Missing assets");
  const plaintext = (id: string) => {
    const bytes = reads.find((read) => read.id === id && read.bytes)?.bytes;
    if (!bytes) throw new Error("Missing decrypted bytes");
    return bytes;
  };
  const wiped = (bytes: Uint8Array) => bytes.every((byte) => byte === 0);
  const cached = {
    trashed: plaintext(trashed.id),
    removed: plaintext(removed.id),
    relocated: plaintext(relocated.id),
  };

  await session.remove(trashed.id);
  await session.permanentRemove(removed.id);
  expect(await session.assetsForNote(moved.id)).toHaveLength(1);
  expect(wiped(cached.trashed)).toBe(true);
  expect(wiped(cached.removed)).toBe(true);
  expect(wiped(cached.relocated)).toBe(false);

  const folder = (await session.database.items.toArray()).find(
    (record) =>
      record.id !== current.id &&
      record.id !== moved.id &&
      !record.chunkHashes?.length,
  );
  if (!folder) throw new Error("Missing folder");
  await session.database.items.delete(folder.id);
  expect(await session.repairGraph()).toHaveLength(1);
  reads.length = 0;
  const [superseded] = await session.assetsForNote(moved.id);
  expect(superseded?.id).toBe(relocated.id);
  expect(wiped(cached.relocated)).toBe(true);
  expect(reads.filter((read) => read.bytes).map((read) => read.id)).toEqual([
    relocated.id,
  ]);
  expect(await session.open(moved.id)).toBe("![[moved.png]]");
  session.lock();
});
test("attachments over the preview limit are refused without being cached", async () => {
  const session = createSession({
    owner: "did:plc:asset-limit",
    vault: crypto.randomUUID(),
    key: await createVaultKey(),
  });
  const large = (size: number) => {
    const bytes = new Uint8Array(size);
    bytes.set([137, 80, 78, 71, 13, 10, 26, 10]);
    return bytes;
  };
  await session.import([
    { path: "near.md", bytes: new TextEncoder().encode("![[near.png]]") },
    { path: "far.md", bytes: new TextEncoder().encode("![[far.png]]") },
    { path: "near.png", bytes: large(8_100_000) },
    { path: "far.png", bytes: large(9_000_000) },
  ]);
  const notes = await session.listNotes();
  const near = notes.find((note) => note.path === "near.md");
  const far = notes.find((note) => note.path === "far.md");
  if (!near || !far) throw new Error("Missing fixture");
  const reads = countReads(session);
  await expect(session.assetsForNote(near.id)).rejects.toThrow(
    "Note asset preview exceeds bounds",
  );
  const nearReads = reads.filter((read) => read.bytes && read.id !== near.id);
  expect(nearReads).toHaveLength(1);
  expect(nearReads[0]?.bytes?.every((byte) => byte === 0)).toBe(true);
  reads.length = 0;
  await expect(session.assetsForNote(near.id)).rejects.toThrow(
    "Note asset preview exceeds bounds",
  );
  expect(
    reads.filter((read) => read.bytes && read.id !== near.id),
  ).toHaveLength(1);
  reads.length = 0;
  await expect(session.assetsForNote(far.id)).rejects.toThrow(
    "Note asset preview exceeds bounds",
  );
  expect(reads.filter((read) => read.bytes && read.id !== far.id)).toEqual([]);
  session.lock();
});
test("decrypted attachments stay within the cache bound and evicted plaintext is wiped", async () => {
  const session = createSession({
    owner: "did:plc:asset-cache",
    vault: crypto.randomUUID(),
    key: await createVaultKey(),
  });
  const notes = 3;
  const perNote = 30;
  await session.import([
    ...Array.from({ length: notes }, (_, note) => ({
      path: `notes/${note}.md`,
      bytes: new TextEncoder().encode(
        Array.from(
          { length: perNote },
          (_, index) => `![[${note}-${index}.png]]`,
        ).join("\n"),
      ),
    })),
    ...Array.from({ length: notes * perNote }, (_, index) => ({
      path: `assets/${Math.floor(index / perNote)}-${index % perNote}.png`,
      bytes: new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10, index % 256]),
    })),
  ]);
  const summaries = await session.listNotes();
  const reads = countReads(session);
  const attachmentIds = new Set<string>();
  for (let note = 0; note < notes; note++) {
    const summary = summaries.find((item) => item.path === `notes/${note}.md`);
    if (!summary) throw new Error("Missing fixture");
    const assets = await session.assetsForNote(summary.id);
    expect(assets).toHaveLength(perNote);
    for (const asset of assets) attachmentIds.add(asset.id);
  }
  const attachments = reads.filter(
    (read): read is { id: string; bytes: Uint8Array } =>
      read.bytes !== null && attachmentIds.has(read.id),
  );
  expect(attachments).toHaveLength(notes * perNote);
  const wiped = attachments.filter((read) =>
    read.bytes.every((byte) => byte === 0),
  );
  expect(wiped).toHaveLength(notes * perNote - 64);
  expect(wiped.map((read) => read.id)).toEqual(
    attachments.slice(0, wiped.length).map((read) => read.id),
  );
  session.lock();
});
test("unsaved current source scopes media aliases and removed references", async () => {
  const session = createSession({
    owner: "did:plc:scope",
    vault: crypto.randomUUID(),
    key: await createVaultKey(),
  });
  const png = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]);
  await session.import([
    {
      path: "notes/current.md",
      bytes: new TextEncoder().encode("![old](../assets/image.png)"),
    },
    { path: "assets/image.png", bytes: png },
  ]);
  const [note] = await session.listNotes();
  if (!note) throw new Error();
  expect(await session.assetsForNote(note.id, "no image now")).toHaveLength(0);
  const selected = await session.assetsForNote(
    note.id,
    "![[image.png]] ![same](../assets/image.png)",
  );
  expect(selected).toHaveLength(1);
  expect(selected[0]?.paths).toEqual(["image.png", "../assets/image.png"]);
  session.lock();
});
test("two sessions sharing one IndexedDB reject concurrent stale writes", async () => {
  const key = await createVaultKey();
  const options = {
    owner: "did:plc:two-tabs",
    vault: crypto.randomUUID(),
    key,
  };
  const first = createSession(options);
  const second = createSession(options);
  const id = await first.create("tabs.md");
  await first.save(id, "baseline");
  const original = second.database.items.get.bind(second.database.items);
  let release: () => void = () => {};
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  let observed: () => void = () => {};
  const loaded = new Promise<void>((resolve) => {
    observed = resolve;
  });
  // SAFETY: This test intercepts the key-only overload used by save and retains Dexie's extended promise.
  second.database.items.get = ((key: string) =>
    Dexie.Promise.resolve(original(key)).then(async (value) => {
      observed();
      await gate;
      return value;
    })) as typeof second.database.items.get;
  const stale = second.save(id, "second stale source");
  await loaded;
  await first.save(id, "first acknowledged source");
  release();
  await expect(stale).rejects.toThrow("Concurrent");
  expect(await first.open(id)).toBe("first acknowledged source");
  expect(await first.database.outbox.count()).toBe(1);
  first.lock();
  second.lock();
});

test("rename atomically repairs encrypted references, moved asset paths and preserves original histories", async () => {
  const session = createSession({
    owner: "did:plc:rename",
    vault: crypto.randomUUID(),
    key: await createVaultKey(),
  });
  const source =
    '\ufeff[[folder/Old#Part|label]] [link](folder/Old.md#part "title") `[[folder/Old]]`\r\n';
  await session.import([
    { path: "Ref.md", bytes: new TextEncoder().encode(source) },
    {
      path: "folder/Old.md",
      bytes: new TextEncoder().encode("# Part\n![pic](../pic.png)"),
    },
    {
      path: "pic.png",
      bytes: new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]),
    },
  ]);
  const notes = await session.listNotes();
  const old = notes.find((note) => note.path === "folder/Old.md")!;
  const ref = notes.find((note) => note.path === "Ref.md")!;
  await session.rename(old.id, "nested/deep/New.md");
  expect(await session.open(ref.id)).toBe(
    '\ufeff[[/nested/deep/New#Part|label]] [link](nested/deep/New.md#part "title") `[[folder/Old]]`\r\n',
  );
  expect(await session.open(old.id)).toBe("# Part\n![pic](../../pic.png)");
  expect(await session.history(ref.id)).toHaveLength(1);
  const stored = JSON.stringify(await session.database.items.toArray());
  expect(stored).not.toContain("nested/deep");
  expect(stored).not.toContain("label");
  expect(
    (await session.assetsForNote(old.id, await session.open(old.id)))[0]?.bytes,
  ).toEqual(new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]));
  session.lock();
});

test("rename path collision leaves note paths, sources, history and outbox unchanged", async () => {
  const session = createSession({
    owner: "did:plc:rename-rollback",
    vault: crypto.randomUUID(),
    key: await createVaultKey(),
  });
  const target = await session.create("Old.md");
  const ref = await session.create("Ref.md");
  await session.save(ref, "[[Old]]");
  const beforeItems = await session.database.items.toArray();
  const beforeOutbox = await session.database.outbox.toArray();
  const beforeHistory = await session.database.history.toArray();
  await expect(session.rename(target, "Ref.md")).rejects.toThrow("collision");
  expect(await session.database.items.toArray()).toEqual(beforeItems);
  expect(await session.database.outbox.toArray()).toEqual(beforeOutbox);
  expect(await session.database.history.toArray()).toEqual(beforeHistory);
  expect(await session.open(ref)).toBe("[[Old]]");
  session.lock();
});
test("search reuses an unchanged index and sees writes from this and other sessions", async () => {
  const key = await createVaultKey();
  const options = { owner: "did:plc:search", vault: crypto.randomUUID(), key };
  const session = createSession(options);
  let scans = 0;
  session.database.use({
    stack: "dbcore",
    name: "count-item-scans",
    create(core) {
      return {
        ...core,
        table(name) {
          const table = core.table(name);
          return name === "items"
            ? {
                ...table,
                query(request) {
                  scans++;
                  return table.query(request);
                },
              }
            : table;
        },
      };
    },
  });
  const id = await session.create("orchard.md");
  await session.save(id, "ripe tangerine");
  const search = async (query: string) =>
    (await session.search(query)).map((note) => note.id);
  expect(await search("tangerine")).toEqual([id]);
  let before = scans;
  expect(await search("tangerine")).toEqual([id]);
  expect(scans).toBe(before);
  await session.save(id, "saffron flowers");
  before = scans;
  expect(await search("tangerine")).toEqual([]);
  expect(scans).toBeGreaterThan(before);
  expect(await search("saffron")).toEqual([id]);
  const other = createSession(options);
  await other.save(id, "cobalt mineral");
  other.lock();
  expect(await search("cobalt")).toEqual([id]);
  before = scans;
  Dexie.on.storagemutated.fire({ all: new RangeSet(-Infinity, [[]]) });
  expect(await search("cobalt")).toEqual([id]);
  expect(scans).toBeGreaterThan(before);
  before = scans;
  await expect(session.search("x".repeat(257))).rejects.toThrow(
    "Search query too long",
  );
  expect(await search("cobalt")).toEqual([id]);
  expect(scans).toBe(before);
  session.lock();
});

test("active session chunk reader rejects missing and reordered chunks and lock zeroes its owned key", async () => {
  const key = await createVaultKey();
  const session = createSession({
    owner: "did:plc:chunk-lifetime",
    vault: crypto.randomUUID(),
    key,
  });
  const retained = Object.getOwnPropertyDescriptor(session, "key")?.value;
  if (!(retained instanceof Uint8Array))
    throw new Error("Missing owned session key");
  try {
    await session.import([
      { path: "chunks.bin", bytes: new Uint8Array(300_000).fill(42) },
    ]);
    const stored = (await session.database.items.toArray())[0]!;
    expect(stored.encryptedBlobs).toHaveLength(2);
    expect((await session.export())[0]?.bytes.length).toBe(300_000);
    await session.database.items.put({
      ...stored,
      encryptedBlobs: stored.encryptedBlobs!.slice(0, 1),
    });
    await expect(session.export()).rejects.toThrow("Missing encrypted chunks");
    await session.database.items.put({
      ...stored,
      encryptedBlobs: [...stored.encryptedBlobs!].reverse(),
    });
    await expect(session.export()).rejects.toThrow("mapping mismatch");
  } finally {
    session.lock();
    expect(retained.every((byte) => byte === 0)).toBe(true);
    expect(key.some((byte) => byte !== 0)).toBe(true);
    await expect(session.open("unavailable")).rejects.toThrow();
    key.fill(0);
    await session.database.delete();
  }
});

test("lock between decryption and source caching cannot retain a completed plaintext read", async () => {
  const session = createSession({
    owner: "did:plc:read-lifetime",
    vault: crypto.randomUUID(),
    key: await createVaultKey(),
  });
  const id = await session.create("lifetime.md");
  await session.save(id, "private source");
  const original: (
    stored: import("./storage.ts").StoredRevision,
    includeBytes?: boolean,
  ) => Promise<import("./model.ts").VaultItem> = Object.getOwnPropertyDescriptor(
    Object.getPrototypeOf(session),
    "read",
  )!.value;
  Object.defineProperty(session, "read", {
    value: async (...args: Parameters<typeof original>) => {
      const item = await original.call(session, ...args);
      session.lock();
      return item;
    },
  });
  try {
    await expect(session.open(id)).rejects.toThrow("Vault locked");
    const cache = Object.getOwnPropertyDescriptor(
      session,
      "sourceCache",
    )?.value;
    expect(cache instanceof Map && cache.size === 0).toBe(true);
  } finally {
    session.lock();
    await session.database.delete();
  }
});

test("one metadata snapshot binds active, trash and preference sources to their listed revisions", async () => {
  const session = createSession({
    owner: "did:plc:read-snapshot",
    vault: crypto.randomUUID(),
    key: await createVaultKey(),
  });
  try {
    const id = await session.create("Journal/Before.md");
    await session.save(id, "before source");
    const trashId = await session.create("Journal/Discarded.md");
    await session.save(trashId, "recoverable source");
    await session.remove(trashId);
    const settingsId = await session.create(".note/settings.md");
    await session.save(settingsId, '{"dailyFolder":"Before"}');
    const snapshot = await session.readMetadata();
    const listed = snapshot.notes.find((note) => note.id === id);
    if (!listed) throw new Error("Missing snapshot note");
    const captured = { ...listed };
    expect(listed.created).toEqual(expect.any(String));
    expect(listed.modified).toEqual(expect.any(String));
    expect(snapshot.notes.find((note) => note.id === id)?.path).toBe(
      "Journal/Before.md",
    );
    expect(snapshot.trash.find((note) => note.id === trashId)?.path).toBe(
      "Journal/Discarded.md",
    );
    expect(snapshot.folders).toContain("Journal");
    await session.saveNote(id, "Journal/After.md", "after source");
    await session.save(settingsId, '{"dailyFolder":"After"}');
    expect(snapshot.notes.find((note) => note.id === id)).toEqual(captured);
    expect(
      (await session.listNotes()).find((note) => note.id === id)?.created,
    ).toBe(captured.created);
    expect((await snapshot.read(id)).source).toBe("before source");
    expect((await snapshot.read(settingsId)).source).toBe(
      '{"dailyFolder":"Before"}',
    );
    expect((await snapshot.read(trashId)).source).toBe("recoverable source");
    expect(
      (await session.readView()).notes.find((note) => note.id === id),
    ).toMatchObject({
      path: "Journal/After.md",
      source: "after source",
    });
    session.lock();
    await expect(snapshot.read(id)).rejects.toThrow("Vault locked");
  } finally {
    session.lock();
    await session.database.delete();
  }
});
