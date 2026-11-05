import Dexie from "dexie";
import { IDBKeyRange, indexedDB } from "fake-indexeddb";

Dexie.dependencies.indexedDB = indexedDB;
Dexie.dependencies.IDBKeyRange = IDBKeyRange;

import { expect, test } from "bun:test";
import { createVaultKey } from "../crypto/index.ts";
import { createSession } from "../vault/session.ts";

async function fixture() {
  const options = {
    owner: "did:plc:composer",
    vault: crypto.randomUUID(),
    key: await createVaultKey(),
  };
  const session = createSession(options);
  const source = "---\ncustom: source\n---\n# Body\nSelected [asset](pic.png)";
  await session.import([
    { path: "folder/Source.md", bytes: new TextEncoder().encode(source) },
    { path: "Target.md", bytes: new TextEncoder().encode("Target body") },
    {
      path: "Ref.md",
      bytes: new TextEncoder().encode("[[folder/Source#Body|label]]"),
    },
    {
      path: "folder/pic.png",
      bytes: new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]),
    },
  ]);
  const notes = await session.listNotes();
  const originId = notes.find((note) => note.path === "folder/Source.md")!.id;
  const targetId = notes.find((note) => note.path === "Target.md")!.id;
  const refId = notes.find((note) => note.path === "Ref.md")!.id;
  return { session, options, source, originId, targetId, refId };
}

async function durable(session: ReturnType<typeof createSession>) {
  return {
    items: await session.database.items.toArray(),
    outbox: await session.database.outbox.toArray(),
    history: await session.database.history.toArray(),
  };
}

test("composer extraction commits source, new folders, encrypted note and recoverable history together", async () => {
  const { session, source, originId } = await fixture();
  const from = source.indexOf("Selected");
  const result = await session.compose({
    kind: "extract",
    originId,
    expectedSource: source,
    from,
    to: source.length,
    path: "new/deep/Extract.md",
  });
  expect(await session.open(originId)).toBe(
    source.slice(0, from) + "[Extract](../new/deep/Extract.md)",
  );
  expect(await session.open(result.selectedId)).toBe(
    "Selected [asset](../../folder/pic.png)",
  );
  expect(await session.history(originId)).toHaveLength(1);
  expect(await session.listFolders()).toContain("new/deep");
  expect(JSON.stringify(await durable(session))).not.toContain("Selected");
  session.lock();
});

test("composer merge atomically repairs incoming links and leaves exact original in restorable Trash", async () => {
  const { session, source, originId, targetId, refId } = await fixture();
  const result = await session.compose({
    kind: "merge",
    originId,
    targetId,
    expectedSource: source,
    expectedTargetSource: "Target body",
  });
  expect(result.selectedId).toBe(targetId);
  expect(await session.open(targetId)).toBe(
    "Target body\n\n# Body\nSelected [asset](folder/pic.png)",
  );
  expect(await session.open(refId)).toBe("[[/Target.md#Body|label]]");
  expect(await session.listTrash()).toHaveLength(1);
  expect(await session.open(originId)).toBe(source);
  const restored = await session.restore(originId);
  expect(await session.open(restored)).toBe(source);
  session.lock();
});

test("composer rejects concurrent writes after planning without overwriting their durable state", async () => {
  const { session, source, originId, targetId } = await fixture();
  const transaction = session.database.transaction.bind(session.database);
  let afterConcurrent: Awaited<ReturnType<typeof durable>> | undefined;
  // SAFETY: Intercept the overloaded transaction API to inject a real write between planning and commit.
  session.database.transaction = (async (
    ...args: Parameters<typeof transaction>
  ) => {
    session.database.transaction = transaction;
    await session.save(targetId, "Concurrent edit");
    afterConcurrent = await durable(session);
    return transaction(...args);
  }) as typeof session.database.transaction;
  await expect(
    session.compose({
      kind: "merge",
      originId,
      targetId,
      expectedSource: source,
    }),
  ).rejects.toThrow("Concurrent");
  expect(afterConcurrent).toBeDefined();
  expect(await durable(session)).toEqual(afterConcurrent!);
  expect(await session.open(originId)).toBe(source);
  session.lock();
});

test("locking after composer planning rejects all durable writes", async () => {
  const { session, options, source, originId, targetId } = await fixture();
  const before = await durable(session);
  const transaction = session.database.transaction.bind(session.database);
  // SAFETY: Intercept the overloaded transaction boundary to lock after planning.
  session.database.transaction = ((...args: Parameters<typeof transaction>) => {
    session.lock();
    return transaction(...args);
  }) as typeof session.database.transaction;
  await expect(
    session.compose({
      kind: "merge",
      originId,
      targetId,
      expectedSource: source,
    }),
  ).rejects.toThrow();
  const reopened = createSession(options);
  expect(await durable(reopened)).toEqual(before);
  reopened.lock();
});

test("composer rejects path collisions and internal destinations without durable writes", async () => {
  const { session, source, originId } = await fixture();
  const before = await durable(session);
  const request = {
    kind: "extract" as const,
    originId,
    expectedSource: source,
    from: source.indexOf("Selected"),
    to: source.length,
    path: "target.md",
  };
  await expect(session.compose(request)).rejects.toThrow("collision");
  await expect(
    session.compose({ ...request, path: ".note/settings.md" }),
  ).rejects.toThrow("internal");
  expect(await durable(session)).toEqual(before);
  session.lock();
});
