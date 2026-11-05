import { expect, test } from "bun:test";
import Dexie from "dexie";
import { IDBKeyRange, indexedDB } from "fake-indexeddb";
import { createVaultKey } from "../crypto/index.ts";
import { createSession } from "./session.ts";

Dexie.dependencies.indexedDB = indexedDB;
Dexie.dependencies.IDBKeyRange = IDBKeyRange;
async function fixture() {
  return createSession({
    owner: "did:plc:path-regression",
    vault: crypto.randomUUID(),
    key: await createVaultKey(),
  });
}
const encode = (source: string) => new TextEncoder().encode(source);
async function snapshot(session: Awaited<ReturnType<typeof fixture>>) {
  return {
    items: await session.database.items.toArray(),
    outbox: await session.database.outbox.toArray(),
    history: await session.database.history.toArray(),
  };
}

test("create rename and import reuse existing folder spelling across case and NFC", async () => {
  const session = await fixture();
  try {
    await session.createFolder("Docs/Café");
    const id = await session.create("docs/Cafe\u0301/first.md");
    await session.saveNote(id, "DOCS/CAFÉ/renamed.mdx", "exact source");
    await session.import([
      { path: "docs/Cafe\u0301/imported.md", bytes: encode("import source") },
    ]);
    expect((await session.listFolders()).sort()).toEqual(["Docs", "Docs/Café"]);
    expect((await session.listNotes()).map((note) => note.path).sort()).toEqual(
      ["Docs/Café/imported.md", "Docs/Café/renamed.mdx"],
    );
    expect(await session.open(id)).toBe("exact source");
  } finally {
    session.lock();
    await session.database.delete();
  }
});

test("normalized file-folder and final note collisions leave no orphan graph or outbox writes", async () => {
  const session = await fixture();
  try {
    const id = await session.create("existing.md");
    await session.save(id, "original");
    const before = await snapshot(session);
    await expect(session.create("EXISTING.MD/child.md")).rejects.toThrow(
      "not a folder",
    );
    await expect(session.createFolder("EXISTING.MD/new")).rejects.toThrow(
      "not a folder",
    );
    await expect(
      session.saveNote(crypto.randomUUID(), "EXISTING.MD", "new"),
    ).rejects.toThrow("collision");
    await expect(
      session.import([
        { path: "new/deep/valid.md", bytes: encode("must rollback") },
        { path: "EXISTING.MD", bytes: encode("collision") },
      ]),
    ).rejects.toThrow("collision");
    expect(await snapshot(session)).toEqual(before);
    expect(await session.open(id)).toBe("original");
  } finally {
    session.lock();
    await session.database.delete();
  }
});

test("failed new note write atomically rolls back planned folders source and outbox", async () => {
  const session = await fixture();
  try {
    const id = crypto.randomUUID();
    const before = await snapshot(session);
    const save = session.database.save.bind(session.database);
    session.database.save = (value, ...args) => {
      if (value.id === id) throw new Error("injected final write failure");
      return save(value, ...args);
    };
    await expect(
      session.saveNote(id, "new/deep/note.md", "replacement"),
    ).rejects.toThrow("injected final write failure");
    session.database.save = save;
    expect(await snapshot(session)).toEqual(before);
    await session.saveNote(id, "new/deep/note.md", "replacement");
    expect(await session.open(id)).toBe("replacement");
  } finally {
    session.lock();
    await session.database.delete();
  }
});

test("failed import write rolls back the entire prepared folder chain", async () => {
  const session = await fixture();
  try {
    const before = await snapshot(session);
    const save = session.database.save.bind(session.database);
    let writes = 0;
    session.database.save = (...args) => {
      if (++writes === 2) throw new Error("injected import failure");
      return save(...args);
    };
    await expect(
      session.import([{ path: "new/deep/file.md", bytes: encode("import") }]),
    ).rejects.toThrow("injected import failure");
    session.database.save = save;
    expect(await snapshot(session)).toEqual(before);
    expect(await session.listFolders()).toEqual([]);
  } finally {
    session.lock();
    await session.database.delete();
  }
});

test("concurrent normalized folder plans reject stale graphs without duplicate paths", async () => {
  const key = await createVaultKey();
  const options = {
    owner: "did:plc:path-race",
    vault: crypto.randomUUID(),
    key,
  };
  const first = createSession(options);
  const second = createSession(options);
  try {
    const outcomes = await Promise.allSettled([
      first.saveNote(crypto.randomUUID(), "Docs/deep/one.md", "one"),
      second.saveNote(crypto.randomUUID(), "docs/DEEP/two.md", "two"),
    ]);
    expect(
      outcomes.filter((result) => result.status === "fulfilled"),
    ).toHaveLength(1);
    const failed = outcomes.find((result) => result.status === "rejected");
    expect(
      failed?.status === "rejected" ? String(failed.reason) : "",
    ).toContain("Concurrent local path edit");
    expect(
      (await first.listFolders()).map((path) => path.toLowerCase()).sort(),
    ).toEqual(["docs", "docs/deep"]);
    expect(await first.database.items.count()).toBe(3);
    expect(await first.database.outbox.count()).toBe(3);
    expect(await first.database.history.count()).toBe(0);
  } finally {
    first.lock();
    second.lock();
    key.fill(0);
    await first.database.delete();
    second.database.close();
  }
});

test("acknowledgement during path encryption preserves the newest remote base CID", async () => {
  const session = await fixture();
  let notify: () => void = () => {};
  const started = new Promise<void>((resolve) => {
    notify = resolve;
  });
  let release: () => void = () => {};
  const resumed = new Promise<void>((resolve) => {
    release = resolve;
  });
  // biome-ignore lint/complexity/useLiteralKeys: Test intercepts private preparation while preserving its typed implementation.
  const prepare = session["prepare"].bind(session);
  try {
    const id = crypto.randomUUID();
    await session.saveNote(id, "original.md", "oldsource");
    const previous = await session.database.items.get(id);
    if (!previous) throw new Error("Missing note");
    // biome-ignore lint/complexity/useLiteralKeys: Test intercepts private preparation while preserving its typed implementation.
    session["prepare"] = async (...args) => {
      const result = await prepare(...args);
      if (args[0].kind === "note") {
        notify();
        await resumed;
      }
      return result;
    };
    const writing = session.saveNote(id, "new/deep/renamed.md", "newsource");
    await started;
    await session.database.acknowledge(
      id,
      previous.revision,
      "newly-acknowledged-cid",
    );
    expect(await session.database.outbox.get(id)).toBeUndefined();
    release();
    await writing;
    expect((await session.database.items.get(id))?.baseCid).toBe(
      "newly-acknowledged-cid",
    );
    expect((await session.database.outbox.get(id))?.baseCid).toBe(
      "newly-acknowledged-cid",
    );
    expect(await session.open(id)).toBe("newsource");
  } finally {
    release();
    // biome-ignore lint/complexity/useLiteralKeys: Test intercepts private preparation while preserving its typed implementation.
    session["prepare"] = prepare;
    session.lock();
    await session.database.delete();
  }
});

test("key-only commit checks reject a concurrent edit outside the target note", async () => {
  const key = await createVaultKey();
  const options = {
    owner: "did:plc:key-only-race",
    vault: crypto.randomUUID(),
    key,
  };
  const first = createSession(options);
  const second = createSession(options);
  let release = () => {};
  let observed = () => {};
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  const started = new Promise<void>((resolve) => {
    observed = resolve;
  });
  // biome-ignore lint/complexity/useLiteralKeys: Pause encryption after the read snapshot, before the atomic commit.
  const prepare = first["prepare"].bind(first);
  try {
    const target = await first.create("target.md");
    const other = await first.create("other.md");
    await first.readView();
    const before = await first.database.items.get(target);
    // biome-ignore lint/complexity/useLiteralKeys: Preserve preparation and pause only its completion.
    first["prepare"] = async (...args) => {
      const prepared = await prepare(...args);
      observed();
      await held;
      return prepared;
    };
    const pending = first.saveNote(target, "target.md", "stale target edit");
    await started;
    await second.saveNote(other, "other.md", "other writer");
    release();
    await expect(pending).rejects.toThrow("Concurrent local path edit");
    expect(await first.database.items.get(target)).toEqual(before);
    expect(await first.open(target)).toBe("");
    expect(await first.open(other)).toBe("other writer");
    expect(
      await first.database.history.where("id").equals(target).count(),
    ).toBe(0);
    expect((await first.database.outbox.get(target))?.revision).toBe(
      before?.revision,
    );
  } finally {
    release();
    first.lock();
    second.lock();
    key.fill(0);
    await first.database.delete();
  }
});
