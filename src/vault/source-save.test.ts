import { expect, test } from "bun:test";
import Dexie from "dexie";
import { IDBKeyRange, indexedDB } from "fake-indexeddb";
import { createVaultKey } from "../crypto/index.ts";
import { resolvePath } from "./links.ts";
import { createSession } from "./session.ts";

Dexie.dependencies.indexedDB = indexedDB;
Dexie.dependencies.IDBKeyRange = IDBKeyRange;

async function fixture() {
  return createSession({
    owner: "did:plc:source-save",
    vault: crypto.randomUUID(),
    key: await createVaultKey(),
  });
}

function gate() {
  let release = () => {};
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
}

test("warm unchanged-path saves decrypt only changed metadata and retain exact history", async () => {
  const session = await fixture();
  try {
    await session.import([
      { path: "Source.md", bytes: new TextEncoder().encode("old") },
      {
        path: "Large.md",
        bytes: new TextEncoder().encode("x".repeat(100_000)),
      },
      { path: "asset.bin", bytes: new Uint8Array(100_000) },
    ]);
    const id = (await session.listNotes()).find(
      (note) => note.path === "Source.md",
    )!.id;
    await session.saveNote(id, "Source.md", "warm");
    // biome-ignore lint/complexity/useLiteralKeys: Count authenticated reads without changing their implementation.
    const read = session["read"].bind(session);
    const reads: { id: string; bytes: boolean | undefined }[] = [];
    // biome-ignore lint/complexity/useLiteralKeys: Observe metadata-only reads for the changed revision.
    session["read"] = async (stored, bytes) => {
      reads.push({ id: stored.id, bytes });
      return read(stored, bytes);
    };
    await session.saveNote(id, "Source.md", "\uFEFFexact\r\ntext");
    expect(reads).toEqual([{ id, bytes: false }]);
    expect(await session.open(id)).toBe("\uFEFFexact\r\ntext");
    expect((await session.history(id)).map((entry) => entry.source)).toEqual([
      "old",
      "warm",
    ]);
  } finally {
    session.lock();
    await session.database.delete();
  }
});

test("source save rejects a concurrent rename of another note even when its own revision is unchanged", async () => {
  const session = await fixture();
  const ready = gate();
  const resume = gate();
  // biome-ignore lint/complexity/useLiteralKeys: Gate encryption to interleave a real rename transaction.
  const prepare = session["prepare"].bind(session);
  try {
    const origin = await session.create("Origin.md");
    const target = await session.create("Target.md");
    await session.saveNote(origin, "Origin.md", "baseline");
    // biome-ignore lint/complexity/useLiteralKeys: Only the pending source save waits at the encryption boundary.
    session["prepare"] = async (...args) => {
      const result = await prepare(...args);
      if (args[0].id === origin) {
        ready.release();
        await resume.promise;
      }
      return result;
    };
    const writing = session.saveNote(origin, "Origin.md", "[[Target]]");
    void writing.catch(() => {});
    await ready.promise;
    await session.rename(target, "Moved.md");
    resume.release();
    await expect(writing).rejects.toThrow("Concurrent");
    expect(await session.open(origin)).toBe("baseline");
    expect(
      (await session.listNotes()).find((note) => note.id === target)?.path,
    ).toBe("Moved.md");
  } finally {
    resume.release();
    session.lock();
    await session.database.delete();
  }
});

test("source saves keep acknowledgements received during encryption and encrypted base proofs", async () => {
  const session = await fixture();
  const ready = gate();
  const resume = gate();
  // biome-ignore lint/complexity/useLiteralKeys: Gate encryption while the previous revision is acknowledged.
  const prepare = session["prepare"].bind(session);
  try {
    const id = await session.create("Source.md");
    await session.saveNote(id, "Source.md", "baseline");
    const previous = (await session.database.items.get(id))!;
    // biome-ignore lint/complexity/useLiteralKeys: Preserve encryption while injecting the acknowledgement interleaving.
    session["prepare"] = async (...args) => {
      const result = await prepare(...args);
      ready.release();
      await resume.promise;
      return result;
    };
    const writing = session.saveNote(id, "Source.md", "new source");
    await ready.promise;
    await session.database.acknowledge(
      id,
      previous.revision,
      "acknowledged-cid",
    );
    resume.release();
    await writing;
    const pending = await session.database.outbox.get(id);
    expect(pending?.baseCid).toBe("acknowledged-cid");
    expect(pending?.baseRevision?.revision).toBe(previous.revision);
    expect(pending?.baseRevision?.cid).toBe("acknowledged-cid");
    expect(await session.open(id)).toBe("new source");
  } finally {
    resume.release();
    session.lock();
    await session.database.delete();
  }
});

test("concurrent unchanged-path saves reject the stale source after warming metadata", async () => {
  const session = await fixture();
  const ready = gate();
  const resume = gate();
  try {
    const id = await session.create("Source.md");
    await session.saveNote(id, "Source.md", "baseline");
    // biome-ignore lint/complexity/useLiteralKeys: Delay only the first save to exercise optimistic concurrency.
    const prepare = session["prepare"].bind(session);
    let pause = true;
    // biome-ignore lint/complexity/useLiteralKeys: Retain real encryption and transaction behavior for both edits.
    session["prepare"] = async (...args) => {
      const result = await prepare(...args);
      if (pause) {
        pause = false;
        ready.release();
        await resume.promise;
      }
      return result;
    };
    const stale = session.saveNote(id, "Source.md", "stale source");
    void stale.catch(() => {});
    await ready.promise;
    await session.saveNote(id, "Source.md", "acknowledged source");
    resume.release();
    await expect(stale).rejects.toThrow("Concurrent");
    expect(await session.open(id)).toBe("acknowledged source");
  } finally {
    resume.release();
    session.lock();
    await session.database.delete();
  }
});

test("locking a pending metadata read clears the cache and prevents its repopulation", async () => {
  const session = await fixture();
  const ready = gate();
  const resume = gate();
  try {
    const id = await session.create("Source.md");
    // biome-ignore lint/complexity/useLiteralKeys: Gate a completed decrypt before the metadata cache can consume it.
    const read = session["read"].bind(session);
    // biome-ignore lint/complexity/useLiteralKeys: Inject lock at the metadata-return boundary.
    session["read"] = async (...args) => {
      const result = await read(...args);
      ready.release();
      await resume.promise;
      return result;
    };
    const writing = session.saveNote(id, "Source.md", "must not persist");
    void writing.catch(() => {});
    await ready.promise;
    session.lock();
    resume.release();
    await expect(writing).rejects.toThrow("locked");
    // biome-ignore lint/complexity/useLiteralKeys: Verify decrypted metadata is absent after lock and the delayed read.
    expect(session["metadataCache"].size).toBe(0);
  } finally {
    resume.release();
    session.lock();
    await session.database.delete();
  }
});

test("case-only renames take the path transaction and preserve incoming references after warming metadata", async () => {
  const session = await fixture();
  try {
    const id = await session.create("Source.md");
    await session.saveNote(id, "Source.md", "baseline");
    const ref = await session.create("Ref.md");
    await session.saveNote(ref, "Ref.md", "[source](Source.md)");
    await session.saveNote(id, "SOURCE.md", "renamed");
    expect(
      (await session.listNotes()).find((note) => note.id === id),
    ).toMatchObject({ path: "SOURCE.md", format: "md" });
    expect(await session.open(id)).toBe("renamed");
    expect(await session.open(ref)).toBe("[source](Source.md)");
    expect(
      resolvePath("Source.md", "Ref.md", await session.listNotes(), "markdown"),
    ).toBe(id);
  } finally {
    session.lock();
    await session.database.delete();
  }
});
