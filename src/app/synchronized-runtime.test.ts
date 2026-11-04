import { expect, setSystemTime, spyOn, test } from "bun:test";
import Dexie from "dexie";
import { IDBKeyRange, indexedDB } from "fake-indexeddb";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { SyncNotice } from "../components/save-status";
import { createVaultKey } from "../crypto/index.ts";
import { SyncFailure } from "../sync/records.ts";
import type {
  SnapshotEntry,
  VaultSnapshot,
  VaultSnapshotTransport,
} from "../sync/vault-snapshot.ts";
import { createSession } from "../vault/session.ts";
import {
  type NoteRuntime,
  parseSyncBackoff,
  SYNC_AUTHORIZATION_REQUIRED,
  SYNC_BLOCKED,
  SYNC_PENDING,
  SYNC_QUOTA_REACHED,
  SYNC_RATE_LIMITED,
  SYNC_TOO_LARGE,
  SYNCED,
  type SyncStatus,
  syncBackoffStatus,
} from "./runtime.ts";
import {
  SYNC_BACKOFF_MS,
  SYNC_INTERVAL_MS,
  synchronizedRuntime,
} from "./synchronized-runtime.ts";

Dexie.dependencies.indexedDB = indexedDB;
Dexie.dependencies.IDBKeyRange = IDBKeyRange;
test("automatic publication uses one cadence and lock keeps encrypted pending edits for reopen", async () => {
  const key = await createVaultKey();
  const vault = crypto.randomUUID();
  const session = createSession({ owner: "did:plc:batch", vault, key });
  let snapshot: VaultSnapshot | null = null;
  let writes = 0;
  let tick: (() => void) | undefined;
  const transport: VaultSnapshotTransport = {
    version: 2,
    async readSnapshot() {
      return structuredClone(snapshot);
    },
    async writeSnapshot(entries) {
      snapshot = { cid: `cid-${++writes}`, entries: structuredClone(entries) };
      return { cid: snapshot.cid };
    },
  };
  const schedule = spyOn(globalThis, "setInterval");
  const runtime = synchronizedRuntime(session, async () => transport);
  const call = schedule.mock.calls[0];
  expect(call?.[1]).toBe(SYNC_INTERVAL_MS);
  const handler = call?.[0];
  // biome-ignore lint/plugin: TimerHandler is a browser union; the runtime registers a function.
  if (typeof handler === "function") tick = () => handler();
  schedule.mockRestore();
  await runtime.sync?.();
  const id = await session.create("batched.md");
  for (const source of ["one", "two", "three"])
    await runtime.save({ id, path: "batched.md", source, kind: "md" });
  expect(writes).toBe(0);
  tick?.();
  await runtime.sync?.();
  expect(writes).toBe(1);
  await runtime.save({
    id,
    path: "batched.md",
    source: "saved before lock",
    kind: "md",
  });
  runtime.lock();
  expect(writes).toBe(1);
  const reopened = createSession({ owner: "did:plc:batch", vault, key });
  expect(await reopened.open(id)).toBe("saved before lock");
  expect(await reopened.database.outbox.count()).toBe(1);
  const next = synchronizedRuntime(reopened, async () => transport);
  await next.sync?.();
  expect(writes).toBe(2);
  expect(await reopened.database.outbox.count()).toBe(0);
  next.lock();
});

test("fatal remote access failure locks immediately without discarding local pending work", async () => {
  const { VaultAccessError } = await import("../sync/vault-snapshot.ts");
  const { SYNC_LOCKED } = await import("./runtime.ts");
  const key = await createVaultKey();
  const vault = crypto.randomUUID();
  const session = createSession({ owner: "did:plc:lost", vault, key });
  let lost = false;
  let stopped = false;
  const transport: VaultSnapshotTransport = {
    version: 2,
    async readSnapshot() {
      if (lost) throw new VaultAccessError("Missing vault");
      return { cid: "initial", entries: [] };
    },
    async writeSnapshot() {
      throw new Error("Must not publish after access loss");
    },
    stop() {
      stopped = true;
    },
  };
  const runtime = synchronizedRuntime(session, async () => transport);
  await runtime.sync?.();
  const statuses: string[] = [];
  runtime.subscribe?.((status) => {
    statuses.push(status);
  });
  const id = await session.create("local.md");
  await session.save(id, "durable offline");
  lost = true;
  await runtime.sync?.();
  expect(stopped).toBe(true);
  expect(statuses).toContain(SYNC_LOCKED);
  await expect(session.open(id)).rejects.toThrow();
  const reopened = createSession({ owner: "did:plc:lost", vault, key });
  expect(await reopened.open(id)).toBe("durable offline");
  expect(await reopened.database.outbox.count()).toBe(1);
  reopened.lock();
});

test("access loss saves a queued edit and an unsaved draft before it wipes the key", async () => {
  const { VaultAccessError } = await import("../sync/vault-snapshot.ts");
  const { SYNC_LOCKED } = await import("./runtime.ts");
  const { WritingSession } = await import("./writing-session");
  const key = await createVaultKey();
  const vault = crypto.randomUUID();
  const owner = "did:plc:flush-on-lock";
  const session = createSession({ owner, vault, key });
  let lost = false;
  let stopped = false;
  const transport: VaultSnapshotTransport = {
    version: 2,
    async readSnapshot() {
      if (lost) throw new VaultAccessError("Vault format is newer");
      return { cid: "initial", entries: [] };
    },
    async writeSnapshot() {
      throw new Error("Must not publish after access loss");
    },
    stop() {
      stopped = true;
    },
  };
  const synchronized = synchronizedRuntime(session, async () => transport);
  const writing = new WritingSession();
  const until = async (condition: () => boolean) => {
    while (!condition()) await new Promise((resolve) => setTimeout(resolve, 0));
  };
  try {
    await synchronized.sync?.();
    const first = await session.create("first.md");
    const second = await session.create("second.md");
    let release = () => {};
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    let saves = 0;
    writing.runtime = {
      ...synchronized,
      async save(note) {
        if (saves++ === 0) await held;
        await synchronized.save(note);
      },
    };
    const edit = (id: string, path: string, source: string) =>
      writing.edit({ id, path, source, kind: "md" }, () => {});
    edit(first, "first.md", "typed");
    await until(() => saves === 1);
    edit(first, "first.md", "typed, then");
    edit(first, "first.md", "typed, then queued");
    edit(second, "second.md", "unsaved draft");
    synchronized.subscribe?.(async (status) => {
      if (status === SYNC_LOCKED) await writing.drain();
    });
    lost = true;
    const locking = synchronized.sync?.();
    await until(() => stopped);
    expect(await session.open(first)).toBe("");
    release();
    await locking;
    expect(saves).toBe(3);
    expect(writing.hasPendingEdits).toBe(false);
    await expect(session.open(first)).rejects.toThrow();
    const reopened = createSession({ owner, vault, key });
    expect(await reopened.open(first)).toBe("typed, then queued");
    expect(await reopened.open(second)).toBe("unsaved draft");
    expect(await reopened.database.outbox.count()).toBeGreaterThan(0);
    reopened.lock();
  } finally {
    writing.dispose();
    key.fill(0);
  }
});

test("access loss wipes the key after the flush limit even when a listener never settles", async () => {
  const { VaultAccessError } = await import("../sync/vault-snapshot.ts");
  const { SYNC_LOCKED } = await import("./runtime.ts");
  const key = await createVaultKey();
  const vault = crypto.randomUUID();
  const session = createSession({ owner: "did:plc:hung-flush", vault, key });
  let lost = false;
  const transport: VaultSnapshotTransport = {
    version: 2,
    async readSnapshot() {
      if (lost) throw new VaultAccessError("Access removed");
      return { cid: "initial", entries: [] };
    },
    async writeSnapshot() {
      throw new Error("Must not publish after access loss");
    },
  };
  const runtime = synchronizedRuntime(session, async () => transport, 50);
  try {
    await runtime.sync?.();
    const id = await session.create("hung.md");
    await session.save(id, "saved before the loss");
    let notified = false;
    runtime.subscribe?.((status) => {
      if (status !== SYNC_LOCKED) return;
      notified = true;
      return new Promise<void>(() => {});
    });
    lost = true;
    const started = performance.now();
    const locking = runtime.sync?.();
    while (!notified) await new Promise((resolve) => setTimeout(resolve, 0));
    expect(await session.open(id)).toBe("saved before the loss");
    await locking;
    expect(performance.now() - started).toBeGreaterThanOrEqual(45);
    await expect(session.open(id)).rejects.toThrow();
    await expect(session.save(id, "after the limit")).rejects.toThrow();
  } finally {
    runtime.lock();
    key.fill(0);
  }
});

test("remote edits refresh subscribers even when sync status remains Synced", async () => {
  const { captureSnapshot } = await import("../sync/vault-snapshot.ts");
  const { VaultDatabase } = await import("../vault/storage.ts");
  const key = await createVaultKey();
  const vault = crypto.randomUUID();
  const owner = "did:plc:refresh";
  const local = createSession({ owner, vault, key });
  const remote = createSession({ owner, vault, key });
  Object.defineProperty(remote, "database", {
    value: new VaultDatabase(owner, `${vault}-remote`),
  });
  let snapshot: VaultSnapshot = { cid: "first", entries: [] };
  const transport: VaultSnapshotTransport = {
    version: 2,
    async readSnapshot() {
      return structuredClone(snapshot);
    },
    async writeSnapshot() {
      throw new Error("No local edits");
    },
  };
  const runtime = synchronizedRuntime(local, async () => transport);
  await runtime.sync?.();
  const notifications: string[] = [];
  let changes = 0;
  runtime.subscribeChanges(() => changes++);
  runtime.subscribe?.((status) => {
    notifications.push(status);
  });
  expect(notifications).toEqual([SYNCED]);
  await runtime.sync?.();
  await new Promise((resolve) => setTimeout(resolve, 0));
  expect(changes).toBe(0);
  const id = await remote.create("incoming.md");
  await remote.save(id, "received while already synced");
  snapshot = {
    cid: "second",
    entries: (await captureSnapshot(remote.database)).entries,
  };
  await runtime.sync?.();
  await new Promise((resolve) => setTimeout(resolve, 0));
  expect(notifications).toEqual([SYNCED, SYNCED, SYNCED]);
  expect(changes).toBeGreaterThan(0);
  expect((await runtime.list()).find((note) => note.id === id)?.source).toBe(
    "received while already synced",
  );
  runtime.lock();
  remote.lock();
});

test("malformed authenticated snapshot items are quarantined: never applied, carried untouched, an edit kept beside them, and no lock", async () => {
  const { SYNC_LOCKED } = await import("./runtime.ts");
  const key = await createVaultKey();
  const vault = crypto.randomUUID();
  const session = createSession({ owner: "did:plc:invalid-inner", vault, key });
  let snapshot: VaultSnapshot = { cid: "initial", entries: [] };
  const written: VaultSnapshot["entries"][] = [];
  const transport: VaultSnapshotTransport = {
    version: 2,
    async readSnapshot() {
      return structuredClone(snapshot);
    },
    async writeSnapshot(entries) {
      written.push(structuredClone(entries));
      snapshot = { cid: `written-${written.length}`, entries };
      return { cid: snapshot.cid };
    },
  };
  const runtime = synchronizedRuntime(session, async () => transport);
  try {
    await runtime.sync?.();
    const id = await session.create("local.md");
    await session.save(id, "retained source");
    const { captureSnapshot } = await import("../sync/vault-snapshot.ts");
    const entries = (await captureSnapshot(session.database)).entries;
    const item = entries[0];
    if (!item) throw new Error("Missing inner item");
    const planted = {
      ...structuredClone(item),
      id: "planted",
      envelope: { ...item.envelope, ciphertext: "bad-ciphertext" },
    };
    item.envelope.ciphertext = "bad-ciphertext";
    snapshot = { cid: "malformed", entries: [item, planted] };
    const statuses: string[] = [];
    runtime.subscribe?.((status) => {
      statuses.push(status);
    });
    await runtime.sync?.();
    expect(statuses).not.toContain(SYNC_LOCKED);
    expect(await session.open(id)).toBe("retained source");
    expect(runtime.unreadable?.()).toBe(2);
    // The remote revision may be a newer client's, so it is carried as it is, and the pending edit becomes a conflict copy.
    const published = written.at(-1) ?? [];
    expect(published.find((entry) => entry.id === id)).toEqual(item);
    expect(published.find((entry) => entry.id === "planted")).toEqual(planted);
    const copies = (await runtime.list()).filter(
      (note) => note.id !== id && note.source === "retained source",
    );
    expect(copies).toHaveLength(1);
    expect(copies[0]?.path).toContain("conflict");
    expect(published.some((entry) => entry.id === copies[0]?.id)).toBe(true);
    expect(await session.database.outbox.count()).toBe(0);
  } finally {
    runtime.lock();
    key.fill(0);
  }
});

test("v2 snapshots retain composition, recoverable source and private writing preferences across devices", async () => {
  const { VaultDatabase } = await import("../vault/storage.ts");
  const { DEFAULT_WRITING_PREFERENCES } = await import(
    "../writing/preferences.ts"
  );
  const options = {
    owner: "did:plc:writing-snapshot",
    vault: crypto.randomUUID(),
    key: await createVaultKey(),
  };
  const first = createSession(options);
  const second = createSession(options);
  Object.defineProperty(second, "database", {
    value: new VaultDatabase(options.owner, `${options.vault}-second-device`),
  });
  let snapshot: VaultSnapshot | null = null;
  let publications = 0;
  const transport: VaultSnapshotTransport = {
    version: 2,
    async readSnapshot() {
      return structuredClone(snapshot);
    },
    async writeSnapshot(entries, expectedCid) {
      expect(expectedCid).toBe(snapshot?.cid ?? null);
      snapshot = {
        cid: `writing-${++publications}`,
        entries: structuredClone(entries),
      };
      return { cid: snapshot.cid };
    },
  };
  const writer = synchronizedRuntime(first, async () => transport);
  let reader: ReturnType<typeof synchronizedRuntime> | undefined;
  try {
    await writer.sync?.();
    const originId = crypto.randomUUID();
    const targetId = crypto.randomUUID();
    await writer.save({
      id: originId,
      path: "Origin.md",
      kind: "md",
      source: "Source body",
    });
    await writer.save({
      id: targetId,
      path: "Target.md",
      kind: "md",
      source: "Target",
    });
    const preferences = {
      ...DEFAULT_WRITING_PREFERENCES,
      bookmarks: [targetId],
      dailyFolder: "Journal",
    };
    await writer.savePreferences?.(preferences);
    const extracted = await writer.compose?.({
      kind: "extract",
      originId,
      expectedSource: "Source body",
      from: 7,
      to: 11,
      path: "Extract.md",
    });
    if (!extracted) throw new Error("Missing extraction result");
    await writer.compose?.({
      kind: "merge",
      originId: extracted.selectedId,
      targetId,
      expectedSource: "body",
      expectedTargetSource: "Target",
    });
    expect(publications).toBe(0);
    await writer.sync?.();
    expect(publications).toBe(1);
    expect(await first.database.outbox.count()).toBe(0);
    expect(JSON.stringify(snapshot)).not.toContain("Journal");
    expect(JSON.stringify(snapshot)).not.toContain("Source body");
    reader = synchronizedRuntime(second, async () => transport);
    await reader.sync?.();
    const notes = await reader.list();
    expect(notes).toHaveLength(2);
    expect(notes.find((note) => note.id === originId)?.source).toBe(
      "Source [Extract](/Target.md)",
    );
    expect(notes.find((note) => note.id === targetId)?.source).toBe(
      "Target\n\nbody",
    );
    expect(await reader.preferences?.()).toEqual(preferences);
    expect((await reader.trash?.())?.map((note) => note.source)).toEqual([
      "body",
    ]);
    expect(await second.database.outbox.count()).toBe(0);
  } finally {
    writer.lock();
    reader?.lock();
    second.lock();
    options.key.fill(0);
    await first.database.delete();
    await second.database.delete();
  }
});

for (const [reason, blocked] of [
  ["consent", SYNC_AUTHORIZATION_REQUIRED],
  ["quota", SYNC_QUOTA_REACHED],
] as const)
  test(`repeated ${reason} results restore sync attention after local edits`, async () => {
    const key = await createVaultKey();
    const session = createSession({
      owner: "did:plc:blocked-status",
      vault: crypto.randomUUID(),
      key,
    });
    const transport: VaultSnapshotTransport = {
      version: 2,
      readSnapshot: async () => null,
      async writeSnapshot() {
        throw new SyncFailure(reason, "Synthetic blocked publication");
      },
    };
    const runtime = synchronizedRuntime(session, async () => transport);
    try {
      await runtime.sync?.();
      let shown: SyncStatus = SYNC_PENDING;
      runtime.subscribe?.((status) => {
        shown = status;
      });
      expect<SyncStatus>(shown).toBe(SYNCED);
      const note = {
        id: crypto.randomUUID(),
        path: "local.md",
        kind: "md" as const,
        source: "first edit",
      };
      await runtime.save(note);
      await runtime.sync?.();
      expect(shown.startsWith(blocked)).toBe(true);
      await runtime.save({ ...note, source: "second edit" });
      shown = SYNC_PENDING;
      await runtime.sync?.();
      await new Promise((resolve) => setTimeout(resolve, 0));
      expect(shown.startsWith(blocked)).toBe(true);
      const notice = renderToStaticMarkup(
        createElement(SyncNotice, { status: shown, onAuthorize() {} }),
      );
      if (reason === "consent") expect(notice).toContain("Authorize sync");
      else expect(notice).toContain("Your PDS storage is full");
    } finally {
      runtime.lock();
      key.fill(0);
      await session.database.delete();
    }
  });

/** Drives the runtime's own interval at chosen clock times and hands back what each tick published. */
function automaticSyncs(create: () => NoteRuntime) {
  const schedule = spyOn(globalThis, "setInterval");
  const runtime = create();
  const handler = schedule.mock.calls[0]?.[0];
  schedule.mockRestore();
  const published: SyncStatus[] = [];
  let wake = () => {};
  const next = async () => {
    while (!published.length)
      await new Promise<void>((resolve) => {
        wake = resolve;
      });
    return published.shift();
  };
  return {
    runtime,
    next,
    async watch() {
      runtime.subscribe?.((status) => {
        published.push(status);
        wake();
      });
      await next();
    },
    async tickAt(time: number) {
      setSystemTime(time);
      // biome-ignore lint/plugin: TimerHandler is a browser union; the runtime registers a function.
      if (typeof handler === "function") handler();
      return next();
    },
  };
}
const localEditsSettle = () => new Promise((resolve) => setTimeout(resolve, 5));

function refusingWrites(reason: SyncFailure["reason"]) {
  let snapshot: VaultSnapshot | null = null;
  let refusing = true;
  let hold: Promise<void> | null = null;
  let onWrite = () => {};
  const written: SnapshotEntry[][] = [];
  const transport: VaultSnapshotTransport = {
    version: 2,
    async readSnapshot() {
      return structuredClone(snapshot);
    },
    async writeSnapshot(entries) {
      written.push(entries);
      onWrite();
      await hold;
      if (refusing) throw new SyncFailure(reason, "Synthetic refusal");
      snapshot = {
        cid: `cid-${written.length}`,
        entries: structuredClone(entries),
      };
      return { cid: snapshot.cid };
    },
  };
  return {
    transport,
    written,
    accept() {
      refusing = false;
    },
    holdNextWrite() {
      let release = () => {};
      hold = new Promise<void>((resolve) => {
        release = () => {
          hold = null;
          resolve();
        };
      });
      const entered = new Promise<void>((resolve) => {
        onWrite = resolve;
      });
      return { entered, release: () => release() };
    },
  };
}
async function until(condition: () => boolean) {
  while (!condition()) await new Promise((resolve) => setTimeout(resolve, 5));
}
const pendingNote = (path: string) => ({
  id: crypto.randomUUID(),
  path,
  kind: "md" as const,
  source: `source of ${path}`,
});
const tombstoneIn = (entries: SnapshotEntry[] | undefined, id: string) =>
  entries?.find((entry) => entry.id === id)?.recordType ===
  "game.flow.note.tombstone";

test("a delete during a too-large wait tries again at once; an edit doesn't", async () => {
  const key = await createVaultKey();
  const session = createSession({
    owner: "did:plc:too-large-delete",
    vault: crypto.randomUUID(),
    key,
  });
  const { transport, written, accept } = refusingWrites("too-large");
  const runtime = synchronizedRuntime(session, async () => transport);
  const statuses: SyncStatus[] = [];
  runtime.subscribe((status) => {
    statuses.push(status);
  });
  const [kept, first, second] = ["kept.md", "first.md", "second.md"].map(
    pendingNote,
  );
  if (!kept || !first || !second) throw new Error("Missing notes");
  try {
    await runtime.sync();
    for (const note of [kept, first, second]) await runtime.save(note);
    await runtime.sync();
    expect(written).toHaveLength(1);

    await runtime.save({ ...kept, source: "edited during the wait" });
    await localEditsSettle();
    expect(written).toHaveLength(1);

    await runtime.permanentRemove(first.id);
    await until(() => written.length === 2);
    expect(tombstoneIn(written[1], first.id)).toBe(true);
    await until(
      () => statuses.filter((status) => parseSyncBackoff(status)).length === 2,
    );
    expect(parseSyncBackoff(statuses.at(-1) ?? "")?.refusal).toBe(
      SYNC_TOO_LARGE,
    );

    accept();
    await runtime.permanentRemove(second.id);
    await until(() => statuses.at(-1) === SYNCED);
    expect(written).toHaveLength(3);
    expect(await session.database.outbox.count()).toBe(0);
  } finally {
    runtime.lock();
    key.fill(0);
  }
});

test("a delete landing during a too-large attempt is tried once that attempt ends", async () => {
  const key = await createVaultKey();
  const session = createSession({
    owner: "did:plc:too-large-racing-delete",
    vault: crypto.randomUUID(),
    key,
  });
  const { transport, written, holdNextWrite } = refusingWrites("too-large");
  const runtime = synchronizedRuntime(session, async () => transport);
  const [first, second] = ["first.md", "second.md"].map(pendingNote);
  if (!first || !second) throw new Error("Missing notes");
  try {
    await runtime.sync();
    for (const note of [first, second]) await runtime.save(note);
    await runtime.sync();
    expect(written).toHaveLength(1);

    const { entered, release } = holdNextWrite();
    const attempt = runtime.sync();
    await entered;
    await runtime.permanentRemove(first.id);
    expect(written).toHaveLength(2);
    release();
    await attempt;
    await until(() => written.length === 3);
    expect(tombstoneIn(written[1], first.id)).toBe(false);
    expect(tombstoneIn(written[2], first.id)).toBe(true);
  } finally {
    runtime.lock();
    key.fill(0);
  }
});

for (const reason of ["quota", "rate-limited"] as const)
  test(`a delete during a ${reason} wait keeps waiting`, async () => {
    const key = await createVaultKey();
    const session = createSession({
      owner: `did:plc:${reason}-delete`,
      vault: crypto.randomUUID(),
      key,
    });
    const { transport, written } = refusingWrites(reason);
    const runtime = synchronizedRuntime(session, async () => transport);
    const note = pendingNote("note.md");
    try {
      await runtime.sync();
      await runtime.save(note);
      await runtime.sync();
      expect(written).toHaveLength(1);
      await runtime.permanentRemove(note.id);
      await localEditsSettle();
      expect(written).toHaveLength(1);
    } finally {
      runtime.lock();
      key.fill(0);
    }
  });

for (const [reason, refusal] of [
  ["quota", SYNC_QUOTA_REACHED],
  ["rate-limited", SYNC_RATE_LIMITED],
  ["too-large", SYNC_TOO_LARGE],
] as const)
  test(`a ${reason} refusal stops automatic uploads until its backoff ends or the person syncs`, async () => {
    const key = await createVaultKey();
    const session = createSession({
      owner: `did:plc:${reason}-backoff`,
      vault: crypto.randomUUID(),
      key,
    });
    let snapshot: VaultSnapshot | null = null;
    let refusing = true;
    let uploads = 0;
    const transport: VaultSnapshotTransport = {
      version: 2,
      async readSnapshot() {
        return structuredClone(snapshot);
      },
      async writeSnapshot(entries) {
        uploads++;
        if (refusing) throw new SyncFailure(reason, "Synthetic refusal");
        snapshot = { cid: `cid-${uploads}`, entries: structuredClone(entries) };
        return { cid: snapshot.cid };
      },
    };
    const start = Date.now();
    const { runtime, next, watch, tickAt } = automaticSyncs(() =>
      synchronizedRuntime(session, async () => transport),
    );
    const note = {
      id: crypto.randomUUID(),
      path: "blocked.md",
      kind: "md" as const,
      source: "first edit",
    };
    try {
      await runtime.sync?.();
      await watch();
      await runtime.save(note);
      let now = start;
      let retryAt = start;
      for (const wait of [...SYNC_BACKOFF_MS, 1_800_000]) {
        retryAt = now + wait;
        expect(await tickAt(now)).toBe(syncBackoffStatus(refusal, retryAt));
        const attempts = uploads;
        await runtime.save({ ...note, source: `edited at ${now}` });
        await localEditsSettle();
        for (const time of [now + SYNC_INTERVAL_MS, retryAt - 1])
          expect(await tickAt(time)).toBe(syncBackoffStatus(refusal, retryAt));
        expect(uploads).toBe(attempts);
        now = retryAt;
      }
      expect(uploads).toBe(SYNC_BACKOFF_MS.length + 1);

      // A local edit after the wait restarts the ladder at its first step.
      setSystemTime(now);
      await runtime.save({ ...note, source: "edited after the wait" });
      await localEditsSettle();
      expect(await tickAt(now)).toBe(
        syncBackoffStatus(refusal, now + SYNC_BACKOFF_MS[0]),
      );

      // Sync now uploads during the wait, and its refusal starts over too.
      now += 1_000;
      setSystemTime(now);
      const before = uploads;
      await runtime.sync?.();
      expect(uploads).toBe(before + 1);
      const restarted = syncBackoffStatus(refusal, now + SYNC_BACKOFF_MS[0]);
      expect(await next()).toBe(restarted);
      expect(await tickAt(now + SYNC_INTERVAL_MS)).toBe(restarted);
      expect(uploads).toBe(before + 1);

      refusing = false;
      await runtime.sync?.();
      expect(await next()).toBe(SYNCED);
      expect(await session.database.outbox.count()).toBe(0);
      await runtime.save({ ...note, source: "after the refusal cleared" });
      expect(await tickAt(now + 2 * SYNC_INTERVAL_MS)).toBe(SYNCED);
      expect(uploads).toBe(before + 3);
    } finally {
      setSystemTime();
      runtime.lock();
      key.fill(0);
      await session.database.delete();
    }
  });

test("offline failures keep retrying on the normal cadence", async () => {
  const key = await createVaultKey();
  const session = createSession({
    owner: "did:plc:offline-cadence",
    vault: crypto.randomUUID(),
    key,
  });
  let uploads = 0;
  const transport: VaultSnapshotTransport = {
    version: 2,
    readSnapshot: async () => null,
    async writeSnapshot() {
      uploads++;
      throw new SyncFailure("offline", "Synthetic outage");
    },
  };
  const start = Date.now();
  const { runtime, watch, tickAt } = automaticSyncs(() =>
    synchronizedRuntime(session, async () => transport),
  );
  try {
    await runtime.sync?.();
    await watch();
    await runtime.save({
      id: crypto.randomUUID(),
      path: "offline.md",
      kind: "md",
      source: "waiting for the network",
    });
    for (let tick = 0; tick < 4; tick++) {
      expect(await tickAt(start + tick * SYNC_INTERVAL_MS)).toBe(SYNC_BLOCKED);
      expect(uploads).toBe(tick + 1);
    }
  } finally {
    setSystemTime();
    runtime.lock();
    key.fill(0);
    await session.database.delete();
  }
});
