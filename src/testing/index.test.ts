import { afterEach, expect, test } from "bun:test";
import type { NoteDeviceCredentials } from "@flow-industries/id";
import Dexie from "dexie";
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { AccessRemovedError, SYNC_LOCKED } from "../app/runtime.ts";
import { createSeedRecipient } from "../crypto/access-v3.ts";
import { createVaultKey } from "../crypto/index.ts";
import {
  createDeviceSeed,
  type DeviceCheckpoint,
  type DeviceVault,
  deleteDeviceStorage,
  type LinkPrompt,
  linkDevice,
  NoteChangedError,
  openDeviceVault,
} from "../device/client.ts";
import { createSession } from "../vault/session.ts";
import { databaseName, vaultDatabaseNames } from "../vault/storage.ts";
import {
  type AdminBrowser,
  adminBrowser,
  approveLink,
  dropDevices,
  fakeFlowId,
  memoryStore,
  openAdminVault,
  TEST_DID,
  TEST_HOST,
} from "./index.ts";

Dexie.dependencies.IDBKeyRange = IDBKeyRange;
const opened: DeviceVault[] = [];
afterEach(() => {
  for (const vault of opened.splice(0)) vault.stop();
  Dexie.dependencies.indexedDB = new IDBFactory();
});

async function linkedDevice(
  admin: AdminBrowser,
  label: string,
  indexedDB?: { factory: IDBFactory; keyRange: typeof IDBKeyRange },
  fetch = admin.flowId.fetch,
) {
  const seed = createDeviceSeed();
  const options = {
    host: TEST_HOST,
    credentials: memoryStore<NoteDeviceCredentials>(),
    checkpoints: memoryStore<DeviceCheckpoint>(),
    fetch,
    ...(indexedDB && { indexedDB }),
  };
  const shown = Promise.withResolvers<LinkPrompt>();
  const linking = linkDevice(seed, {
    ...options,
    label,
    onPrompt: shown.resolve,
  });
  await approveLink(admin, await shown.promise);
  expect((await linking).trust).toBe("handed");
  const open = async () => {
    const vault = await openDeviceVault(seed, options);
    opened.push(vault);
    return vault;
  };
  return { seed, options, open };
}
const vaultDatabases = async () =>
  (await Dexie.getDatabaseNames()).filter((name) =>
    name.startsWith("flow-note:"),
  );

test("a device and the passkey's notepad exchange notes and attachments through the in-memory Flow ID", async () => {
  Dexie.dependencies.indexedDB = new IDBFactory();
  const admin = await adminBrowser(fakeFlowId());
  const vault = await (await linkedDevice(admin, "Laptop")).open();
  const note = crypto.randomUUID();
  const attachment = crypto.randomUUID();
  await vault.saveNote({ id: note, path: "From device.md", source: "# Hi" });
  await vault.saveAttachment({
    id: attachment,
    path: "Files/data.bin",
    bytes: new Uint8Array([1, 2, 3]),
  });
  await vault.sync();

  const notepad = await openAdminVault(admin);
  try {
    await notepad.sync();
    expect(
      (await notepad.read()).notes.map(({ id, path, source }) => ({
        id,
        path,
        source,
      })),
    ).toEqual([{ id: note, path: "From device.md", source: "# Hi" }]);
    await notepad.save({
      id: crypto.randomUUID(),
      path: "Admin.mdx",
      kind: "mdx",
      source: "export const answer = 42\n\n# {answer}\n",
    });
    await notepad.sync();
  } finally {
    notepad.lock();
  }
  await vault.sync();
  const { notes } = await vault.read();
  expect(notes.find((value) => value.path === "Admin.mdx")?.origin?.runs).toBe(
    true,
  );
  expect(await vault.readAttachment(attachment)).toEqual(
    new Uint8Array([1, 2, 3]),
  );
  expect(admin.flowId.violations).toEqual([]);
}, 30_000);

test("two devices on one origin keep separate databases, and deleting one's storage leaves the other's", async () => {
  Dexie.dependencies.indexedDB = new IDBFactory();
  const admin = await adminBrowser(fakeFlowId());
  const first = await linkedDevice(admin, "Work vault");
  const second = await linkedDevice(admin, "Home vault");
  const one = await first.open();
  const two = await second.open();
  await one.saveNote({ id: crypto.randomUUID(), path: "One.md", source: "1" });
  expect((await two.read()).notes).toEqual([]);
  const own = async (seed: Uint8Array) =>
    `#${(await createSeedRecipient(seed, "device")).id}`;
  const suffixes = [await own(first.seed), await own(second.seed)];
  expect(
    (await vaultDatabases()).map((name) => name.slice(name.indexOf("#"))),
  ).toEqual(expect.arrayContaining(suffixes));

  one.stop();
  await deleteDeviceStorage(first.seed);
  const left = await vaultDatabases();
  expect(left.some((name) => name.endsWith(suffixes[0] ?? ""))).toBe(false);
  expect(left.some((name) => name.endsWith(suffixes[1] ?? ""))).toBe(true);
  // The unsynced note went with the first device's storage; the second device's is untouched.
  expect((await (await first.open()).read()).notes).toEqual([]);
  expect((await two.read()).notes).toEqual([]);
}, 30_000);

/** The device's current view of a note, as its revision base. */
async function baseOf(vault: DeviceVault, path: string) {
  const note = (await vault.read()).notes.find((value) => value.path === path);
  if (!note?.revision || !note.digest) throw new Error(`Missing ${path}`);
  return { note, base: { revision: note.revision, digest: note.digest } };
}

test("a strict write refuses a base another device's synced edit replaced; a default one still replaces that edit", async () => {
  Dexie.dependencies.indexedDB = new IDBFactory();
  const admin = await adminBrowser(fakeFlowId());
  const a = await (await linkedDevice(admin, "Device A")).open();
  const b = await (await linkedDevice(admin, "Device B")).open();
  const id = crypto.randomUUID();
  await a.saveNote({ id, path: "Shared.md", source: "first" });
  await a.sync();
  await b.sync();
  const seen = await baseOf(a, "Shared.md");
  const edit = await baseOf(b, "Shared.md");
  await b.saveNote({ ...edit.note, source: "B's edit" });
  await b.sync();
  // A's own sync takes in B's edit after A read: A's base is now an older row it can still place.
  await a.sync();
  const plan = { ...seen.note, source: "A's plan" };
  await expect(a.saveNote(plan, { current: true })).rejects.toBeInstanceOf(
    NoteChangedError,
  );
  await expect(a.rename(id, "Moved.md", seen.base)).rejects.toBeInstanceOf(
    NoteChangedError,
  );
  await expect(a.remove(id, seen.base)).rejects.toBeInstanceOf(
    NoteChangedError,
  );
  expect((await baseOf(a, "Shared.md")).note.source).toBe("B's edit");

  // On the current revision each one goes through.
  const current = await baseOf(a, "Shared.md");
  const saved = await a.saveNote(
    { ...current.note, source: "A, after reading B" },
    { current: true },
  );
  const moved = await a.rename(id, "Moved.md", saved);
  expect((await baseOf(a, "Moved.md")).base).toEqual(moved);
  await a.remove(id, moved);
  expect((await a.read()).notes).toEqual([]);

  // Without `current`, the same stale plan is an edit of the older row and replaces B's text.
  const again = crypto.randomUUID();
  await a.saveNote({ id: again, path: "Again.md", source: "first" });
  await a.sync();
  await b.sync();
  const stale = await baseOf(a, "Again.md");
  await b.saveNote({ ...(await baseOf(b, "Again.md")).note, source: "B" });
  await b.sync();
  await a.sync();
  await a.saveNote({ ...stale.note, source: "A's plan" });
  expect((await baseOf(a, "Again.md")).note.source).toBe("A's plan");
}, 60_000);

test("a strict attachment save refuses a base the device itself already wrote past", async () => {
  Dexie.dependencies.indexedDB = new IDBFactory();
  const admin = await adminBrowser(fakeFlowId());
  const vault = await (await linkedDevice(admin, "Laptop")).open();
  const id = crypto.randomUUID();
  const path = "Files/data.bin";
  const first = await vault.saveAttachment({
    id,
    path,
    bytes: new Uint8Array([1]),
  });
  const second = await vault.saveAttachment({
    id,
    path,
    bytes: new Uint8Array([2]),
    ...first,
  });
  const write = { id, path, bytes: new Uint8Array([3]), ...first };
  await expect(
    vault.saveAttachment(write, { current: true }),
  ).rejects.toBeInstanceOf(NoteChangedError);
  expect(await vault.readAttachment(id)).toEqual(new Uint8Array([2]));
  await vault.saveAttachment({ ...write, ...second }, { current: true });
  expect(await vault.readAttachment(id)).toEqual(new Uint8Array([3]));
}, 30_000);

test("dropDevices removes every linked device's slot: a running device locks and a new open is refused", async () => {
  Dexie.dependencies.indexedDB = new IDBFactory();
  const admin = await adminBrowser(fakeFlowId());
  const device = await linkedDevice(admin, "Laptop");
  const vault = await device.open();
  await vault.saveNote({ id: crypto.randomUUID(), path: "A.md", source: "a" });
  await vault.sync();
  const statuses: string[] = [];
  vault.subscribe((status) => {
    statuses.push(status);
  });
  await dropDevices(admin);
  await vault.sync();
  expect(statuses).toContain(SYNC_LOCKED);
  await expect(
    openDeviceVault(device.seed, device.options),
  ).rejects.toBeInstanceOf(AccessRemovedError);
  const notepad = await openAdminVault(admin);
  try {
    await notepad.sync();
    expect((await notepad.read()).notes.map((note) => note.path)).toEqual([
      "A.md",
    ]);
  } finally {
    notepad.lock();
  }
}, 30_000);

test("passkey sessions keep today's database names, and deleting a device's storage never touches them", async () => {
  Dexie.dependencies.indexedDB = new IDBFactory();
  const vault = crypto.randomUUID();
  expect(databaseName("did:plc:x", vault, 1)).toBe(
    `flow-note:did:plc:x:${vault}`,
  );
  expect(databaseName("did:plc:x", vault, 3)).toBe(
    `flow-note:did:plc:x:${vault}:3`,
  );
  expect(() => databaseName("did:plc:x", `${vault}#device`, 1)).toThrow(
    "Invalid vault database name",
  );
  expect(() => databaseName("did:plc:x#y", vault, 1, "device")).toThrow(
    "Invalid vault database name",
  );
  const key = await createVaultKey();
  for (const epoch of [1, 2]) {
    const session = createSession({ owner: "did:plc:x", vault, key, epoch });
    expect(session.database.name).toBe(
      epoch > 1
        ? `flow-note:did:plc:x:${vault}:2`
        : `flow-note:did:plc:x:${vault}`,
    );
    session.lock();
  }

  const admin = await adminBrowser(fakeFlowId());
  const device = await linkedDevice(admin, "Laptop");
  await (await device.open()).sync();
  const notepad = await openAdminVault(admin);
  await notepad.save({
    id: crypto.randomUUID(),
    path: "Unsynced.md",
    kind: "md",
    source: "kept",
  });
  notepad.lock();
  const own = (await createSeedRecipient(device.seed, "device")).id;
  const names = await vaultDatabases();
  const passkey = names.find((name) => !name.includes("#")) ?? "";
  expect(passkey).toMatch(
    new RegExp(`^flow-note:${TEST_DID}:[0-9a-f-]{36}$`, "u"),
  );
  expect(names.toSorted()).toEqual([passkey, `${passkey}#${own}`]);
  for (const vault of opened.splice(0)) vault.stop();
  await deleteDeviceStorage(device.seed);
  expect(await vaultDatabases()).toContain(passkey);
  expect(await vaultDatabases()).not.toContain(`${passkey}#${own}`);
  const reopened = await openAdminVault(admin);
  try {
    expect((await reopened.read()).notes.map((note) => note.source)).toEqual([
      "kept",
    ]);
  } finally {
    reopened.lock();
  }
}, 30_000);

test("a device given its own IndexedDB keeps its databases there, and deletes them there", async () => {
  Dexie.dependencies.indexedDB = new IDBFactory();
  const factory = new IDBFactory();
  const indexedDB = { factory, keyRange: IDBKeyRange };
  const admin = await adminBrowser(fakeFlowId());
  const device = await linkedDevice(admin, "Laptop", indexedDB);
  const vault = await device.open();
  await vault.saveNote({ id: crypto.randomUUID(), path: "A.md", source: "a" });
  expect(await vaultDatabaseNames({ indexedDB })).toHaveLength(1);
  expect(await vaultDatabases()).toEqual([]);
  vault.stop();
  await deleteDeviceStorage(device.seed, { indexedDB });
  expect(await vaultDatabaseNames({ indexedDB })).toEqual([]);
}, 30_000);

/**
 * Flow ID as `admin` serves it, except that vault record requests fail while
 * `offline`, and wait while held: every one, or with `puts` only the writes.
 */
function unreliable(admin: AdminBrowser) {
  const state = {
    held: false,
    putsOnly: false,
    offline: false,
    release: () => {},
    /** Resolves when a held request first reaches the gate. */
    reached: Promise.resolve(),
  };
  let gate = Promise.resolve();
  let arrived = () => {};
  const fetch: AdminBrowser["flowId"]["fetch"] = async (url, init) => {
    if (new URL(url).pathname === "/api/atproto/note/records") {
      if (state.offline) throw new TypeError("fetch failed");
      const put = JSON.parse(String(init.body)).method === "put";
      if (state.held && (put || !state.putsOnly)) {
        arrived();
        await gate;
      }
    }
    return admin.flowId.fetch(url, init);
  };
  return {
    state,
    fetch,
    hold(puts = false) {
      const { promise, resolve } = Promise.withResolvers<void>();
      const reached = Promise.withResolvers<void>();
      gate = promise;
      arrived = reached.resolve;
      Object.assign(state, {
        held: true,
        putsOnly: puts,
        reached: reached.promise,
        release: () => {
          state.held = false;
          resolve();
        },
      });
    },
  };
}

test("stop() lets a running save land and waits out a sync in flight, so deleting the device's storage races nothing", async () => {
  Dexie.dependencies.indexedDB = new IDBFactory();
  const admin = await adminBrowser(fakeFlowId());
  const network = unreliable(admin);
  const device = await linkedDevice(admin, "Laptop", undefined, network.fetch);
  const vault = await device.open();
  await vault.sync();
  network.hold();
  const syncing = vault.sync();
  const saving = vault.saveNote({
    id: crypto.randomUUID(),
    path: "Kept.md",
    source: "kept",
  });
  let stopped = false;
  const stopping = vault.stop().then(() => {
    stopped = true;
  });
  await expect(
    vault.saveNote({ id: crypto.randomUUID(), path: "Late.md", source: "" }),
  ).rejects.toThrow("Vault locked");
  expect(await saving).toMatchObject({ revision: expect.any(String) });
  await Bun.sleep(50);
  expect(stopped).toBe(false);
  network.state.release();
  await stopping;
  expect(await syncing).toEqual({ read: false });
  await deleteDeviceStorage(device.seed);
  expect(await vaultDatabases()).toEqual([]);
}, 30_000);

test("sync() says whether it read the vault from the PDS", async () => {
  Dexie.dependencies.indexedDB = new IDBFactory();
  const admin = await adminBrowser(fakeFlowId());
  const network = unreliable(admin);
  const vault = await (
    await linkedDevice(admin, "Laptop", undefined, network.fetch)
  ).open();
  expect(await vault.sync()).toEqual({ read: true });
  network.state.offline = true;
  expect(await vault.sync()).toEqual({ read: false });
  network.state.offline = false;
  expect(await vault.sync()).toEqual({ read: true });
  await vault.stop();
  expect(await vault.sync()).toEqual({ read: false });
}, 30_000);

/** Alpha, Beta and an Index linking to both, as one device holds them. */
async function linkedNotes() {
  Dexie.dependencies.indexedDB = new IDBFactory();
  const admin = await adminBrowser(fakeFlowId());
  const vault = await (await linkedDevice(admin, "Laptop")).open();
  const ids = {
    alpha: crypto.randomUUID(),
    beta: crypto.randomUUID(),
    index: crypto.randomUUID(),
  };
  await vault.saveNote({ id: ids.alpha, path: "Alpha.md", source: "alpha" });
  await vault.saveNote({ id: ids.beta, path: "Beta.md", source: "beta" });
  const index = { id: ids.index, path: "Index.md" };
  const written = await vault.saveNote({
    ...index,
    source: "first [[Alpha]] then [[Beta]]",
  });
  const source = async (id: string) =>
    (await vault.read()).notes.find((note) => note.id === id)?.source;
  /** The Index text an editor already rewrote for the new names, saved first, as a plugin pushes it. */
  const edited = (text: string) =>
    vault.saveNote({ ...index, ...written, source: text });
  return { vault, ids, source, edited };
}

/** What a plugin passes for a move Obsidian made: it rewrote the `.md` notes it indexes, and nothing else. */
const unindexedOnly = (path: string) => !path.endsWith(".md");

test.each([
  ["false", false],
  ["a predicate that leaves .md notes alone", unindexedOnly],
] as const)(
  "moves with repairLinks %s keep .md links an editor already rewrote, through a swap and a chain",
  async (_, repairLinks) => {
    const skip = { repairLinks };
    const swap = await linkedNotes();
    await swap.edited("first [[Beta]] then [[Alpha]]");
    await swap.vault.rename(swap.ids.alpha, "Alpha moving.md", undefined, skip);
    await swap.vault.rename(swap.ids.beta, "Alpha.md", undefined, skip);
    await swap.vault.rename(swap.ids.alpha, "Beta.md", undefined, skip);
    expect(await swap.source(swap.ids.index)).toBe(
      "first [[Beta]] then [[Alpha]]",
    );

    const chain = await linkedNotes();
    await chain.edited("first [[Beta]] then [[Gamma]]");
    const beta = (await chain.vault.read()).notes.find(
      (note) => note.id === chain.ids.beta,
    );
    if (!beta) throw new Error("Missing Beta");
    await chain.vault.saveNote({ ...beta, path: "Gamma.md" }, skip);
    await chain.vault.rename(chain.ids.alpha, "Beta.md", undefined, skip);
    expect(await chain.source(chain.ids.index)).toBe(
      "first [[Beta]] then [[Gamma]]",
    );
  },
  30_000,
);

test("a repairLinks predicate repairs the linking notes it accepts and leaves the rest as written", async () => {
  const { vault, ids, source } = await linkedNotes();
  const mdx = crypto.randomUUID();
  await vault.saveNote({ id: mdx, path: "Chart.mdx", source: "see [[Alpha]]" });
  const asked: string[] = [];
  await vault.rename(ids.alpha, "Zeta.md", undefined, {
    repairLinks: (path) => {
      asked.push(path);
      return unindexedOnly(path);
    },
  });
  expect(await source(mdx)).toBe("see [[/Zeta]]");
  expect(await source(ids.index)).toBe("first [[Alpha]] then [[Beta]]");
  expect(asked.toSorted()).toEqual(["Chart.mdx", "Index.md"]);

  const beta = (await vault.read()).notes.find((note) => note.id === ids.beta);
  if (!beta) throw new Error("Missing Beta");
  await vault.saveNote({ ...beta, path: "Delta.md" }, { repairLinks: true });
  expect(await source(ids.index)).toBe("first [[Alpha]] then [[/Delta]]");
}, 30_000);

test("moves repair links by default, and re-target links an editor already rewrote when names swap", async () => {
  const single = await linkedNotes();
  await single.vault.rename(single.ids.alpha, "Gamma.md");
  expect(await single.source(single.ids.index)).toBe(
    "first [[/Gamma]] then [[Beta]]",
  );
  const beta = (await single.vault.read()).notes.find(
    (note) => note.id === single.ids.beta,
  );
  if (!beta) throw new Error("Missing Beta");
  await single.vault.saveNote({ ...beta, path: "Delta.md" });
  expect(await single.source(single.ids.index)).toBe(
    "first [[/Gamma]] then [[/Delta]]",
  );

  const swap = await linkedNotes();
  await swap.edited("first [[Beta]] then [[Alpha]]");
  await swap.vault.rename(swap.ids.alpha, "Alpha moving.md");
  await swap.vault.rename(swap.ids.beta, "Alpha.md");
  await swap.vault.rename(swap.ids.alpha, "Beta.md");
  expect(await swap.source(swap.ids.index)).not.toBe(
    "first [[Beta]] then [[Alpha]]",
  );
}, 30_000);

test("a sync() that finds one running waits for a run of its own, so a save made meanwhile reaches the PDS before stop()", async () => {
  Dexie.dependencies.indexedDB = new IDBFactory();
  const admin = await adminBrowser(fakeFlowId());
  const network = unreliable(admin);
  const vault = await (
    await linkedDevice(admin, "Laptop", undefined, network.fetch)
  ).open();
  await vault.sync();
  await vault.saveNote({
    id: crypto.randomUUID(),
    path: "First.md",
    source: "1",
  });
  network.hold(true);
  const first = vault.sync();
  await network.state.reached;
  await vault.saveNote({
    id: crypto.randomUUID(),
    path: "Second.md",
    source: "2",
  });
  const second = vault.sync();
  network.state.release();
  expect(await first).toEqual({ read: true });
  expect(await second).toEqual({ read: true });
  await vault.stop();
  const notepad = await openAdminVault(admin);
  try {
    await notepad.sync();
    expect(
      (await notepad.read()).notes.map((note) => note.path).toSorted(),
    ).toEqual(["First.md", "Second.md"]);
  } finally {
    notepad.lock();
  }
}, 30_000);

test("a repairLinks predicate is asked about each linking note at its path after the move, the moved note's own links included", async () => {
  Dexie.dependencies.indexedDB = new IDBFactory();
  const admin = await adminBrowser(fakeFlowId());
  const vault = await (await linkedDevice(admin, "Laptop")).open();
  const moved = crypto.randomUUID();
  await vault.saveNote({
    id: crypto.randomUUID(),
    path: "A/Sibling.md",
    source: "sibling",
  });
  await vault.saveNote({
    id: moved,
    path: "A/x.md",
    source: "[s](Sibling.md)",
  });
  const asked: string[] = [];
  await vault.rename(moved, "B/x.mdx", undefined, {
    repairLinks: (path) => {
      asked.push(path);
      return unindexedOnly(path);
    },
  });
  expect(asked).toEqual(["B/x.mdx"]);
  const note = (await vault.read()).notes.find((value) => value.id === moved);
  expect(note?.source).toBe("[s](../A/Sibling.md)");
}, 30_000);

test("a status listener that throws neither fails a sync nor stops later sync() calls from waiting for a run of their own", async () => {
  Dexie.dependencies.indexedDB = new IDBFactory();
  const admin = await adminBrowser(fakeFlowId());
  const network = unreliable(admin);
  const vault = await (
    await linkedDevice(admin, "Laptop", undefined, network.fetch)
  ).open();
  await vault.sync();
  let throwing = false;
  const heard: string[] = [];
  const unsubscribe = vault.subscribe(() => {
    if (throwing) throw new Error("listener bug");
  });
  vault.subscribe((status) => {
    heard.push(status);
  });
  throwing = true;
  const save = (path: string) =>
    vault.saveNote({ id: crypto.randomUUID(), path, source: path });

  await save("B.md");
  network.hold(true);
  const running = vault.sync();
  await network.state.reached;
  const joined = vault.sync();
  network.state.release();
  expect(await running).toEqual({ read: true });
  expect(await joined).toEqual({ read: true });
  expect(heard.length).toBeGreaterThan(0);
  throwing = false;
  unsubscribe();

  await save("C.md");
  network.hold(true);
  const next = vault.sync();
  await network.state.reached;
  await save("D.md");
  let settled = false;
  const later = vault.sync().finally(() => {
    settled = true;
  });
  await Bun.sleep(50);
  expect(settled).toBe(false);
  network.state.release();
  await next;
  expect(await later).toEqual({ read: true });
  await vault.stop();
  const notepad = await openAdminVault(admin);
  try {
    await notepad.sync();
    expect(
      (await notepad.read()).notes.map((note) => note.path).toSorted(),
    ).toEqual(["B.md", "C.md", "D.md"]);
  } finally {
    notepad.lock();
  }
}, 30_000);
