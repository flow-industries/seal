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
) {
  const seed = createDeviceSeed();
  const options = {
    host: TEST_HOST,
    credentials: memoryStore<NoteDeviceCredentials>(),
    checkpoints: memoryStore<DeviceCheckpoint>(),
    fetch: admin.note.fetch,
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
  expect(admin.note.violations).toEqual([]);
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
  const passkey = `flow-note:${TEST_DID}:${admin.state.vault}`;
  const own = (await createSeedRecipient(device.seed, "device")).id;
  expect(await vaultDatabases()).toEqual(
    expect.arrayContaining([passkey, `${passkey}#${own}`]),
  );
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
