import { afterEach, expect, test } from "bun:test";
import type { NoteDeviceCredentials } from "@flow-industries/id";
import Dexie from "dexie";
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { createSeedRecipient } from "../crypto/access-v3.ts";
import {
  createDeviceSeed,
  type DeviceCheckpoint,
  type DeviceVault,
  deleteDeviceStorage,
  type LinkPrompt,
  linkDevice,
  openDeviceVault,
} from "../device/client.ts";
import {
  type AdminBrowser,
  adminBrowser,
  approveLink,
  fakeFlowId,
  memoryStore,
  openAdminVault,
  TEST_HOST,
} from "./index.ts";

Dexie.dependencies.IDBKeyRange = IDBKeyRange;
const opened: DeviceVault[] = [];
afterEach(() => {
  for (const vault of opened.splice(0)) vault.stop();
  Dexie.dependencies.indexedDB = new IDBFactory();
});

async function linkedDevice(admin: AdminBrowser, label: string) {
  const seed = createDeviceSeed();
  const options = {
    host: TEST_HOST,
    credentials: memoryStore<NoteDeviceCredentials>(),
    checkpoints: memoryStore<DeviceCheckpoint>(),
    fetch: admin.note.fetch,
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
