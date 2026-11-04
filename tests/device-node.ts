import { strict as assert } from "node:assert";
import { test } from "node:test";
import Dexie from "dexie";
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { LINK_DEVICES } from "../src/app/flow-devices.ts";
import {
  createDeviceSeed,
  type DeviceCheckpoint,
  type LinkPrompt,
  linkDevice,
  type NoteDeviceCredentials,
  openDeviceVault,
} from "../src/index.ts";
import {
  adminBrowser,
  approveLink,
  fakeFlowId,
  memoryStore,
  TEST_HOST,
} from "../src/testing/index.ts";

// `bun run test:node` bundles this for Node and runs it there, as a plugin or an agent ships the device client.
Dexie.dependencies.indexedDB = new IDBFactory();
Dexie.dependencies.IDBKeyRange = IDBKeyRange;

test("a device links, writes and reads its note and attachment back under Node, at the release's switches", async () => {
  assert.equal(process.versions.bun, undefined);
  assert.equal("document" in globalThis, false);
  assert.equal(LINK_DEVICES, true);
  const note = fakeFlowId();
  const admin = await adminBrowser(note);
  const seed = createDeviceSeed();
  const options = {
    host: TEST_HOST,
    credentials: memoryStore<NoteDeviceCredentials>(),
    checkpoints: memoryStore<DeviceCheckpoint>(),
    fetch: note.fetch,
  };
  const shown = Promise.withResolvers<LinkPrompt>();
  const linking = linkDevice(seed, {
    ...options,
    label: "Build agent",
    onPrompt: shown.resolve,
  });
  // The approving tab at the release's own switches, as the link page runs it.
  await approveLink(admin, await shown.promise);
  assert.equal((await linking).trust, "handed");

  const id = crypto.randomUUID();
  const attachment = crypto.randomUUID();
  const written = await openDeviceVault(seed, options);
  try {
    await written.sync();
    const first = await written.saveNote({
      id,
      path: "From Node.md",
      source: "# Written",
    });
    await written.saveNote({
      id,
      path: "From Node.md",
      source: "# Written under Node",
      ...first,
    });
    await written.saveAttachment({
      id: attachment,
      path: "From Node.bin",
      bytes: new Uint8Array([4, 5, 6]),
    });
    await written.sync();
  } finally {
    written.stop();
  }
  assert.deepEqual(note.violations, []);

  // A fresh local database, so the note can only come back from the PDS.
  Dexie.dependencies.indexedDB = new IDBFactory();
  const reopened = await openDeviceVault(seed, options);
  try {
    await reopened.sync();
    const { notes } = await reopened.read();
    assert.deepEqual(
      notes.map(({ id, path, source }) => ({ id, path, source })),
      [{ id, path: "From Node.md", source: "# Written under Node" }],
    );
    assert.deepEqual(
      [...(await reopened.readAttachment(attachment))],
      [4, 5, 6],
    );
  } finally {
    reopened.stop();
  }
});
