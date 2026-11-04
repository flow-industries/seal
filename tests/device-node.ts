import { strict as assert } from "node:assert";
import { test } from "node:test";
import type { NoteDeviceCredentials } from "@flow-industries/id";
import Dexie from "dexie";
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { LINK_DEVICES } from "../src/app/flow-devices.ts";
import { addVaultRecipient } from "../src/app/unlock.ts";
import { seedRecipientFromKeys } from "../src/crypto/access-v3.ts";
import { typedPairingCode } from "../src/crypto/link.ts";
import {
  createDeviceSeed,
  type DeviceCheckpoint,
  type LinkPrompt,
  linkDevice,
  openDeviceVault,
} from "../src/device/client.ts";
import { adminBrowser, fakeFlowId, host, memory } from "./device-fixture.ts";

// `bun run test:node` bundles this for Node and runs it there, as the Obsidian plugin and agents run the device client.
Dexie.dependencies.indexedDB = new IDBFactory();
Dexie.dependencies.IDBKeyRange = IDBKeyRange;

test("a device links, writes and reads its note back under Node, at the release's switches", async () => {
  assert.equal(process.versions.bun, undefined);
  assert.equal("document" in globalThis, false);
  assert.equal(LINK_DEVICES, true);
  const note = fakeFlowId();
  const admin = await adminBrowser(note);
  const seed = createDeviceSeed();
  const options = {
    host,
    credentials: memory<NoteDeviceCredentials>(),
    checkpoints: memory<DeviceCheckpoint>(),
    fetch: note.fetch,
  };
  const shown = Promise.withResolvers<LinkPrompt>();
  const linking = linkDevice(seed, {
    ...options,
    label: "Build agent",
    onPrompt: shown.resolve,
  });
  const prompt = await shown.promise;
  const pending = note.lookup(prompt.userCode);
  // The approving tab at the release's own switches, as `/link` runs it.
  await addVaultRecipient(admin.port, {
    recipient: await seedRecipientFromKeys(
      "device",
      pending.boxPublicKey ?? "",
      pending.signPublicKey ?? "",
      pending.label ?? "",
    ),
    link: {
      secret: typedPairingCode(prompt.pairingCode),
      commitment: pending.commitment ?? "",
      approve: async () => note.approve(prompt.userCode),
      revoke: async () => {},
    },
    confirm: async () => {},
  });
  assert.equal((await linking).trust, "handed");

  const id = crypto.randomUUID();
  const written = await openDeviceVault(seed, options);
  try {
    await written.sync();
    await written.saveNote({
      id,
      path: "From Node.md",
      source: "# Written under Node",
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
  } finally {
    reopened.stop();
  }
});
