import { expect, test } from "bun:test";
import Dexie from "dexie";
import { IDBKeyRange, indexedDB } from "fake-indexeddb";
import { createAccessRecipient } from "../crypto/access-v2.ts";
import { createSeedRecipient } from "../crypto/access-v3.ts";
import type { VaultRecordV2 } from "../sync/vault-transport.ts";
import { VaultDatabase } from "../vault/storage.ts";
import {
  encryptedHeader,
  legacyHeader,
  passkeyVault,
  signedVault,
} from "../../tests/unlock-fixture.ts";
import { localRuntime } from "./local-runtime.ts";
import type { NoteRuntime } from "./runtime.ts";
import {
  type CheckpointPolicy,
  linkedCheckpoint,
  type SeedUnlockPort,
  type UnlockPort,
  unlockVault,
  unlockVaultWithSeed,
} from "./unlock.ts";

Dexie.dependencies.indexedDB = indexedDB;
Dexie.dependencies.IDBKeyRange = IDBKeyRange;
const did = "did:plc:authorship-unlock";
const prf = () => new Uint8Array(32).fill(7);

function passkeyPort(
  header: VaultRecordV2,
  checkpoint: CheckpointPolicy | null,
): UnlockPort {
  return {
    current: () => ({
      userId: "u",
      did,
      credentialId: "connected",
      sessionVersion: 1,
    }),
    checkpoint: async () => checkpoint,
    saveCheckpoint: async () => {},
    resolve: async () => ({ did, active: true, authorized: true }),
    readHeader: async () => ({ header, cid: "cid" }),
    publish: async () => {
      throw new Error("This test publishes nothing");
    },
    evaluatePrf: async () => prf(),
    runtime: (session) => localRuntime(session),
  };
}
async function writeAndRead(runtime: NoteRuntime, path: string) {
  await runtime.save({
    id: crypto.randomUUID(),
    path,
    source: "# Hi",
    kind: "mdx",
  });
  const note = (await runtime.list()).find((value) => value.path === path);
  runtime.lock();
  return note?.origin;
}
async function forget(vault: string) {
  await new VaultDatabase(did, vault).delete();
}

test("a passkey unlock of a signed vault signs its writes as the admin", async () => {
  const key = new Uint8Array(32).fill(9);
  const { state } = await passkeyVault(key, did, prf(), "connected");
  const header = await encryptedHeader(key, state, did);
  const { runtime } = await unlockVault(passkeyPort(header, null));
  expect(await writeAndRead(runtime, "Mine.mdx")).toEqual({
    runs: true,
    author: "Signed by a passkey",
  });
  await forget(state.vault);
});

test("a passkey unlock of an unsigned vault signs nothing and runs nothing", async () => {
  const key = new Uint8Array(32).fill(9);
  const vault = crypto.randomUUID();
  const header = await legacyHeader(
    key,
    {
      vault,
      epoch: 1,
      recipients: [await createAccessRecipient(prf(), "connected", did)],
    },
    did,
  );
  const { runtime } = await unlockVault(passkeyPort(header, null), {}, false);
  expect(await writeAndRead(runtime, "Legacy.mdx")).toEqual({
    runs: false,
    author: "Not signed",
  });
  await forget(vault);
});

test("a linked device signs as a writer, so its MDX waits for Run in the passkey's browser", async () => {
  const key = new Uint8Array(32).fill(9);
  const { admin, state } = await passkeyVault(key, did, prf(), "connected");
  const seed = new Uint8Array(32).fill(3);
  const device = await createSeedRecipient(seed, "device", "Laptop");
  const enrolled = await signedVault(
    key,
    { did, vault: state.vault, epoch: 1 },
    [admin.recipient, device],
    admin,
    "change",
    2,
  );
  const header = await encryptedHeader(key, enrolled, did);
  const port: SeedUnlockPort = {
    current: () => ({
      userId: "u",
      did,
      recipientId: device.id,
      sessionVersion: 1,
    }),
    checkpoint: async () => linkedCheckpoint(enrolled),
    saveCheckpoint: async () => {},
    resolve: async () => ({ did, active: true, authorized: true }),
    readHeader: async () => ({ header, cid: "cid" }),
    runtime: (session) => localRuntime(session),
  };
  const { runtime } = await unlockVaultWithSeed(port, seed);
  expect(await writeAndRead(runtime, "Plugin.mdx")).toEqual({
    runs: false,
    author: "Signed by device “Laptop”",
  });
  expect(seed.some((byte) => byte !== 0)).toBe(true);
  const { runtime: admins } = await unlockVault(
    passkeyPort(header, linkedCheckpoint(enrolled)),
  );
  expect(
    (await admins.list()).find((note) => note.path === "Plugin.mdx")?.origin,
  ).toEqual({ runs: false, author: "Signed by device “Laptop”" });
  admins.lock();
  await forget(state.vault);
});
