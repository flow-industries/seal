import { describe, expect, test } from "bun:test";
import Dexie from "dexie";
import { IDBKeyRange, indexedDB } from "fake-indexeddb";
import golden from "../../tests/fixtures/note-v2-vault.json";
import {
  encryptedHeader,
  legacyHeader,
  passkeyVault,
  signedVault,
} from "../../tests/unlock-fixture.ts";
import {
  accessHeaderCommitment,
  createAccessRecipient,
  unwrapAccessKey,
  v2PrfInput,
} from "../crypto/access-v2.ts";
import {
  createSeedRecipient,
  passkeyAdmin,
  UNTRUSTED_ACCESS,
} from "../crypto/access-v3.ts";
import { createRecoveryFile } from "../crypto/index.ts";
import {
  readVerifiedVaultRoot,
  type VaultRecordV2,
  vaultRecordSchema,
} from "../sync/vault-transport.ts";
import { localRuntime } from "./local-runtime.ts";
import { MigrationConfirmationError } from "./runtime.ts";
import {
  type Checkpoint,
  type CheckpointPolicy,
  linkedCheckpoint,
  type SeedUnlockPort,
  type UnlockPort,
  unlockVault,
  unlockVaultWithSeed,
  type VerifiedVault,
  verifyHeader,
} from "./unlock.ts";

Dexie.dependencies.indexedDB = indexedDB;
Dexie.dependencies.IDBKeyRange = IDBKeyRange;
const did = "did:plc:test";
const prf = () => new Uint8Array(32).fill(7);
const record = (key: Uint8Array, state: VerifiedVault) =>
  encryptedHeader(key, state, did);
const contextOf = (state: VerifiedVault) => ({
  did,
  vault: state.vault,
  epoch: state.epoch,
});
const checkpointOf = (state: VerifiedVault): Checkpoint => ({
  vault: state.vault,
  epoch: state.epoch,
  pinned: state.pinned ?? undefined,
  trust: state.trust,
});
async function metadataOf(key: Uint8Array, header: VaultRecordV2) {
  return (await readVerifiedVaultRoot(key, did, header)).metadata;
}
async function fixture() {
  const key = new Uint8Array(32).fill(9);
  const { admin, state } = await passkeyVault(key, did, prf(), "connected");
  let header: VaultRecordV2 | null = await record(key, state);
  let checkpoint: CheckpointPolicy | null = checkpointOf(state);
  let evaluations = 0;
  let writes = 0;
  let credentialId = "connected";
  const port: UnlockPort = {
    current: () => ({ userId: "u", did, credentialId, sessionVersion: 1 }),
    checkpoint: async () => checkpoint,
    saveCheckpoint: async (value) => {
      checkpoint = value;
    },
    resolve: async () => ({ did, active: true, authorized: true }),
    readHeader: async () => (header ? { header, cid: "cid" } : null),
    publish: async (publishedKey, publishedState) => {
      writes++;
      header = await record(publishedKey, publishedState);
    },
    evaluatePrf: async (input) => {
      expect(input).toEqual(await v2PrfInput());
      evaluations++;
      return prf();
    },
    runtime: (session) => localRuntime(session),
  };
  return {
    port,
    key,
    admin,
    state,
    header: () => {
      if (!header) throw new Error("Missing test header");
      return header;
    },
    setHeader: (value: VaultRecordV2 | null) => {
      header = value;
    },
    checkpoint: () => checkpoint,
    setCheckpoint: (value: CheckpointPolicy | null) => {
      checkpoint = value;
    },
    setCredential: (value: string) => {
      credentialId = value;
    },
    counts: () => ({ evaluations, writes }),
  };
}
describe("strict v2 unlock", () => {
  test("evaluates actual fixed-domain PRF on every unlock and does not rewrite existing access", async () => {
    const f = await fixture();
    const before = f.header();
    (await unlockVault(f.port)).runtime.lock();
    (await unlockVault(f.port)).runtime.lock();
    expect(f.counts()).toEqual({ evaluations: 2, writes: 0 });
    expect(f.header()).toBe(before);
  });
  test("authenticates a pinned admin's re-randomized header and rejects revoked membership and rollback", async () => {
    const f = await fixture();
    const changed = await signedVault(
      f.key,
      contextOf(f.state),
      [f.admin.recipient],
      f.admin,
      "change",
      2,
    );
    const fresh = await record(f.key, changed);
    expect(fresh.accessSalt).not.toBe(f.header().accessSalt);
    const verified = await verifyHeader(
      f.key,
      did,
      fresh,
      f.state.ownRecipient,
      checkpointOf(f.state),
    );
    expect(verified.access).toEqual(changed.access);
    expect(verified.pinned).toEqual(changed.pinned);
    const other = await passkeyAdmin(prf(), "other", did);
    const dropped = await record(
      f.key,
      await signedVault(f.key, contextOf(f.state), [other.recipient], other),
    );
    await expect(
      verifyHeader(f.key, did, dropped, f.state.ownRecipient, null),
    ).rejects.toThrow("cannot unlock");
    await expect(
      verifyHeader(f.key, did, fresh, f.state.ownRecipient, {
        ...checkpointOf(f.state),
        epoch: 2,
      }),
    ).rejects.toThrow("rollback");
    await expect(
      verifyHeader(
        f.key,
        did,
        { ...fresh, accessSalt: f.header().accessSalt },
        f.state.ownRecipient,
        checkpointOf(f.state),
      ),
    ).rejects.toThrow();
  });
  test("refuses unsigned metadata over the v3 slot it opened, which only a downgrade produces", async () => {
    const f = await fixture();
    const { header } = f.state.access;
    const downgraded = await encryptedHeader(
      f.key,
      {
        vault: f.state.vault,
        epoch: f.state.epoch,
        access: {
          header,
          metadata: {
            recipients: [
              {
                credentialHash: f.admin.recipient.id,
                publicKey: f.admin.recipient.boxPublicKey,
              },
            ],
            accessCommitment: await accessHeaderCommitment(header),
          },
        },
      },
      did,
    );
    const verify = (slotVersion?: 2 | 3) =>
      verifyHeader(f.key, did, downgraded, f.state.ownRecipient, null, {
        slotVersion,
      });
    await expect(verify(3)).rejects.toThrow(UNTRUSTED_ACCESS);
    // The same root read through a v2 slot is a legacy vault, judged by the unlock that migrates it.
    expect((await verify(2)).pinned).toBeNull();
  });
  test("recovery of an unsigned vault evaluates PRF once and adds the passkey only after authenticating it, dropping nobody", async () => {
    const f = await fixture();
    const first = await createAccessRecipient(prf(), "connected", did);
    f.setHeader(
      await legacyHeader(
        f.key,
        { vault: f.state.vault, epoch: 1, recipients: [first] },
        did,
      ),
    );
    f.setCheckpoint({ vault: f.state.vault, epoch: 1 });
    const recovery = await createRecoveryFile(f.key, {
      did,
      vault: f.state.vault,
      epoch: 1,
      item: "recovery",
      revision: "vault-key-v1",
      assets: [],
    });
    f.setCredential("second");
    const evaluatePrf = f.port.evaluatePrf;
    f.port.evaluatePrf = async () => {
      throw new Error("PRF unsupported");
    };
    await expect(unlockVault(f.port, { recovery }, false)).rejects.toThrow(
      "PRF unsupported",
    );
    expect(f.counts().writes).toBe(0);
    f.port.evaluatePrf = evaluatePrf;
    (await unlockVault(f.port, { recovery }, false)).runtime.lock();
    expect(f.counts()).toEqual({ evaluations: 1, writes: 1 });
    const second = await createAccessRecipient(prf(), "second", did);
    expect(await metadataOf(f.key, f.header())).toEqual({
      recipients: [first, second],
      accessCommitment: expect.any(String),
    });
  });
  test.each([false, true])(
    "setup is explicit, refuses loss of an existing checkpoint and signs only when enabled (%p)",
    async (signAccess) => {
      const f = await fixture();
      f.setHeader(null);
      await expect(
        unlockVault(f.port, { setup: true }, signAccess),
      ).rejects.toThrow("rollback");
      f.setCheckpoint(null);
      await expect(unlockVault(f.port, {}, signAccess)).rejects.toThrow(
        "Existing vault",
      );
      (await unlockVault(f.port, { setup: true }, signAccess)).runtime.lock();
      expect(f.counts()).toEqual({ evaluations: 1, writes: 1 });
      expect(Object.keys(f.header()).sort()).toEqual([
        "$type",
        "access",
        "accessSalt",
        "blobs",
        "root",
        "version",
      ]);
      expect(f.header().access).toHaveLength(16);
      const opened = await unwrapAccessKey(
        { accessSalt: f.header().accessSalt, access: f.header().access },
        prf(),
        "connected",
        did,
      );
      expect(opened.version).toBe(signAccess ? 3 : 2);
      const created = await metadataOf(opened.key, f.header());
      if (signAccess)
        expect(created).toMatchObject({
          version: 3,
          epoch: 1,
          statement: {
            kind: "create",
            signer: f.admin.recipient.id,
            sequence: 1,
          },
        });
      else
        expect(created).toEqual({
          recipients: [
            {
              credentialHash: f.admin.recipient.id,
              publicKey: f.admin.recipient.boxPublicKey,
            },
          ],
          accessCommitment: expect.any(String),
        });
      expect(f.checkpoint()).toMatchObject({
        pinned: signAccess ? expect.any(Object) : null,
      });
    },
  );
  test("a wrong recovery key cannot poison recipient access and setup ABA zeroes PRF", async () => {
    const f = await fixture();
    const recovery = await createRecoveryFile(new Uint8Array(32).fill(2), {
      did,
      vault: f.state.vault,
      epoch: 1,
      item: "recovery",
      revision: "vault-key-v1",
      assets: [],
    });
    f.setCredential("second");
    await expect(unlockVault(f.port, { recovery })).rejects.toThrow();
    expect(f.counts().writes).toBe(0);
    f.setHeader(null);
    f.setCheckpoint(null);
    let generation = 1;
    f.port.current = () => ({
      userId: "u",
      did,
      credentialId: "connected",
      sessionVersion: generation,
    });
    const output = prf();
    f.port.evaluatePrf = async () => {
      generation += 2;
      return output;
    };
    await expect(unlockVault(f.port, { setup: true })).rejects.toThrow(
      "Account changed",
    );
    expect(output.every((byte) => byte === 0)).toBe(true);
    expect(f.counts().writes).toBe(0);
  });
  test("inactive or unauthorized resolution cannot prompt or publish", async () => {
    for (const resolution of [
      { did, active: false, authorized: true },
      { did, active: true, authorized: false },
    ]) {
      const f = await fixture();
      f.port.resolve = async () => resolution;
      await expect(unlockVault(f.port)).rejects.toThrow(
        "Authorized active PDS required",
      );
      expect(f.counts()).toEqual({ evaluations: 0, writes: 0 });
    }
  });
});

interface Publication {
  state?: VerifiedVault;
  expectedCid?: string | null;
}
describe("signed access", () => {
  async function goldenFixture() {
    const header = vaultRecordSchema.parse(golden.record);
    const f = await fixture();
    f.setHeader(header);
    f.setCheckpoint({ vault: golden.vault, epoch: 1 });
    return { ...f, original: header };
  }
  test("a vault written by the v2 code unlocks unchanged while signed access is off", async () => {
    const f = await goldenFixture();
    f.port.current = () => ({
      userId: "u",
      did: golden.did,
      credentialId: "golden-first",
      sessionVersion: 1,
    });
    f.port.resolve = async () => ({
      did: golden.did,
      active: true,
      authorized: true,
    });
    (await unlockVault(f.port, {}, false)).runtime.lock();
    expect(f.counts().writes).toBe(0);
    expect(f.header()).toBe(f.original);
    expect(f.checkpoint()).toEqual({
      vault: golden.vault,
      epoch: 1,
      pinned: null,
    });
  });
  test("a vault written by the v2 code migrates once signed access is on, signing in only the passkey that unlocks; a co-passkey Flow ID lists holds it back", async () => {
    const f = await goldenFixture();
    f.port.current = () => ({
      userId: "u",
      did: golden.did,
      credentialId: "golden-first",
      sessionVersion: 1,
    });
    f.port.resolve = async () => ({
      did: golden.did,
      active: true,
      authorized: true,
    });
    const listing = (...credentialIds: string[]) => ({
      rpId: "id.flow.industries",
      origin: "https://note.flow.talk",
      registered: async () =>
        credentialIds.map((credentialId) => ({
          credentialId,
          publicKey: `0x${"a".repeat(128)}`,
        })),
    });
    const captured: Publication = {};
    f.port.publish = async (publishedKey, state, expectedCid) => {
      captured.state = state;
      captured.expectedCid = expectedCid;
      f.setHeader(await encryptedHeader(publishedKey, state, golden.did));
    };
    // The second entry's keys can't be checked without its passkey, so dropping it while Flow ID lists it is the person's call.
    f.port.passkeys = listing("golden-first", "golden-second");
    const asked = await unlockVault(f.port, {}, true).catch((error) => error);
    expect(asked).toBeInstanceOf(MigrationConfirmationError);
    expect(captured.state).toBeUndefined();
    expect(f.header()).toBe(f.original);
    expect(f.checkpoint()).toEqual({ vault: golden.vault, epoch: 1 });
    const first = await passkeyAdmin(prf(), "golden-first", golden.did);
    (
      await unlockVault(f.port, { confirmMigration: asked.confirmation }, true)
    ).runtime.lock();
    const published = captured.state;
    expect(captured.expectedCid).toBe("cid");
    if (!published) throw new Error("Migration did not publish");
    const migrated = published.access.metadata;
    if (!("version" in migrated)) throw new Error("Migration left v2 access");
    expect(migrated.statement).toMatchObject({
      kind: "migrate",
      signer: first.recipient.id,
      sequence: 1,
    });
    expect(migrated.recipients).toEqual([first.recipient]);
    expect(published.access.header.accessSalt).not.toBe(f.original.accessSalt);
    for (const slot of published.access.header.access)
      expect(
        f.original.access.some(
          (old) => old.keyId === slot.keyId || old.wrapped === slot.wrapped,
        ),
      ).toBe(false);
    // It signed nothing it didn't derive itself, so the pin is one it created.
    expect(published.trust).toBe("created");
    expect(f.checkpoint()).toEqual(checkpointOf(published));
    const migratedHeader = f.header();
    const writes = f.counts().writes;
    (await unlockVault(f.port, {}, true)).runtime.lock();
    expect(f.header()).toBe(migratedHeader);
    expect(f.counts().writes).toBe(writes);
  });
  test("a pinned device refuses an unsigned v2 rollback, an unpinned signer and a re-key without a change", async () => {
    const f = await fixture();
    const intruder = await passkeyAdmin(
      new Uint8Array(32).fill(4),
      "intruder",
      did,
    );
    const forged = await signedVault(
      f.key,
      contextOf(f.state),
      [f.admin.recipient, intruder.recipient],
      intruder,
      "change",
    );
    f.setHeader(await record(f.key, forged));
    await expect(unlockVault(f.port)).rejects.toThrow(
      "not signed by a trusted key",
    );
    f.setHeader(vaultRecordSchema.parse(golden.record));
    f.setCheckpoint({ ...checkpointOf(f.state), vault: golden.vault });
    f.port.current = () => ({
      userId: "u",
      did: golden.did,
      credentialId: "golden-first",
      sessionVersion: 1,
    });
    f.port.resolve = async () => ({
      did: golden.did,
      active: true,
      authorized: true,
    });
    await expect(unlockVault(f.port)).rejects.toThrow(
      "not signed by a trusted key",
    );
    expect(f.counts().writes).toBe(0);
  });
  test("an epoch increase is accepted only with a change signed by a pinned admin", async () => {
    const f = await fixture();
    const rotated = new Uint8Array(32).fill(12);
    const context = { did, vault: f.state.vault, epoch: 2 };
    for (const kind of ["migrate", "recover"] as const) {
      f.setHeader(
        await record(
          rotated,
          await signedVault(
            rotated,
            context,
            [f.admin.recipient],
            f.admin,
            kind,
          ),
        ),
      );
      for (const checkpoint of [
        checkpointOf(f.state),
        { vault: f.state.vault, epoch: 1 },
      ])
        await expect(
          verifyHeader(
            rotated,
            did,
            f.header(),
            f.state.ownRecipient,
            checkpoint,
          ),
        ).rejects.toThrow("not signed by a trusted key");
    }
    const change = await signedVault(
      rotated,
      context,
      [f.admin.recipient],
      f.admin,
      "change",
      2,
    );
    f.setHeader(await record(rotated, change));
    await expect(
      verifyHeader(rotated, did, f.header(), f.state.ownRecipient, {
        vault: f.state.vault,
        epoch: 1,
      }),
    ).rejects.toThrow("not signed by a trusted key");
    (await unlockVault(f.port)).runtime.lock();
    expect(f.checkpoint()).toEqual(checkpointOf(change));
    f.setCheckpoint({ vault: f.state.vault, epoch: 1 });
    (await unlockVault(f.port)).runtime.lock();
    expect(f.checkpoint()).toEqual({ ...checkpointOf(change), trust: "tofu" });
  });
  test("a device seed opens its slot without a PRF and never changes access", async () => {
    const f = await fixture();
    const seed = new Uint8Array(32).fill(3);
    const device = await createSeedRecipient(seed, "device", "Laptop");
    const enrolled = await signedVault(
      f.key,
      contextOf(f.state),
      [f.admin.recipient, device],
      f.admin,
      "change",
      2,
    );
    f.setHeader(await record(f.key, enrolled));
    let checkpoint: CheckpointPolicy | null = linkedCheckpoint(f.state);
    let recipientId = device.id;
    const port: SeedUnlockPort = {
      current: () => ({ userId: "u", did, recipientId, sessionVersion: 1 }),
      checkpoint: async () => checkpoint,
      saveCheckpoint: async (value) => {
        checkpoint = value;
      },
      resolve: async () => ({ did, active: true, authorized: true }),
      readHeader: async () => ({ header: f.header(), cid: "cid" }),
      runtime: (session) => localRuntime(session),
    };
    const header = f.header();
    (await unlockVaultWithSeed(port, seed)).runtime.lock();
    expect(f.header()).toBe(header);
    expect(checkpoint).toEqual(linkedCheckpoint(enrolled));
    // FN1: a first-use pin hands over a first-use pin.
    expect(linkedCheckpoint({ ...enrolled, trust: "tofu" }).trust).toBe("tofu");
    await expect(
      unlockVaultWithSeed(port, new Uint8Array(32).fill(4)),
    ).rejects.toThrow("Vault recipient changed");
    recipientId = (
      await createSeedRecipient(new Uint8Array(32).fill(4), "agent")
    ).id;
    await expect(
      unlockVaultWithSeed(port, new Uint8Array(32).fill(4)),
    ).rejects.toThrow("isn’t in your notepad’s access any more");
    recipientId = device.id;
    const intruder = await passkeyAdmin(
      new Uint8Array(32).fill(4),
      "intruder",
      did,
    );
    f.setHeader(
      await record(
        f.key,
        await signedVault(
          f.key,
          contextOf(f.state),
          [f.admin.recipient, device, intruder.recipient],
          intruder,
          "change",
        ),
      ),
    );
    await expect(unlockVaultWithSeed(port, seed)).rejects.toThrow(
      "Link it again",
    );
    f.setHeader(await record(f.key, enrolled));
    for (const unpinned of [null, { vault: f.state.vault, epoch: 1 }]) {
      checkpoint = unpinned;
      await expect(unlockVaultWithSeed(port, seed)).rejects.toThrow(
        "isn't pinned",
      );
    }
  });
});
