import { describe, expect, test } from "bun:test";
import sodium from "libsodium-wrappers-sumo";
import {
  encryptedHeader,
  legacyHeader,
  passkeyVault,
  signedVault,
} from "../../tests/unlock-fixture.ts";
import {
  accessHeaderCommitment,
  createAccessRecipient,
  deriveSeed,
} from "../crypto/access-v2.ts";
import {
  type AccessMetadata,
  type AccessSigner,
  createSeedRecipient,
  passkeyAdmin,
  type VaultRecipient,
} from "../crypto/access-v3.ts";
import { createRecoveryFile } from "../crypto/index.ts";
import {
  readVerifiedVaultRoot,
  type VaultRecordV2,
} from "../sync/vault-transport.ts";
import { localRuntime } from "./local-runtime.ts";
import { RecoveryConfirmationError } from "./runtime.ts";
import {
  type Checkpoint,
  type CheckpointPolicy,
  RECOVERY_SUPERSEDED,
  type UnlockPort,
  unlockVault,
  type VerifiedVault,
  verifyHeader,
} from "./unlock.ts";

const did = "did:plc:review";
const prf = () => new Uint8Array(32).fill(7);
const encode = (bytes: Uint8Array) =>
  sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING);
const checkpointOf = (state: VerifiedVault): Checkpoint => ({
  vault: state.vault,
  epoch: state.epoch,
  pinned: state.pinned,
  trust: state.trust,
});
const pinnedOf = (policy: CheckpointPolicy | null) =>
  policy && !("resetCandidates" in policy) ? policy.pinned : undefined;
const refOf = (recipient: VaultRecipient) => ({
  id: recipient.id,
  boxPublicKey: recipient.boxPublicKey,
});
const recoveryFor = (key: Uint8Array, vault: string, epoch = 1) =>
  createRecoveryFile(key, {
    did,
    vault,
    epoch,
    item: "recovery",
    revision: "vault-key-v1",
    assets: [],
  });
/** A key holder's own "recovery" admin: any seed yields a schema-valid admin recipient. */
async function selfMadeAdmin(fill: number): Promise<AccessSigner> {
  await sodium.ready;
  const seed = new Uint8Array(32).fill(fill);
  const derived = await deriveSeed(
    seed,
    new Uint8Array(32),
    "flow-note/v3/sign",
  );
  return {
    recipient: await createSeedRecipient(seed, "recovery", "Backup"),
    privateKey: sodium.crypto_sign_seed_keypair(derived).privateKey,
  };
}
/** Signs any statement over an existing header, as a device token could pair it with frozen slots. */
async function statementOverHeader(
  context: { did: string; vault: string; epoch: number },
  header: { accessSalt: string; access: VaultRecordV2["access"] },
  recipients: VaultRecipient[],
  signer: AccessSigner,
  sequence: number,
): Promise<AccessMetadata> {
  const accessCommitment = await accessHeaderCommitment(header);
  const sorted = [...recipients].sort((a, b) => (a.id < b.id ? -1 : 1));
  const tuples = sorted.map((r) => [
    r.id,
    r.kind,
    r.role,
    r.boxPublicKey,
    r.signPublicKey ?? null,
    r.label ?? null,
  ]);
  const message = JSON.stringify([
    "flow-note/v3/access",
    "change",
    context.did,
    context.vault,
    context.epoch,
    signer.recipient.id,
    sequence,
    accessCommitment,
    tuples,
  ]);
  return {
    version: 3,
    epoch: context.epoch,
    recipients: sorted,
    accessCommitment,
    statement: {
      kind: "change",
      signer: signer.recipient.id,
      sequence,
      nonce: encode(sodium.randombytes_buf(32)),
      signature: encode(
        sodium.crypto_sign_detached(
          new TextEncoder().encode(message),
          signer.privateKey,
        ),
      ),
    },
  };
}

async function world() {
  const key = new Uint8Array(32).fill(9);
  const { admin, state } = await passkeyVault(key, did, prf(), "connected");
  const device = await createSeedRecipient(
    new Uint8Array(32).fill(3),
    "device",
    "Laptop",
  );
  const context = { did, vault: state.vault, epoch: 1 };
  const enrolled = await signedVault(
    key,
    context,
    [admin.recipient, device],
    admin,
    "change",
    2,
  );
  let header: VaultRecordV2 = await encryptedHeader(key, enrolled, did);
  let checkpoint: CheckpointPolicy | null = checkpointOf(enrolled);
  const published: VerifiedVault[] = [];
  const revocations: Parameters<NonNullable<UnlockPort["revokeDevices"]>>[0][] =
    [];
  let current = key;
  let credentialId = "connected";
  let prompts = 0;
  const port: UnlockPort = {
    current: () => ({ userId: "u", did, credentialId, sessionVersion: 1 }),
    checkpoint: async () => checkpoint,
    saveCheckpoint: async (value) => {
      checkpoint = value;
    },
    resolve: async () => ({ did, active: true, authorized: true }),
    readHeader: async () => ({ header, cid: "cid" }),
    publish: async (publishedKey, value) => {
      published.push(value);
      header = await encryptedHeader(publishedKey, value, did);
    },
    rekey: async (_from, to, _expectedCid, reencrypt) => {
      const entries = await reencrypt([]);
      published.push(to.state);
      header = await encryptedHeader(to.key, to.state, did);
      // unlockVault wipes the key it opened with once it locks.
      current = to.key.slice();
      return entries;
    },
    revokeDevices: async (select) => {
      revocations.push(select);
    },
    evaluatePrf: async () => {
      prompts++;
      return prf();
    },
    runtime: (session) => localRuntime(session),
  };
  return {
    key,
    admin,
    device,
    context,
    enrolled,
    port,
    published,
    revocations,
    /** The vault key now, which a recovery that re-keys replaces. */
    currentKey: () => current,
    header: () => header,
    setHeader: (value: VaultRecordV2) => {
      header = value;
    },
    checkpoint: () => checkpoint,
    setCheckpoint: (value: CheckpointPolicy | null) => {
      checkpoint = value;
    },
    setCredential: (value: string) => {
      credentialId = value;
    },
    prompts: () => prompts,
  };
}
/** A recovery that re-keys asks before the passkey prompt and writes nothing until the person confirms. */
async function recoverConfirmed(
  w: Awaited<ReturnType<typeof world>>,
  recovery: Awaited<ReturnType<typeof recoveryFor>>,
  signAccess?: boolean,
) {
  const before = {
    prompts: w.prompts(),
    published: w.published.length,
    revocations: w.revocations.length,
  };
  await expect(
    unlockVault(w.port, { recovery }, signAccess),
  ).rejects.toBeInstanceOf(RecoveryConfirmationError);
  expect({
    prompts: w.prompts(),
    published: w.published.length,
    revocations: w.revocations.length,
  }).toEqual(before);
  (
    await unlockVault(w.port, { recovery, confirmRecovery: true }, signAccess)
  ).runtime.lock();
}
const lastStatement = async (w: Awaited<ReturnType<typeof world>>) => {
  const { metadata } = await readVerifiedVaultRoot(
    w.currentKey(),
    did,
    w.header(),
  );
  if (!("version" in metadata)) throw new Error("Expected signed access");
  return metadata;
};

describe("security review regressions", () => {
  test("a statement swapped in over frozen slots fails header authentication, even unpinned and in recovery", async () => {
    const w = await world();
    const attacker = await selfMadeAdmin(66);
    const frozen = {
      accessSalt: w.header().accessSalt,
      access: w.header().access,
    };
    const forged = await statementOverHeader(
      w.context,
      frozen,
      [w.admin.recipient, w.device, attacker.recipient],
      attacker,
      3,
    );
    const rewritten = await encryptedHeader(
      w.key,
      { ...w.context, access: { header: frozen, metadata: forged } },
      did,
    );
    expect(rewritten.accessSalt).toBe(w.enrolled.access.header.accessSalt);
    expect(rewritten.access).toEqual(w.enrolled.access.header.access);
    w.setHeader(rewritten);
    await expect(
      verifyHeader(w.key, did, rewritten, refOf(w.admin.recipient), null),
    ).rejects.toThrow("Vault header authentication failed");
    await expect(unlockVault(w.port)).rejects.toThrow(
      "Vault header authentication failed",
    );
    await expect(
      unlockVault(w.port, {
        recovery: await recoveryFor(w.key, w.context.vault),
      }),
    ).rejects.toThrow("Vault header authentication failed");
    expect(w.published).toEqual([]);
  });

  test("recovery judges an untrusted statement against the old pin, and re-keys to only what it trusted", async () => {
    const w = await world();
    const attacker = await selfMadeAdmin(66);
    const otherDevice = checkpointOf(w.enrolled);
    const takeover = await signedVault(
      w.key,
      w.context,
      [w.admin.recipient, w.device, attacker.recipient],
      attacker,
      "change",
      3,
    );
    w.setHeader(await encryptedHeader(w.key, takeover, did));
    await expect(unlockVault(w.port)).rejects.toThrow(
      "not signed by a trusted key",
    );
    const recovery = await recoveryFor(w.key, w.context.vault);
    await recoverConfirmed(w, recovery);
    const repaired = await lastStatement(w);
    // The attacker held the old key, so the repair can't keep it.
    expect(repaired.epoch).toBe(2);
    await expect(
      readVerifiedVaultRoot(w.key, did, w.header()),
    ).rejects.toThrow();
    expect(repaired.statement).toMatchObject({
      kind: "change",
      signer: w.admin.recipient.id,
      sequence: 3,
    });
    expect(repaired.recipients.map((r) => r.id).sort()).toEqual(
      [w.admin.recipient.id, w.device.id].sort(),
    );
    expect(w.revocations).toEqual([
      { except: repaired.recipients.map((r) => r.id) },
    ]);
    const accepted = await verifyHeader(
      w.currentKey(),
      did,
      w.header(),
      refOf(w.admin.recipient),
      otherDevice,
    );
    expect(accepted.pinned?.sequence).toBe(3);
    await expect(unlockVault(w.port, { recovery })).rejects.toThrow(
      RECOVERY_SUPERSEDED,
    );
    (await unlockVault(w.port)).runtime.lock();
    expect(w.published).toHaveLength(1);
  });

  test("recovery on a device with no pin keeps only the recovering passkey", async () => {
    const w = await world();
    const attacker = await selfMadeAdmin(66);
    w.setHeader(
      await encryptedHeader(
        w.key,
        await signedVault(
          w.key,
          w.context,
          [w.admin.recipient, w.device, attacker.recipient],
          attacker,
          "change",
          3,
        ),
        did,
      ),
    );
    w.setCheckpoint(null);
    await recoverConfirmed(w, await recoveryFor(w.key, w.context.vault));
    const recovered = await lastStatement(w);
    expect(recovered.epoch).toBe(2);
    expect(recovered.statement).toMatchObject({ kind: "change", sequence: 4 });
    expect(recovered.recipients).toEqual([w.admin.recipient]);
    expect(w.revocations).toEqual([{ except: [w.admin.recipient.id] }]);
  });

  test("an unpinned checkpoint refuses a re-key the unlocking passkey didn't sign", async () => {
    const w = await world();
    const attacker = await selfMadeAdmin(67);
    const rotated = new Uint8Array(32).fill(12);
    const rekey = await signedVault(
      rotated,
      { ...w.context, epoch: 2 },
      [w.device, attacker.recipient],
      attacker,
      "change",
      3,
    );
    await expect(
      verifyHeader(
        rotated,
        did,
        await encryptedHeader(rotated, rekey, did),
        refOf(w.device),
        { vault: w.context.vault, epoch: 1 },
      ),
    ).rejects.toThrow("not signed by a trusted key");
  });

  test("an older change signed by a still-pinned admin cannot be replayed", async () => {
    const w = await world();
    const older = w.header();
    const dropped = await signedVault(
      w.key,
      w.context,
      [w.admin.recipient],
      w.admin,
      "change",
      3,
    );
    w.setHeader(await encryptedHeader(w.key, dropped, did));
    w.setCheckpoint(checkpointOf(dropped));
    (await unlockVault(w.port)).runtime.lock();
    w.setHeader(older);
    await expect(unlockVault(w.port)).rejects.toThrow(
      "not signed by a trusted key",
    );
    expect(pinnedOf(w.checkpoint())).toEqual(dropped.pinned);
  });

  test("a planted v2 root is never signed while signed access is off, and never accepted over v3 slots", async () => {
    const key = new Uint8Array(32).fill(9);
    const vault = crypto.randomUUID();
    const user = await createAccessRecipient(prf(), "connected", did);
    const attackerBox = sodium.crypto_box_seed_keypair(
      new Uint8Array(32).fill(5),
    );
    const planted = {
      credentialHash: encode(new Uint8Array(32).fill(1)),
      publicKey: encode(attackerBox.publicKey),
    };
    let header = await legacyHeader(
      key,
      { vault, epoch: 1, recipients: [user, planted] },
      did,
    );
    let checkpoint: CheckpointPolicy | null = { vault, epoch: 1 };
    let writes = 0;
    const port: UnlockPort = {
      current: () => ({
        userId: "u",
        did,
        credentialId: "connected",
        sessionVersion: 1,
      }),
      checkpoint: async () => checkpoint,
      saveCheckpoint: async (value) => {
        checkpoint = value;
      },
      resolve: async () => ({ did, active: true, authorized: true }),
      readHeader: async () => ({ header, cid: "cid" }),
      publish: async (publishedKey, value) => {
        writes++;
        header = await encryptedHeader(publishedKey, value, did);
      },
      evaluatePrf: async () => prf(),
      runtime: (session) => localRuntime(session),
    };
    (await unlockVault(port, {}, false)).runtime.lock();
    expect(writes).toBe(0);
    expect(pinnedOf(checkpoint)).toBeNull();
    const w = await world();
    const frozen = w.enrolled.access.header;
    w.setHeader(
      await encryptedHeader(
        w.key,
        {
          ...w.context,
          access: {
            header: frozen,
            metadata: {
              recipients: [
                {
                  credentialHash: w.admin.recipient.id,
                  publicKey: w.admin.recipient.boxPublicKey,
                },
                planted,
              ],
              accessCommitment: await accessHeaderCommitment(frozen),
            },
          },
        },
        did,
      ),
    );
    w.setCheckpoint({ vault: w.context.vault, epoch: 1 });
    await expect(unlockVault(w.port, {}, true)).rejects.toThrow(
      "not signed by a trusted key",
    );
    expect(w.published).toEqual([]);
  });

  test("with signed access off, recovery on a pinned device never downgrades a signed vault", async () => {
    const w = await world();
    const attackerBox = sodium.crypto_box_seed_keypair(
      new Uint8Array(32).fill(5),
    );
    const frozen = w.enrolled.access.header;
    w.setHeader(
      await encryptedHeader(
        w.key,
        {
          ...w.context,
          access: {
            header: frozen,
            metadata: {
              recipients: [
                {
                  credentialHash: w.admin.recipient.id,
                  publicKey: w.admin.recipient.boxPublicKey,
                },
                {
                  credentialHash: encode(new Uint8Array(32).fill(1)),
                  publicKey: encode(attackerBox.publicKey),
                },
              ],
              accessCommitment: await accessHeaderCommitment(frozen),
            },
          },
        },
        did,
      ),
    );
    await expect(unlockVault(w.port, {}, false)).rejects.toThrow(
      "not signed by a trusted key",
    );
    await recoverConfirmed(w, await recoveryFor(w.key, w.context.vault), false);
    const repaired = await lastStatement(w);
    expect(repaired.statement).toMatchObject({
      kind: "change",
      signer: w.admin.recipient.id,
      sequence: 3,
    });
    expect(repaired.recipients).toEqual([w.admin.recipient]);
    expect(repaired.epoch).toBe(2);
    expect(pinnedOf(w.checkpoint())?.sequence).toBe(3);
  });

  test("an untrusted root's sequence can't block recovery", async () => {
    const w = await world();
    const intruder = await passkeyAdmin(
      new Uint8Array(32).fill(4),
      "intruder",
      did,
    );
    w.setHeader(
      await encryptedHeader(
        w.key,
        await signedVault(
          w.key,
          w.context,
          [w.admin.recipient, intruder.recipient],
          intruder,
          "recover",
          Number.MAX_SAFE_INTEGER,
        ),
        did,
      ),
    );
    await recoverConfirmed(w, await recoveryFor(w.key, w.context.vault));
    expect(await lastStatement(w)).toMatchObject({
      epoch: 2,
      statement: { kind: "change", sequence: 3 },
    });
  });

  test("recovery on a fresh browser caps an unpinned root's sequence", async () => {
    const w = await world();
    const intruder = await passkeyAdmin(
      new Uint8Array(32).fill(4),
      "intruder",
      did,
    );
    w.setHeader(
      await encryptedHeader(
        w.key,
        await signedVault(
          w.key,
          w.context,
          [w.admin.recipient, intruder.recipient],
          intruder,
          "recover",
          Number.MAX_SAFE_INTEGER,
        ),
        did,
      ),
    );
    w.setCheckpoint(null);
    await recoverConfirmed(w, await recoveryFor(w.key, w.context.vault));
    const recovered = await lastStatement(w);
    expect(recovered.statement).toMatchObject({
      kind: "change",
      signer: w.admin.recipient.id,
      sequence: 2 ** 32 + 1,
    });
    expect(recovered.epoch).toBe(2);
    expect(recovered.recipients).toEqual([w.admin.recipient]);
  });

  test("a pinned admin's v1 recovery keeps the key; a new passkey's asks, then starts over instead of listing itself under a `recover` other devices refuse", async () => {
    const w = await world();
    const recovery = await recoveryFor(w.key, w.context.vault);
    (await unlockVault(w.port, { recovery })).runtime.lock();
    expect(w.published).toEqual([]);
    const second = await passkeyAdmin(prf(), "second", did);
    w.setCredential("second");
    await recoverConfirmed(w, recovery);
    const started = await lastStatement(w);
    expect(started).toMatchObject({
      epoch: 2,
      statement: { kind: "change", signer: second.recipient.id },
    });
    expect(started.recipients).toEqual([second.recipient]);
    expect(w.revocations).toEqual([{ except: [second.recipient.id] }]);
    // The admin it replaced has no slot left to unlock with, rather than one under a statement its devices refuse.
    w.setCredential("connected");
    w.setCheckpoint(checkpointOf(w.enrolled));
    await expect(unlockVault(w.port)).rejects.toThrow(
      "isn’t in your notepad’s access",
    );
  });
});
