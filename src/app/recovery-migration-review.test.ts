import { describe, expect, test } from "bun:test";
import Dexie from "dexie";
import { IDBKeyRange, indexedDB } from "fake-indexeddb";
import {
  encryptedHeader,
  legacyHeader,
  passkeyVault,
  signedVault,
} from "../../tests/unlock-fixture.ts";
import { createAccessRecipient, unwrapAccessKey } from "../crypto/access-v2.ts";
import {
  createAccess,
  createSeedRecipient,
  passkeyAdmin,
  passkeyBinding,
  recipientsOf,
  UNTRUSTED_ACCESS,
  type VaultRecipient,
} from "../crypto/access-v3.ts";
import { createRecoveryFile } from "../crypto/index.ts";
import type { RegisteredPasskey } from "../crypto/passkey-proof.ts";
import {
  readVerifiedVaultRoot,
  type VaultRecordV2,
} from "../sync/vault-transport.ts";
import { localRuntime } from "./local-runtime.ts";
import {
  MigrationConfirmationError,
  PasskeysUnavailableError,
  RecoveryConfirmationError,
} from "./runtime.ts";
import {
  type Checkpoint,
  type CheckpointPolicy,
  type UnlockPort,
  unlockVault,
  type VerifiedVault,
} from "./unlock.ts";

Dexie.dependencies.indexedDB = indexedDB;
Dexie.dependencies.IDBKeyRange = IDBKeyRange;
const did = "did:plc:recovery-migration";
const fill = (value: number) => new Uint8Array(32).fill(value);
const checkpointOf = (state: VerifiedVault): Checkpoint => ({
  vault: state.vault,
  epoch: state.epoch,
  pinned: state.pinned,
  trust: state.trust,
});
const recoveryFor = (key: Uint8Array, vault: string) =>
  createRecoveryFile(key, {
    did,
    vault,
    epoch: 1,
    item: "recovery",
    revision: "vault-key-v1",
    assets: [],
  });
const legacyVault = async (
  key: Uint8Array,
  passkeys: [credentialId: string, prf: number][],
) => {
  const vault = crypto.randomUUID();
  const recipients = await Promise.all(
    passkeys.map(([id, prf]) => createAccessRecipient(fill(prf), id, did)),
  );
  return {
    vault,
    recipients,
    header: await legacyHeader(key, { vault, epoch: 1, recipients }, did),
  };
};

/** Flow ID's passkey list as the port reaches it, answering with `registered`. */
const flowId = (
  registered: () => Promise<RegisteredPasskey[]>,
): UnlockPort["passkeys"] => ({
  rpId: "id.flow.industries",
  origin: "https://note.flow.talk",
  registered,
});
/** Flow ID's answer listing these credential ids as the account's passkeys. */
const listing = (...credentialIds: string[]) =>
  flowId(async () =>
    credentialIds.map((credentialId) => ({
      credentialId,
      publicKey: `0x${"a".repeat(128)}`,
    })),
  );
const unavailable = flowId(async () => {
  throw new Error("Flow ID unavailable");
});
/** The recipients a signed root lists; none while the root is unsigned. */
async function signedRecipients(m: Pds) {
  const metadata = await m.metadata();
  return "version" in metadata ? metadata.recipients : [];
}
interface Passkey {
  id: string;
  prf: Uint8Array;
}
/** One PDS record, with whichever passkey and browser checkpoint the test switches to. */
function pds(initial: VaultRecordV2, key: Uint8Array) {
  let header = initial;
  let current = key;
  let checkpoint: CheckpointPolicy | null = null;
  let passkey: Passkey = { id: "a", prf: fill(7) };
  const revocations: unknown[] = [];
  let prompts = 0;
  let writes = 0;
  const port: UnlockPort = {
    current: () => ({
      userId: "u",
      did,
      credentialId: passkey.id,
      sessionVersion: 1,
    }),
    checkpoint: async () => checkpoint,
    saveCheckpoint: async (value) => {
      checkpoint = value;
    },
    resolve: async () => ({ did, active: true, authorized: true }),
    readHeader: async () => ({ header, cid: `cid-${writes}` }),
    publish: async (published, state) => {
      writes++;
      header = await encryptedHeader(published, state, did);
    },
    rekey: async (_from, to, _cid, reencrypt) => {
      writes++;
      const entries = await reencrypt([]);
      header = await encryptedHeader(to.key, to.state, did);
      current = to.key.slice();
      return entries;
    },
    revokeDevices: async (select) => {
      revocations.push(select);
    },
    evaluatePrf: async () => {
      prompts++;
      return passkey.prf.slice();
    },
    runtime: (session) => localRuntime(session),
  };
  return {
    port,
    /** Switches to another passkey on a browser holding `browser` as its checkpoint. */
    as(id: string, prf: Uint8Array, browser: CheckpointPolicy | null) {
      passkey = { id, prf };
      checkpoint = browser;
    },
    header: () => header,
    setHeader: (value: VaultRecordV2) => {
      header = value;
    },
    checkpoint: () => checkpoint,
    pin(): Checkpoint {
      if (!checkpoint || "resetCandidates" in checkpoint)
        throw new Error("Expected a checkpoint");
      return checkpoint;
    },
    counts: () => ({ prompts, writes, revocations: revocations.length }),
    revocations,
    async listed() {
      const { metadata } = await readVerifiedVaultRoot(current, did, header);
      return recipientsOf(metadata)
        .map((recipient) => recipient.id)
        .sort();
    },
    async metadata() {
      return (await readVerifiedVaultRoot(current, did, header)).metadata;
    },
  };
}
type Pds = ReturnType<typeof pds>;
const ids = (...recipients: (VaultRecipient | { credentialHash: string })[]) =>
  recipients
    .map((recipient) =>
      "credentialHash" in recipient ? recipient.credentialHash : recipient.id,
    )
    .sort();
/** Asks before the passkey prompt, and changes nothing, until the person confirms. */
async function asksFirst(
  m: Pds,
  options: Parameters<typeof unlockVault>[1],
  signAccess: boolean,
) {
  const before = { counts: m.counts(), header: m.header() };
  await expect(unlockVault(m.port, options, signAccess)).rejects.toBeInstanceOf(
    RecoveryConfirmationError,
  );
  expect({ counts: m.counts(), header: m.header() }).toEqual(before);
}

describe("recovery never drops another passkey or device without asking", () => {
  for (const signAccess of [false, true]) {
    test(`R3: a v1 recovery on a fresh browser asks before re-keying a signed vault to itself (signAccess=${signAccess})`, async () => {
      const key = fill(9);
      const { state } = await passkeyVault(key, did, fill(7), "a");
      const recovery = await recoveryFor(key, state.vault);
      const m = pds(await encryptedHeader(key, state, did), key);
      const c = await passkeyAdmin(fill(8), "c", did);
      m.as("c", fill(8), null);
      await asksFirst(m, { recovery }, signAccess);
      // A's pinned device is untouched until the person accepts.
      m.as("a", fill(7), checkpointOf(state));
      (await unlockVault(m.port, {}, signAccess)).runtime.lock();
      m.as("c", fill(8), null);
      (
        await unlockVault(
          m.port,
          { recovery, confirmRecovery: true },
          signAccess,
        )
      ).runtime.lock();
      expect(await m.listed()).toEqual([c.recipient.id]);
      expect(m.revocations).toEqual([{ except: [c.recipient.id] }]);
    });

    test(`R3: a new passkey's v1 recovery on a trusted pin asks, rather than sign a recover the other devices refuse (signAccess=${signAccess})`, async () => {
      const key = fill(9);
      const { state } = await passkeyVault(key, did, fill(7), "a");
      const m = pds(await encryptedHeader(key, state, did), key);
      const recovery = await recoveryFor(key, state.vault);
      m.as("c", fill(8), checkpointOf(state));
      await asksFirst(m, { recovery }, signAccess);
      m.as("a", fill(7), checkpointOf(state));
      (await unlockVault(m.port, {}, signAccess)).runtime.lock();
      expect(m.counts().writes).toBe(0);
    });

    test(`FN2: a v1 recovery on a trusted but stale pin asks before re-keying away the recipients added since (signAccess=${signAccess})`, async () => {
      const key = fill(9);
      const a = await passkeyAdmin(fill(7), "a", did);
      const c = await passkeyAdmin(fill(8), "c", did);
      const device = await createSeedRecipient(fill(3), "device", "Laptop");
      const context = { did, vault: crypto.randomUUID(), epoch: 1 };
      const stale = await signedVault(key, context, [a.recipient], a);
      // C was added by A; this browser never saw it, so C's own change is one its pin can't follow.
      const later = await signedVault(
        key,
        context,
        [a.recipient, c.recipient, device],
        c,
        "change",
        3,
      );
      const m = pds(await encryptedHeader(key, later, did), key);
      const recovery = await recoveryFor(key, context.vault);
      m.as("a", fill(7), checkpointOf(stale));
      await asksFirst(m, { recovery }, signAccess);
      (
        await unlockVault(
          m.port,
          { recovery, confirmRecovery: true },
          signAccess,
        )
      ).runtime.lock();
      expect(await m.listed()).toEqual([a.recipient.id]);
      expect(m.revocations).toEqual([{ except: [a.recipient.id] }]);
    });
  }

  test("with signed access off, a new passkey's v1 recovery of an unsigned vault keeps every co-passkey, as production does today", async () => {
    const key = fill(9);
    const v2 = await legacyVault(key, [
      ["a", 7],
      ["b", 6],
    ]);
    const recovery = await recoveryFor(key, v2.vault);
    const m = pds(v2.header, key);
    const c = await passkeyAdmin(fill(8), "c", did);
    m.as("c", fill(8), null);
    (await unlockVault(m.port, { recovery }, false)).runtime.lock();
    expect(m.counts()).toMatchObject({ writes: 1, revocations: 0 });
    expect(await m.listed()).toEqual(
      [...ids(...v2.recipients), c.recipient.id].sort(),
    );
    expect("version" in (await m.metadata())).toBe(false);
    for (const [id, prf] of [
      ["a", 7],
      ["b", 6],
    ] as const) {
      m.as(id, fill(prf), { vault: v2.vault, epoch: 1 });
      (await unlockVault(m.port, {}, false)).runtime.lock();
    }
  });

  test("with signed access on, a v1 recovery of an unsigned vault asks rather than carry a co-passkey it can't verify, and refuses without Flow ID's list", async () => {
    const key = fill(9);
    const v2 = await legacyVault(key, [
      ["a", 7],
      ["b", 6],
    ]);
    const recovery = await recoveryFor(key, v2.vault);
    const m = pds(v2.header, key);
    m.as("c", fill(8), null);
    // A list that doesn't name this passkey says nothing about the rest, so it asks too: nobody is stuck on an answer that won't change.
    for (const passkeys of [
      listing("a", "b", "c"),
      listing("c", "b"),
      listing("a", "b"),
    ]) {
      m.port.passkeys = passkeys;
      await asksFirst(m, { recovery }, true);
    }
    // No answer can be judged yet, so it changes nothing and can be retried.
    for (const passkeys of [undefined, unavailable]) {
      m.port.passkeys = passkeys;
      const before = { counts: m.counts(), header: m.header() };
      await expect(
        unlockVault(m.port, { recovery, confirmRecovery: true }, true),
      ).rejects.toBeInstanceOf(PasskeysUnavailableError);
      expect({ counts: m.counts(), header: m.header() }).toEqual(before);
    }
  });
});

describe("migration signs in only the passkey that unlocks, never an entry on an id match", () => {
  test("a v2 entry planted before migration is dropped, so it can't upgrade itself into an admin", async () => {
    const key = fill(9);
    const v2 = await legacyVault(key, [
      ["a", 7],
      ["evil", 5],
    ]);
    const m = pds(v2.header, key);
    m.port.passkeys = listing("a");
    m.as("a", fill(7), { vault: v2.vault, epoch: 1 });
    (await unlockVault(m.port, {}, false)).runtime.lock();
    expect(m.counts().writes).toBe(0);
    (await unlockVault(m.port, {}, true)).runtime.lock();
    const a = await passkeyAdmin(fill(7), "a", did);
    expect(await m.listed()).toEqual([a.recipient.id]);
    const pin = m.pin();
    // Nothing it signed came from the unsigned root unchecked, so the pin is one it created.
    expect(pin.trust).toBe("created");
    expect(pin.pinned?.admins).toHaveLength(1);
    // The planter, holding the key and a session, signs the upgrade its legacy entry would have needed.
    // Its admin recipient has the planted entry's id and box key, plus the signing key the upgrade adds.
    const { recipient: upgraded, privateKey } = await passkeyAdmin(
      fill(5),
      "evil",
      did,
    );
    const context = { did, vault: v2.vault, epoch: 1 };
    const crafted = await createAccess(key, context, {
      kind: "upgrade",
      sequence: 2,
      recipients: [a.recipient, upgraded],
      signer: { recipient: upgraded, privateKey },
      binding: await passkeyBinding(fill(5), "evil", context, upgraded),
    });
    m.setHeader(
      await encryptedHeader(key, { ...context, access: crafted }, did),
    );
    await expect(unlockVault(m.port, {}, true)).rejects.toThrow(
      UNTRUSTED_ACCESS,
    );
    expect(m.pin().pinned?.admins).toHaveLength(1);
  });

  test("with signed access on, an unsigned root never opens as a session: without Flow ID's list unlock refuses, and a co-passkey it lists is dropped only once confirmed", async () => {
    const key = fill(9);
    const v2 = await legacyVault(key, [
      ["a", 7],
      ["b", 6],
    ]);
    const m = pds(v2.header, key);
    const unsigned = { vault: v2.vault, epoch: 1 };
    m.as("a", fill(7), unsigned);
    for (const passkeys of [undefined, unavailable]) {
      m.port.passkeys = passkeys;
      await expect(unlockVault(m.port, {}, true)).rejects.toBeInstanceOf(
        PasskeysUnavailableError,
      );
      expect(m.header()).toBe(v2.header);
      expect(m.checkpoint()).toEqual(unsigned);
    }
    // B may be real, and its keys can't be checked without it, so dropping it is the person's call.
    m.port.passkeys = listing("a", "b");
    const asked = await unlockVault(m.port, {}, true).catch((error) => error);
    expect(asked).toBeInstanceOf(MigrationConfirmationError);
    expect(asked.losing).toBe(
      "the other passkey listed on your notepad loses access",
    );
    expect(m.header()).toBe(v2.header);
    expect(m.counts().writes).toBe(0);
    (
      await unlockVault(m.port, { confirmMigration: asked.confirmation }, true)
    ).runtime.lock();
    const a = await passkeyAdmin(fill(7), "a", did);
    expect(await m.listed()).toEqual([a.recipient.id]);
    expect(m.pin().trust).toBe("created");
  });

  for (const signAccess of [false, true]) {
    test(`a planted entry under the unlocking passkey's own credential hash, with an attacker's keys, is replaced by the entry it derives (signAccess=${signAccess})`, async () => {
      const key = fill(9);
      // Credential ids are public: the planter lists C's real id beside a box key it holds, next to an entry no registered passkey owns.
      const v2 = await legacyVault(key, [
        ["c", 5],
        ["gone", 6],
      ]);
      const planted = await createAccessRecipient(fill(5), "c", did);
      const recovery = await recoveryFor(key, v2.vault);
      const m = pds(v2.header, key);
      m.port.passkeys = listing("c");
      const c = await passkeyAdmin(fill(8), "c", did);
      m.as("c", fill(8), null);
      // The slot under C's id is the planter's, so C opens nothing until it recovers.
      await expect(unlockVault(m.port, {}, signAccess)).rejects.toThrow();
      (await unlockVault(m.port, { recovery }, signAccess)).runtime.lock();
      expect(m.counts()).toMatchObject({ writes: 1, revocations: 0 });
      const metadata = await m.metadata();
      const boxes = recipientsOf(metadata).map(
        (recipient) => recipient.boxPublicKey,
      );
      expect(boxes).toContain(c.recipient.boxPublicKey);
      expect(boxes).not.toContain(planted.publicKey);
      expect("version" in metadata).toBe(signAccess);
      if ("version" in metadata) {
        expect(metadata.statement).toMatchObject({
          kind: "migrate",
          signer: c.recipient.id,
        });
        expect(metadata.recipients).toEqual([c.recipient]);
        // A file is all this browser has to go on, so it can't vouch for the key either.
        expect(m.pin().trust).toBe("tofu");
      }
    });

    test(`a planted entry under a listed co-passkey's credential hash, with an attacker's keys, is never signed in (signAccess=${signAccess})`, async () => {
      const key = fill(9);
      // Credential ids are public: the planter lists B's real id beside a box key it holds.
      const v2 = await legacyVault(key, [
        ["a", 7],
        ["b", 5],
      ]);
      const planted = await passkeyAdmin(fill(5), "b", did);
      const m = pds(v2.header, key);
      m.port.passkeys = listing("a", "b", "c");
      m.as("a", fill(7), { vault: v2.vault, epoch: 1 });
      const recovery = await recoveryFor(key, v2.vault);
      if (signAccess) {
        const asked = await unlockVault(m.port, {}, true).catch(
          (error) => error,
        );
        expect(asked).toBeInstanceOf(MigrationConfirmationError);
        expect(m.header()).toBe(v2.header);
        m.as("c", fill(8), null);
        await asksFirst(m, { recovery }, true);
        m.as("a", fill(7), { vault: v2.vault, epoch: 1 });
        (
          await unlockVault(
            m.port,
            { confirmMigration: asked.confirmation },
            true,
          )
        ).runtime.lock();
        const a = await passkeyAdmin(fill(7), "a", did);
        expect(await m.listed()).toEqual([a.recipient.id]);
      } else {
        (await unlockVault(m.port, {}, false)).runtime.lock();
        expect(m.header()).toBe(v2.header);
        m.as("c", fill(8), null);
        (await unlockVault(m.port, { recovery }, false)).runtime.lock();
      }
      const signed = await signedRecipients(m);
      expect(signed.map((recipient) => recipient.id)).not.toContain(
        planted.recipient.id,
      );
      expect(signed.map((recipient) => recipient.boxPublicKey)).not.toContain(
        planted.recipient.boxPublicKey,
      );
    });
  }

  test("an unsigned vault the migrating passkey alone is listed in needs no list from Flow ID", async () => {
    const key = fill(9);
    const v2 = await legacyVault(key, [["a", 7]]);
    const m = pds(v2.header, key);
    m.as("a", fill(7), { vault: v2.vault, epoch: 1 });
    (await unlockVault(m.port, {}, true)).runtime.lock();
    expect(m.pin().trust).toBe("created");
    const opened = await unwrapAccessKey(
      { accessSalt: m.header().accessSalt, access: m.header().access },
      fill(7),
      "a",
      did,
    );
    opened.key.fill(0);
    expect(opened.version).toBe(3);
  });
});
