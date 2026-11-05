import { describe, expect, spyOn, test } from "bun:test";
import Dexie from "dexie";
import { IDBKeyRange, indexedDB } from "fake-indexeddb";
import sodium from "libsodium-wrappers-sumo";
import {
  NOTE_ORIGIN,
  PASSKEY_RP_ID,
  type SoftwarePasskey,
  softwarePasskey,
} from "../../tests/passkey-authenticator.ts";
import {
  encryptedHeader,
  legacyHeader,
  passkeyVault,
  signedVault,
} from "../../tests/unlock-fixture.ts";
import { openAccessSlot, v2PrfInput } from "../crypto/access-v2.ts";
import {
  createSeedRecipient,
  type LinkHandoff,
  passkeyAdmin,
  type VaultRecipient,
} from "../crypto/access-v3.ts";
import { linkCommitment, sealLinkHandoff } from "../crypto/link.ts";
import { passkeyRequestChallenge } from "../crypto/passkey-proof.ts";
import { handedCheckpoint, LINK_UNVERIFIED } from "../device/client.ts";
import {
  readVerifiedVaultRoot,
  type VaultRecordV2,
} from "../sync/vault-transport.ts";
import type { TrustLoss } from "../vault/session.ts";
import { localRuntime } from "./local-runtime.ts";
import type { NoteRuntime } from "./runtime.ts";
import {
  ALREADY_LISTED,
  addVaultRecipient,
  type CarriedRecipient,
  type Checkpoint,
  type CheckpointPolicy,
  CONFIRM_EXPIRED,
  FIRST_USE_PIN,
  LINK_CHECK_FAILED,
  LINK_SECRET_MISMATCH,
  LinkCleanupError,
  LinkedWithCleanupError,
  linkedCheckpoint,
  PASSKEY_REQUEST_EXPIRED,
  type RecipientRequest,
  type SeedUnlockPort,
  savedCheckpoint,
  UNANCHORED_PASSKEY,
  UNSIGNED_ACCESS,
  UNTRUSTED_PIN,
  type UnlockPort,
  unlockVault,
  unlockVaultWithSeed,
} from "./unlock.ts";

Dexie.dependencies.indexedDB = indexedDB;
Dexie.dependencies.IDBKeyRange = IDBKeyRange;
const did = "did:plc:link";
const SECRET = "123456789012";
const prfFor = (fill: number) => new Uint8Array(32).fill(fill);

/** A PDS holding one record, and a browser port for whichever passkey is connected. */
async function fixture(initial?: {
  key: Uint8Array;
  header: VaultRecordV2;
  checkpoint: CheckpointPolicy | null;
}) {
  const key = initial?.key ?? new Uint8Array(32).fill(9);
  const created = initial
    ? null
    : await passkeyVault(key, did, prfFor(7), "connected");
  const first = created
    ? await encryptedHeader(key, created.state, did)
    : initial?.header;
  if (!first) throw new Error("Missing fixture header");
  let header: VaultRecordV2 = first;
  let cid = 1;
  let checkpoint: CheckpointPolicy | null = created
    ? savedCheckpoint(created.state)
    : (initial?.checkpoint ?? null);
  let credential = "connected";
  let prf = prfFor(7);
  const writes: VaultRecordV2[] = [];
  const scopes: (string | undefined)[] = [];
  let failPublish = false;
  const passkeys = new Map<string, SoftwarePasskey>();
  const port: UnlockPort = {
    current: () => ({
      userId: "u",
      did,
      credentialId: credential,
      sessionVersion: 1,
    }),
    checkpoint: async () => checkpoint,
    saveCheckpoint: async (value) => {
      checkpoint = value;
    },
    resolve: async () => ({ did, active: true, authorized: true }),
    readHeader: async () => ({ header, cid: `cid-${cid}` }),
    publish: async (publishedKey, state, expectedCid, scope) => {
      scopes.push(scope);
      if (failPublish) throw new Error("PDS unavailable");
      if (expectedCid !== `cid-${cid}`) throw new Error("CONFLICT");
      header = await encryptedHeader(publishedKey, state, did);
      writes.push(header);
      cid++;
    },
    evaluatePrf: async (input) => {
      expect(input).toEqual(await v2PrfInput());
      return prf.slice();
    },
    runtime: (session) => localRuntime(session),
    passkeys: {
      rpId: PASSKEY_RP_ID,
      origin: NOTE_ORIGIN,
      registered: async () =>
        [...passkeys.values()].map((passkey) => passkey.registered),
    },
  };
  return {
    port,
    /** Registers a passkey to the account at Flow ID, as a second device's passkey would be. */
    async register(credentialId: string) {
      const passkey = await softwarePasskey(credentialId);
      passkeys.set(credentialId, passkey);
      return passkey;
    },
    key,
    admin: created?.admin,
    header: () => header,
    setHeader: (value: VaultRecordV2) => {
      header = value;
      cid++;
    },
    checkpoint: () => checkpoint,
    setCheckpoint: (value: CheckpointPolicy | null) => {
      checkpoint = value;
    },
    connect: (credentialId: string, fill: number) => {
      credential = credentialId;
      prf = prfFor(fill);
    },
    writes,
    scopes,
    failPublishes: () => {
      failPublish = true;
    },
  };
}
type Fixture = Awaited<ReturnType<typeof fixture>>;
const lastPin = (checkpoint: CheckpointPolicy | null) =>
  checkpoint && "resetCandidates" in checkpoint ? null : checkpoint;
function pinnedVault(f: Fixture): Checkpoint {
  const checkpoint = f.checkpoint();
  if (!checkpoint || "resetCandidates" in checkpoint)
    throw new Error("Expected a checkpoint");
  return checkpoint;
}

const DEVICE_ID = "00000000-0000-4000-8000-000000000001";
const enabled = { devices: true, passkeys: true };
/** What Flow ID approved and revoked; `approve` commits before it may fail, as a lost response would. */
function grant(options: { lostAnswer?: boolean; revokeFails?: boolean } = {}) {
  const revoked: { deviceId?: string; recipientId: string }[] = [];
  const calls = { approved: 0, revokeAttempts: 0, revoked };
  return {
    calls,
    approve: async () => {
      calls.approved++;
      if (options.lostAnswer) throw new Error("PDS_UNAVAILABLE");
      return DEVICE_ID;
    },
    revoke: async (device: { deviceId?: string; recipientId: string }) => {
      calls.revokeAttempts++;
      if (options.revokeFails) throw new Error("PDS_UNAVAILABLE");
      revoked.push(device);
    },
  };
}
/** What a device commits to: its kind, label and keys. */
const committed = (recipient: VaultRecipient, kind = "device") => ({
  kind,
  label: recipient.label ?? "",
  boxPublicKey: recipient.boxPublicKey,
  signPublicKey: recipient.signPublicKey ?? "",
});
/** Each device's commitment to `SECRET`, as it registered it at Flow ID. */
const commitments = new Map<string, string>();
async function device(fill = 3) {
  const seed = new Uint8Array(32).fill(fill);
  const recipient = await createSeedRecipient(seed, "device", "Laptop");
  commitments.set(
    recipient.id,
    await linkCommitment(SECRET, committed(recipient)),
  );
  return { seed, recipient };
}
const accept = async () => {};
function request(
  recipient: VaultRecipient,
  g = grant(),
  confirm: RecipientRequest["confirm"] = accept,
  link: Partial<NonNullable<RecipientRequest["link"]>> = {},
): RecipientRequest {
  return {
    recipient,
    link: {
      secret: SECRET,
      commitment: commitments.get(recipient.id) ?? "",
      approve: g.approve,
      revoke: g.revoke,
      ...link,
    },
    confirm,
  };
}
/** A passkey request from `credentialId`'s own browser, asserted over the newcomer's keys. */
async function enroll(
  f: Fixture,
  newcomer: VaultRecipient,
  credentialId: string,
  options: { issuedAt?: number; passkey?: SoftwarePasskey } = {},
): Promise<RecipientRequest> {
  const issuedAt = options.issuedAt ?? Date.now();
  const passkey = options.passkey ?? (await f.register(credentialId));
  return {
    recipient: newcomer,
    passkey: {
      credentialId,
      issuedAt,
      assertion: await passkey.assert(
        await passkeyRequestChallenge({
          did,
          boxPublicKey: newcomer.boxPublicKey,
          signPublicKey: newcomer.signPublicKey ?? "",
          issuedAt,
        }),
      ),
    },
    confirm: accept,
  };
}
const add = (f: Fixture, value: RecipientRequest) =>
  addVaultRecipient(f.port, value, enabled);
/** What the device client accepts: the statement that lists it, if the sealed handoff vouches for it. */
async function handed(f: Fixture, seed: Uint8Array, secret = SECRET) {
  try {
    return await handedCheckpoint({ header: f.header() }, seed, did, secret);
  } catch (error) {
    if (error instanceof Error && error.message === LINK_UNVERIFIED)
      return null;
    throw error;
  }
}
function seedPort(
  f: Fixture,
  recipientId: string,
  checkpoint: CheckpointPolicy | null,
) {
  let saved = checkpoint;
  const port: SeedUnlockPort = {
    current: () => ({ userId: "u", did, recipientId, sessionVersion: 1 }),
    checkpoint: async () => saved,
    saveCheckpoint: async (value) => {
      saved = value;
    },
    resolve: async () => ({ did, active: true, authorized: true }),
    readHeader: async () => ({ header: f.header(), cid: "cid" }),
  };
  return { port, saved: () => saved };
}
/** An unsigned (v2) vault this browser has opened before, so it holds a checkpoint without a pin. */
async function legacyVault() {
  const key = new Uint8Array(32).fill(9);
  const admin = await passkeyAdmin(prfFor(7), "connected", did);
  const vault = crypto.randomUUID();
  return fixture({
    key,
    header: await legacyHeader(
      key,
      {
        vault,
        epoch: 1,
        recipients: [
          {
            credentialHash: admin.recipient.id,
            publicKey: admin.recipient.boxPublicKey,
          },
        ],
      },
      did,
    ),
    checkpoint: { vault, epoch: 1, pinned: null },
  });
}

describe("linking a device", () => {
  test("an admin's change lists the device and hands it the pin through its sealed handoff", async () => {
    const f = await fixture();
    const { seed, recipient } = await device();
    const g = grant();
    const before = f.checkpoint();
    expect(await add(f, request(recipient, g))).toEqual({
      deviceId: DEVICE_ID,
    });
    expect(g.calls).toMatchObject({ approved: 1, revoked: [] });
    expect(f.writes).toHaveLength(1);
    const { metadata } = await readVerifiedVaultRoot(f.key, did, f.header());
    if (!("version" in metadata)) throw new Error("Expected signed access");
    expect(metadata.statement).toMatchObject({ kind: "change", sequence: 2 });
    expect(
      metadata.recipients.find((entry) => entry.id === recipient.id),
    ).toEqual(recipient);
    const pin = await handed(f, seed);
    expect(pin).not.toBeNull();
    expect(f.checkpoint()).not.toEqual(before);
    expect(pinnedVault(f).pinned).toEqual(pin?.pinned);
    const { port, saved } = seedPort(f, recipient.id, pin);
    (await unlockVaultWithSeed(port, seed)).runtime.lock();
    if (!pin || !f.admin) throw new Error("Missing handoff");
    const { runners, ...checkpoint } = pin;
    expect(saved()).toEqual(checkpoint);
    expect(runners).toEqual([
      {
        recipientId: f.admin.recipient.id,
        signPublicKey: f.admin.recipient.signPublicKey ?? "",
      },
    ]);
    expect(await handed(f, seed, "123456789013")).toBeNull();
    expect(await handed(f, new Uint8Array(32).fill(4))).toBeNull();
  });
  test("the person sees everyone the change carries, marked against this browser's earlier pin, and can stop it", async () => {
    const f = await fixture();
    const owner = f.admin;
    if (!owner) throw new Error("Missing owner");
    const { recipient } = await device();
    const other = await device(5);
    await add(f, request(other.recipient));
    const seen: CarriedRecipient[][] = [];
    const g = grant();
    const before = f.header();
    await expect(
      add(
        f,
        request(recipient, g, async (carried) => {
          seen.push(carried);
          throw new Error("Link cancelled");
        }),
      ),
    ).rejects.toThrow("Link cancelled");
    expect(
      seen[0]
        ?.map(({ recipient: listed, trusted, self }) => [
          listed.id,
          trusted,
          self,
        ])
        .sort(),
    ).toEqual(
      [
        [owner.recipient.id, true, true],
        [other.recipient.id, true, false],
      ].sort(),
    );
    expect(g.calls.approved).toBe(0);
    expect(f.header()).toBe(before);
    // A browser whose pin predates the other device sees it marked as new.
    const owners = await fixture();
    const stale = owners.checkpoint();
    await add(owners, request(other.recipient));
    owners.setCheckpoint(stale);
    const marks: CarriedRecipient[] = [];
    await add(
      owners,
      request(recipient, grant(), async (carried) => {
        marks.push(...carried);
      }),
    );
    expect(
      marks.find((carried) => carried.recipient.id === other.recipient.id)
        ?.trusted,
    ).toBe(false);
  });
  test("a failed publish revokes the approval it got, and a refused approval writes nothing", async () => {
    const f = await fixture();
    const { recipient } = await device();
    const before = f.header();
    const refused = grant();
    await expect(
      add(f, {
        ...request(recipient, refused),
        link: {
          secret: SECRET,
          commitment: commitments.get(recipient.id) ?? "",
          approve: async () => {
            throw new Error("DEVICE_CODE_INVALID");
          },
          revoke: refused.revoke,
        },
      }),
    ).rejects.toThrow("DEVICE_CODE_INVALID");
    expect(f.header()).toBe(before);
    expect(f.writes).toHaveLength(0);
    const g = grant();
    f.failPublishes();
    await expect(add(f, request(recipient, g))).rejects.toThrow(
      "PDS unavailable",
    );
    expect(g.calls.revoked).toEqual([
      { deviceId: DEVICE_ID, recipientId: recipient.id },
    ]);
    expect(f.header()).toBe(before);
  });
  test("refuses before any approval: a forged id, an agent, a listed device, a full vault or switched-off linking", async () => {
    const f = await fixture();
    const { recipient } = await device();
    const g = grant();
    await expect(
      add(f, request({ ...recipient, id: (await device(4)).recipient.id }, g)),
    ).rejects.toThrow("Invalid vault recipient request");
    const agent = await createSeedRecipient(
      new Uint8Array(32).fill(6),
      "agent",
    );
    await expect(add(f, request(agent, g))).rejects.toThrow(
      "Invalid vault recipient request",
    );
    await expect(
      addVaultRecipient(f.port, request(recipient, g), {
        devices: false,
        passkeys: true,
      }),
    ).rejects.toThrow("Vault linking is off");
    await add(f, request(recipient));
    await expect(add(f, request(recipient, g))).rejects.toThrow(ALREADY_LISTED);
    const full = await fixture();
    for (let fill = 20; full.writes.length < 15; fill++)
      await add(full, request((await device(fill)).recipient));
    await expect(
      add(full, request((await device(40)).recipient, g)),
    ).rejects.toThrow("Vault credential limit reached");
    expect(g.calls.approved).toBe(0);
    // Filling the vault runs two Argon2id commitments per device.
  }, 30_000);
  test("an unsigned vault is refused, never migrated by a link", async () => {
    const f = await legacyVault();
    const { recipient } = await device();
    const g = grant();
    await expect(add(f, request(recipient, g))).rejects.toThrow(
      UNSIGNED_ACCESS,
    );
    expect(f.writes).toHaveLength(0);
    expect(g.calls.approved).toBe(0);
  });
  test("a legacy co-passkey publishes its own upgrade before the change, so pinned devices follow both", async () => {
    const key = new Uint8Array(32).fill(9);
    const owner = await passkeyAdmin(prfFor(7), "connected", did);
    const co = await passkeyAdmin(prfFor(8), "co", did);
    const legacyCo = {
      id: co.recipient.id,
      kind: "passkey" as const,
      role: "admin" as const,
      boxPublicKey: co.recipient.boxPublicKey,
    };
    const vault = crypto.randomUUID();
    const state = await signedVault(
      key,
      { did, vault, epoch: 1 },
      [owner.recipient, legacyCo],
      owner,
      "migrate",
    );
    const f = await fixture({
      key,
      header: await encryptedHeader(key, state, did),
      checkpoint: savedCheckpoint(state),
    });
    f.connect("co", 8);
    const { seed, recipient } = await device();
    await add(f, request(recipient));
    expect(f.writes).toHaveLength(2);
    // The upgrade and the change both keep the key, so neither moves a chunk.
    expect(f.scopes).toEqual(["root", "root"]);
    const { metadata } = await readVerifiedVaultRoot(key, did, f.header());
    if (!("version" in metadata)) throw new Error("Expected signed access");
    expect(metadata.statement).toMatchObject({
      kind: "change",
      sequence: 3,
      signer: co.recipient.id,
    });
    expect(await handed(f, seed)).not.toBeNull();
    const upgrade = f.writes[0];
    if (!upgrade) throw new Error("Missing upgrade");
    const latest = f.header();
    f.connect("connected", 7);
    f.setCheckpoint(savedCheckpoint(state));
    f.setHeader(upgrade);
    (await unlockVault(f.port)).runtime.lock();
    f.setHeader(latest);
    (await unlockVault(f.port)).runtime.lock();
    // A device that slept through the upgrade can't follow the co-passkey's change: the known multi-hop gap.
    f.setCheckpoint(savedCheckpoint(state));
    await expect(unlockVault(f.port)).rejects.toThrow(
      "not signed by a trusted key",
    );
  });
});

describe("a linked device's runner", () => {
  /** A vault the owner linked a device to, listing a second admin too, with one MDX note from each admin. */
  async function linkedVault() {
    const f = await fixture();
    const owner = f.admin;
    if (!owner) throw new Error("Missing owner");
    const intruder = await passkeyAdmin(prfFor(4), "intruder", did);
    const { seed, recipient } = await device();
    const enrolled = await signedVault(
      f.key,
      { did, vault: pinnedVault(f).vault, epoch: 1 },
      [owner.recipient, intruder.recipient, recipient],
      owner,
      "change",
      2,
    );
    f.setHeader(await encryptedHeader(f.key, enrolled, did));
    const write = async (path: string, source = "# Hi") => {
      const { runtime } = await unlockVault(f.port);
      await runtime.save({
        id: crypto.randomUUID(),
        path,
        source,
        kind: path.endsWith(".mdx") ? "mdx" : "md",
      });
      runtime.lock();
    };
    await write("Owner.mdx");
    await write("Kept.mdx");
    await write("Target.md");
    await write("Page.mdx", "[t](Target.md)");
    f.connect("intruder", 4);
    f.setCheckpoint(null);
    await write("Planted.mdx");
    f.connect("connected", 7);
    f.setCheckpoint(savedCheckpoint(enrolled));
    const unlockDevice = async (runners?: VaultRecipient[]) => {
      const { port } = seedPort(f, recipient.id, linkedCheckpoint(enrolled));
      return (
        await unlockVaultWithSeed(
          {
            ...port,
            runtime: (session) => localRuntime(session),
            ...(runners && {
              runners: runners.map((admin) => ({
                recipientId: admin.id,
                signPublicKey: admin.signPublicKey ?? "",
              })),
            }),
          },
          seed,
        )
      ).runtime;
    };
    return { f, owner, unlockDevice };
  }
  const origins = async (runtime: Pick<NoteRuntime, "list">) =>
    Object.fromEntries(
      (await runtime.list()).map((note) => [note.path, note.origin]),
    );

  test("runs MDX by itself only from the passkey that linked it, and nobody's without a handed runner", async () => {
    const { owner, unlockDevice } = await linkedVault();
    const runs = async (runners?: VaultRecipient[]) => {
      const runtime = await unlockDevice(runners);
      const seen = await origins(runtime);
      runtime.lock();
      return {
        owner: seen["Owner.mdx"]?.runs,
        planted: seen["Planted.mdx"]?.runs,
      };
    };
    expect(await runs([owner.recipient])).toEqual({
      owner: true,
      planted: false,
    });
    expect(await runs()).toEqual({ owner: false, planted: false });
  });
  test("never re-signs an admin's MDX as itself, nor asks to: an unchanged save keeps it, a rename or a trip through the trash strips it and says so", async () => {
    const { f, owner, unlockDevice } = await linkedVault();
    const runtime = await unlockDevice([owner.recipient]);
    const losses: TrustLoss[] = [];
    runtime.subscribeTrustLoss?.((loss) => losses.push(loss));
    const note = (await runtime.list()).find(
      (listed) => listed.path === "Owner.mdx",
    );
    if (!note) throw new Error("Missing note");
    const planted = (await runtime.list()).find(
      (listed) => listed.path === "Planted.mdx",
    );
    if (!planted?.digest) throw new Error("Missing note");
    expect(await runtime.writerToEndorse(note)).toBeNull();
    expect(await runtime.writerToEndorse(planted)).toBeNull();
    await expect(
      runtime.trust([{ id: planted.id, digest: planted.digest }]),
    ).rejects.toThrow("can’t record your trust");
    const { source } = note;
    await runtime.save({ id: note.id, path: note.path, source, kind: "mdx" });
    expect((await origins(runtime))["Owner.mdx"]).toEqual({
      runs: true,
      author: "Signed by a passkey",
    });
    await runtime.save({
      id: note.id,
      path: "Moved/Owner.mdx",
      source,
      kind: "mdx",
    });
    expect(losses).toEqual([{ unsigned: ["Owner.mdx"], stale: [] }]);
    const signedVersion = (await runtime.history(note.id)).find(
      (version) => version.source === source,
    );
    if (!signedVersion?.historyId) throw new Error("Missing version");
    await runtime.restoreVersion(note.id, signedVersion.historyId, true);
    expect((await origins(runtime))["Moved/Owner.mdx"]?.author).toBe(
      "Not signed",
    );
    expect(losses.at(-1)).toEqual({ unsigned: ["Owner.mdx"], stale: [] });
    const kept = (await runtime.list()).find(
      (listed) => listed.path === "Kept.mdx",
    );
    if (!kept) throw new Error("Missing note");
    // Even a digest offered as the person's endorsement signs nothing here.
    const held = async () => (await runtime.holdsCode(kept.id)) ?? undefined;
    const offered = await held();
    expect(offered).toBeString();
    await runtime.remove(kept.id, offered);
    expect(losses.at(-1)).toEqual({ unsigned: ["Kept.mdx"], stale: [] });
    await runtime.restore(kept.id, await held());
    const page = (await runtime.list()).find(
      (listed) => listed.path === "Page.mdx",
    );
    if (!page) throw new Error("Missing note");
    await runtime.save({ ...page, path: "Sub/Page.mdx" });
    const moved = (await runtime.list()).find(
      (listed) => listed.id === page.id,
    );
    // Link repair rewrote the moved note's own link; that isn't the device typing.
    expect(moved?.source).not.toBe(page.source);
    expect(moved?.origin?.author).toBe("Not signed");
    expect(losses.at(-1)).toEqual({ unsigned: ["Page.mdx"], stale: [] });
    expect((await origins(runtime))["Kept.mdx"]?.author).toBe("Not signed");
    const restored = (await runtime.list()).find(
      (listed) => listed.id === note.id,
    );
    if (!restored) throw new Error("Missing note");
    await runtime.save({ ...restored, source: "# Mine" });
    expect((await origins(runtime))["Moved/Owner.mdx"]?.author).toBe(
      "Signed by device “Laptop”",
    );
    runtime.lock();
    const { runtime: owners } = await unlockVault(f.port);
    expect((await origins(owners))["Moved/Owner.mdx"]?.runs).toBe(false);
    owners.lock();
  });
});

describe("attacks on linking", () => {
  test("a browser with no earlier pin, or only one it took on first use, can't re-sign a planted root into every pinned device", async () => {
    const f = await fixture();
    const owner = f.admin;
    if (!owner) throw new Error("Missing owner");
    const pinned = f.checkpoint();
    const vault = pinnedVault(f).vault;
    const intruder = await passkeyAdmin(prfFor(4), "intruder", did);
    const keyB = new Uint8Array(32).fill(66);
    const planted = await signedVault(
      keyB,
      { did, vault, epoch: 2 },
      [owner.recipient, intruder.recipient],
      intruder,
      "change",
      1000,
    );
    f.setHeader(await encryptedHeader(keyB, planted, did));
    await expect(unlockVault(f.port)).rejects.toThrow(
      "not signed by a trusted key",
    );
    const g = grant();
    const plantedHeader = f.header();
    for (const fresh of [null, { resetCandidates: [] }]) {
      f.setCheckpoint(fresh);
      await expect(
        add(f, request((await device()).recipient, g)),
      ).rejects.toThrow(FIRST_USE_PIN);
    }
    f.setCheckpoint(null);
    (await unlockVault(f.port)).runtime.lock();
    expect(lastPin(f.checkpoint())?.trust).toBe("tofu");
    await expect(
      add(f, request((await device()).recipient, g)),
    ).rejects.toThrow(UNTRUSTED_PIN);
    expect(g.calls.approved).toBe(0);
    expect(f.header()).toBe(plantedHeader);
    f.setCheckpoint(pinned);
    await expect(
      add(f, request((await device()).recipient, g)),
    ).rejects.toThrow("not signed by a trusted key");
    expect(g.calls.approved).toBe(0);
  });
  test("an approval whose answer was lost is revoked by recipient, and a revoke that keeps failing is reported, not swallowed", async () => {
    const f = await fixture();
    const { recipient } = await device();
    const before = f.header();
    const lost = grant({ lostAnswer: true });
    await expect(add(f, request(recipient, lost))).rejects.toThrow(
      "PDS_UNAVAILABLE",
    );
    expect(lost.calls).toMatchObject({
      approved: 1,
      revoked: [{ deviceId: undefined, recipientId: recipient.id }],
    });
    expect(f.header()).toBe(before);
    f.failPublishes();
    const stuck = grant({ revokeFails: true });
    await expect(add(f, request(recipient, stuck))).rejects.toBeInstanceOf(
      LinkCleanupError,
    );
    expect(stuck.calls.revokeAttempts).toBe(3);
  });
  test("a confirmation left unanswered expires before anything is approved or written", async () => {
    const f = await fixture();
    const { recipient } = await device();
    const before = f.header();
    const g = grant();
    const unanswered = request(recipient, g, () => new Promise(() => {}));
    await expect(
      addVaultRecipient(f.port, unanswered, enabled, 20),
    ).rejects.toThrow(CONFIRM_EXPIRED);
    expect(g.calls.approved).toBe(0);
    expect(f.header()).toBe(before);
  });
  test("a failure after the change is published keeps the device approved and says it is linked", async () => {
    const f = await fixture();
    const { seed, recipient } = await device();
    const g = grant();
    const port: UnlockPort = {
      ...f.port,
      saveCheckpoint: async () => {
        throw new Error("Storage unavailable");
      },
    };
    const outcome = await addVaultRecipient(
      port,
      request(recipient, g),
      enabled,
    ).catch((error: Error) => error);
    expect(outcome).toBeInstanceOf(LinkedWithCleanupError);
    expect(outcome).toMatchObject({ deviceId: DEVICE_ID });
    expect(g.calls).toMatchObject({ approved: 1, revokeAttempts: 0 });
    expect(await handed(f, seed)).not.toBeNull();
  });
  test("a device token that strips or garbles the handoff makes the device refuse, and a first-use pin stays first-use", async () => {
    const f = await fixture();
    const { seed, recipient } = await device();
    await add(f, request(recipient));
    const linked = await readVerifiedVaultRoot(f.key, did, f.header());
    if (!("version" in linked.metadata) || !linked.metadata.link)
      throw new Error("Expected a handoff");
    const { link, ...stripped } = linked.metadata;
    expect(link.trust).toBe("handed");
    const rewrite = async (metadata: typeof linked.metadata) =>
      encryptedHeader(
        f.key,
        {
          vault: linked.manifest.vault,
          epoch: 1,
          access: {
            header: {
              accessSalt: f.header().accessSalt,
              access: f.header().access,
            },
            metadata,
          },
        },
        did,
      );
    f.setHeader(await rewrite(stripped));
    expect(await handed(f, seed)).toBeNull();
    // The last of 107 characters carries 4 bits: A and E decode, B doesn't.
    for (const last of [link.sealed.at(-1) === "A" ? "E" : "A", "B"]) {
      f.setHeader(
        await rewrite({
          ...stripped,
          link: { ...link, sealed: `${link.sealed.slice(0, -1)}${last}` },
        }),
      );
      expect(await handed(f, seed)).toBeNull();
    }
    f.setHeader(
      await rewrite({ ...stripped, link: { ...link, trust: "tofu" } }),
    );
    expect(await handed(f, seed)).toBeNull();
    f.setHeader(await rewrite({ ...stripped, link }));
    const genuine = await handed(f, seed);
    if (!genuine) throw new Error("Expected the handoff to verify");
    expect(genuine.trust).toBe("handed");
    const { runners, ...pin } = genuine;
    f.setHeader(
      await rewrite({
        ...stripped,
        link: await sealLinkHandoff(
          { secret: SECRET, did, recipient },
          { ...pin, trust: "tofu" },
        ),
      }),
    );
    // A pin handed over from a browser that trusted it on first use stays a first-use pin.
    expect((await handed(f, seed))?.trust).toBe("tofu");
  });
  test("a session and key holder's own statement listing the device fails the handoff, even with the real one copied in", async () => {
    const f = await fixture();
    const { seed, recipient } = await device();
    await add(f, request(recipient));
    const real = await readVerifiedVaultRoot(f.key, did, f.header());
    if (!("version" in real.metadata))
      throw new Error("Expected signed access");
    const intruder = await passkeyAdmin(prfFor(4), "intruder", did);
    const forged = await signedVault(
      f.key,
      { did, vault: real.manifest.vault, epoch: 1 },
      [intruder.recipient, recipient],
      intruder,
      "change",
      3,
    );
    f.setHeader(await encryptedHeader(f.key, forged, did));
    expect(await handed(f, seed)).toBeNull();
    f.setHeader(
      await encryptedHeader(
        f.key,
        {
          ...forged,
          access: {
            ...forged.access,
            metadata: { ...forged.access.metadata, link: real.metadata.link },
          },
        },
        did,
      ),
    );
    expect(await handed(f, seed)).toBeNull();
  });
});

describe("admin-signed passkey enrollment", () => {
  test("a pinned admin lists a new passkey that then unlocks on its own, and pinned devices accept the change", async () => {
    const f = await fixture();
    const newcomer = await passkeyAdmin(prfFor(8), "newcomer", did);
    const pinBefore = f.checkpoint();
    await add(f, await enroll(f, newcomer.recipient, "newcomer"));
    expect(f.writes).toHaveLength(1);
    const { metadata } = await readVerifiedVaultRoot(f.key, did, f.header());
    if (!("version" in metadata)) throw new Error("Expected signed access");
    expect(metadata.statement).toMatchObject({ kind: "change", sequence: 2 });
    f.connect("newcomer", 8);
    (await unlockVault(f.port)).runtime.lock();
    f.connect("connected", 7);
    f.setCheckpoint(pinBefore);
    (await unlockVault(f.port)).runtime.lock();
    await expect(
      add(f, await enroll(f, newcomer.recipient, "newcomer")),
    ).rejects.toThrow(ALREADY_LISTED);
    expect(f.writes).toHaveLength(1);
  });
  test("a passkey comes without a Flow ID approval, a device never comes without one, and enrollment can be switched off", async () => {
    const f = await fixture();
    const newcomer = await passkeyAdmin(prfFor(8), "newcomer", did);
    const { recipient } = await device();
    const g = grant();
    const enrollment = await enroll(f, newcomer.recipient, "newcomer");
    for (const invalid of [
      { ...request(recipient, g), recipient: newcomer.recipient },
      { ...enrollment, link: request(recipient, g).link },
      { ...request(recipient, g), passkey: enrollment.passkey },
      { recipient, confirm: accept },
      { recipient: newcomer.recipient, confirm: accept },
      {
        ...enrollment,
        recipient: { ...newcomer.recipient, signPublicKey: undefined },
      },
    ])
      await expect(add(f, invalid)).rejects.toThrow(
        "Invalid vault recipient request",
      );
    await expect(
      addVaultRecipient(f.port, enrollment, { devices: true, passkeys: false }),
    ).rejects.toThrow("Vault linking is off");
    expect(g.calls.approved).toBe(0);
    expect(f.writes).toHaveLength(0);
  });
  test("the release's own switches link a device and enroll a passkey", async () => {
    const f = await fixture();
    const { seed, recipient } = await device();
    const g = grant();
    await addVaultRecipient(f.port, request(recipient, g));
    expect(g.calls.approved).toBe(1);
    expect(await handed(f, seed)).not.toBeNull();
    const newcomer = await passkeyAdmin(prfFor(8), "newcomer", did);
    await addVaultRecipient(
      f.port,
      await enroll(f, newcomer.recipient, "newcomer"),
    );
    expect(f.writes).toHaveLength(2);
    const { metadata } = await readVerifiedVaultRoot(f.key, did, f.header());
    if (!("version" in metadata)) throw new Error("Expected signed access");
    expect(metadata.recipients.map((listed) => listed.id)).toEqual(
      expect.arrayContaining([recipient.id, newcomer.recipient.id]),
    );
  });
  test("an unsigned vault refuses enrollment rather than adding an unsigned slot", async () => {
    const f = await legacyVault();
    const newcomer = await passkeyAdmin(prfFor(8), "newcomer", did);
    await expect(
      add(f, await enroll(f, newcomer.recipient, "newcomer")),
    ).rejects.toThrow(UNSIGNED_ACCESS);
    expect(f.writes).toHaveLength(0);
  });
});

/** The fixture's port, counting passkey prompts, so a refusal can show it came before any unlock. */
function counted(f: Fixture) {
  const calls = { prompts: 0 };
  const port: UnlockPort = {
    ...f.port,
    evaluatePrf: async (input) => {
      calls.prompts++;
      return f.port.evaluatePrf(input);
    },
  };
  return { port, calls };
}
/** What a phisher can make: keys of their own for any credential id, asserted by any key they hold. */
async function phished(
  credentialId: string,
  signer: SoftwarePasskey,
  options: { origin?: string } = {},
) {
  const admin = await passkeyAdmin(prfFor(66), credentialId, did);
  const issuedAt = Date.now();
  const request: RecipientRequest = {
    recipient: admin.recipient,
    passkey: {
      credentialId,
      issuedAt,
      assertion: await signer.assert(
        await passkeyRequestChallenge({
          did,
          boxPublicKey: admin.recipient.boxPublicKey,
          signPublicKey: admin.recipient.signPublicKey ?? "",
          issuedAt,
        }),
        options.origin ? { origin: options.origin } : {},
      ),
    },
    confirm: accept,
  };
  return { admin, request };
}

describe("a passkey request counts only when a passkey on this account made it", () => {
  test("a link a phisher makes up enrolls nothing, and fails before any unlock", async () => {
    const f = await fixture();
    const own = await f.register("own-second-passkey");
    const { port, calls } = counted(f);
    const before = f.header();
    const attacker = await softwarePasskey("AnyCredentialIdTheAttackerLikes");
    const cases: [string, RecipientRequest, string][] = [];
    const bare = await phished("AnyCredentialIdTheAttackerLikes", attacker);
    cases.push([
      "raw keys and no assertion, as requests once carried",
      { recipient: bare.admin.recipient, confirm: accept },
      "Invalid vault recipient request",
    ]);
    cases.push([
      "an assertion by a passkey Flow ID doesn't list",
      bare.request,
      UNANCHORED_PASSKEY,
    ]);
    cases.push([
      "the attacker's key claiming a listed credential id",
      (await phished("own-second-passkey", attacker)).request,
      UNANCHORED_PASSKEY,
    ]);
    const genuine = await enroll(
      f,
      (await passkeyAdmin(prfFor(8), "own-second-passkey", did)).recipient,
      "own-second-passkey",
      { passkey: own },
    );
    const swapped = await passkeyAdmin(prfFor(66), "own-second-passkey", did);
    cases.push([
      "the owner's genuine assertion with the attacker's keys swapped in",
      { ...genuine, recipient: swapped.recipient },
      UNANCHORED_PASSKEY,
    ]);
    cases.push([
      "the owner's passkey asserting on another site",
      (
        await phished("own-second-passkey", own, {
          origin: "https://other.example",
        })
      ).request,
      UNANCHORED_PASSKEY,
    ]);
    cases.push([
      "a request older than ten minutes",
      await enroll(
        f,
        (await passkeyAdmin(prfFor(8), "own-second-passkey", did)).recipient,
        "own-second-passkey",
        { passkey: own, issuedAt: Date.now() - 11 * 60_000 },
      ),
      PASSKEY_REQUEST_EXPIRED,
    ]);
    cases.push([
      "a request with no time at all",
      await enroll(
        f,
        (await passkeyAdmin(prfFor(8), "own-second-passkey", did)).recipient,
        "own-second-passkey",
        { passkey: own, issuedAt: Number.NaN },
      ),
      PASSKEY_REQUEST_EXPIRED,
    ]);
    cases.push([
      "a request dated in the future",
      await enroll(
        f,
        (await passkeyAdmin(prfFor(8), "own-second-passkey", did)).recipient,
        "own-second-passkey",
        { passkey: own, issuedAt: Date.now() + 5 * 60_000 },
      ),
      PASSKEY_REQUEST_EXPIRED,
    ]);
    for (const [name, request, refusal] of cases)
      expect([
        name,
        await addVaultRecipient(port, request, enabled).then(
          () => "enrolled",
          (error: Error) => error.message,
        ),
      ]).toEqual([name, refusal]);
    await expect(
      addVaultRecipient({ ...port, passkeys: undefined }, genuine, enabled),
    ).rejects.toThrow(UNANCHORED_PASSKEY);
    expect(calls.prompts).toBe(0);
    expect(f.writes).toHaveLength(0);
    expect(f.header()).toBe(before);
    // The attacker's box key opens no slot in the record it can read.
    await expect(
      openAccessSlot(
        { accessSalt: before.accessSalt, access: before.access },
        { publicKey: new Uint8Array(32), privateKey: new Uint8Array(32) },
        did,
      ),
    ).rejects.toThrow();
  });
  test("the owner's own second passkey, listed at Flow ID, is enrolled with one unlock", async () => {
    const f = await fixture();
    const { port, calls } = counted(f);
    const newcomer = await passkeyAdmin(prfFor(8), "own-second-passkey", did);
    await addVaultRecipient(
      port,
      await enroll(f, newcomer.recipient, "own-second-passkey"),
      enabled,
    );
    expect(calls.prompts).toBe(1);
    expect(f.writes).toHaveLength(1);
  });
  test("a session thief can read Flow ID's list but can't assert for any passkey on it", async () => {
    const f = await fixture();
    await f.register("own-second-passkey");
    const listed = await f.port.passkeys?.registered();
    expect(listed?.map((passkey) => passkey.credentialId)).toEqual([
      "own-second-passkey",
    ]);
    const thief = await softwarePasskey("own-second-passkey");
    const { request } = await phished("own-second-passkey", thief);
    await expect(add(f, request)).rejects.toThrow(UNANCHORED_PASSKEY);
    expect(f.writes).toHaveLength(0);
  });
});

describe("Flow ID knows the user code but never the device's secret", () => {
  test("Flow ID can't hand the device a vault of its own: no handoff it can seal verifies without the secret", async () => {
    const seed = new Uint8Array(32).fill(3);
    const device = await createSeedRecipient(seed, "device", "Laptop");
    const keyX = new Uint8Array(32).fill(77);
    const flowId = await passkeyAdmin(prfFor(5), "flow-id", did);
    const state = await signedVault(
      keyX,
      { did, vault: crypto.randomUUID(), epoch: 1 },
      [flowId.recipient, device],
      flowId,
      "create",
    );
    const substitute = async (link: LinkHandoff) => ({
      header: await encryptedHeader(
        keyX,
        {
          ...state,
          access: {
            ...state.access,
            metadata: { ...state.access.metadata, link },
          },
        },
        did,
      ),
    });
    // Flow ID issued the user code and saw it in plaintext; it is no longer the key.
    await expect(
      sealLinkHandoff(
        { secret: "BCDF-GHJK", did, recipient: device },
        linkedCheckpoint(state),
      ),
    ).rejects.toThrow("Invalid link secret");
    for (const guess of ["000000000000", "123456789013", "999999999999"]) {
      const forged = await sealLinkHandoff(
        { secret: guess, did, recipient: device },
        linkedCheckpoint(state),
      );
      await expect(
        handedCheckpoint(await substitute(forged), seed, did, SECRET),
      ).rejects.toThrow(LINK_UNVERIFIED);
    }
    // Only the secret the device showed and the user typed seals a handoff it accepts.
    const sealed = await sealLinkHandoff(
      { secret: SECRET, did, recipient: device },
      linkedCheckpoint(state),
    );
    expect(
      (await handedCheckpoint(await substitute(sealed), seed, did, SECRET))
        ?.vault,
    ).toBe(state.vault);
  });
  test("keys Flow ID swaps into lookup don't match the typed secret, so nothing is approved or unlocked", async () => {
    const f = await fixture();
    const { recipient } = await device();
    const swapped = await createSeedRecipient(
      new Uint8Array(32).fill(44),
      "device",
      "Laptop",
    );
    const { port, calls } = counted(f);
    const g = grant();
    // Swapped keys under the device's real commitment, or under one Flow ID made for a secret of its own.
    for (const commitment of [
      commitments.get(recipient.id) ?? "",
      await linkCommitment("555555555555", committed(swapped)),
    ])
      await expect(
        addVaultRecipient(
          port,
          request(swapped, g, accept, { commitment }),
          enabled,
        ),
      ).rejects.toThrow(LINK_SECRET_MISMATCH);
    await expect(
      addVaultRecipient(
        port,
        request(recipient, g, accept, { secret: "123456789013" }),
        enabled,
      ),
    ).rejects.toThrow(LINK_SECRET_MISMATCH);
    expect(calls.prompts).toBe(0);
    expect(g.calls.approved).toBe(0);
    expect(f.writes).toHaveLength(0);
  });
  test("a kind or label Flow ID rewrites in lookup doesn't match the commitment, so the user's agent can't pass as a device", async () => {
    const f = await fixture();
    const seed = new Uint8Array(32).fill(3);
    const agent = await createSeedRecipient(seed, "device", "Build agent");
    const { port, calls } = counted(f);
    const g = grant();
    // The agent committed as an agent; Flow ID tells the tab it is a device.
    const asAgent = await linkCommitment(SECRET, committed(agent, "agent"));
    await expect(
      addVaultRecipient(
        port,
        request(agent, g, accept, { commitment: asAgent }),
        enabled,
      ),
    ).rejects.toThrow(LINK_SECRET_MISMATCH);
    // A device that committed to one label, enrolled under another.
    const named = await linkCommitment(SECRET, committed(agent));
    await expect(
      addVaultRecipient(
        port,
        request({ ...agent, label: "Your MacBook" }, g, accept, {
          commitment: named,
        }),
        enabled,
      ),
    ).rejects.toThrow(LINK_SECRET_MISMATCH);
    expect(calls.prompts).toBe(0);
    expect(g.calls.approved).toBe(0);
    expect(f.writes).toHaveLength(0);
  });
  test("a browser that can't run Argon2id says so instead of calling the code wrong", async () => {
    const f = await fixture();
    const { recipient } = await device();
    const { port, calls } = counted(f);
    const g = grant();
    const failing = spyOn(sodium, "crypto_pwhash").mockImplementation(() => {
      throw new Error("Cannot enlarge memory");
    });
    try {
      await expect(
        addVaultRecipient(port, request(recipient, g), enabled),
      ).rejects.toThrow(LINK_CHECK_FAILED);
    } finally {
      failing.mockRestore();
    }
    expect(calls.prompts).toBe(0);
    expect(g.calls.approved).toBe(0);
    expect(f.writes).toHaveLength(0);
  });
});
