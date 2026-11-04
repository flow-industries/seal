import {
  afterEach,
  beforeEach,
  describe,
  expect,
  setSystemTime,
  spyOn,
  test,
} from "bun:test";
import type {
  NoteDeviceCredentialStore,
  NoteDeviceCredentials,
} from "@flow-industries/id";
import Dexie from "dexie";
import { IDBKeyRange, indexedDB } from "fake-indexeddb";
import sodium from "libsodium-wrappers-sumo";
import {
  adminBrowser,
  did,
  fakeFlowId,
  host,
  memory,
  uri,
} from "../../tests/device-fixture.ts";
import { noteEntry } from "../../tests/entry-fixture.ts";
import { encryptedHeader, signedVault } from "../../tests/unlock-fixture.ts";
import { AccessRemovedError } from "../app/runtime.ts";
import { addVaultRecipient, linkedCheckpoint } from "../app/unlock.ts";
import {
  type AccessSigner,
  createSeedRecipient,
  passkeyAdmin,
  seedRecipientFromKeys,
  type VaultRecipient,
} from "../crypto/access-v3.ts";
import {
  authorityOf,
  type EntrySigner,
  entrySigner,
} from "../crypto/authorship.ts";
import { decrypt } from "../crypto/index.ts";
import {
  linkCommitment,
  matchesLinkCommitment,
  sealLinkHandoff,
  typedPairingCode,
} from "../crypto/link.ts";
import type { SnapshotEntry } from "../sync/vault-snapshot.ts";
import {
  AuthVaultTransport,
  type VaultRecordV2,
} from "../sync/vault-transport.ts";
import type { TrustLoss } from "../vault/session.ts";
import {
  createDeviceSeed,
  type DeviceCheckpointStore,
  type DeviceOptions,
  type DeviceVault,
  handedCheckpoint,
  LINK_EXPIRED,
  LINK_UNVERIFIED,
  LINK_WINDOW_MS,
  type LinkPrompt,
  linkDevice,
  NoteChangedError,
  openDeviceVault,
  PUBLISH_WAIT_MS,
} from "./client.ts";

Dexie.dependencies.indexedDB = indexedDB;
Dexie.dependencies.IDBKeyRange = IDBKeyRange;
const opened: DeviceVault[] = [];
afterEach(() => {
  for (const vault of opened.splice(0)) vault.stop();
});
async function open(seed: Uint8Array, options: DeviceOptions) {
  const vault = await openDeviceVault(seed, options);
  opened.push(vault);
  return vault;
}

/** The prompt the device shows, or the error that stopped it before it could. */
function prompted(linking: Promise<unknown>, onPrompt: Promise<LinkPrompt>) {
  return Promise.race([
    onPrompt,
    linking.then(() => {
      throw new Error("Linked without a prompt");
    }),
  ]);
}
/**
 * Runs the whole link: the device asks Flow ID for a code, the user looks it
 * up in the browser and types the device's secret, and the browser approves.
 * `sealedWith` stands in for a handoff sealed under any secret but the one
 * the device showed, with a commitment to match: what Flow ID would have to
 * forge to hand the device a vault of its own.
 */
async function linked(
  options: {
    sealedWith?: string;
    publishTimeoutMs?: number;
    admins?: readonly VaultRecipient[];
  } = {},
) {
  const { sealedWith, publishTimeoutMs } = options;
  const note = fakeFlowId();
  const admin = await adminBrowser(note, options.admins);
  const seed = createDeviceSeed();
  const credentials: NoteDeviceCredentialStore =
    memory<NoteDeviceCredentials>();
  const checkpoints: DeviceCheckpointStore = memory();
  const removals: string[] = [];
  const onRemoved = async (reason: string) => {
    removals.push(reason);
  };
  const { promise, resolve } = Promise.withResolvers<LinkPrompt>();
  const linking = linkDevice(seed, {
    host,
    label: "Agent box",
    credentials,
    checkpoints,
    fetch: note.fetch,
    onPrompt: resolve,
    onRemoved,
    publishTimeoutMs,
  });
  // Bun's `rejects` drives a promise to completion on the spot, which would wait out the approval; capture it instead.
  const outcome = linking.then(
    (checkpoint) => ({ checkpoint, error: null }),
    (error: Error) => ({ checkpoint: null, error: error.message }),
  );
  const shown = await prompted(linking, promise);
  const pending = note.lookup(shown.userCode);
  const keys = [
    pending.boxPublicKey ?? "",
    pending.signPublicKey ?? "",
  ] as const;
  expect(shown.pairingCode).toMatch(/^\d{4} \d{4} \d{4}$/);
  const typed = typedPairingCode(shown.pairingCode);
  await addVaultRecipient(
    admin.port,
    {
      recipient: await seedRecipientFromKeys(
        "device",
        ...keys,
        pending.label ?? "",
      ),
      link: {
        secret: sealedWith ?? typed,
        commitment: sealedWith
          ? await linkCommitment(sealedWith, {
              kind: "device",
              label: pending.label ?? "",
              boxPublicKey: keys[0],
              signPublicKey: keys[1],
            })
          : (pending.commitment ?? ""),
        approve: async () => note.approve(shown.userCode),
        revoke: async () => {},
      },
      confirm: async () => {},
    },
    { devices: true, passkeys: false },
  );
  return {
    note,
    admin,
    seed,
    typed,
    credentials,
    checkpoints,
    removals,
    onRemoved,
    ...(await outcome),
  };
}

type Linked = Awaited<ReturnType<typeof linked>>;
const signerOf = (admin: AccessSigner): EntrySigner => ({
  recipientId: admin.recipient.id,
  signPublicKey: admin.recipient.signPublicKey ?? "",
  privateKey: admin.privateKey,
});
const deviceOptions = (w: Linked) => ({
  host,
  credentials: w.credentials,
  checkpoints: w.checkpoints,
  fetch: w.note.fetch,
});
const adminTransport = (w: Linked) =>
  new AuthVaultTransport(w.note.browserRpc, {
    key: w.admin.key,
    did,
    ...w.admin.state,
  });
/** An admin's browser rewrites the PDS snapshot, as any key holder can. */
async function publish(
  w: Linked,
  edit: (entries: SnapshotEntry[]) => Promise<SnapshotEntry[]>,
) {
  const transport = adminTransport(w);
  const snapshot = await transport.readSnapshot();
  if (!snapshot) throw new Error("Missing snapshot");
  await transport.writeSnapshot(await edit(snapshot.entries), snapshot.cid);
  transport.stop();
}
/** What an admin reads back from the PDS: each item's name, text and verified signer. */
async function published(w: Linked) {
  const transport = adminTransport(w);
  const snapshot = await transport.readSnapshot();
  transport.stop();
  if (!snapshot?.access) throw new Error("Missing snapshot");
  const recipients = authorityOf(snapshot.access) ?? [];
  const context = { did, vault: w.admin.state.vault };
  const decoder = new TextDecoder();
  return Promise.all(
    snapshot.entries.map(async (entry) => {
      const item = JSON.parse(
        decoder.decode(
          await decrypt(entry.envelope, w.admin.key, {
            ...context,
            epoch: 1,
            item: entry.id,
            revision: entry.revision,
            assets: entry.chunkHashes,
          }),
        ),
      );
      return {
        id: entry.id,
        revision: entry.revision,
        name: String(item.name),
        text: decoder.decode(Uint8Array.from(item.bytes)),
        trashed: !!item.trashed,
        signer: (await entrySigner(entry, context, recipients))?.id ?? null,
      };
    }),
  );
}

describe("device client", () => {
  test("authorize, approve in the browser, take the token, unlock with the seed, then save and read back through the device vault", async () => {
    const w = await linked();
    const { note, admin, seed, typed, checkpoints, checkpoint, error } = w;
    expect(error).toBeNull();
    // Flow ID got the keys, a commitment and a proof of the signing key; never the secret the user typed.
    const [request] = note.authorized;
    expect(Object.keys(request ?? {}).sort()).toEqual([
      "boxPublicKey",
      "commitment",
      "kind",
      "label",
      "proof",
      "signPublicKey",
    ]);
    expect(
      await matchesLinkCommitment(
        typed,
        {
          kind: "device",
          label: "Agent box",
          boxPublicKey: request?.boxPublicKey ?? "",
          signPublicKey: request?.signPublicKey ?? "",
        },
        request?.commitment ?? "",
      ),
    ).toBe(true);
    expect(JSON.stringify(note.authorized)).not.toContain(typed);
    expect(checkpoint?.pinned.sequence).toBe(2);
    expect(checkpoint?.trust).toBe("handed");
    expect(await checkpoints.read()).toEqual(checkpoint);
    // Only the passkey whose change linked the device runs MDX on it by itself.
    expect(checkpoint?.runners).toEqual([
      {
        recipientId: admin.admin.recipient.id,
        signPublicKey: admin.admin.recipient.signPublicKey ?? "",
      },
    ]);

    const vault = await open(seed, deviceOptions(w));
    await vault.sync();
    expect(await vault.read()).toEqual({ notes: [], folders: [] });
    expect(await checkpoints.read()).toMatchObject({
      trust: "handed",
      runners: checkpoint?.runners,
    });
    const id = crypto.randomUUID();
    await vault.saveNote({
      id,
      path: "From device.mdx",
      source: "# Written by the device",
    });
    await vault.sync();
    vault.stop();
    await expect(
      vault.saveNote({ id, path: "From device.mdx", source: "# Later" }),
    ).rejects.toThrow("Vault locked");
    await expect(vault.rename(id, "Moved.mdx")).rejects.toThrow("Vault locked");
    expect(note.violations).toEqual([]);

    const own = await createSeedRecipient(seed, "device");
    expect(await published(w)).toEqual([
      expect.objectContaining({
        id,
        name: "From device.mdx",
        text: "# Written by the device",
        signer: own.id,
      }),
    ]);
    const reopened = await open(seed, deviceOptions(w));
    await reopened.sync();
    expect((await reopened.read()).notes).toEqual([
      expect.objectContaining({
        id,
        path: "From device.mdx",
        source: "# Written by the device",
        origin: { runs: false, author: "Signed by device “Agent box”" },
      }),
    ]);
  }, 30_000);

  test("a pin the open device follows forward keeps the trust and runner it was handed", async () => {
    const w = await linked();
    const { admin, checkpoints, checkpoint, error } = w;
    expect(error).toBeNull();
    const vault = await open(w.seed, deviceOptions(w));
    await vault.sync();
    const second = await createSeedRecipient(
      new Uint8Array(32).fill(5),
      "device",
      "Phone",
    );
    await addVaultRecipient(
      admin.port,
      {
        recipient: second,
        link: {
          secret: "123456789012",
          commitment: await linkCommitment("123456789012", {
            kind: "device",
            label: "Phone",
            boxPublicKey: second.boxPublicKey,
            signPublicKey: second.signPublicKey ?? "",
          }),
          approve: async () => crypto.randomUUID(),
          revoke: async () => {},
        },
        confirm: async () => {},
      },
      { devices: true, passkeys: false },
    );
    await vault.sync();
    expect(await checkpoints.read()).toMatchObject({
      pinned: { sequence: 3 },
      trust: "handed",
      runners: checkpoint?.runners,
    });
  }, 30_000);

  test("a device listed with a handoff sealed under any secret but its own refuses to link", async () => {
    const { checkpoints, checkpoint, error, removals } = await linked({
      sealedWith: "000000000000",
      publishTimeoutMs: 3000,
    });
    expect(checkpoint).toBeNull();
    expect(error).toBe(LINK_UNVERIFIED);
    expect(await checkpoints.read()).toBeNull();
    expect(removals).toEqual(["unverified"]);
  }, 30_000);

  test("a linked device without its saved pin never opens the vault", async () => {
    const { note, seed, credentials, error } = await linked();
    expect(error).toBeNull();
    await expect(
      openDeviceVault(seed, {
        host,
        credentials,
        checkpoints: memory(),
        fetch: note.fetch,
      }),
    ).rejects.toThrow("isn't pinned");
  }, 30_000);

  test("a device the vault dropped, or Flow ID revoked, gets a typed removal and keeps its pin", async () => {
    const { note, admin, seed, credentials, checkpoints, removals, onRemoved } =
      await linked();
    const options = {
      host,
      credentials,
      checkpoints,
      fetch: note.fetch,
      onRemoved,
    };
    const pinned = await checkpoints.read();
    const dropped = await signedVault(
      admin.key,
      { did, vault: admin.state.vault, epoch: 1 },
      [admin.admin.recipient],
      admin.admin,
      "change",
      3,
    );
    const current = note.record();
    const writer = new AuthVaultTransport(note.browserRpc, {
      key: admin.key,
      did,
      ...dropped,
    });
    await writer.writeSnapshot([], current?.cid ?? null);
    writer.stop();
    await expect(openDeviceVault(seed, options)).rejects.toBeInstanceOf(
      AccessRemovedError,
    );
    note.revokeAll();
    await expect(openDeviceVault(seed, options)).rejects.toBeInstanceOf(
      AccessRemovedError,
    );
    expect(removals).toEqual(["removed", "revoked"]);
    expect(await checkpoints.read()).toEqual(pinned);
  }, 30_000);
});

describe("a device vault's writes follow the session's carry rules", () => {
  /**
   * The owner linked this device, and the vault also lists a second admin.
   * Each admin's notes reach the device from the PDS. The device runs only
   * the owner's MDX by itself.
   */
  async function carried() {
    const other = await passkeyAdmin(new Uint8Array(32).fill(4), "other", did);
    const w = await linked({ admins: [other.recipient] });
    if (w.error) throw new Error(w.error);
    const owner = signerOf(w.admin.admin);
    const second = signerOf(other);
    const entry = (
      signer: EntrySigner,
      item: Parameters<typeof noteEntry>[3],
      source: string,
      revision?: string,
    ) =>
      noteEntry(
        w.admin.key,
        { did, vault: w.admin.state.vault },
        signer,
        item,
        source,
        revision,
      );
    await publish(w, async (entries) => [
      ...entries,
      await entry(owner, { id: "target", name: "Target.md" }, "# Target"),
      await entry(owner, { id: "index", name: "Index.mdx" }, "[t](Target.md)"),
      await entry(owner, { id: "a", name: "A.mdx" }, "# A"),
      await entry(owner, { id: "plain", name: "Plain.md" }, "[t](Target.md)"),
      await entry(second, { id: "other", name: "Other.mdx" }, "[t](Target.md)"),
      await entry(second, { id: "b", name: "B.mdx" }, "# B"),
    ]);
    /** Replaces the PDS entry for `id`, or adds it. */
    const replace = (next: SnapshotEntry) =>
      publish(w, async (entries) => [
        ...entries.filter((value) => value.id !== next.id),
        next,
      ]);
    const vault = await open(w.seed, deviceOptions(w));
    await vault.sync();
    const losses: TrustLoss[] = [];
    vault.subscribeTrustLoss((loss) => losses.push(loss));
    const view = async (path: string) => {
      const note = (await vault.read()).notes.find(
        (value) => value.path === path,
      );
      if (!note) throw new Error(`Missing ${path}`);
      return note;
    };
    const rows = async () => {
      await vault.sync();
      return published(w);
    };
    const row = async (id: string) => (await rows()).find((r) => r.id === id);
    const deviceId = (await createSeedRecipient(w.seed, "device")).id;
    /** Names of PDS items whose verified signer is this device. */
    const deviceSigned = async () =>
      (await rows())
        .filter((value) => value.signer === deviceId)
        .map((value) => value.name);
    return {
      w,
      vault,
      losses,
      entry,
      replace,
      view,
      rows,
      row,
      deviceSigned,
      ids: {
        owner: owner.recipientId,
        other: second.recipientId,
        device: deviceId,
      },
      owner,
      second,
    };
  }

  test("exposes session operations only, and runs MDX by itself only from the passkey that linked it", async () => {
    const { vault, view } = await carried();
    expect(Object.keys(vault).sort()).toEqual([
      "compose",
      "read",
      "remove",
      "rename",
      "saveNote",
      "stop",
      "subscribe",
      "subscribeChanges",
      "subscribeTrustLoss",
      "sync",
    ]);
    expect((await view("A.mdx")).origin).toEqual({
      runs: true,
      author: "Signed by a passkey",
    });
    const other = (await view("Other.mdx")).origin;
    expect(other?.runs).toBe(false);
    expect(other?.reason).toBeTruthy();
  }, 30_000);

  test("a move leaves both admins' MDX signed with stale links and says so; only the folder it made is the device's", async () => {
    const { w, vault, losses, rows, deviceSigned, ids } = await carried();
    await vault.rename("target", "Sub/Target.md");
    expect(losses).toHaveLength(1);
    expect(losses[0]?.unsigned).toEqual([]);
    expect(losses[0]?.stale.sort()).toEqual(["Index.mdx", "Other.mdx"]);
    const pds = await rows();
    expect(pds.find((value) => value.id === "index")).toMatchObject({
      text: "[t](Target.md)",
      signer: ids.owner,
    });
    expect(pds.find((value) => value.id === "other")).toMatchObject({
      text: "[t](Target.md)",
      signer: ids.other,
    });
    expect(pds.find((value) => value.id === "plain")).toMatchObject({
      text: "[t](Sub/Target.md)",
      signer: null,
    });
    expect(pds.find((value) => value.id === "target")?.signer).toBeNull();
    expect(await deviceSigned()).toEqual(["Sub"]);
    expect(w.note.violations).toEqual([]);
  }, 30_000);

  test("moving admin MDX whose own links need repair writes it unsigned and says so, by rename or by saving to a new path", async () => {
    const { vault, losses, view, row, deviceSigned } = await carried();
    await vault.rename("index", "Sub/Index.mdx");
    await vault.saveNote({
      ...(await view("Other.mdx")),
      path: "Sub/Other.mdx",
    });
    expect(losses).toEqual([
      { unsigned: ["Index.mdx"], stale: [] },
      { unsigned: ["Other.mdx"], stale: [] },
    ]);
    for (const id of ["index", "other"])
      expect(await row(id)).toMatchObject({
        text: "[t](../Target.md)",
        signer: null,
      });
    expect(await deviceSigned()).toEqual(["Sub"]);
  }, 30_000);

  test("trashing or merging admin MDX writes it unsigned and says so", async () => {
    const { vault, losses, rows, deviceSigned } = await carried();
    await vault.remove("a");
    expect(losses).toEqual([{ unsigned: ["A.mdx"], stale: [] }]);
    await vault.compose({
      kind: "merge",
      originId: "b",
      targetId: "index",
      expectedSource: "# B",
      expectedTargetSource: "[t](Target.md)",
    });
    expect(losses[1]?.unsigned.sort()).toEqual(["B.mdx", "Index.mdx"]);
    const pds = await rows();
    for (const id of ["a", "b", "index"])
      expect(pds.find((value) => value.id === id)?.signer).toBeNull();
    expect(pds.find((value) => value.id === "a")?.trashed).toBe(true);
    expect(await deviceSigned()).toEqual([]);
  }, 30_000);

  test("sync never re-signs: a sibling revision, a tombstone or an orphan leaves admin MDX unsigned and says so", async () => {
    const { vault, losses, entry, replace, rows, deviceSigned, owner, second } =
      await carried();
    await replace(
      await entry(second, { id: "a", name: "A.mdx" }, "# A, the other admin's"),
    );
    await vault.sync();
    expect(losses).toEqual([
      {
        unsigned: [expect.stringMatching(/^A conflict \w+\.mdx$/u), "A.mdx"],
        stale: [],
      },
    ]);
    const tombstone = await entry(
      owner,
      {
        id: "index",
        name: "Index.mdx",
        trashed: true,
        permanent: true,
        revisionCounter: 2,
      },
      "",
    );
    await replace({ ...tombstone, recordType: "game.flow.note.tombstone" });
    await vault.sync();
    expect(losses[1]).toEqual({
      unsigned: [expect.stringMatching(/^Index recovered draft \w+\.mdx$/u)],
      stale: [],
    });
    await replace(
      await entry(
        owner,
        { id: "orphan", name: "Orphan.mdx", parent: "missing" },
        "# Orphan",
      ),
    );
    await vault.sync();
    expect(losses[2]).toEqual({ unsigned: ["Orphan.mdx"], stale: [] });
    const pds = await rows();
    for (const name of [/^A conflict/u, /^A\.mdx$/u, /^Index recovered/u])
      expect(pds.find((value) => name.test(value.name))?.signer).toBeNull();
    expect(pds.find((value) => value.id === "orphan")?.signer).toBeNull();
    expect(await deviceSigned()).toEqual([]);
  }, 30_000);

  test("signs only its own typing, judged against the stored row before any base it names", async () => {
    const { vault, losses, entry, replace, view, row, ids, second } =
      await carried();
    const shown = await view("A.mdx");
    await replace(
      await entry(
        second,
        { id: "a", name: "A.mdx", revisionCounter: 2 },
        "# A, the other admin's",
        "a-2",
      ),
    );
    await vault.sync();
    const newer = { revision: "a-2", signer: ids.other };
    // The newer row's own bytes, named with the older base, are no edit of the device's.
    await vault.saveNote({ ...shown, source: "# A, the other admin's" });
    expect(await row("a")).toMatchObject(newer);
    // A flush of the view the device was shown, never edited, writes nothing either.
    await vault.saveNote(shown);
    expect(await row("a")).toMatchObject(newer);
    await vault.saveNote({ ...shown, source: "# A, mine" });
    expect(await row("a")).toMatchObject({
      text: "# A, mine",
      signer: ids.device,
    });
    expect(losses).toEqual([]);

    const id = crypto.randomUUID();
    await vault.saveNote({ id, path: "Own.mdx", source: "# Own" });
    expect((await row(id))?.signer).toBe(ids.device);
  }, 30_000);

  test("refuses to save an existing note over a revision it can't place, or none, and writes nothing", async () => {
    const { vault, losses, entry, replace, view, row, ids, second } =
      await carried();
    const shown = await view("A.mdx");
    const index = await view("Index.mdx");
    await replace(
      await entry(
        second,
        { id: "a", name: "A.mdx", revisionCounter: 2 },
        "# A, the other admin's",
        "a-2",
      ),
    );
    await vault.sync();
    const unplaced = { revision: "gone", digest: "0".repeat(64) };
    // A stale copy kept across a fresh local database, a pruned history or a restart, saved in place or moved.
    for (const note of [
      { ...shown, ...unplaced },
      { ...shown, ...unplaced, path: "Sub/A.mdx" },
      { id: "a", path: "A.mdx", source: "# A" },
      { id: "a", path: "Sub/A.mdx", source: "# A" },
      { ...index, ...unplaced },
    ])
      await expect(vault.saveNote(note)).rejects.toBeInstanceOf(
        NoteChangedError,
      );
    expect(await row("a")).toMatchObject({
      name: "A.mdx",
      revision: "a-2",
      signer: ids.other,
    });
    expect(await row("index")).toMatchObject({
      revision: index.revision,
      signer: ids.owner,
    });
    expect(losses).toEqual([]);
  }, 30_000);

  test("hands out origin verdicts no caller can rewrite", async () => {
    const { vault, losses, view } = await carried();
    const { origin: a } = await view("A.mdx");
    const { origin: b } = await view("B.mdx");
    if (!a || !b) throw new Error("Missing origin");
    expect(() => {
      a.runs = false;
    }).toThrow(TypeError);
    expect(() => Object.assign(b, { runs: true })).toThrow(TypeError);
    await vault.rename("a", "Sub/A.mdx");
    expect(losses).toEqual([{ unsigned: ["A.mdx"], stale: [] }]);
    expect((await view("B.mdx")).origin).toEqual(b);
    expect(b.runs).toBe(false);
  }, 30_000);
});

/**
 * A Flow ID that answers `authorize` with `expiresIn` and then plays the
 * rest through `token` and `records`, for the window tests. `records` serves
 * whatever vault it is handed, as a compromised Flow ID proxying the PDS can.
 */
function stalling(
  expiresIn: number,
  token: () => Response | Promise<Response>,
  records: () => VaultRecordV2 | null | Promise<VaultRecordV2 | null> = () =>
    null,
) {
  const authorized: Record<string, string>[] = [];
  const calls = { token: 0, records: 0 };
  async function fetch(url: string, init: RequestInit): Promise<Response> {
    const path = new URL(url).pathname;
    if (path === "/api/atproto/note/device/authorize") {
      authorized.push(JSON.parse(String(init.body)));
      return Response.json({
        deviceCode: "fndc_window",
        userCode: "BCDF-GHJK",
        verificationUri: "https://note.example/link?code=BCDF-GHJK",
        interval: 1,
        expiresIn,
      });
    }
    if (path === "/api/atproto/note/device/token") {
      calls.token++;
      return token();
    }
    if (path === "/api/atproto/note/records") {
      calls.records++;
      const value = await records();
      return value
        ? Response.json({ uri, cid: `cid-${calls.records}`, value })
        : Response.json({ code: "NOTE_NOT_FOUND" }, { status: 404 });
    }
    return Response.json({ code: "NOT_FOUND" }, { status: 404 });
  }
  return { fetch, authorized, calls };
}
const pending = () =>
  Response.json({ code: "AUTHORIZATION_PENDING" }, { status: 400 });
const issued = () =>
  Response.json({
    accessToken: "fnd_window",
    refreshToken: "fndr_window",
    expiresIn: 900,
    deviceId: crypto.randomUUID(),
    userId: "owner",
    did,
  });
/** Runs a link against `flowId`, capturing its prompt and outcome instead of letting a rejection escape. */
function attempt(
  seed: Uint8Array,
  flowId: ReturnType<typeof stalling>,
  publishTimeoutMs?: number,
) {
  const prompts: LinkPrompt[] = [];
  const removals: string[] = [];
  const credentials = memory<NoteDeviceCredentials>();
  const checkpoints: DeviceCheckpointStore = memory();
  const outcome = linkDevice(seed, {
    host,
    label: "Laptop",
    credentials,
    checkpoints,
    fetch: flowId.fetch,
    onPrompt: (prompt) => prompts.push(prompt),
    onRemoved: async (reason) => {
      removals.push(reason);
    },
    publishTimeoutMs,
  }).then(
    (checkpoint) => ({ checkpoint, error: null }),
    (error: Error) => ({ checkpoint: null, error: error.message }),
  );
  return { prompts, removals, credentials, checkpoints, outcome };
}
/** The device's window runs on `performance.now()`; these tests move it, and the wall clock with it. */
let skew = 0;
const monotonic = performance.now.bind(performance);
function advance(ms: number) {
  skew += ms;
  setSystemTime(new Date(Date.now() + ms));
}
/** A vault under Flow ID's own key `keyX` that lists the device, its handoff sealed under the secret Flow ID searched out. */
async function substitute(
  seed: Uint8Array,
  secret: string,
  listsDevice = true,
) {
  const device = await createSeedRecipient(seed, "device", "Laptop");
  const keyX = new Uint8Array(32).fill(77);
  const flowAdmin = await passkeyAdmin(
    new Uint8Array(32).fill(5),
    "flow-id",
    did,
  );
  const theirs = await signedVault(
    keyX,
    { did, vault: crypto.randomUUID(), epoch: 1 },
    listsDevice ? [flowAdmin.recipient, device] : [flowAdmin.recipient],
    flowAdmin,
    "create",
  );
  return {
    vault: theirs.vault,
    header: await encryptedHeader(
      keyX,
      listsDevice
        ? {
            ...theirs,
            access: {
              ...theirs.access,
              metadata: {
                ...theirs.access.metadata,
                link: await sealLinkHandoff(
                  { secret, did, recipient: device },
                  linkedCheckpoint(theirs),
                ),
              },
            },
          }
        : theirs,
      did,
    ),
  };
}

describe("the device keeps its own ten minutes, and no search carries over", () => {
  let clock: ReturnType<typeof spyOn>;
  beforeEach(() => {
    clock = spyOn(performance, "now").mockImplementation(
      () => monotonic() + skew,
    );
  });
  afterEach(() => {
    clock.mockRestore();
    skew = 0;
    setSystemTime();
  });

  test("a code Flow ID says lasts thirty days is refused before the secret is shown", async () => {
    const flowId = stalling(30 * 24 * 3600, issued);
    const { prompts, outcome } = attempt(createDeviceSeed(), flowId);
    expect(await outcome).toEqual({ checkpoint: null, error: LINK_EXPIRED });
    expect(prompts).toEqual([]);
    expect(flowId.calls.token).toBe(0);
  });

  test("a Flow ID that stalls the token past the device's ten minutes gets no link, whatever it serves later", async () => {
    const flowId = stalling(LINK_WINDOW_MS / 1000, () => {
      // Each poll stands for minutes of a search Flow ID is running on the commitment.
      advance(4 * 60_000);
      return pending();
    });
    const { prompts, credentials, checkpoints, outcome } = attempt(
      createDeviceSeed(),
      flowId,
    );
    expect(await outcome).toEqual({ checkpoint: null, error: LINK_EXPIRED });
    expect(prompts).toHaveLength(1);
    expect(flowId.calls.token).toBeLessThanOrEqual(3);
    expect(await credentials.read()).toBeNull();
    expect(await checkpoints.read()).toBeNull();
  }, 30_000);

  test("a handoff Flow ID could only seal after the window, once it had the secret, is never accepted", async () => {
    const seed = createDeviceSeed();
    // Until its search of the commitment finishes, Flow ID serves a vault that doesn't list the device, while the clock runs on.
    const decoy = await substitute(seed, "000000000000", false);
    const searchDone = Date.now() + LINK_WINDOW_MS + 2 * 60_000;
    let forged: Awaited<ReturnType<typeof substitute>> | null = null;
    const flowId = stalling(LINK_WINDOW_MS / 1000, issued, () => {
      advance(4 * 60_000);
      return Date.now() > searchDone && forged ? forged.header : decoy.header;
    });
    const { prompts, checkpoints, outcome } = attempt(seed, flowId);
    while (!prompts[0]) await Bun.sleep(10);
    const secret = typedPairingCode(prompts[0].pairingCode);
    forged = await substitute(seed, secret);
    expect(await outcome).toEqual({ checkpoint: null, error: LINK_UNVERIFIED });
    expect(await checkpoints.read()).toBeNull();
    // The forged handoff would have verified: only the device's deadline kept it out.
    expect(
      (await handedCheckpoint({ header: forged.header }, seed, did, secret))
        ?.vault,
    ).toBe(forged.vault);
  }, 30_000);

  test("a handoff read Flow ID starts inside the window and answers three days later is refused", async () => {
    const seed = createDeviceSeed();
    const { promise: readStarted, resolve: startRead } =
      Promise.withResolvers<void>();
    const { promise: searched, resolve: finishSearch } =
      Promise.withResolvers<VaultRecordV2>();
    // Flow ID holds the first read open (in practice by trickling body bytes) while it searches.
    const flowId = stalling(LINK_WINDOW_MS / 1000, issued, () => {
      startRead();
      return searched;
    });
    const { prompts, removals, checkpoints, outcome } = attempt(seed, flowId);
    await readStarted;
    const secret = typedPairingCode(prompts[0]?.pairingCode ?? "");
    advance(3 * 24 * 60 * 60_000);
    const forged = await substitute(seed, secret);
    finishSearch(forged.header);
    expect(await outcome).toEqual({ checkpoint: null, error: LINK_UNVERIFIED });
    expect(flowId.calls.records).toBe(1);
    expect(await checkpoints.read()).toBeNull();
    expect(removals).toEqual(["unverified"]);
    // What the held read carried would have verified; only the check after it kept it out.
    expect(
      (await handedCheckpoint({ header: forged.header }, seed, did, secret))
        ?.vault,
    ).toBe(forged.vault);
  }, 30_000);

  test("tokens that arrive after the window, through a fetch that ignores the abort, are refused and never stored", async () => {
    const { promise: polled, resolve: startPoll } =
      Promise.withResolvers<void>();
    const { promise: late, resolve: answer } =
      Promise.withResolvers<Response>();
    const flowId = stalling(LINK_WINDOW_MS / 1000, () => {
      startPoll();
      return late;
    });
    const { credentials, checkpoints, outcome } = attempt(
      createDeviceSeed(),
      flowId,
    );
    await polled;
    advance(LINK_WINDOW_MS + 60_000);
    answer(issued());
    expect(await outcome).toEqual({ checkpoint: null, error: LINK_EXPIRED });
    expect(await credentials.read()).toBeNull();
    expect(await checkpoints.read()).toBeNull();
    expect(flowId.calls.records).toBe(0);
  }, 30_000);

  test("a caller can't stretch the handoff wait past PUBLISH_WAIT_MS", async () => {
    const seed = createDeviceSeed();
    const decoy = await substitute(seed, "000000000000", false);
    const flowId = stalling(LINK_WINDOW_MS / 1000, issued, () => {
      advance(30_000);
      return decoy.header;
    });
    const { outcome } = attempt(seed, flowId, 10 * 60_000);
    expect(await outcome).toEqual({ checkpoint: null, error: LINK_UNVERIFIED });
    expect(flowId.calls.records).toBeLessThanOrEqual(PUBLISH_WAIT_MS / 30_000);
  }, 30_000);

  test("each attempt commits under a fresh nonce, so a table built from one link says nothing about the next", async () => {
    const seed = createDeviceSeed();
    const expired = () =>
      Response.json({ code: "EXPIRED_TOKEN" }, { status: 400 });
    const first = stalling(600, expired);
    const second = stalling(600, expired);
    const one = attempt(seed, first);
    const two = attempt(seed, second);
    expect((await one.outcome).error).toBe(LINK_EXPIRED);
    expect((await two.outcome).error).toBe(LINK_EXPIRED);
    const [a] = first.authorized;
    const [b] = second.authorized;
    if (!a || !b || !one.prompts[0] || !two.prompts[0])
      throw new Error("Expected two attempts");
    expect([a.boxPublicKey, a.signPublicKey]).toEqual([
      b.boxPublicKey,
      b.signPublicKey,
    ]);
    const request = (body: Record<string, string>) => ({
      kind: body.kind ?? "",
      label: body.label ?? "",
      boxPublicKey: body.boxPublicKey ?? "",
      signPublicKey: body.signPublicKey ?? "",
    });
    const nonceOf = (commitment: string) =>
      sodium
        .from_base64(commitment, sodium.base64_variants.URLSAFE_NO_PADDING)
        .slice(0, 16);
    // Everything a table could be built from after the first link: its request and its nonce.
    const table = (secret: string) =>
      linkCommitment(secret, request(a), nonceOf(a.commitment ?? ""));
    const secretOne = typedPairingCode(one.prompts[0].pairingCode);
    const secretTwo = typedPairingCode(two.prompts[0].pairingCode);
    expect(await table(secretOne)).toBe(a.commitment);
    expect(nonceOf(b.commitment ?? "")).not.toEqual(
      nonceOf(a.commitment ?? ""),
    );
    expect(await table(secretTwo)).not.toBe(b.commitment);
    expect(
      await matchesLinkCommitment(secretTwo, request(b), b.commitment ?? ""),
    ).toBe(true);
  }, 30_000);
});
