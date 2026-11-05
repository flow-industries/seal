import { expect, test } from "bun:test";
import Dexie from "dexie";
import { IDBKeyRange, indexedDB } from "fake-indexeddb";
import {
  attachment,
  encodedLength,
  legacyWorld,
  managedPds,
  note,
  tombstone,
} from "../../tests/managed-pds-fixture.ts";
import { passkeyPort } from "../../tests/passkey-port.ts";
import { signedVault } from "../../tests/unlock-fixture.ts";
import { passkeyAdmin } from "../crypto/access-v3.ts";
import {
  CHUNK_PLAINTEXT_BYTES,
  decryptContainerRoot,
} from "../crypto/container.ts";
import { createVaultKey } from "../crypto/index.ts";
import { VaultSyncEngine } from "../sync/vault-engine.ts";
import type { SnapshotEntry } from "../sync/vault-snapshot.ts";
import {
  AuthVaultTransport,
  MANAGED_QUOTA_BYTES,
  readVerifiedVaultRoot,
  type VaultRecordV2,
} from "../sync/vault-transport.ts";
import { createSession } from "../vault/session.ts";
import { VaultDatabase } from "../vault/storage.ts";
import { parseSyncBackoff, SYNC_TOO_LARGE, SYNCED } from "./runtime.ts";
import { unlockVault } from "./unlock.ts";

Dexie.dependencies.indexedDB = indexedDB;
Dexie.dependencies.IDBKeyRange = IDBKeyRange;

const PRF = new Uint8Array(32).fill(5);
const CREDENTIAL = "am91cm5hbA";

function band() {
  const entries: SnapshotEntry[] = [
    attachment("a", 64_000_000),
    attachment("b", 62_000_000),
  ];
  for (let index = 0; index < 50; index++)
    entries.push(note(`n${index}`, 90_000));
  expect(encodedLength(entries)).toBeGreaterThan(31 * CHUNK_PLAINTEXT_BYTES);
  expect(encodedLength(entries)).toBeLessThanOrEqual(
    32 * CHUNK_PLAINTEXT_BYTES,
  );
  return entries;
}
const edit = (entries: SnapshotEntry[], from: number, to: number) =>
  entries.map((entry, index) =>
    index >= from + 2 && index < to + 2 ? note(entry.id, 90_000) : entry,
  );
/** Over the band by one attachment, so a flipped writer journals it at 64 blobs; deleting that attachment leaves it in the band. */
const overBand = () => [...band(), attachment("c", 5_000_000)];
const inBand = (entries: SnapshotEntry[]) =>
  entries.map((entry) => (entry.id === "c" ? tombstone("c") : entry));

function manifestOf(key: Uint8Array, did: string, record?: VaultRecordV2) {
  if (!record) throw new Error("Missing stored vault");
  return decryptContainerRoot(key, { did }, record.root);
}

/** The port an app builds over Flow ID for this passkey; Flow-hosted accounts get the managed PDS's quota. */
function appPort(
  did: string,
  rpc: ReturnType<typeof managedPds>["rpc"],
  hosting: "flow" | "external" = "flow",
) {
  return passkeyPort({
    userId: `user-${did}`,
    did,
    credentialId: CREDENTIAL,
    rpc,
    prf: () => PRF.slice(),
    resolved: { hosting },
  });
}

test("a vault needing exactly 32 chunks, synced an hour apart, stays at 32 blobs with no orphans and journals again once it leaves the band", async () => {
  const did = "did:plc:band-stays";
  const w = await legacyWorld(did, PRF, CREDENTIAL);
  const pds = managedPds(did);
  const previous = new AuthVaultTransport(pds.rpc, {
    ...w.options,
    writeJournal: false,
  });
  let entries = band();
  let { cid } = await previous.writeSnapshot(entries, null);
  previous.stop();
  const transport = new AuthVaultTransport(pds.rpc, w.options);
  try {
    for (const [from, to] of [
      [0, 1],
      [1, 46],
      [46, 49],
    ] as const) {
      ({ cid } = await transport.readSnapshot());
      entries = edit(entries, from, to);
      await transport.writeSnapshot(entries, cid);
      expect(pds.stored?.value.blobs).toHaveLength(32);
      pds.advance(3600_000);
    }
    expect(pds.count("orphan")).toBe(0);
    expect((await manifestOf(w.key, did, pds.stored?.value)).version).toBe(2);
    ({ cid } = await transport.readSnapshot());
    entries = entries.map((entry) =>
      entry.id === "b" ? tombstone("b") : entry,
    );
    await transport.writeSnapshot(entries, cid);
    expect(pds.stored?.value.blobs).toHaveLength(32);
    expect(await manifestOf(w.key, did, pds.stored?.value)).toMatchObject({
      version: 3,
      chunkCount: 31,
    });
    const uploads = pds.uploads;
    ({ cid } = await transport.readSnapshot());
    entries = edit(entries, 0, 1);
    await transport.writeSnapshot(entries, cid);
    expect(pds.uploads - uploads).toBe(1);
    expect((await transport.readSnapshot()).entries).toHaveLength(
      entries.length,
    );
  } finally {
    transport.stop();
    w.key.fill(0);
  }
}, 300_000);

test("a vault growing out of the band journals at 64 blobs", async () => {
  const did = "did:plc:band-grows";
  const w = await legacyWorld(did, PRF, CREDENTIAL);
  const pds = managedPds(did);
  const transport = new AuthVaultTransport(pds.rpc, w.options);
  try {
    let entries = band();
    let { cid } = await transport.writeSnapshot(entries, null);
    expect(pds.stored?.value.blobs).toHaveLength(32);
    entries = overBand();
    ({ cid } = await transport.writeSnapshot(entries, cid));
    expect(pds.stored?.value.blobs).toHaveLength(64);
    const uploads = pds.uploads;
    await transport.writeSnapshot(edit(entries, 0, 1), cid);
    expect(pds.uploads - uploads).toBe(1);
  } finally {
    transport.stop();
    w.key.fill(0);
  }
}, 300_000);

test("a vault already at 64 blobs returns to 32 at its next forced compaction", async () => {
  const did = "did:plc:band-returns";
  const w = await legacyWorld(did, PRF, CREDENTIAL);
  const pds = managedPds(did);
  const transport = new AuthVaultTransport(pds.rpc, w.options);
  try {
    let entries = overBand();
    await transport.writeSnapshot(entries, null);
    expect(pds.stored?.value.blobs).toHaveLength(64);
    let { cid } = await transport.readSnapshot();
    entries = inBand(entries);
    await transport.writeSnapshot(entries, cid);
    expect(pds.stored?.value.blobs).toHaveLength(64);
    ({ cid } = await transport.readSnapshot());
    entries = edit(entries, 0, 46);
    await transport.writeSnapshot(entries, cid);
    expect(pds.stored?.value.blobs).toHaveLength(64);
    ({ cid } = await transport.readSnapshot());
    entries = edit(entries, 46, 49);
    const uploads = pds.uploads;
    await transport.writeSnapshot(entries, cid);
    expect(pds.uploads - uploads).toBe(32);
    expect(pds.stored?.value.blobs).toHaveLength(32);
    expect(pds.count("orphan")).toBe(0);
    expect((await manifestOf(w.key, did, pds.stored?.value)).version).toBe(2);
    expect((await transport.readSnapshot()).entries).toHaveLength(
      entries.length,
    );
  } finally {
    transport.stop();
    w.key.fill(0);
  }
}, 300_000);

test("migrating a band vault to signed access through a passkey port stays at 32 blobs, and later writes keep the slots", async () => {
  const did = "did:plc:band-signed";
  const w = await legacyWorld(did, PRF, CREDENTIAL);
  const pds = managedPds(did);
  const entries = band();
  const previous = new AuthVaultTransport(pds.rpc, {
    ...w.options,
    writeJournal: false,
  });
  await previous.writeSnapshot(entries, null);
  previous.stop();
  const uploads = pds.uploads;
  const unlocked = await unlockVault(appPort(did, pds.rpc), {}, true);
  try {
    expect(pds.uploads - uploads).toBe(0);
    expect(pds.stored?.value.blobs).toHaveLength(32);
    expect(pds.count("orphan")).toBe(0);
    const record = pds.stored?.value;
    if (!record) throw new Error("Missing stored vault");
    const { manifest, metadata } = await readVerifiedVaultRoot(
      w.key,
      did,
      record,
    );
    expect(manifest.version).toBe(2);
    expect(metadata).toMatchObject({
      version: 3,
      statement: { kind: "migrate" },
    });
    const writer = new AuthVaultTransport(pds.rpc, {
      ...w.options,
      access: {
        header: { accessSalt: record.accessSalt, access: record.access },
        metadata,
      },
    });
    const { cid, entries: held } = await writer.readSnapshot();
    await writer.writeSnapshot(edit(held, 0, 1), cid);
    writer.stop();
    expect(pds.stored?.value.blobs).toHaveLength(32);
    expect(pds.stored?.value.accessSalt).toBe(record.accessSalt);
    expect(pds.stored?.value.access).toEqual(record.access);
    expect(pds.count("orphan")).toBe(0);
  } finally {
    unlocked.runtime.lock();
    w.key.fill(0);
  }
}, 300_000);

test("re-keying a 64-blob band vault returns it to 32 blobs under the new key", async () => {
  const did = "did:plc:band-rekey";
  const key = await createVaultKey();
  const next = await createVaultKey();
  const vault = crypto.randomUUID();
  const pds = managedPds(did);
  const admin = await passkeyAdmin(PRF, CREDENTIAL, did);
  const state = await signedVault(
    key,
    { did, vault, epoch: 1 },
    [admin.recipient],
    admin,
  );
  const transport = new AuthVaultTransport(pds.rpc, { key, did, ...state });
  let entries = overBand();
  await transport.writeSnapshot(entries, null);
  const { cid: full } = await transport.readSnapshot();
  entries = inBand(entries);
  const { cid } = await transport.writeSnapshot(entries, full);
  transport.stop();
  expect(pds.stored?.value.blobs).toHaveLength(64);
  const rotated = await signedVault(
    next,
    { did, vault, epoch: 2 },
    [admin.recipient],
    admin,
    "change",
    2,
  );
  const port = appPort(did, pds.rpc);
  await port.rekey?.(
    { key, state },
    { key: next, state: rotated },
    cid,
    async (held) => held,
  );
  expect(pds.stored?.value.blobs).toHaveLength(32);
  expect(pds.count("orphan")).toBe(0);
  key.fill(0);
  next.fill(0);
}, 300_000);

test("a self-hosted 128-blob vault that empties compacts at once", async () => {
  const did = "did:plc:band-selfhosted";
  const w = await legacyWorld(did, PRF, CREDENTIAL);
  const pds = managedPds(did, Number.POSITIVE_INFINITY);
  const transport = new AuthVaultTransport(pds.rpc, w.options);
  try {
    const ids = ["a", "b", "c", "d", "e"];
    pds.discardBytes(true);
    const { cid } = await transport.writeSnapshot(
      ids.map((id) => attachment(id, 54_000_000)),
      null,
    );
    pds.discardBytes(false);
    expect(pds.stored?.value.blobs).toHaveLength(128);
    const uploads = pds.uploads;
    const emptied = ids.map((id) => tombstone(id));
    await transport.writeSnapshot(emptied, cid);
    expect(pds.uploads - uploads).toBe(1);
    expect(pds.stored?.value.blobs).toHaveLength(1);
    expect((await transport.readSnapshot()).entries).toEqual(emptied);
  } finally {
    transport.stop();
    w.key.fill(0);
  }
}, 300_000);

const pastTheBand = () => [...band(), attachment("c", 60_000_000)];
const refusedAsTooLarge = (write: Promise<unknown>) =>
  expect(write).rejects.toMatchObject({ reason: "too-large" });

test("a journaled 64-blob vault past its journal refuses before uploading, and a delete lands at once", async () => {
  const did = "did:plc:guard-journal";
  const w = await legacyWorld(did, PRF, CREDENTIAL);
  const pds = managedPds(did);
  const transport = new AuthVaultTransport(pds.rpc, {
    ...w.options,
    quotaBytes: MANAGED_QUOTA_BYTES,
  });
  try {
    let entries = pastTheBand();
    await transport.writeSnapshot(entries, null);
    expect(pds.stored?.value.blobs).toHaveLength(64);
    let { cid } = await transport.readSnapshot();
    entries = edit(entries, 0, 46);
    await transport.writeSnapshot(entries, cid);
    ({ cid } = await transport.readSnapshot());
    entries = edit(entries, 46, 49);
    const held = pds.stored?.cid;
    let uploads = pds.uploads;
    await refusedAsTooLarge(transport.writeSnapshot(entries, cid));
    expect(pds.uploads - uploads).toBe(0);
    expect(pds.count("orphan")).toBe(0);
    expect(pds.stored?.cid).toBe(held);
    entries = entries.map((entry) =>
      entry.id === "b" || entry.id === "c" ? tombstone(entry.id) : entry,
    );
    uploads = pds.uploads;
    await transport.writeSnapshot(entries, cid);
    expect(pds.uploads - uploads).toBe(32);
    expect(pds.stored?.value.blobs).toHaveLength(32);
    expect(pds.count("orphan")).toBe(0);
  } finally {
    transport.stop();
    w.key.fill(0);
  }
}, 300_000);

test("a v2 root at 64 blobs refuses before uploading, and a delete down to the band lands at once at 32 blobs", async () => {
  const did = "did:plc:guard-v2";
  const w = await legacyWorld(did, PRF, CREDENTIAL);
  const pds = managedPds(did);
  const previous = new AuthVaultTransport(pds.rpc, {
    ...w.options,
    writeJournal: false,
  });
  let entries = pastTheBand();
  await previous.writeSnapshot(entries, null);
  previous.stop();
  const transport = new AuthVaultTransport(pds.rpc, {
    ...w.options,
    quotaBytes: MANAGED_QUOTA_BYTES,
  });
  try {
    const { cid } = await transport.readSnapshot();
    const uploads = pds.uploads;
    await refusedAsTooLarge(transport.writeSnapshot(edit(entries, 0, 1), cid));
    expect(pds.uploads - uploads).toBe(0);
    entries = entries.map((entry) =>
      entry.id === "c" ? tombstone("c") : entry,
    );
    await transport.writeSnapshot(entries, cid);
    expect(pds.stored?.value.blobs).toHaveLength(32);
    expect(pds.count("orphan")).toBe(0);
  } finally {
    transport.stop();
    w.key.fill(0);
  }
}, 300_000);

test("a jump past 63 chunks refuses before uploading, and the journal still takes a write that fits", async () => {
  const did = "did:plc:guard-jump";
  const w = await legacyWorld(did, PRF, CREDENTIAL);
  const pds = managedPds(did);
  const transport = new AuthVaultTransport(pds.rpc, {
    ...w.options,
    quotaBytes: MANAGED_QUOTA_BYTES,
  });
  try {
    const start = [attachment("a", 64_000_000)];
    const { cid } = await transport.writeSnapshot(start, null);
    const uploads = pds.uploads;
    await refusedAsTooLarge(
      transport.writeSnapshot(
        [
          ...start,
          attachment("x", 69_000_000),
          attachment("y", 69_000_000),
          attachment("z", 69_000_000),
        ],
        cid,
      ),
    );
    expect(pds.uploads - uploads).toBe(0);
    await transport.writeSnapshot([...start, note("small", 500)], cid);
    expect(pds.uploads - uploads).toBe(1);
  } finally {
    transport.stop();
    w.key.fill(0);
  }
}, 300_000);

test("the guard counts the blobs of a record this transport just wrote", async () => {
  const did = "did:plc:guard-wrote";
  const w = await legacyWorld(did, PRF, CREDENTIAL);
  const pds = managedPds(did);
  const transport = new AuthVaultTransport(pds.rpc, {
    ...w.options,
    quotaBytes: MANAGED_QUOTA_BYTES,
  });
  try {
    const entries = pastTheBand();
    const { cid } = await transport.writeSnapshot(entries, null);
    const uploads = pds.uploads;
    await refusedAsTooLarge(transport.writeSnapshot(edit(entries, 0, 49), cid));
    expect(pds.uploads - uploads).toBe(0);
  } finally {
    transport.stop();
    w.key.fill(0);
  }
}, 300_000);

test("the guard never refuses 32 chunks or fewer, from any live state", async () => {
  const did = "did:plc:guard-sizes";
  const w = await legacyWorld(did, PRF, CREDENTIAL);
  const pds = managedPds(did);
  const transport = new AuthVaultTransport(pds.rpc, {
    ...w.options,
    quotaBytes: MANAGED_QUOTA_BYTES,
  });
  try {
    let cid: string | null = null;
    for (const entries of [
      band(),
      [attachment("a", 64_000_000), attachment("b", 60_000_000)],
      pastTheBand(),
      [
        attachment("a", 64_000_000),
        attachment("b", 62_000_000),
        note("n", 2_000_000),
        tombstone("c"),
      ],
      [attachment("a", 3_000_000), tombstone("b"), tombstone("c")],
      [note("only", 100), tombstone("a"), tombstone("b"), tombstone("c")],
    ] satisfies SnapshotEntry[][]) {
      ({ cid } = await transport.writeSnapshot(entries, cid));
      pds.advance(3600_000);
    }
    expect(pds.stored?.value.blobs).toHaveLength(1);
    expect(pds.count("orphan")).toBe(0);
  } finally {
    transport.stop();
    w.key.fill(0);
  }
}, 300_000);

function patterned(length: number) {
  const pattern = crypto.getRandomValues(new Uint8Array(65_536));
  const bytes = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += pattern.length)
    bytes.set(pattern.subarray(0, length - offset), offset);
  return bytes;
}

test.each([
  { hosting: "flow", limit: undefined, refused: true },
  {
    hosting: "external",
    limit: Number.POSITIVE_INFINITY,
    refused: false,
  },
] as const)(
  "through a passkey port, hosting $hosting decides whether a write that can't fit is refused",
  async ({ hosting, limit, refused }) => {
    const did = `did:plc:guard-${hosting}`;
    const key = await createVaultKey();
    const pds = managedPds(did, limit);
    const port = appPort(did, pds.rpc, hosting);
    const admin = await passkeyAdmin(PRF, CREDENTIAL, did);
    const transport = port.transport(
      key,
      await signedVault(
        key,
        { did, vault: crypto.randomUUID(), epoch: 1 },
        [admin.recipient],
        admin,
      ),
    );
    try {
      let entries = pastTheBand();
      await transport.writeSnapshot(entries, null);
      let { cid } = await transport.readSnapshot();
      entries = edit(entries, 0, 46);
      await transport.writeSnapshot(entries, cid);
      ({ cid } = await transport.readSnapshot());
      const uploads = pds.uploads;
      const write = transport.writeSnapshot(edit(entries, 46, 49), cid);
      if (refused) await refusedAsTooLarge(write);
      else await write;
      expect(pds.uploads - uploads).toBe(refused ? 0 : 64);
    } finally {
      transport.stop();
      key.fill(0);
    }
  },
  300_000,
);

test("a Flow-hosted sync the guard stops keeps its edits, says the notepad is too large, and a delete gets it moving", async () => {
  const did = "did:plc:guard-runtime";
  const key = await createVaultKey();
  const vault = crypto.randomUUID();
  const pds = managedPds(did);
  const admin = await passkeyAdmin(PRF, CREDENTIAL, did);
  const state = await signedVault(
    key,
    { did, vault, epoch: 1 },
    [admin.recipient],
    admin,
  );
  const port = appPort(did, pds.rpc);
  const setup = port.transport(key, state);
  await setup.writeSnapshot([], null);
  setup.stop();
  const session = createSession({ owner: did, vault, key });
  if (!port.runtime) throw new Error("Missing runtime");
  const runtime = port.runtime(session, key, state);
  const statuses: string[] = [];
  runtime.subscribe?.((status) => {
    statuses.push(status);
  });
  const device = createSession({ owner: did, vault, key });
  Object.defineProperty(device, "database", {
    value: new VaultDatabase(did, `${vault}-device`),
  });
  try {
    await runtime.sync?.();
    await session.import(
      ["one", "two", "three"].map((name) => ({
        path: `${name}.bin`,
        bytes: patterned(26 * 1024 * 1024),
      })),
    );
    await runtime.sync?.();
    expect(pds.stored?.value.blobs).toHaveLength(64);
    expect(await session.database.outbox.count()).toBe(0);
    await session.import([
      { path: "overflow.bin", bytes: patterned(2_500_000) },
    ]);
    const uploads = pds.uploads;
    const held = pds.stored?.cid;
    await runtime.sync?.();
    expect(pds.uploads - uploads).toBe(0);
    expect(pds.count("orphan")).toBe(0);
    expect(pds.stored?.cid).toBe(held);
    expect(await session.database.outbox.count()).toBe(1);
    expect(parseSyncBackoff(statuses.at(-1) ?? "")?.refusal).toBe(
      SYNC_TOO_LARGE,
    );
    const large = (await session.database.items.toArray())
      .filter((row) => (row.encryptedBlobs?.length ?? 0) > 20)
      .map((row) => row.id);
    expect(large).toHaveLength(3);
    await runtime.permanentRemove(large[0] ?? "");
    while (statuses.at(-1) !== SYNCED)
      await new Promise((resolve) => setTimeout(resolve, 25));
    expect(await session.database.outbox.count()).toBe(0);
    expect(pds.stored?.value.blobs).toHaveLength(32);
    expect(pds.count("orphan")).toBe(0);
    const follower = new VaultSyncEngine(device, port.transport(key, state));
    expect((await follower.sync()).blocked).toBeUndefined();
    follower.stop();
    const files = (await device.export()).map((file) => file.path);
    expect(files).toContain("overflow.bin");
    expect(files.filter((path) => path.endsWith(".bin"))).toHaveLength(3);
  } finally {
    runtime.lock();
    device.lock();
    key.fill(0);
  }
}, 300_000);
