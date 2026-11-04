import { expect, test } from "bun:test";
import Dexie from "dexie";
import { IDBKeyRange, indexedDB } from "fake-indexeddb";
import { z } from "zod";
import { passkeyVault, signedVault } from "../../tests/unlock-fixture.ts";
import { SYNC_BLOCKED, SYNC_LOCKED, SYNC_PENDING } from "../app/runtime.ts";
import { synchronizedRuntime } from "../app/synchronized-runtime.ts";
import { createVaultKey } from "../crypto/index.ts";
import {
  createSeedRecipient,
  type PinnedAccess,
  passkeyAdmin,
  type RecipientRef,
} from "../crypto/access-v3.ts";
import { signEntry } from "../crypto/authorship.ts";
import {
  decryptContainerChunks,
  decryptContainerRoot,
  encryptContainer,
  JOURNAL_PLAINTEXT_BYTES,
} from "../crypto/container.ts";
import { createSession } from "../vault/session.ts";
import { VaultDatabase } from "../vault/storage.ts";
import { VaultSyncEngine } from "./vault-engine.ts";
import {
  decodeSnapshot,
  encodeBlob,
  encodeSnapshot,
  type SnapshotEntry,
} from "./vault-snapshot.ts";
import {
  AuthVaultTransport,
  staysJournal,
  type VaultRecordV2,
  type VaultTransportRpc,
  vaultBlobSchema,
  vaultRecordSchema,
} from "./vault-transport.ts";

Dexie.dependencies.indexedDB = indexedDB;
Dexie.dependencies.IDBKeyRange = IDBKeyRange;

async function fixture() {
  const key = await createVaultKey();
  const did = "did:plc:transport";
  const vault = crypto.randomUUID();
  const { admin, state } = await passkeyVault(
    key,
    did,
    new Uint8Array(32).fill(7),
    "credential",
    vault,
  );
  let stored: { cid: string; uri: string; value: VaultRecordV2 } | null = null;
  const blobs = new Map<string, Uint8Array>();
  let commits = 0;
  let uploads = 0;
  let puts = 0;
  let beforePut: (() => Promise<void>) | null = null;
  const uri = `at://${did}/industries.flow.note.vault/vault`;
  const rpc: VaultTransportRpc = {
    async records(operation) {
      if (operation.method === "read") {
        if (!stored) throw { code: "NOTE_NOT_FOUND", status: 404 };
        return structuredClone(stored);
      }
      puts++;
      if (beforePut) {
        const run = beforePut;
        beforePut = null;
        await run();
      }
      if ((stored?.cid ?? null) !== operation.swapRecord)
        throw { code: "CONFLICT", status: 409 };
      stored = {
        cid: `cid-${++commits}`,
        uri,
        value: structuredClone(operation.record),
      };
      return { cid: stored.cid, uri };
    },
    async upload(bytes) {
      uploads++;
      const cid = crypto.randomUUID();
      blobs.set(cid, bytes.slice());
      return {
        blob: {
          $type: "blob",
          ref: { $link: cid },
          mimeType: "application/octet-stream",
          size: bytes.length,
        },
      };
    },
    async download(cid) {
      const bytes = blobs.get(cid);
      if (!bytes) throw new Error("Missing blob");
      return bytes.slice();
    },
  };
  return {
    key,
    did,
    vault,
    admin,
    state,
    rpc,
    blobs,
    get stored() {
      return stored;
    },
    get uploads() {
      return uploads;
    },
    get puts() {
      return puts;
    },
    duringPut(run: () => Promise<void>) {
      beforePut = run;
    },
  };
}
test("SDK missing-vault code supports setup and readback verifies the padded snapshot", async () => {
  const f = await fixture();
  const adapter = new AuthVaultTransport(f.rpc, { ...f, ...f.state });
  const result = await adapter.writeSnapshot([], null);
  expect(await adapter.readSnapshot()).toEqual({
    cid: result.cid,
    entries: [],
    access: f.state.access.metadata,
  });
  expect(f.stored?.value.blobs).toHaveLength(1);
  expect(f.stored?.value.blobs[0]?.size).toBe(4 * 1024 * 1024);
  await expect(adapter.writeSnapshot([], null)).rejects.toMatchObject({
    reason: "conflict",
  });
  adapter.stop();
  await expect(adapter.readSnapshot()).rejects.toThrow("Vault locked");
});
test("chunk corruption is rejected before snapshot ingest", async () => {
  const f = await fixture();
  const adapter = new AuthVaultTransport(f.rpc, { ...f, ...f.state });
  await adapter.writeSnapshot([], null);
  const bytes = f.blobs.values().next().value;
  if (!bytes) throw new Error("Missing test chunk");
  bytes[200] ^= 1;
  await expect(adapter.readSnapshot()).rejects.toThrow();
  adapter.stop();
}, 60_000);
test("a removed recipient cannot publish after reading a fresh header", async () => {
  const f = await fixture();
  const context = { did: f.did, vault: f.vault, epoch: 1 };
  const other = await passkeyAdmin(new Uint8Array(32).fill(9), "other", f.did);
  const shared = await signedVault(
    f.key,
    context,
    [f.admin.recipient, other.recipient],
    f.admin,
  );
  const writer = new AuthVaultTransport(f.rpc, {
    ...f,
    ...(await signedVault(
      f.key,
      context,
      [f.admin.recipient],
      f.admin,
      "change",
      2,
    )),
  });
  await writer.writeSnapshot([], null);
  const removed = new AuthVaultTransport(f.rpc, {
    ...f,
    ...shared,
    ownRecipient: {
      id: other.recipient.id,
      boxPublicKey: other.recipient.boxPublicKey,
    },
  });
  await expect(removed.readSnapshot()).rejects.toThrow(
    "Your notepad access changed",
  );
  await expect(removed.writeSnapshot([], null)).rejects.toThrow("Vault locked");
  writer.stop();
  removed.stop();
});

test("a missing unlocked vault cannot be silently recreated", async () => {
  const f = await fixture();
  const adapter = new AuthVaultTransport(f.rpc, { ...f, ...f.state });
  await expect(adapter.readSnapshot()).rejects.toThrow(
    "Your notepad is no longer available",
  );
  await expect(adapter.writeSnapshot([], null)).rejects.toThrow("Vault locked");
  expect(f.stored).toBeNull();
});

test.each([
  "root",
  "header",
  "identity",
  "schema",
  "chunk",
  "size",
  "sdk",
  "rotation",
])(
  "a definitive %s failure locks the real runtime and preserves encrypted pending edits",
  async (failure) => {
    const f = await fixture();
    const options = { ...f, ...f.state };
    const adapter = new AuthVaultTransport(f.rpc, options);
    await adapter.writeSnapshot([], null);
    const session = createSession({ owner: f.did, vault: f.vault, key: f.key });
    const runtime = synchronizedRuntime(session, async () => adapter);
    let replacement: AuthVaultTransport | undefined;
    const statuses: string[] = [];
    try {
      await runtime.sync?.();
      runtime.subscribe?.((status) => {
        statuses.push(status);
      });
      const id = await session.create("pending.md");
      await session.save(id, "durable pending source");
      const stored = f.stored;
      if (!stored) throw new Error("Missing stored vault");
      if (failure === "root")
        stored.value.root.ciphertext =
          (stored.value.root.ciphertext[0] === "A" ? "B" : "A") +
          stored.value.root.ciphertext.slice(1);
      if (failure === "header") stored.value.access.reverse();
      if (failure === "identity")
        stored.uri = "at://did:plc:other/industries.flow.note.vault/vault";
      if (failure === "schema" || failure === "sdk") {
        const records = f.rpc.records;
        f.rpc.records = async (operation) => {
          if (operation.method === "read") {
            if (failure === "sdk")
              throw { code: "INVALID_RESPONSE", status: 502 };
            return { ...stored, value: { ...stored.value, root: null } };
          }
          return records(operation);
        };
      }
      if (failure === "chunk") {
        const bytes = f.blobs.values().next().value;
        if (!bytes) throw new Error("Missing blob");
        bytes[123] ^= 1;
      }
      if (failure === "size") {
        const download = f.rpc.download;
        f.rpc.download = async (cid) => {
          const bytes = await download(cid);
          if (!(bytes instanceof Uint8Array))
            throw new Error("Invalid test blob");
          return bytes.slice(1);
        };
      }
      if (failure === "rotation") {
        const nextKey = await createVaultKey();
        replacement = new AuthVaultTransport(f.rpc, {
          ...options,
          key: nextKey,
          epoch: 2,
        });
        nextKey.fill(0);
        await replacement.writeSnapshot([], stored.cid);
      }
      await runtime.sync?.();
      expect(statuses).toContain(SYNC_LOCKED);
      await expect(session.open(id)).rejects.toThrow();
      await expect(adapter.writeSnapshot([], stored.cid)).rejects.toThrow(
        "Vault locked",
      );
      const reopened = createSession({
        owner: f.did,
        vault: f.vault,
        key: f.key,
      });
      try {
        expect(await reopened.open(id)).toBe("durable pending source");
        expect(await reopened.database.outbox.count()).toBe(1);
      } finally {
        reopened.lock();
      }
    } finally {
      runtime.lock();
      replacement?.stop();
      f.key.fill(0);
    }
  },
);

test.each(["read", "download"])(
  "a transient %s failure stays unlocked and retries",
  async (stage) => {
    const f = await fixture();
    const adapter = new AuthVaultTransport(f.rpc, { ...f, ...f.state });
    await adapter.writeSnapshot([], null);
    const session = createSession({ owner: f.did, vault: f.vault, key: f.key });
    const runtime = synchronizedRuntime(session, async () => adapter);
    const records = f.rpc.records;
    const download = f.rpc.download;
    try {
      await runtime.sync?.();
      const id = await session.create("offline.md");
      await session.save(id, "offline pending");
      const statuses: string[] = [];
      runtime.subscribe?.((status) => {
        statuses.push(status);
      });
      if (stage === "read")
        f.rpc.records = async () => {
          throw { code: "PDS_UNAVAILABLE", status: 503 };
        };
      else
        f.rpc.download = async () => {
          throw new Error("Temporary network failure");
        };
      await runtime.sync?.();
      expect(await session.open(id)).toBe("offline pending");
      expect(statuses).toContain(
        stage === "read" ? SYNC_BLOCKED : SYNC_PENDING,
      );
      expect(statuses).not.toContain(SYNC_LOCKED);
      f.rpc.records = records;
      f.rpc.download = download;
      await runtime.sync?.();
      expect(await session.database.outbox.count()).toBe(0);
    } finally {
      runtime.lock();
      f.key.fill(0);
    }
  },
);

test("locking during an awaited commit callback does not return transport success", async () => {
  const f = await fixture();
  const adapter = new AuthVaultTransport(f.rpc, {
    ...f,
    ...f.state,
    onCommitted: async () => {
      adapter.stop();
    },
  });
  await expect(adapter.writeSnapshot([], null)).rejects.toThrow("Vault locked");
  f.key.fill(0);
});

test("relocating only the outer namespace preserves encrypted root, access and snapshot bytes", async () => {
  const f = await fixture();
  const options = { ...f, ...f.state };
  const writer = new AuthVaultTransport(f.rpc, options);
  const entry = {
    id: "encrypted-item",
    recordType: "game.flow.note.item" as const,
    revision: "revision",
    envelope: {
      version: 1 as const,
      nonce: "private-nonce",
      ciphertext: "private-ciphertext",
    },
    chunkHashes: [],
    encryptedBlobs: [],
  };
  await writer.writeSnapshot([entry], null);
  const current = f.stored;
  if (!current) throw new Error("Missing fixture record");
  const legacy = {
    ...structuredClone(current.value),
    $type: "game.flow.note.vault",
  };
  const relocated = { ...legacy, $type: "industries.flow.note.vault" as const };
  expect(relocated.root).toEqual(legacy.root);
  expect(relocated.access).toEqual(legacy.access);
  expect(relocated.blobs).toEqual(legacy.blobs);
  current.value = relocated;
  const reader = new AuthVaultTransport(f.rpc, options);
  expect((await reader.readSnapshot()).entries).toEqual([entry]);
  writer.stop();
  reader.stop();
  f.key.fill(0);
});

test.each([
  ["QUOTA", "quota"],
  ["RATE_LIMITED", "rate-limited"],
  ["PDS_UNAVAILABLE", "offline"],
])("an upload refused with %s is a %s sync failure", async (code, reason) => {
  const f = await fixture();
  const adapter = new AuthVaultTransport(f.rpc, { ...f, ...f.state });
  f.rpc.upload = async () => {
    throw { code, status: 429 };
  };
  await expect(adapter.writeSnapshot([], null)).rejects.toMatchObject({
    reason,
  });
  expect(f.puts).toBe(0);
  adapter.stop();
  f.key.fill(0);
});

test.each([
  "QUOTA",
  "RATE_LIMITED",
  "CONSENT_REQUIRED",
  "NOTE_MIGRATION_REQUIRED",
])(
  "%s on canonical publication retains encrypted pending edits, bookmarks and local history",
  async (code) => {
    const f = await fixture();
    const adapter = new AuthVaultTransport(f.rpc, { ...f, ...f.state });
    await adapter.writeSnapshot([], null);
    const session = createSession({ owner: f.did, vault: f.vault, key: f.key });
    const runtime = synchronizedRuntime(session, async () => adapter);
    try {
      await runtime.sync?.();
      const id = await session.create("pending.md");
      await session.save(id, "private pending content");
      const preferences = await runtime.preferences?.();
      if (!preferences || !runtime.savePreferences)
        throw new Error("Missing writing preferences");
      await runtime.savePreferences({ ...preferences, bookmarks: [id] });
      const pending = await session.database.outbox.count();
      const history = await session.database.history.toArray();
      const records = f.rpc.records;
      f.rpc.records = async (operation) => {
        if (operation.method === "put") throw { code, status: 409 };
        return records(operation);
      };
      await runtime.sync?.();
      expect(await session.open(id)).toBe("private pending content");
      expect(await session.database.outbox.count()).toBe(pending);
      expect((await runtime.preferences?.())?.bookmarks).toEqual([id]);
      expect(await session.database.history.toArray()).toEqual(history);
      expect(
        JSON.stringify(await session.database.items.toArray()),
      ).not.toContain("private pending content");
      f.rpc.records = records;
      await runtime.sync?.();
      expect(await session.database.outbox.count()).toBe(0);
    } finally {
      runtime.lock();
      f.key.fill(0);
    }
  },
);

function entry(id: string, revision: string, size = 32): SnapshotEntry {
  return {
    id,
    revision,
    recordType: "game.flow.note.item",
    envelope: {
      version: 1,
      nonce: `nonce-${revision}`,
      ciphertext: revision.padEnd(size, "x"),
    },
    chunkHashes: [],
    encryptedBlobs: [],
  };
}
const filler = (prefix: string, revision: string, bytes: number) =>
  Array.from({ length: Math.ceil(bytes / 800_000) }, (_, index) =>
    entry(
      `${prefix}-${index}`,
      `${revision}-${index}`,
      Math.min(800_000, bytes - index * 800_000),
    ),
  );
const largeVault = (revision = "1") => filler("large", revision, 5_400_000);
async function storedManifest(f: Awaited<ReturnType<typeof fixture>>) {
  const stored = f.stored;
  if (!stored) throw new Error("Missing stored vault");
  return decryptContainerRoot(f.key, { did: f.did }, stored.value.root);
}
async function publishV2(
  f: Awaited<ReturnType<typeof fixture>>,
  entries: SnapshotEntry[],
) {
  const { header, metadata } = f.state.access;
  const container = await encryptContainer(
    f.key,
    { did: f.did, vault: f.vault, epoch: 1 },
    encodeSnapshot(entries),
    metadata,
  );
  const blobs = [];
  for (const chunk of container.chunks)
    blobs.push(
      z.object({ blob: vaultBlobSchema }).parse(await f.rpc.upload(chunk)).blob,
    );
  await f.rpc.records({
    method: "put",
    collection: "industries.flow.note.vault",
    rkey: "vault",
    record: vaultRecordSchema.parse({
      $type: "industries.flow.note.vault",
      version: 2,
      ...header,
      root: container.root,
      blobs,
    }),
    swapRecord: null,
  });
  return container.manifest;
}
const journalOptions = (
  f: Awaited<ReturnType<typeof fixture>>,
  own?: RecipientRef,
) => ({
  ...f,
  ...f.state,
  ownRecipient: own,
  writeJournal: true,
});
function patterned(length: number) {
  const pattern = crypto.getRandomValues(new Uint8Array(65_536));
  const bytes = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += pattern.length)
    bytes.set(pattern.subarray(0, length - offset), offset);
  return bytes;
}

test("an edit over a multi-chunk base uploads only the journal chunk and reads back exactly", async () => {
  const f = await fixture();
  const writer = new AuthVaultTransport(f.rpc, journalOptions(f));
  const reader = new AuthVaultTransport(f.rpc, journalOptions(f));
  try {
    const initial = [entry("a", "1"), entry("b", "1"), ...largeVault()];
    const created = await writer.writeSnapshot(initial, null);
    expect(f.uploads).toBe(4);
    const baseRecord = structuredClone(f.stored?.value);
    expect(baseRecord?.blobs).toHaveLength(4);
    expect((await reader.readSnapshot()).entries).toEqual(initial);
    const edited = [entry("a", "2"), ...largeVault().slice(1), entry("c", "1")];
    const { cid } = await reader.writeSnapshot(edited, created.cid);
    expect(f.uploads).toBe(5);
    expect(f.puts).toBe(2);
    const record = f.stored?.value;
    expect(record?.blobs).toHaveLength(4);
    expect(record?.blobs.slice(0, 3)).toEqual(baseRecord?.blobs.slice(0, 3));
    expect(record?.blobs[3]).not.toEqual(baseRecord?.blobs[3]);
    expect(record?.root).not.toEqual(baseRecord?.root);
    expect(Object.keys(record ?? {}).sort()).toEqual(
      Object.keys(baseRecord ?? {}).sort(),
    );
    expect(await storedManifest(f)).toMatchObject({
      version: 3,
      chunkCount: 3,
      journal: { entries: 4 },
    });
    const result = await writer.readSnapshot();
    expect(result.cid).toBe(cid);
    expect(new Map(result.entries.map((value) => [value.id, value]))).toEqual(
      new Map(edited.map((value) => [value.id, value])),
    );
  } finally {
    writer.stop();
    reader.stop();
    f.key.fill(0);
  }
}, 60_000);

test("a journal past its randomized threshold compacts into a fresh base", async () => {
  const f = await fixture();
  const adapter = new AuthVaultTransport(f.rpc, journalOptions(f));
  try {
    const base = largeVault();
    let { cid } = await adapter.writeSnapshot(base, null);
    const manifest = await storedManifest(f);
    if (manifest.version !== 3) throw new Error("Expected a journaled vault");
    const { compactAt } = manifest.journal;
    expect(compactAt).toBeGreaterThanOrEqual(JOURNAL_PLAINTEXT_BYTES / 2);
    expect(compactAt).toBeLessThanOrEqual(JOURNAL_PLAINTEXT_BYTES);
    const below = [...base, ...filler("small", "1", compactAt - 65_536)];
    ({ cid } = await adapter.writeSnapshot(below, cid));
    expect(f.uploads).toBe(5);
    const baseBlobs = f.stored?.value.blobs.slice(0, 3);
    const above = [...base, ...filler("small", "2", compactAt + 1)];
    ({ cid } = await adapter.writeSnapshot(above, cid));
    expect(f.uploads).toBe(9);
    const compacted = await storedManifest(f);
    expect(compacted).toMatchObject({
      version: 3,
      chunkCount: 3,
      journal: { entries: 0 },
    });
    expect(compacted.generation).not.toBe(manifest.generation);
    for (const blob of f.stored?.value.blobs ?? [])
      expect(baseBlobs).not.toContainEqual(blob);
    const reader = new AuthVaultTransport(f.rpc, journalOptions(f));
    expect((await reader.readSnapshot()).entries).toEqual(above);
    reader.stop();
    await adapter.writeSnapshot([...above, entry("next", "1")], cid);
    expect(f.uploads).toBe(10);
  } finally {
    adapter.stop();
    f.key.fill(0);
  }
}, 60_000);

test("a vault small enough for one journal chunk keeps a single blob", async () => {
  const f = await fixture();
  const adapter = new AuthVaultTransport(f.rpc, journalOptions(f));
  try {
    let { cid } = await adapter.writeSnapshot([entry("a", "1")], null);
    for (let revision = 2; revision < 5; revision++)
      ({ cid } = await adapter.writeSnapshot([entry("a", `${revision}`)], cid));
    expect(f.uploads).toBe(4);
    expect(f.stored?.value.blobs).toHaveLength(1);
    expect(await storedManifest(f)).toMatchObject({
      version: 3,
      chunkCount: 0,
      journal: { entries: 1 },
    });
  } finally {
    adapter.stop();
    f.key.fill(0);
  }
}, 60_000);

test.each<{
  label: string;
  entries: SnapshotEntry[];
  v2: number;
  upgraded: number;
}>([
  { label: "one-chunk", entries: [entry("a", "1")], v2: 1, upgraded: 1 },
  { label: "two-chunk", entries: largeVault(), v2: 2, upgraded: 4 },
])(
  "a $label v2 vault from the previous release opens, then upgrades on its first write",
  async ({ entries, v2, upgraded }) => {
    const f = await fixture();
    const previous = await publishV2(f, entries);
    expect(previous).toMatchObject({ version: 2, chunkCount: v2 });
    expect(f.stored?.value.blobs).toHaveLength(v2);
    const adapter = new AuthVaultTransport(
      f.rpc,
      journalOptions(f, f.state.ownRecipient),
    );
    try {
      const opened = await adapter.readSnapshot();
      expect(opened.entries).toEqual(entries);
      const uploads = f.uploads;
      const next = [...entries, entry("added", "1")];
      const { cid } = await adapter.writeSnapshot(next, opened.cid);
      expect(f.uploads - uploads).toBe(upgraded);
      expect(f.stored?.value.blobs).toHaveLength(upgraded);
      expect((await storedManifest(f)).version).toBe(3);
      const reader = new AuthVaultTransport(
        f.rpc,
        journalOptions(f, f.state.ownRecipient),
      );
      expect((await reader.readSnapshot()).entries).toEqual(next);
      reader.stop();
      await adapter.writeSnapshot([...next, entry("again", "1")], cid);
      expect(f.uploads - uploads).toBe(upgraded + 1);
    } finally {
      adapter.stop();
      f.key.fill(0);
    }
  },
);

test("a stale journal or reordered base chunk is rejected and locks the reader", async () => {
  const f = await fixture();
  const adapter = new AuthVaultTransport(f.rpc, journalOptions(f));
  try {
    const { cid } = await adapter.writeSnapshot(largeVault(), null);
    const first = structuredClone(f.stored);
    await adapter.writeSnapshot([...largeVault(), entry("a", "1")], cid);
    const second = f.stored;
    if (!first || !second) throw new Error("Missing stored vault");
    const stale = structuredClone(second);
    stale.value.blobs[3] = first.value.blobs[3];
    const reordered = structuredClone(second);
    reordered.value.blobs = [
      reordered.value.blobs[1],
      reordered.value.blobs[0],
      ...reordered.value.blobs.slice(2),
    ];
    for (const tampered of [stale, reordered]) {
      const records = f.rpc.records;
      f.rpc.records = async (operation) =>
        operation.method === "read"
          ? structuredClone(tampered)
          : records(operation);
      const reader = new AuthVaultTransport(f.rpc, journalOptions(f));
      await expect(reader.readSnapshot()).rejects.toThrow(
        "Couldn’t verify your notepad",
      );
      await expect(reader.writeSnapshot([], second.cid)).rejects.toThrow(
        "Vault locked",
      );
      f.rpc.records = records;
    }
  } finally {
    adapter.stop();
    f.key.fill(0);
  }
}, 60_000);

test("two devices converge through journal writes and a CAS conflict keeps both edits", async () => {
  const f = await fixture();
  const one = createSession({ owner: f.did, vault: f.vault, key: f.key });
  const two = createSession({ owner: f.did, vault: f.vault, key: f.key });
  Object.defineProperty(two, "database", {
    value: new VaultDatabase(f.did, `${f.vault}-two`),
  });
  const setup = new AuthVaultTransport(f.rpc, journalOptions(f));
  await setup.writeSnapshot([], null);
  setup.stop();
  const a = new VaultSyncEngine(
    one,
    new AuthVaultTransport(f.rpc, journalOptions(f, f.state.ownRecipient)),
  );
  const b = new VaultSyncEngine(
    two,
    new AuthVaultTransport(f.rpc, journalOptions(f, f.state.ownRecipient)),
  );
  try {
    const large = patterned(5 * 1024 * 1024);
    await one.import([{ path: "large.bin", bytes: large }]);
    const first = await one.create("first.md");
    await one.save(first, "base");
    expect((await a.sync()).blocked).toBeUndefined();
    expect((await b.sync()).blocked).toBeUndefined();
    const base = f.stored?.value.blobs.slice(0, -1);
    expect(base?.length).toBeGreaterThanOrEqual(3);
    const uploads = f.uploads;
    const puts = f.puts;
    await one.save(first, "from one");
    const second = await two.create("second.md");
    await two.save(second, "from two");
    f.duringPut(async () => {
      expect((await a.sync()).blocked).toBeUndefined();
    });
    expect((await b.sync()).blocked).toBeUndefined();
    expect((await a.sync()).blocked).toBeUndefined();
    expect(f.puts - puts).toBe(3);
    expect(f.uploads - uploads).toBe(3);
    expect(f.stored?.value.blobs.slice(0, -1)).toEqual(base);
    expect(await one.open(second)).toBe("from two");
    expect(await two.open(first)).toBe("from one");
    expect(
      (await two.export()).find((file) => file.path === "large.bin")?.bytes,
    ).toEqual(large);
    expect(await one.database.outbox.count()).toBe(0);
    expect(await two.database.outbox.count()).toBe(0);
  } finally {
    a.stop();
    b.stop();
    one.lock();
    two.lock();
    f.key.fill(0);
  }
}, 60_000);

test("the default writer publishes a journaled root", async () => {
  const f = await fixture();
  const adapter = new AuthVaultTransport(f.rpc, { ...f, ...f.state });
  try {
    const { cid } = await adapter.writeSnapshot(largeVault(), null);
    expect(await storedManifest(f)).toMatchObject({
      version: 3,
      chunkCount: 3,
    });
    const uploads = f.uploads;
    await adapter.writeSnapshot([...largeVault(), entry("a", "1")], cid);
    expect(f.uploads - uploads).toBe(1);
  } finally {
    adapter.stop();
    f.key.fill(0);
  }
}, 60_000);

test("a rollback's v2 writer keeps publishing v2 while it reads journaled vaults", async () => {
  const f = await fixture();
  const journal = new AuthVaultTransport(f.rpc, journalOptions(f));
  const legacy = new AuthVaultTransport(f.rpc, {
    ...f,
    ...f.state,
    writeJournal: false,
  });
  try {
    await journal.writeSnapshot(largeVault(), null);
    expect(await storedManifest(f)).toMatchObject({
      version: 3,
      chunkCount: 3,
    });
    const journaled = f.stored?.value.blobs ?? [];
    const opened = await legacy.readSnapshot();
    expect(opened.entries).toEqual(largeVault());
    const uploads = f.uploads;
    const next = [...largeVault(), entry("a", "1")];
    await legacy.writeSnapshot(next, opened.cid);
    expect(await storedManifest(f)).toMatchObject({
      version: 2,
      chunkCount: 2,
    });
    expect(f.uploads - uploads).toBe(2);
    expect(f.stored?.value.blobs).toHaveLength(2);
    for (const blob of journaled)
      expect(f.stored?.value.blobs).not.toContainEqual(blob);
    expect((await journal.readSnapshot()).entries).toEqual(next);
  } finally {
    journal.stop();
    legacy.stop();
    f.key.fill(0);
  }
}, 60_000);

test("permanently deleting a large attachment drops its ciphertext from the live record", async () => {
  const f = await fixture();
  const setup = new AuthVaultTransport(f.rpc, journalOptions(f));
  await setup.writeSnapshot([], null);
  setup.stop();
  const session = createSession({ owner: f.did, vault: f.vault, key: f.key });
  const engine = new VaultSyncEngine(
    session,
    new AuthVaultTransport(f.rpc, journalOptions(f, f.state.ownRecipient)),
  );
  try {
    await session.import([
      { path: "secret.bin", bytes: patterned(5 * 1024 * 1024) },
    ]);
    expect((await engine.sync()).blocked).toBeUndefined();
    const before = f.stored?.value.blobs ?? [];
    expect(before).toHaveLength(4);
    const attachment = (await session.database.items.toArray()).find(
      (item) => (item.encryptedBlobs?.length ?? 0) > 0,
    );
    if (!attachment) throw new Error("Missing attachment");
    await session.permanentRemove(attachment.id);
    expect((await engine.sync()).blocked).toBeUndefined();
    expect(f.stored?.value.blobs).toHaveLength(1);
    for (const blob of before)
      expect(f.stored?.value.blobs).not.toContainEqual(blob);
    expect(await storedManifest(f)).toMatchObject({
      version: 3,
      chunkCount: 0,
    });
    const reader = new AuthVaultTransport(f.rpc, journalOptions(f));
    const removed = (await reader.readSnapshot()).entries.find(
      (value) => value.id === attachment.id,
    );
    reader.stop();
    expect(removed?.recordType).toBe("game.flow.note.tombstone");
    expect(removed?.encryptedBlobs.join("").length).toBeLessThan(1_024);
  } finally {
    engine.stop();
    session.lock();
    f.key.fill(0);
  }
}, 60_000);

/** The snapshot the live record's base still publishes to anyone holding the vault key. */
async function liveBase(f: Awaited<ReturnType<typeof fixture>>) {
  const manifest = await storedManifest(f);
  if (manifest.version !== 3 || !manifest.chunkCount) return [];
  const chunks = (f.stored?.value.blobs ?? [])
    .slice(0, manifest.chunkCount)
    .map((blob) => f.blobs.get(blob.ref.$link) ?? new Uint8Array());
  return decodeSnapshot(
    await decryptContainerChunks(f.key, { did: f.did }, manifest, chunks),
  );
}

test("deleting anything that holds blobs drops its ciphertext at that write, and a short note waits for a compaction", async () => {
  const f = await fixture();
  const setup = new AuthVaultTransport(f.rpc, journalOptions(f));
  await setup.writeSnapshot([], null);
  setup.stop();
  const session = createSession({ owner: f.did, vault: f.vault, key: f.key });
  const engine = new VaultSyncEngine(
    session,
    new AuthVaultTransport(f.rpc, journalOptions(f, f.state.ownRecipient)),
  );
  const links = () =>
    (f.stored?.value.blobs ?? []).slice(0, -1).map((blob) => blob.ref.$link);
  const deleteAndSync = async (id: string) => {
    const uploads = f.uploads;
    const before = links();
    await session.permanentRemove(id);
    expect((await engine.sync()).blocked).toBeUndefined();
    return {
      uploads: f.uploads - uploads,
      baseKept: links().every((link) => before.includes(link)),
      held: (await liveBase(f))
        .find((value) => value.id === id)
        ?.encryptedBlobs.join("").length,
    };
  };
  try {
    await session.import([
      { path: "kept.bin", bytes: patterned(9 * 1024 * 1024) },
      { path: "large.bin", bytes: patterned(2 * 1024 * 1024) },
      { path: "tiny.png", bytes: patterned(1024) },
    ]);
    const short = await session.create("short.md");
    const long = await session.create("long.md");
    await session.save(short, "a short note");
    await session.save(long, "x".repeat(70_000));
    expect((await engine.sync()).blocked).toBeUndefined();
    expect(f.stored?.value.blobs).toHaveLength(8);
    const rows = await session.database.items.toArray();
    const bySize = (index: number) =>
      rows
        .filter((row) => row.id !== long && row.encryptedBlobs?.length)
        .map((row) => ({
          id: row.id,
          size: row.encryptedBlobs?.reduce((sum, blob) => sum + blob.length, 0),
        }))
        .sort((a, b) => (a.size ?? 0) - (b.size ?? 0))[index]?.id ?? "";
    const heldBefore = (await liveBase(f)).find((value) => value.id === short);
    expect(heldBefore?.encryptedBlobs).toEqual([]);
    expect(await deleteAndSync(short)).toEqual({
      uploads: 1,
      baseKept: true,
      held: 0,
    });
    for (const id of [long, bySize(0), bySize(1)]) {
      const result = await deleteAndSync(id);
      expect(result.uploads).toBeGreaterThan(1);
      expect(result.baseKept).toBe(false);
      expect(result.held ?? 0).toBeLessThan(1_024);
    }
  } finally {
    engine.stop();
    session.lock();
    f.key.fill(0);
  }
}, 120_000);

test("trashing an attachment keeps it, so it stays a journal write", async () => {
  const f = await fixture();
  const setup = new AuthVaultTransport(f.rpc, journalOptions(f));
  await setup.writeSnapshot([], null);
  setup.stop();
  const session = createSession({ owner: f.did, vault: f.vault, key: f.key });
  const engine = new VaultSyncEngine(
    session,
    new AuthVaultTransport(f.rpc, journalOptions(f, f.state.ownRecipient)),
  );
  try {
    await session.import([
      { path: "kept.bin", bytes: patterned(9 * 1024 * 1024) },
      { path: "trashed.bin", bytes: patterned(1024) },
    ]);
    expect((await engine.sync()).blocked).toBeUndefined();
    const base = f.stored?.value.blobs.slice(0, -1);
    const [trashed] = (await session.database.items.toArray())
      .filter((row) => row.encryptedBlobs?.length)
      .sort(
        (a, b) =>
          (a.encryptedBlobs?.length ?? 0) - (b.encryptedBlobs?.length ?? 0),
      );
    if (!trashed) throw new Error("Missing attachment");
    await session.remove(trashed.id);
    const uploads = f.uploads;
    expect((await engine.sync()).blocked).toBeUndefined();
    expect(f.uploads - uploads).toBe(1);
    expect(f.stored?.value.blobs.slice(0, -1)).toEqual(base);
  } finally {
    engine.stop();
    session.lock();
    f.key.fill(0);
  }
}, 60_000);

test("re-deleting what a base already tombstoned stays a journal write", async () => {
  const f = await fixture();
  const adapter = new AuthVaultTransport(f.rpc, journalOptions(f));
  try {
    const tombstone = (revision: string): SnapshotEntry => ({
      ...entry("gone", revision),
      recordType: "game.flow.note.tombstone",
      chunkHashes: ["a".repeat(64)],
      encryptedBlobs: ["b".repeat(100)],
    });
    const large = filler("large", "1", 9_000_000);
    const { cid } = await adapter.writeSnapshot(
      [...large, tombstone("1")],
      null,
    );
    const uploads = f.uploads;
    await adapter.writeSnapshot([...large, tombstone("2")], cid);
    expect(f.uploads - uploads).toBe(1);
  } finally {
    adapter.stop();
    f.key.fill(0);
  }
}, 60_000);

test("editing a long note over a quarter of the base uploads one journal chunk", async () => {
  const f = await fixture();
  const setup = new AuthVaultTransport(f.rpc, journalOptions(f));
  await setup.writeSnapshot([], null);
  setup.stop();
  const session = createSession({ owner: f.did, vault: f.vault, key: f.key });
  const engine = new VaultSyncEngine(
    session,
    new AuthVaultTransport(f.rpc, journalOptions(f, f.state.ownRecipient)),
  );
  try {
    await session.import([{ path: "kept.bin", bytes: patterned(2_500_000) }]);
    const long = await session.create("long.md");
    await session.save(long, "a".repeat(950_000));
    expect((await engine.sync()).blocked).toBeUndefined();
    const manifest = await storedManifest(f);
    if (manifest.version !== 3) throw new Error("Expected a journaled vault");
    const row = await session.database.items.get(long);
    const bytes = encodeSnapshot([
      {
        id: long,
        revision: row?.revision ?? "",
        recordType: "game.flow.note.item",
        envelope: row?.envelope ?? { version: 1, nonce: "", ciphertext: "" },
        chunkHashes: row?.chunkHashes ?? [],
        encryptedBlobs: (row?.encryptedBlobs ?? []).map(encodeBlob),
      },
    ]).length;
    expect(row?.encryptedBlobs?.length).toBeGreaterThan(0);
    expect(bytes).toBeGreaterThan(manifest.byteLength / 4);
    expect(bytes).toBeGreaterThan(1024 * 1024);
    expect(bytes).toBeLessThan(JOURNAL_PLAINTEXT_BYTES / 2);
    const base = f.stored?.value.blobs.slice(0, -1);
    for (const edit of ["b", "c", "d"]) {
      const uploads = f.uploads;
      await session.save(long, edit.repeat(950_000));
      expect((await engine.sync()).blocked).toBeUndefined();
      expect(f.uploads - uploads).toBe(1);
      expect(f.stored?.value.blobs.slice(0, -1)).toEqual(base);
    }
    const reader = createSession({
      owner: f.did,
      vault: f.vault,
      key: f.key,
    });
    Object.defineProperty(reader, "database", {
      value: new VaultDatabase(f.did, `${f.vault}-reader`),
    });
    const follower = new VaultSyncEngine(
      reader,
      new AuthVaultTransport(f.rpc, journalOptions(f, f.state.ownRecipient)),
    );
    expect((await follower.sync()).blocked).toBeUndefined();
    expect(await reader.open(long)).toBe("d".repeat(950_000));
    follower.stop();
    reader.lock();
  } finally {
    engine.stop();
    session.lock();
    f.key.fill(0);
  }
}, 120_000);

test("superseding over a quarter of the base compacts even while the journal stays small", async () => {
  const f = await fixture();
  const adapter = new AuthVaultTransport(f.rpc, journalOptions(f));
  try {
    const base = filler("large", "1", 8_000_000);
    const superseding = (count: number) =>
      base.map((value, index) =>
        index < count ? entry(value.id, "2") : value,
      );
    let { cid } = await adapter.writeSnapshot(base, null);
    expect(f.uploads).toBe(4);
    ({ cid } = await adapter.writeSnapshot(superseding(2), cid));
    expect(f.uploads).toBe(5);
    await adapter.writeSnapshot(superseding(3), cid);
    expect(f.uploads).toBe(9);
    expect(await storedManifest(f)).toMatchObject({
      version: 3,
      chunkCount: 3,
      journal: { entries: 0 },
    });
  } finally {
    adapter.stop();
    f.key.fill(0);
  }
}, 60_000);

test("a write that fits a smaller blob count compacts into it", async () => {
  const f = await fixture();
  const adapter = new AuthVaultTransport(f.rpc, journalOptions(f));
  try {
    const base = filler("large", "1", 12_800_000);
    const { cid } = await adapter.writeSnapshot(base, null);
    expect(f.stored?.value.blobs).toHaveLength(8);
    const uploads = f.uploads;
    await adapter.writeSnapshot(base.slice(1), cid);
    expect(f.uploads - uploads).toBe(4);
    expect(f.stored?.value.blobs).toHaveLength(4);
    expect(await storedManifest(f)).toMatchObject({
      version: 3,
      chunkCount: 3,
    });
  } finally {
    adapter.stop();
    f.key.fill(0);
  }
}, 60_000);

test("compaction triggers, and journaling on past the decode limit while the change fits", () => {
  const base = {
    base: {
      generation: "generation",
      byteLength: 8_000_000,
      chunkCount: 3,
      chunkHashes: [],
    },
    compactAt: 3_000_000,
  };
  const steady = {
    superseded: 0,
    erasesBlobs: false,
    snapshotBytes: 9_000_000,
  };
  expect(staysJournal(base, 1_000, steady)).toBe(true);
  expect(staysJournal(base, 3_000_001, steady)).toBe(false);
  expect(staysJournal(base, 1_000, { ...steady, superseded: 2_000_001 })).toBe(
    false,
  );
  expect(staysJournal(base, 1_000, { ...steady, erasesBlobs: true })).toBe(
    false,
  );
  expect(
    staysJournal(base, 1_000, {
      ...steady,
      snapshotBytes: JOURNAL_PLAINTEXT_BYTES,
    }),
  ).toBe(false);
  expect(
    staysJournal(
      {
        ...base,
        base: { ...base.base, byteLength: 13_000_000, chunkCount: 7 },
      },
      1_000,
      steady,
    ),
  ).toBe(false);
  const oversized = {
    superseded: 5_000_000,
    erasesBlobs: true,
    snapshotBytes: 9_000_000,
  };
  expect(staysJournal(base, 3_500_000, oversized, 8_000_000)).toBe(true);
  expect(
    staysJournal(base, JOURNAL_PLAINTEXT_BYTES + 1, oversized, 8_000_000),
  ).toBe(false);
}, 60_000);

test("a compaction that can't fit beside its old base under the managed quota waits while the change fits", () => {
  const atChunks = (chunkCount: number) => ({
    base: {
      generation: "generation",
      byteLength: chunkCount * 4_000_000,
      chunkCount,
      chunkHashes: [],
    },
    compactAt: 3_000_000,
  });
  const deleting = (snapshotBytes: number) => ({
    superseded: 10_000_000,
    erasesBlobs: true,
    snapshotBytes,
  });
  const staying = 62 * 4_100_000;
  expect(staysJournal(atChunks(63), 1_000, deleting(staying))).toBe(true);
  expect(staysJournal(atChunks(63), 4_000_000, deleting(staying))).toBe(true);
  expect(
    staysJournal(atChunks(63), JOURNAL_PLAINTEXT_BYTES + 1, deleting(staying)),
  ).toBe(false);
  expect(staysJournal(atChunks(63), 1_000, deleting(30 * 4_100_000))).toBe(
    false,
  );
  expect(staysJournal(atChunks(31), 1_000, deleting(30 * 4_100_000))).toBe(
    false,
  );
  expect(staysJournal(atChunks(127), 1_000, deleting(1_000))).toBe(false);
  expect(staysJournal(atChunks(127), 1_000, deleting(4_000_000))).toBe(false);
});

test("an access change over a vault past the decode limit stays a journal write", async () => {
  const f = await fixture();
  const seeded = new AuthVaultTransport(f.rpc, journalOptions(f));
  await seeded.writeSnapshot(largeVault(), null);
  seeded.stop();
  const reader = new AuthVaultTransport(f.rpc, journalOptions(f));
  const { cid, entries } = await reader.readSnapshot();
  const over = reader.verifiedBase();
  reader.stop();
  if (!over) throw new Error("Expected a verified base");
  const [first] = entries;
  const stamp = first && over.base.stamps.get(first.id);
  if (!first || !stamp) throw new Error("Missing stamp");
  const writer = new AuthVaultTransport(f.rpc, {
    ...journalOptions(f),
    over: {
      cid,
      base: {
        ...over.base,
        stamps: new Map([
          ...over.base.stamps,
          [first.id, { ...stamp, bytes: 600_000_000 }],
        ]),
      },
    },
  });
  const uploads = f.uploads;
  await writer.writeSnapshot(entries, cid);
  writer.stop();
  expect(f.uploads - uploads).toBe(1);
  expect(await storedManifest(f)).toMatchObject({ version: 3, chunkCount: 3 });
  f.key.fill(0);
}, 60_000);

test("a writer handed a base for another record doesn't reuse it", async () => {
  const f = await fixture();
  const seeded = new AuthVaultTransport(f.rpc, journalOptions(f));
  await seeded.writeSnapshot(largeVault(), null);
  seeded.stop();
  const reader = new AuthVaultTransport(f.rpc, journalOptions(f));
  const { cid, entries } = await reader.readSnapshot();
  const over = reader.verifiedBase();
  reader.stop();
  const writer = new AuthVaultTransport(f.rpc, { ...journalOptions(f), over });
  await expect(writer.writeSnapshot(entries, "other")).rejects.toMatchObject({
    reason: "conflict",
  });
  await writer.writeSnapshot(entries, cid);
  writer.stop();
  f.key.fill(0);
}, 60_000);

test("both writers refuse a snapshot no reader can decode before uploading anything", async () => {
  const f = await fixture();
  const ciphertext = "x".repeat(900_000);
  const oversized = Array.from({ length: 570 }, (_, index) => ({
    ...entry(`oversized-${index}`, "1"),
    envelope: { version: 1 as const, nonce: "nonce", ciphertext },
  }));
  for (const writeJournal of [false, true]) {
    const adapter = new AuthVaultTransport(f.rpc, {
      ...journalOptions(f),
      writeJournal,
    });
    await expect(adapter.writeSnapshot(oversized, null)).rejects.toMatchObject({
      reason: "too-large",
    });
    adapter.stop();
  }
  expect(f.uploads).toBe(0);
  expect(f.puts).toBe(0);
  f.key.fill(0);
}, 120_000);
test("content writes reuse the access slots byte for byte and an access change re-randomizes them", async () => {
  const f = await fixture();
  const adapter = new AuthVaultTransport(f.rpc, { ...f, ...f.state });
  const first = await adapter.writeSnapshot([], null);
  const before = structuredClone(f.stored?.value);
  const second = await adapter.writeSnapshot([], first.cid);
  const after = f.stored?.value;
  if (!before || !after) throw new Error("Missing stored vault");
  expect(after.accessSalt).toBe(before.accessSalt);
  expect(after.access).toEqual(before.access);
  expect(after.root).not.toEqual(before.root);
  const device = await createSeedRecipient(
    new Uint8Array(32).fill(3),
    "device",
  );
  const changed = new AuthVaultTransport(f.rpc, {
    ...f,
    ...(await signedVault(
      f.key,
      { did: f.did, vault: f.vault, epoch: 1 },
      [f.admin.recipient, device],
      f.admin,
      "change",
      2,
    )),
  });
  const third = await changed.writeSnapshot([], second.cid);
  const rekeyed = f.stored?.value;
  if (!rekeyed) throw new Error("Missing stored vault");
  expect(rekeyed.accessSalt).not.toBe(after.accessSalt);
  for (const slot of rekeyed.access)
    expect(
      after.access.some(
        (old) => old.keyId === slot.keyId || old.wrapped === slot.wrapped,
      ),
    ).toBe(false);
  await adapter.readSnapshot();
  await adapter.writeSnapshot([], third.cid);
  expect(f.stored?.value.accessSalt).toBe(rekeyed.accessSalt);
  expect(f.stored?.value.access).toEqual(rekeyed.access);
  adapter.stop();
  changed.stop();
  f.key.fill(0);
});

test("a statement from an unpinned signer locks the reader, and accepted changes are pinned", async () => {
  const f = await fixture();
  const context = { did: f.did, vault: f.vault, epoch: 1 };
  const second = await passkeyAdmin(
    new Uint8Array(32).fill(8),
    "second",
    f.did,
  );
  const pins: PinnedAccess[] = [];
  const reader = new AuthVaultTransport(f.rpc, {
    ...f,
    ...f.state,
    onPinned: ({ pinned }) => {
      pins.push(pinned);
    },
  });
  const publish = async (state: Awaited<ReturnType<typeof signedVault>>) => {
    const writer = new AuthVaultTransport(f.rpc, { ...f, ...state });
    await writer.writeSnapshot([], f.stored?.cid ?? null);
    writer.stop();
  };
  await publish(f.state);
  await reader.readSnapshot();
  expect(pins).toEqual([]);
  const added = await signedVault(
    f.key,
    context,
    [f.admin.recipient, second.recipient],
    f.admin,
    "change",
    2,
  );
  await publish(added);
  await reader.readSnapshot();
  expect(pins).toEqual([added.pinned]);
  const handedOver = await signedVault(
    f.key,
    context,
    [f.admin.recipient, second.recipient],
    second,
    "change",
    3,
  );
  await publish(handedOver);
  await reader.readSnapshot();
  expect(pins).toEqual([added.pinned, handedOver.pinned]);
  const intruder = await passkeyAdmin(
    new Uint8Array(32).fill(4),
    "intruder",
    f.did,
  );
  await publish(
    await signedVault(
      f.key,
      context,
      [f.admin.recipient, intruder.recipient],
      intruder,
      "change",
      2,
    ),
  );
  await expect(reader.readSnapshot()).rejects.toThrow(
    "Couldn’t verify your notepad",
  );
  await expect(reader.writeSnapshot([], null)).rejects.toThrow("Vault locked");
  expect(pins).toHaveLength(2);
  f.key.fill(0);
});

test("a pin that fails to persist is not adopted and is offered again on the next read", async () => {
  const f = await fixture();
  const attempts: PinnedAccess[] = [];
  let failing = true;
  const reader = new AuthVaultTransport(f.rpc, {
    ...f,
    ...f.state,
    onPinned: ({ pinned }) => {
      attempts.push(pinned);
      if (failing) throw new Error("Checkpoint storage unavailable");
    },
  });
  const added = await signedVault(
    f.key,
    { did: f.did, vault: f.vault, epoch: 1 },
    [
      f.admin.recipient,
      await createSeedRecipient(new Uint8Array(32).fill(3), "device"),
    ],
    f.admin,
    "change",
    2,
  );
  const writer = new AuthVaultTransport(f.rpc, { ...f, ...added });
  await writer.writeSnapshot([], null);
  writer.stop();
  await expect(reader.readSnapshot()).rejects.toThrow(
    "Checkpoint storage unavailable",
  );
  failing = false;
  await reader.readSnapshot();
  expect(attempts).toEqual([added.pinned, added.pinned]);
  reader.stop();
  f.key.fill(0);
});

/** A PDS whose `device` writer is held to Flow ID's device-token rule: CAS first, then byte-identical slots. */
function deviceRulePds(did: string) {
  let stored: { cid: string; uri: string; value: VaultRecordV2 } | null = null;
  const blobs = new Map<string, Uint8Array>();
  let commits = 0;
  const violations: (string | null)[] = [];
  const uri = `at://${did}/industries.flow.note.vault/vault`;
  const writer = (device: boolean): VaultTransportRpc => ({
    async records(operation) {
      if (operation.method === "read") {
        if (!stored) throw { code: "NOTE_NOT_FOUND", status: 404 };
        return structuredClone(stored);
      }
      if ((stored?.cid ?? null) !== operation.swapRecord)
        throw { code: "CONFLICT", status: 409 };
      if (
        device &&
        (!stored ||
          stored.value.accessSalt !== operation.record.accessSalt ||
          JSON.stringify(stored.value.access) !==
            JSON.stringify(operation.record.access))
      ) {
        violations.push(operation.swapRecord);
        throw { code: "ACCESS_CHANGE_FORBIDDEN", status: 403 };
      }
      stored = {
        cid: `cid-${++commits}`,
        uri,
        value: structuredClone(operation.record),
      };
      return { cid: stored.cid, uri };
    },
    async upload(bytes) {
      const cid = crypto.randomUUID();
      blobs.set(cid, bytes.slice());
      return {
        blob: {
          $type: "blob",
          ref: { $link: cid },
          mimeType: "application/octet-stream",
          size: bytes.length,
        },
      };
    },
    async download(cid) {
      const bytes = blobs.get(cid);
      if (!bytes) throw new Error("Missing blob");
      return bytes.slice();
    },
  });
  return {
    browser: writer(false),
    device: writer(true),
    get stored() {
      return stored;
    },
    violations,
  };
}

test("journal writes by a device token keep the slots byte-identical across journal edits, an admin access change, a stale write and a compaction", async () => {
  const key = await createVaultKey();
  const did = "did:plc:devicerule";
  const vault = crypto.randomUUID();
  const context = { did, vault, epoch: 1 };
  const { admin } = await passkeyVault(
    key,
    did,
    new Uint8Array(32).fill(7),
    "credential",
    vault,
  );
  const linked = await createSeedRecipient(
    new Uint8Array(32).fill(3),
    "device",
  );
  const enrolled = await signedVault(
    key,
    context,
    [admin.recipient, linked],
    admin,
    "change",
    2,
  );
  const pds = deviceRulePds(did);
  const adminWriter = new AuthVaultTransport(pds.browser, {
    key,
    did,
    ...enrolled,
    writeJournal: true,
  });
  const device = new AuthVaultTransport(pds.device, {
    key,
    did,
    ...enrolled,
    ownRecipient: { id: linked.id, boxPublicKey: linked.boxPublicKey },
    writeJournal: true,
  });
  try {
    let entries = [entry("a", "1"), ...largeVault()];
    await adminWriter.writeSnapshot(entries, null);
    const base = structuredClone(pds.stored?.value);
    if (!base) throw new Error("Missing base record");
    for (const revision of ["2", "3"]) {
      const snapshot = await device.readSnapshot();
      entries = [
        ...snapshot.entries.filter((item) => item.id !== "a"),
        entry("a", revision),
      ];
      await device.writeSnapshot(entries, snapshot.cid);
    }
    const journaled = pds.stored?.value;
    const baseCount = base.blobs.length - 1;
    expect(baseCount).toBeGreaterThan(0);
    expect(journaled?.accessSalt).toBe(base.accessSalt);
    expect(journaled?.blobs.slice(0, baseCount)).toEqual(
      base.blobs.slice(0, baseCount),
    );
    expect(journaled?.blobs.at(-1)).not.toEqual(base.blobs.at(-1));
    const stale = pds.stored?.cid ?? null;
    const reader = new AuthVaultTransport(pds.browser, {
      key,
      did,
      ...enrolled,
      writeJournal: true,
    });
    const current = await reader.readSnapshot();
    reader.stop();
    const changer = new AuthVaultTransport(pds.browser, {
      key,
      did,
      ...(await signedVault(
        key,
        context,
        [admin.recipient, linked],
        admin,
        "change",
        3,
      )),
      writeJournal: true,
    });
    await changer.writeSnapshot(current.entries, current.cid);
    changer.stop();
    expect(pds.stored?.value.accessSalt).not.toBe(base.accessSalt);
    await expect(device.writeSnapshot(entries, stale)).rejects.toMatchObject({
      reason: "conflict",
    });
    const changed = await device.readSnapshot();
    entries = [
      ...changed.entries.filter((item) => item.id !== "a"),
      entry("a", "4"),
    ];
    await device.writeSnapshot(entries, changed.cid);
    const latest = await device.readSnapshot();
    await device.writeSnapshot([entry("a", "5")], latest.cid);
    const final = pds.stored?.value;
    if (!final) throw new Error("Missing final record");
    expect(final.blobs.length).toBeLessThan(base.blobs.length);
    const manifest = await decryptContainerRoot(key, { did }, final.root);
    expect(manifest).toMatchObject({
      version: 3,
      metadata: { version: 3, statement: { sequence: 3 } },
    });
    expect(pds.violations).toEqual([]);
  } finally {
    adminWriter.stop();
    device.stop();
    key.fill(0);
  }
}, 120_000);

test("entry signatures round-trip in both formats, and a signature added to a held revision reaches the journal", async () => {
  for (const writeJournal of [false, true]) {
    const f = await fixture();
    const writer = new AuthVaultTransport(f.rpc, {
      ...journalOptions(f),
      writeJournal,
    });
    const reader = new AuthVaultTransport(f.rpc, journalOptions(f));
    try {
      const bare = entry("signed", "1");
      const author = await signEntry(
        bare,
        { did: f.did, vault: f.vault },
        {
          recipientId: f.admin.recipient.id,
          signPublicKey: f.admin.recipient.signPublicKey ?? "",
          privateKey: f.admin.privateKey,
        },
      );
      const created = await writer.writeSnapshot([bare, ...largeVault()], null);
      const before = await reader.readSnapshot();
      expect(before.entries[0]).not.toHaveProperty("author");
      const endorsed = [{ ...bare, author }, ...largeVault()];
      await reader.writeSnapshot(endorsed, created.cid);
      if (writeJournal)
        expect(await storedManifest(f)).toMatchObject({
          version: 3,
          journal: { entries: 1 },
        });
      expect((await writer.readSnapshot()).entries[0]?.author).toEqual(author);
    } finally {
      writer.stop();
      reader.stop();
      f.key.fill(0);
    }
  }
}, 120_000);
