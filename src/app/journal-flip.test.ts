import { describe, expect, test } from "bun:test";
import Dexie from "dexie";
import { IDBKeyRange, indexedDB } from "fake-indexeddb";
import { passkeyPort } from "../../tests/passkey-port.ts";
import { signedVault } from "../../tests/unlock-fixture.ts";
import {
  accessHeaderCommitment,
  createAccessHeader,
  createAccessRecipient,
} from "../crypto/access-v2.ts";
import { passkeyAdmin, type VaultAccess } from "../crypto/access-v3.ts";
import { decryptContainerRoot } from "../crypto/container.ts";
import { createVaultKey } from "../crypto/index.ts";
import { VaultSyncEngine } from "../sync/vault-engine.ts";
import { captureSnapshot } from "../sync/vault-snapshot.ts";
import {
  AuthVaultTransport,
  readVerifiedVaultRoot,
  type VaultRecordV2,
  type VaultTransportRpc,
} from "../sync/vault-transport.ts";
import { createSession, type VaultSession } from "../vault/session.ts";
import { VaultDatabase } from "../vault/storage.ts";
import { unlockVault } from "./unlock.ts";

Dexie.dependencies.indexedDB = indexedDB;
Dexie.dependencies.IDBKeyRange = IDBKeyRange;

function memoryPds(owner: string) {
  const uri = `at://${owner}/industries.flow.note.vault/vault`;
  let stored: { cid: string; value: VaultRecordV2 } | null = null;
  let commits = 0;
  let conflicts = 0;
  let uploads = 0;
  let puts = 0;
  let barrier: {
    waiting: number;
    release: () => void;
    held: Promise<void>;
  } | null = null;
  const blobs = new Map<string, Uint8Array>();
  const rpc: VaultTransportRpc = {
    async records(operation) {
      if (operation.method === "read") {
        if (!stored) throw { code: "NOTE_NOT_FOUND", status: 404 };
        return structuredClone({ uri, ...stored });
      }
      puts++;
      if (barrier) {
        const current = barrier;
        current.waiting--;
        if (current.waiting === 0) {
          barrier = null;
          current.release();
        }
        await current.held;
      }
      if ((stored?.cid ?? null) !== operation.swapRecord) {
        conflicts++;
        throw { code: "CONFLICT", status: 409 };
      }
      stored = {
        cid: `cid-${++commits}`,
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
      return blobs.get(cid)?.slice();
    },
  };
  return {
    rpc,
    get stored() {
      return stored;
    },
    get conflicts() {
      return conflicts;
    },
    get uploads() {
      return uploads;
    },
    get puts() {
      return puts;
    },
    /** Holds the next `count` puts until all of them arrived, so each read the same record. */
    holdPuts(count: number) {
      let release = () => {};
      const held = new Promise<void>((resolve) => {
        release = resolve;
      });
      barrier = { waiting: count, release, held };
    },
  };
}

function patterned(length: number) {
  const pattern = crypto.getRandomValues(new Uint8Array(65_536));
  const bytes = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += pattern.length)
    bytes.set(pattern.subarray(0, length - offset), offset);
  return bytes;
}

const CREDENTIAL = "am91cm5hbA";
const PRF = new Uint8Array(32).fill(5);

async function world(owner: string) {
  const key = await createVaultKey();
  const vault = crypto.randomUUID();
  const pds = memoryPds(owner);
  const admin = await passkeyAdmin(PRF, CREDENTIAL, owner);
  const state = await signedVault(
    key,
    { did: owner, vault, epoch: 1 },
    [admin.recipient],
    admin,
  );
  const options = { key, did: owner, ...state };
  const sessions: VaultSession[] = [];
  const engines: VaultSyncEngine[] = [];
  return {
    key,
    owner,
    vault,
    pds,
    options,
    /** Writes the empty vault an unlock's setup would. */
    async create(writeJournal?: boolean) {
      const setup = new AuthVaultTransport(pds.rpc, {
        ...options,
        writeJournal,
      });
      await setup.writeSnapshot([], null);
      setup.stop();
    },
    /** One browser profile: sessions sharing a `device` share its IndexedDB, as tabs do. */
    session(device?: string) {
      const session = createSession({ owner, vault, key });
      if (device)
        Object.defineProperty(session, "database", {
          value: new VaultDatabase(owner, `${vault}-${device}`),
        });
      sessions.push(session);
      return session;
    },
    /** The flipped release, unless `writeJournal: false` asks for the release before it. */
    engine(session: VaultSession, writeJournal?: boolean) {
      const engine = new VaultSyncEngine(
        session,
        new AuthVaultTransport(pds.rpc, { ...options, writeJournal }),
      );
      engines.push(engine);
      return engine;
    },
    async manifest() {
      if (!pds.stored) throw new Error("Missing stored vault");
      return decryptContainerRoot(key, { did: owner }, pds.stored.value.root);
    },
    baseLinks() {
      return (pds.stored?.value.blobs ?? [])
        .slice(0, -1)
        .map((blob) => blob.ref.$link);
    },
    finish() {
      for (const engine of engines) engine.stop();
      for (const session of sessions) session.lock();
      key.fill(0);
    },
  };
}

async function readable(session: VaultSession) {
  const notes = await session.listNotes();
  return new Map(
    await Promise.all(
      notes.map(
        async (note) => [note.path, await session.open(note.id)] as const,
      ),
    ),
  );
}

const synced = async (engine: VaultSyncEngine) =>
  expect((await engine.sync()).blocked).toBeUndefined();

test("a v2 vault from the release before keeps every note and history row through the flip, and survives a rollback", async () => {
  const w = await world("did:plc:upgrade");
  const one = w.session("one");
  const two = w.session("two");
  try {
    await w.create(false);
    const large = patterned(5 * 1024 * 1024);
    await one.import([
      { path: "large.bin", bytes: large },
      { path: "folder/kept.md", bytes: new TextEncoder().encode("# Kept") },
    ]);
    const edited = await one.create("edited.md");
    for (const text of ["first", "second", "third"])
      await one.save(edited, text);
    const trashed = await one.create("trashed.md");
    await one.save(trashed, "in the trash");
    await one.remove(trashed);
    const gone = await one.create("gone.md");
    await one.save(gone, "deleted");
    await one.permanentRemove(gone);
    const beforeOne = w.engine(one, false);
    const beforeTwo = w.engine(two, false);
    await synced(beforeOne);
    await synced(beforeTwo);
    await two.save(edited, "from the second device");
    await synced(beforeTwo);
    await synced(beforeOne);
    expect(await w.manifest()).toMatchObject({ version: 2, chunkCount: 4 });
    const notes = await readable(one);
    expect(notes.get("edited.md")).toBe("from the second device");
    const historyOne = await one.history(edited);
    const historyTwo = await two.history(edited);
    expect(historyOne.map(({ source }) => source)).toContain("first");
    expect(historyOne.length).toBeGreaterThan(1);
    expect(historyTwo.length).toBeGreaterThan(0);
    const untouched = w.pds.stored?.cid;
    beforeOne.stop();
    beforeTwo.stop();

    const afterOne = w.engine(one);
    const afterTwo = w.engine(two);
    await synced(afterOne);
    await synced(afterTwo);
    expect(w.pds.stored?.cid).toBe(untouched);
    expect(await readable(one)).toEqual(notes);
    expect(await readable(two)).toEqual(notes);

    await one.save(edited, "after the flip");
    const uploadsAtUpgrade = w.pds.uploads;
    await synced(afterOne);
    expect(w.pds.uploads - uploadsAtUpgrade).toBe(4);
    expect(await w.manifest()).toMatchObject({ version: 3, chunkCount: 3 });
    const base = w.baseLinks();
    await synced(afterTwo);
    await two.save(edited, "second journal edit");
    const uploads = w.pds.uploads;
    await synced(afterTwo);
    expect(w.pds.uploads - uploads).toBe(1);
    expect(w.baseLinks()).toEqual(base);
    await synced(afterOne);
    const current = new Map([...notes, ["edited.md", "second journal edit"]]);
    expect(await readable(one)).toEqual(current);
    expect(await readable(two)).toEqual(current);
    for (const row of historyOne)
      expect(
        (await one.history(edited)).map((value) => value.historyId),
      ).toContain(row.historyId);
    for (const row of historyTwo)
      expect(
        (await two.history(edited)).map((value) => value.historyId),
      ).toContain(row.historyId);

    const fresh = w.session("fresh");
    await synced(w.engine(fresh));
    expect(await readable(fresh)).toEqual(current);
    expect(
      (await fresh.export()).find((file) => file.path === "large.bin")?.bytes,
    ).toEqual(large);
    const freshRows = new Map(
      (await fresh.database.items.toArray()).map((row) => [row.id, row]),
    );
    expect(freshRows.get(gone)?.recordType).toBe("game.flow.note.tombstone");
    expect((await fresh.readMetadata()).trash.map((note) => note.id)).toContain(
      trashed,
    );

    afterTwo.stop();
    const rollback = w.engine(two, false);
    await two.save(edited, "after a rollback");
    await synced(rollback);
    expect((await w.manifest()).version).toBe(2);
    const rolled = new Map([...current, ["edited.md", "after a rollback"]]);
    await synced(afterOne);
    expect(await readable(one)).toEqual(rolled);
    await one.save(edited, "rolled forward");
    await synced(afterOne);
    expect((await w.manifest()).version).toBe(3);
    await synced(rollback);
    expect(await two.open(edited)).toBe("rolled forward");
  } finally {
    w.finish();
  }
}, 120_000);

describe.each([
  ["two tabs sharing one database", false],
  ["two devices", true],
])("%s on the flipped release", (_, separate) => {
  test("writing at once keep every edit and reuse the base", async () => {
    const w = await world(`did:plc:race-${separate}`);
    const one = w.session("one");
    const two = w.session(separate ? "two" : "one");
    try {
      await w.create();
      await one.import([
        { path: "large.bin", bytes: patterned(5 * 1024 * 1024) },
      ]);
      const a = await one.create("a.md");
      const b = await one.create("b.md");
      const first = w.engine(one);
      const second = w.engine(two);
      await synced(first);
      await synced(second);
      const base = w.baseLinks();
      expect(base).toHaveLength(3);
      for (const round of [1, 2, 3]) {
        const before = w.pds.conflicts;
        await one.save(a, `a ${round}`);
        await two.save(b, `b ${round}`);
        w.pds.holdPuts(2);
        const uploads = w.pds.uploads;
        const puts = w.pds.puts;
        const results = await Promise.all([first.sync(), second.sync()]);
        for (const result of results) expect(result.blocked).toBeUndefined();
        expect(w.pds.conflicts).toBeGreaterThan(before);
        expect(w.pds.uploads - uploads).toBe(w.pds.puts - puts);
        await synced(first);
        await synced(second);
        expect(w.baseLinks()).toEqual(base);
        expect(await one.open(a)).toBe(`a ${round}`);
        expect(await one.open(b)).toBe(`b ${round}`);
        expect(await two.open(a)).toBe(`a ${round}`);
        expect(await two.open(b)).toBe(`b ${round}`);
        expect(await one.database.outbox.count()).toBe(0);
        expect(await two.database.outbox.count()).toBe(0);
      }
      const fresh = w.session("fresh");
      await synced(w.engine(fresh));
      expect(await fresh.open(a)).toBe("a 3");
      expect(await fresh.open(b)).toBe("b 3");
    } finally {
      w.finish();
    }
  }, 120_000);

  test("a compaction racing a journal write loses nothing, whichever wins", async () => {
    const w = await world(`did:plc:compaction-race-${separate}`);
    const one = w.session("one");
    const two = w.session(separate ? "two" : "one");
    try {
      await w.create();
      const kept = patterned(5 * 1024 * 1024);
      await one.import([
        { path: "kept.bin", bytes: kept },
        { path: "gone.bin", bytes: patterned(1024) },
      ]);
      const note = await one.create("note.md");
      const first = w.engine(one);
      const second = w.engine(two);
      await synced(first);
      await synced(second);
      const base = w.baseLinks();
      const rows = await one.database.items.toArray();
      const gone = rows
        .filter((row) => row.encryptedBlobs?.length)
        .sort(
          (x, y) =>
            (x.encryptedBlobs?.[0]?.length ?? 0) -
            (y.encryptedBlobs?.[0]?.length ?? 0),
        )[0];
      if (!gone) throw new Error("Missing attachment");
      await one.permanentRemove(gone.id);
      await two.save(note, "journal edit");
      w.pds.holdPuts(2);
      const results = await Promise.all([first.sync(), second.sync()]);
      for (const result of results) expect(result.blocked).toBeUndefined();
      await synced(first);
      await synced(second);
      await synced(first);
      for (const link of w.baseLinks()) expect(base).not.toContain(link);
      const fresh = w.session("fresh");
      await synced(w.engine(fresh));
      expect(await fresh.open(note)).toBe("journal edit");
      const files = await fresh.export();
      expect(files.find((file) => file.path === "kept.bin")?.bytes).toEqual(
        kept,
      );
      expect(files.find((file) => file.path === "gone.bin")).toBeUndefined();
      expect((await fresh.database.items.get(gone.id))?.recordType).toBe(
        "game.flow.note.tombstone",
      );
    } finally {
      w.finish();
    }
  }, 120_000);
});

test("two devices editing the same note at once keep both edits", async () => {
  const w = await world("did:plc:same-note");
  const one = w.session("one");
  const two = w.session("two");
  try {
    await w.create();
    await one.import([
      { path: "large.bin", bytes: patterned(5 * 1024 * 1024) },
    ]);
    const shared = await one.create("shared.md");
    const first = w.engine(one);
    const second = w.engine(two);
    await synced(first);
    await synced(second);
    await one.save(shared, "from one");
    await two.save(shared, "from two");
    w.pds.holdPuts(2);
    const results = await Promise.all([first.sync(), second.sync()]);
    for (const result of results) expect(result.blocked).toBeUndefined();
    await synced(first);
    await synced(second);
    await synced(first);
    for (const session of [one, two]) {
      const sources = [...(await readable(session)).values()];
      expect(sources).toContain("from one");
      expect(sources).toContain("from two");
    }
  } finally {
    w.finish();
  }
}, 120_000);

describe.each([
  { journal: false, signed: false },
  { journal: false, signed: true },
  { journal: true, signed: false },
  { journal: true, signed: true },
])("a vault written with journal $journal, signed $signed", (written) => {
  test.each([false, true])(
    "opens and syncs through a passkey port with signed access writes %p",
    async (signAccess) => {
      const owner = `did:plc:matrix-${written.journal}-${written.signed}-${signAccess}`;
      const key = await createVaultKey();
      const vault = crypto.randomUUID();
      const pds = memoryPds(owner);
      const admin = await passkeyAdmin(PRF, CREDENTIAL, owner);
      const signedState = await signedVault(
        key,
        { did: owner, vault, epoch: 1 },
        [admin.recipient],
        admin,
      );
      const legacy = await createAccessRecipient(PRF, CREDENTIAL, owner);
      const header = await createAccessHeader(key, [legacy.publicKey], owner);
      const legacyAccess: VaultAccess = {
        header,
        metadata: {
          recipients: [legacy],
          accessCommitment: await accessHeaderCommitment(header),
        },
      };
      const seedOptions = written.signed
        ? signedState
        : { vault, epoch: 1, access: legacyAccess, pinned: null };
      const source = createSession({ owner, vault, key });
      const large = patterned(5 * 1024 * 1024);
      await source.import([
        { path: "large.bin", bytes: large },
        { path: "kept.md", bytes: new TextEncoder().encode("# Kept") },
      ]);
      const { entries } = await captureSnapshot(source.database);
      source.lock();
      const seeded = new AuthVaultTransport(pds.rpc, {
        key,
        did: owner,
        ...seedOptions,
        writeJournal: written.journal,
      });
      await seeded.writeSnapshot(entries, null);
      seeded.stop();
      const decryptRoot = () => {
        if (!pds.stored) throw new Error("Missing stored vault");
        return decryptContainerRoot(key, { did: owner }, pds.stored.value.root);
      };
      expect(await decryptRoot()).toMatchObject({
        version: written.journal ? 3 : 2,
      });
      const unlocked = await unlockVault(
        passkeyPort({
          userId: `user-${owner}`,
          did: owner,
          credentialId: CREDENTIAL,
          rpc: pds.rpc,
          prf: () => PRF.slice(),
        }),
        {},
        signAccess,
      );
      try {
        await unlocked.runtime.sync?.();
        const notes = await unlocked.runtime.list();
        const kept = notes.find((note) => note.path === "kept.md");
        if (!kept) throw new Error("Missing kept note");
        expect(kept.source).toBe("# Kept");

        const beforeEdit = await decryptRoot();
        const uploads = pds.uploads;
        await unlocked.runtime.save({ ...kept, source: "# Edited" });
        await unlocked.runtime.sync?.();
        expect(pds.uploads - uploads).toBe(beforeEdit.version === 3 ? 1 : 4);
        expect(await decryptRoot()).toMatchObject({
          version: 3,
          chunkCount: 3,
        });

        if (!pds.stored) throw new Error("Missing stored vault");
        const { metadata } = await readVerifiedVaultRoot(
          key,
          owner,
          pds.stored.value,
        );
        expect("version" in metadata).toBe(written.signed || signAccess);

        const reader = (writeJournal?: boolean) =>
          new AuthVaultTransport(pds.rpc, {
            key,
            did: owner,
            vault,
            epoch: 1,
            access: {
              header: {
                accessSalt: pds.stored?.value.accessSalt ?? "",
                access: pds.stored?.value.access ?? [],
              },
              metadata,
            },
            pinned: null,
            writeJournal,
          });
        const previous = reader(false);
        const held = await previous.readSnapshot();
        const flipped = reader();
        expect(await flipped.readSnapshot()).toEqual(held);
        flipped.stop();
        expect(held.entries.length).toBeGreaterThanOrEqual(entries.length);

        await previous.writeSnapshot(held.entries, held.cid);
        previous.stop();
        expect((await decryptRoot()).version).toBe(2);

        await unlocked.runtime.sync?.();
        const after = await unlocked.runtime.list();
        const edited = after.find((note) => note.path === "kept.md");
        if (!edited) throw new Error("Missing edited note");
        expect(edited.source).toBe("# Edited");
        await unlocked.runtime.save({ ...edited, source: "# Forward" });
        await unlocked.runtime.sync?.();
        expect(await decryptRoot()).toMatchObject({
          version: 3,
          chunkCount: 3,
        });
        const final = reader();
        const carried = await final.readSnapshot();
        final.stop();
        expect(carried.entries.length).toBe(held.entries.length);
        const attachment = entries.find((entry) => entry.encryptedBlobs.length);
        expect(
          carried.entries.find((entry) => entry.id === attachment?.id)
            ?.encryptedBlobs,
        ).toEqual(attachment?.encryptedBlobs ?? []);
      } finally {
        unlocked.runtime.lock();
        key.fill(0);
      }
    },
    60_000,
  );
});
