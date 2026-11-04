import { afterEach, expect, test } from "bun:test";
import Dexie from "dexie";
import { IDBKeyRange, indexedDB } from "fake-indexeddb";
import { noteEntry } from "../../tests/entry-fixture.ts";
import { legacyHeader, signedVault } from "../../tests/unlock-fixture.ts";
import { SYNC_LOCKED } from "../app/runtime.ts";
import { synchronizedRuntime } from "../app/synchronized-runtime.ts";
import { createAccessRecipient } from "../crypto/access-v2.ts";
import {
  type AccessSigner,
  createSeedRecipient,
  passkeyAdmin,
  type RootMetadata,
  seedSigningKey,
} from "../crypto/access-v3.ts";
import {
  type EntrySigner,
  type RunPolicy,
  signEntry,
} from "../crypto/authorship.ts";
import { prepareExecution } from "../render/module-loader";
import { SyncFailure } from "../sync/records.ts";
import { VaultSyncEngine } from "../sync/vault-engine.ts";
import {
  captureSnapshot,
  type SnapshotEntry,
  VaultAccessError,
  type VaultSnapshot,
  type VaultSnapshotTransport,
} from "../sync/vault-snapshot.ts";
import { readVerifiedVaultRoot } from "../sync/vault-transport.ts";
import { createSession, type TrustLoss, type VaultSession } from "./session.ts";
import { revisionDigest } from "./storage.ts";

Dexie.dependencies.indexedDB = indexedDB;
Dexie.dependencies.IDBKeyRange = IDBKeyRange;
const owner = "did:plc:authorship-session";
const key = new Uint8Array(32).fill(5);
const encoder = new TextEncoder();
const opened: VaultSession[] = [];
afterEach(async () => {
  const sessions = opened.splice(0);
  for (const session of sessions) session.lock();
  for (const session of sessions) await session.database.delete();
});

function signerOf(signer: AccessSigner): EntrySigner {
  return {
    recipientId: signer.recipient.id,
    signPublicKey: signer.recipient.signPublicKey ?? "",
    privateKey: signer.privateKey,
  };
}
async function seeded(fill: number, kind: "device" | "agent", label: string) {
  const seed = new Uint8Array(32).fill(fill);
  const recipient = await createSeedRecipient(seed, kind, label);
  return {
    recipient,
    signer: {
      recipientId: recipient.id,
      signPublicKey: recipient.signPublicKey ?? "",
      privateKey: await seedSigningKey(seed),
    },
  };
}
/** A signed vault listing a passkey admin, a linked device and an agent. */
async function world() {
  const vault = crypto.randomUUID();
  const admin = await passkeyAdmin(new Uint8Array(32).fill(1), "admin", owner);
  const device = await seeded(2, "device", "Laptop");
  const agent = await seeded(3, "agent", "Bot");
  const state = await signedVault(
    key,
    { did: owner, vault, epoch: 1 },
    [admin.recipient, device.recipient, agent.recipient],
    admin,
  );
  const access = state.access.metadata;
  function open(
    signer?: EntrySigner,
    metadata: RootMetadata = access,
    runners: RunPolicy = signer ? [signer] : [],
  ) {
    const session = createSession({
      owner,
      vault,
      key,
      authorship: { signer, access: metadata, runners },
    });
    opened.push(session);
    return session;
  }
  const entryBy = (
    signer: EntrySigner | null,
    item: Parameters<typeof noteEntry>[3],
    source: string,
    revision?: string,
  ) => noteEntry(key, { did: owner, vault }, signer, item, source, revision);
  return {
    vault,
    access,
    admin: signerOf(admin),
    device: device.signer,
    agent: agent.signer,
    open,
    entryBy,
  };
}
/** A PDS holding one snapshot, read and written through the real sync engine. */
function remote(entries: SnapshotEntry[], access: RootMetadata) {
  let snapshot: VaultSnapshot = { cid: "remote-1", entries, access };
  let writes = 1;
  const transport: VaultSnapshotTransport = {
    version: 2,
    readSnapshot: async () => structuredClone(snapshot),
    async writeSnapshot(written, expectedCid) {
      if (expectedCid !== snapshot.cid)
        throw new SyncFailure("conflict", "CAS");
      snapshot = {
        cid: `remote-${++writes}`,
        entries: structuredClone(written),
        access: snapshot.access,
      };
      return { cid: snapshot.cid };
    },
  };
  return {
    get entries() {
      return snapshot.entries;
    },
    replace(next: SnapshotEntry[], nextAccess = snapshot.access) {
      snapshot = {
        cid: `remote-${++writes}`,
        entries: next,
        access: nextAccess,
      };
    },
    sync: (session: VaultSession) =>
      new VaultSyncEngine(session, transport).sync(),
  };
}
/** The base a save made on `id`'s stored row names. */
async function shownBase(session: VaultSession, id: string) {
  const stored = await session.database.items.get(id);
  if (!stored) throw new Error(`Missing ${id}`);
  return { revision: stored.revision, digest: await revisionDigest(stored) };
}
async function originOf(session: VaultSession, path: string) {
  const note = (await session.readView()).notes.find(
    (value) => value.path === path,
  );
  if (!note) throw new Error(`Missing ${path}`);
  return { id: note.id, origin: note.origin, source: note.source };
}

test("an admin session signs what it writes, and its MDX runs", async () => {
  const w = await world();
  const session = w.open(w.admin);
  const id = await session.create("Run.mdx");
  await session.saveNote(id, "Run.mdx", "# Mine");
  expect((await session.database.items.get(id))?.author?.recipientId).toBe(
    w.admin.recipientId,
  );
  expect((await originOf(session, "Run.mdx")).origin).toEqual({
    runs: true,
    author: "Signed by a passkey",
  });
});

test("a writer's, an agent's or an unsigned revision synced in waits for Run", async () => {
  const w = await world();
  const pds = remote(
    [
      await w.entryBy(w.agent, { id: "agent", name: "Agent.mdx" }, "# A"),
      await w.entryBy(w.device, { id: "device", name: "Device.mdx" }, "# D"),
      await w.entryBy(null, { id: "bare", name: "Bare.mdx" }, "# U"),
      await w.entryBy(w.admin, { id: "admin", name: "Admin.mdx" }, "# P"),
    ],
    w.access,
  );
  const session = w.open(w.admin);
  await pds.sync(session);
  expect((await originOf(session, "Agent.mdx")).origin).toEqual({
    runs: false,
    author: "Signed by agent “Bot”",
  });
  expect((await originOf(session, "Device.mdx")).origin).toEqual({
    runs: false,
    author: "Signed by device “Laptop”",
  });
  expect((await originOf(session, "Bare.mdx")).origin).toEqual({
    runs: false,
    author: "Not signed",
  });
  expect((await originOf(session, "Admin.mdx")).origin?.runs).toBe(true);
});

test("a stripped or transplanted admin signature never runs", async () => {
  const w = await world();
  const signed = await w.entryBy(
    w.admin,
    { id: "legacy", name: "Legacy.mdx" },
    "# Endorsed",
  );
  const { author, ...stripped } = signed;
  const swapped = await w.entryBy(
    null,
    { id: "legacy", name: "Legacy.mdx" },
    "# Swapped content",
    signed.revision,
  );
  const pds = remote([stripped], w.access);
  const fresh = w.open(w.admin);
  await pds.sync(fresh);
  expect((await originOf(fresh, "Legacy.mdx")).origin?.runs).toBe(false);
  fresh.lock();
  await fresh.database.delete();
  pds.replace([{ ...swapped, author }]);
  const other = w.open(w.admin);
  await pds.sync(other);
  expect(await originOf(other, "Legacy.mdx")).toMatchObject({
    source: "# Swapped content",
    origin: { runs: false, author: "Signature not recognized" },
  });
});

test("moving, renaming, trashing or restoring an untrusted note never signs it", async () => {
  const w = await world();
  const pds = remote(
    [
      await w.entryBy(
        w.agent,
        { id: "plain", name: "Plain.md" },
        "export const x = 1\n\n# Not MDX yet",
      ),
    ],
    w.access,
  );
  const session = w.open(w.admin);
  await pds.sync(session);
  const source = "export const x = 1\n\n# Not MDX yet";
  await session.saveNote("plain", "Plain.mdx", source);
  expect((await session.database.items.get("plain"))?.author).toBeUndefined();
  expect((await originOf(session, "Plain.mdx")).origin).toEqual({
    runs: false,
    author: "Not signed",
  });
  await session.rename("plain", "Moved/Plain.mdx");
  expect((await originOf(session, "Moved/Plain.mdx")).origin?.runs).toBe(false);
  await session.remove("plain");
  const restored = await session.restore("plain");
  expect((await session.database.items.get(restored))?.author).toBeUndefined();
  expect((await originOf(session, "Plain.mdx")).origin?.runs).toBe(false);
  await session.saveNote(restored, "Plain.mdx", `${source}\nEdited here.`);
  expect((await originOf(session, "Plain.mdx")).origin?.runs).toBe(false);
  const edited = await session.database.items.get(restored);
  if (!edited) throw new Error("Missing restored note");
  await session.trust([{ id: restored, digest: await revisionDigest(edited) }]);
  expect((await originOf(session, "Plain.mdx")).origin).toEqual({
    runs: true,
    author: "Signed by a passkey",
  });
});

test("link repair and extraction keep an untrusted note's trust", async () => {
  const w = await world();
  const pds = remote(
    [
      await w.entryBy(
        w.agent,
        { id: "linker", name: "Linker.mdx" },
        "See [[Target]]\n\nexport const y = 2",
      ),
    ],
    w.access,
  );
  const session = w.open(w.admin);
  await pds.sync(session);
  const target = await session.create("Target.md");
  await session.saveNote(target, "Target.md", "# Target");
  await session.rename(target, "Renamed.md");
  const linker = await originOf(session, "Linker.mdx");
  expect(linker.source).toContain("Renamed]]");
  expect(linker.origin?.runs).toBe(false);
  expect((await originOf(session, "Renamed.md")).origin).toBeUndefined();
  const { selectedId } = await session.compose({
    kind: "extract",
    originId: "linker",
    expectedSource: linker.source,
    from: 0,
    to: linker.source.length,
    path: "Extracted.mdx",
  });
  expect(
    (await session.database.items.get(selectedId))?.author,
  ).toBeUndefined();
  expect((await originOf(session, "Extracted.mdx")).origin?.runs).toBe(false);
});

test("a sync conflict copy of an agent's revision stays unsigned", async () => {
  const w = await world();
  const pds = remote([], w.access);
  const session = w.open(w.admin);
  const id = await session.create("Shared.mdx");
  await session.saveNote(id, "Shared.mdx", "# A");
  await pds.sync(session);
  await session.saveNote(id, "Shared.mdx", "# B");
  await session.saveNote(id, "Shared.mdx", "# C");
  const base = (await session.readView()).notes.find((note) => note.id === id);
  if (!base) throw new Error("Missing shared note");
  pds.replace([
    await w.entryBy(
      w.agent,
      { id, name: "Shared.mdx", revisionCounter: 2 },
      "export const evil = true",
    ),
  ]);
  await pds.sync(session);
  const notes = (await session.readView()).notes;
  const copy = notes.find((note) => note.path.includes("conflict"));
  expect(copy?.source).toBe("export const evil = true");
  expect(copy?.origin).toEqual({ runs: false, author: "Not signed" });
  expect(notes.find((note) => note.id === id)?.origin?.runs).toBe(true);
  const published = pds.entries.find((entry) => entry.id === copy?.id);
  expect(published?.author).toBeUndefined();
});

test("a device adopts a signature added to a revision it holds, and keeps one stripped remotely", async () => {
  const w = await world();
  const bare = await w.entryBy(null, { id: "old", name: "Old.mdx" }, "# Old");
  const pds = remote([bare], w.access);
  const session = w.open(w.admin);
  await pds.sync(session);
  expect((await originOf(session, "Old.mdx")).origin?.runs).toBe(false);
  const endorsed = {
    ...bare,
    author: await signEntry(bare, { did: owner, vault: w.vault }, w.admin),
  };
  pds.replace([endorsed]);
  await pds.sync(session);
  expect((await originOf(session, "Old.mdx")).origin?.runs).toBe(true);
  pds.replace([bare]);
  await pds.sync(session);
  expect((await originOf(session, "Old.mdx")).origin?.runs).toBe(true);
  const other = await session.create("Other.md");
  await session.saveNote(other, "Other.md", "trigger a write");
  await pds.sync(session);
  expect(pds.entries.find((entry) => entry.id === "old")?.author).toEqual(
    endorsed.author,
  );
});

test("a device adopts only a signature over the ciphertext it holds", async () => {
  const w = await world();
  const bare = await w.entryBy(null, { id: "old", name: "Old.mdx" }, "# Old");
  const pds = remote([bare], w.access);
  const session = w.open(w.admin);
  await pds.sync(session);
  pds.replace([
    await w.entryBy(
      w.admin,
      { id: "old", name: "Old.mdx" },
      "# Other content, same revision",
      bare.revision,
    ),
  ]);
  await pds.sync(session);
  expect((await session.database.items.get("old"))?.author).toBeUndefined();
  expect((await originOf(session, "Old.mdx")).origin).toEqual({
    runs: false,
    author: "Not signed",
  });
  pds.replace([
    {
      ...bare,
      author: await signEntry(bare, { did: owner, vault: w.vault }, w.admin),
    },
  ]);
  await pds.sync(session);
  expect((await originOf(session, "Old.mdx")).origin?.runs).toBe(true);
});

test("a passkey session runs only its own admin signature; a seed holder's runs every admin it accepted", async () => {
  const w = await world();
  const admin = await passkeyAdmin(new Uint8Array(32).fill(1), "admin", owner);
  const seed = new Uint8Array(32).fill(6);
  const recovery = await createSeedRecipient(seed, "recovery", "Recovery");
  const other = await passkeyAdmin(new Uint8Array(32).fill(9), "other", owner);
  const device = await seeded(2, "device", "Laptop");
  const { access } = await signedVault(
    key,
    { did: owner, vault: w.vault, epoch: 1 },
    [admin.recipient, recovery, other.recipient, device.recipient],
    admin,
  );
  const recoverySigner = {
    recipientId: recovery.id,
    signPublicKey: recovery.signPublicKey ?? "",
    privateKey: await seedSigningKey(seed),
  };
  const pds = remote(
    [
      await w.entryBy(w.admin, { id: "mine", name: "Mine.mdx" }, "# M"),
      await w.entryBy(recoverySigner, { id: "rec", name: "Rec.mdx" }, "# R"),
      await w.entryBy(
        signerOf(other),
        { id: "other", name: "Other.mdx" },
        "# O",
      ),
    ],
    access.metadata,
  );
  const passkey = w.open(w.admin, access.metadata);
  await pds.sync(passkey);
  expect((await originOf(passkey, "Mine.mdx")).origin?.runs).toBe(true);
  for (const path of ["Rec.mdx", "Other.mdx"])
    expect((await originOf(passkey, path)).origin).toEqual({
      runs: false,
      author: "Signed by another admin key",
      reason:
        "Signed by another admin key listed for this notepad, which this browser can’t confirm",
    });
  await passkey.saveNote("rec", "Moved/Rec.mdx", "# R");
  expect((await passkey.database.items.get("rec"))?.author).toBeUndefined();
  passkey.lock();
  await passkey.database.delete();
  const linked = w.open(device.signer, access.metadata, "every-admin");
  await pds.sync(linked);
  for (const path of ["Mine.mdx", "Rec.mdx", "Other.mdx"])
    expect((await originOf(linked, path)).origin?.runs).toBe(true);
});

/** Passkey A's session in a vault whose admins are passkeys A and B, reporting every trust loss. */
async function sharedWithAnotherPasskey() {
  const w = await world();
  const admin = await passkeyAdmin(new Uint8Array(32).fill(1), "admin", owner);
  const other = await passkeyAdmin(new Uint8Array(32).fill(9), "other", owner);
  const { access } = await signedVault(
    key,
    { did: owner, vault: w.vault, epoch: 1 },
    [admin.recipient, other.recipient],
    admin,
  );
  const byOther = (item: Parameters<typeof noteEntry>[3], source: string) =>
    w.entryBy(signerOf(other), item, source);
  const losses: TrustLoss[] = [];
  return {
    byOther,
    losses,
    async open(entries: SnapshotEntry[]) {
      const pds = remote(entries, access.metadata);
      const session = w.open(w.admin, access.metadata);
      session.subscribeTrustLoss((loss) => losses.push(loss));
      await pds.sync(session);
      return session;
    },
  };
}

test("moving or trashing another passkey's MDX writes it unsigned and says so", async () => {
  const t = await sharedWithAnotherPasskey();
  const session = await t.open([
    await t.byOther(
      { id: "dash", name: "Dashboard.mdx" },
      "export const n = 1\n\n# Dashboard",
    ),
    await t.byOther({ id: "widget", name: "Widget.mdx" }, "# Widget"),
    await t.byOther({ id: "notes", name: "Notes.mdx" }, "# Notes"),
  ]);
  await session.rename("dash", "Reports/Dashboard.mdx");
  expect((await session.database.items.get("dash"))?.author).toBeUndefined();
  await session.remove("widget");
  expect((await session.database.items.get("widget"))?.author).toBeUndefined();
  const untouched = (await session.database.items.get("notes"))?.revision;
  await session.saveNote("notes", "Notes.mdx", "# Notes");
  expect((await session.database.items.get("notes"))?.revision).toBe(untouched);
  // Typing around it keeps it unsigned: only an explicit trust signs it as this passkey.
  await session.saveNote("notes", "Notes.mdx", "# Notes, edited here");
  const edited = await session.database.items.get("notes");
  if (!edited) throw new Error("Missing notes");
  expect(edited.author).toBeUndefined();
  await session.trust([{ id: "notes", digest: await revisionDigest(edited) }]);
  expect((await session.database.items.get("notes"))?.author?.recipientId).toBe(
    (await passkeyAdmin(new Uint8Array(32).fill(1), "admin", owner)).recipient
      .id,
  );
  expect(t.losses).toEqual([
    { unsigned: ["Dashboard.mdx"], stale: [] },
    { unsigned: ["Widget.mdx"], stale: [] },
    { unsigned: ["Notes.mdx"], stale: [] },
  ]);
});

test("link repair leaves another passkey's MDX signed with stale links, and says so", async () => {
  const t = await sharedWithAnotherPasskey();
  const board = await t.byOther(
    { id: "board", name: "Board.mdx" },
    "See [[Target]].\n",
  );
  const session = await t.open([board]);
  await session.saveNote("target", "Target.md", "# Target");
  await session.saveNote("mine", "Mine.mdx", "See [[Target]].\n");
  await session.rename("target", "Goal.md");
  expect(await session.open("mine")).toContain("Goal]]");
  const after = await session.database.items.get("board");
  expect(after?.revision).toBe(board.revision);
  expect(after?.author).toEqual(board.author);
  expect(await session.open("board")).toContain("[[Target]]");
  expect(t.losses).toEqual([{ unsigned: [], stale: ["Board.mdx"] }]);
});

test("a direct action on another passkey's MDX can ask first, and naming that key claims no kind or label", async () => {
  const t = await sharedWithAnotherPasskey();
  const session = await t.open([
    await t.byOther({ id: "dash", name: "Dashboard.mdx" }, "# Dashboard"),
    await t.byOther({ id: "widget", name: "Widget.mdx" }, "# Widget"),
  ]);
  const mine = await session.create("Mine.mdx");
  await session.saveNote(mine, "Mine.mdx", "# Mine");
  const dashDigest = await session.holdsCode("dash");
  const widgetDigest = await session.holdsCode("widget");
  expect(dashDigest).toBeString();
  expect(await session.holdsCode(mine)).toBeNull();
  expect(
    await session.writerToEndorse({ id: "dash", path: "Dashboard.mdx" }),
  ).toBe(
    "another admin key listed for this notepad, which this browser can’t confirm",
  );
  const source = await session.open("dash");
  await session.saveNote("dash", "Reports/Dashboard.mdx", source, {
    endorsed: true,
  });
  await session.remove("widget", widgetDigest ?? "");
  for (const id of ["dash", "widget"])
    expect((await session.database.items.get(id))?.author?.recipientId).toBe(
      (await passkeyAdmin(new Uint8Array(32).fill(1), "admin", owner)).recipient
        .id,
    );
  expect(await session.holdsCode("dash")).toBeNull();
  expect(dashDigest).not.toBe(widgetDigest);
  expect(t.losses).toEqual([]);
});

test("a session given no run policy runs no admin's MDX", async () => {
  const w = await world();
  const pds = remote(
    [await w.entryBy(w.admin, { id: "mine", name: "Mine.mdx" }, "# M")],
    w.access,
  );
  const session = createSession({
    owner,
    vault: w.vault,
    key,
    // SAFETY: stands in for a caller that omits the required policy, which must fail closed.
    authorship: { signer: w.admin, access: w.access } as never,
  });
  opened.push(session);
  await pds.sync(session);
  expect((await originOf(session, "Mine.mdx")).origin?.runs).toBe(false);
});

test("a removed signer's revisions stop running once the session adopts the new access", async () => {
  const w = await world();
  const pds = remote(
    [await w.entryBy(w.admin, { id: "kept", name: "Kept.mdx" }, "# K")],
    w.access,
  );
  const session = w.open(w.admin);
  await pds.sync(session);
  expect((await originOf(session, "Kept.mdx")).origin?.runs).toBe(true);
  const successor = await passkeyAdmin(
    new Uint8Array(32).fill(8),
    "successor",
    owner,
  );
  const changed = await signedVault(
    key,
    { did: owner, vault: w.vault, epoch: 1 },
    [successor.recipient],
    successor,
  );
  pds.replace(pds.entries, changed.access.metadata);
  await pds.sync(session);
  expect((await originOf(session, "Kept.mdx")).origin).toEqual({
    runs: false,
    author: "Signature not recognized",
  });
  const id = await session.create("After.mdx");
  await session.saveNote(id, "After.mdx", "# Unlisted signer");
  expect((await session.database.items.get(id))?.author).toBeUndefined();
});

test("an imported module attachment carries its own signature", async () => {
  const w = await world();
  const agentSession = w.open(w.agent);
  await agentSession.import([
    {
      path: "view.ts",
      bytes: encoder.encode("export default () => 'from the agent'"),
    },
  ]);
  const { entries } = await captureSnapshot(agentSession.database);
  agentSession.lock();
  await agentSession.database.delete();
  const pds = remote(entries, w.access);
  const session = w.open(w.admin);
  await pds.sync(session);
  const source = "import View from './view.ts'\n\n<View />";
  const id = await session.create("Dash.mdx");
  await session.saveNote(id, "Dash.mdx", source);
  const assets = await session.assetsForNote(id);
  expect(
    assets.map(({ canonicalPath, runs }) => ({ canonicalPath, runs })),
  ).toEqual([{ canonicalPath: "view.ts", runs: false }]);
  expect((await originOf(session, "Dash.mdx")).origin?.runs).toBe(true);
  await expect(
    prepareExecution(source, "Dash.mdx", assets, { runs: true }),
  ).rejects.toThrow("A passkey didn’t sign view.ts, which this note imports");
  const [view] = assets;
  await session.trust([{ id: view?.id ?? "", digest: view?.digest ?? "" }]);
  const trusted = await session.assetsForNote(id);
  expect([
    ...(
      await prepareExecution(source, "Dash.mdx", trusted, { runs: true })
    ).modules.keys(),
  ]).toEqual(["Dash.mdx", "view.ts"]);
});

test("a session over an unsigned root signs nothing and runs nothing, however it syncs", async () => {
  const w = await world();
  const legacy = await legacyHeader(
    key,
    {
      vault: w.vault,
      epoch: 1,
      recipients: [
        await createAccessRecipient(new Uint8Array(32).fill(1), "admin", owner),
      ],
    },
    owner,
  );
  const { metadata } = await readVerifiedVaultRoot(key, owner, legacy);
  const pds = remote(
    [await w.entryBy(w.agent, { id: "agent", name: "Agent.mdx" }, "# A")],
    metadata,
  );
  const session = w.open(w.admin, metadata);
  await pds.sync(session);
  const id = await session.create("Mine.mdx");
  await session.saveNote(id, "Mine.mdx", "# Mine");
  await pds.sync(session);
  expect(pds.entries.find((entry) => entry.id === id)).not.toHaveProperty(
    "author",
  );
  expect((await originOf(session, "Mine.mdx")).origin).toEqual({
    runs: false,
    author: "Not signed",
  });
  expect((await originOf(session, "Agent.mdx")).origin).toEqual({
    runs: false,
    author: "Signature not recognized",
  });
});

test("an unsigned vault repairs a moved note's links in MDX and reports no trust loss, whoever signs", async () => {
  for (const pick of ["admin", "device", "none"] as const) {
    const w = await world();
    const legacy = await legacyHeader(
      key,
      {
        vault: w.vault,
        epoch: 1,
        recipients: [
          await createAccessRecipient(
            new Uint8Array(32).fill(1),
            "admin",
            owner,
          ),
        ],
      },
      owner,
    );
    const { metadata } = await readVerifiedVaultRoot(key, owner, legacy);
    const signer = pick === "none" ? undefined : w[pick];
    const session = w.open(signer, metadata, "every-admin");
    const losses: TrustLoss[] = [];
    session.subscribeTrustLoss((loss) => losses.push(loss));
    const target = await session.create("Target.md");
    const page = await session.create("Page.mdx");
    await session.saveNote(page, "Page.mdx", "[t](Target.md)");
    await session.rename(target, "Sub/Target.md");
    expect(losses).toEqual([]);
    expect(await session.open(page)).toContain("Sub/Target.md");
    const asked: (readonly string[])[] = [];
    await session.import(
      [{ path: "Imported.mdx", bytes: new TextEncoder().encode("# I") }],
      async (code) => {
        asked.push(code);
        return true;
      },
    );
    // Nothing is signed in an unsigned vault, so there is nothing to ask.
    expect(asked).toEqual([]);
  }
});

test("a device signs only what it typed: not a move whose link repair rewrote the note, an unchanged save, or a stale view it didn't edit", async () => {
  const w = await world();
  const pds = remote(
    [
      await w.entryBy(w.admin, { id: "target", name: "Target.md" }, "# T"),
      await w.entryBy(
        w.admin,
        { id: "page", name: "Page.mdx" },
        "[t](Target.md)",
      ),
      await w.entryBy(w.admin, { id: "plain", name: "Plain.md" }, "# Plain"),
    ],
    w.access,
  );
  const session = w.open(w.device, w.access, [w.admin]);
  await pds.sync(session);
  const losses: TrustLoss[] = [];
  session.subscribeTrustLoss((loss) => losses.push(loss));
  const row = (id: string) => session.database.items.get(id);

  const own = await session.create("Own.mdx");
  await session.saveNote(
    own,
    "Own.mdx",
    "# Own",
    undefined,
    await shownBase(session, own),
  );
  const owned = await row(own);
  expect(owned?.author?.recipientId).toBe(w.device.recipientId);
  await session.saveNote(own, "Own.mdx", "# Own");
  expect(await row(own)).toEqual(owned);
  const plain = await row("plain");
  if (!plain) throw new Error("Missing Plain.md");
  await session.saveNote("plain", "Plain.md", "# Plain");
  expect(await row("plain")).toEqual(plain);

  const shown = {
    revision: plain.revision,
    digest: await revisionDigest(plain),
  };
  await pds.sync(session);
  pds.replace([
    ...pds.entries.filter((entry) => entry.id !== "plain"),
    await w.entryBy(
      w.admin,
      { id: "plain", name: "Plain.md", revisionCounter: 2 },
      "# Newer",
      "plain-2",
    ),
  ]);
  await pds.sync(session);
  const newer = await row("plain");
  expect(newer?.revision).toBe("plain-2");
  await session.saveNote("plain", "Plain.md", "# Plain", undefined, shown);
  expect(await row("plain")).toEqual(newer);
  await session.saveNote("plain", "Plain.md", "# Mine", undefined, shown);
  expect((await row("plain"))?.author?.recipientId).toBe(w.device.recipientId);

  await session.rename("page", "Sub/Page.mdx");
  expect(await session.open("page")).not.toBe("[t](Target.md)");
  expect((await row("page"))?.author).toBeUndefined();
  expect(losses).toEqual([{ unsigned: ["Page.mdx"], stale: [] }]);
});

test("a device's save of the stored row's own bytes writes nothing, whatever base it names", async () => {
  const w = await world();
  const pds = remote(
    [await w.entryBy(w.admin, { id: "page", name: "Page.mdx" }, "# v1")],
    w.access,
  );
  const session = w.open(w.device, w.access, [w.admin]);
  await pds.sync(session);
  const losses: TrustLoss[] = [];
  session.subscribeTrustLoss((loss) => losses.push(loss));
  const row = (id: string) => session.database.items.get(id);
  const first = await row("page");
  if (!first) throw new Error("Missing Page.mdx");
  const older = {
    revision: first.revision,
    digest: await revisionDigest(first),
  };
  pds.replace([
    await w.entryBy(
      w.admin,
      { id: "page", name: "Page.mdx", revisionCounter: 2 },
      "# v2",
      "page-2",
    ),
  ]);
  await pds.sync(session);
  const newer = await row("page");
  expect(newer?.revision).toBe("page-2");
  // Named with the older base, the newer revision's bytes would read as the device's typing and be signed as its own.
  await session.saveNote("page", "Page.mdx", "# v2", undefined, older);
  expect(await row("page")).toEqual(newer);

  const unplaced = { revision: "gone", digest: "0".repeat(64) };
  const own = await session.create("Own.mdx");
  await session.saveNote(
    own,
    "Own.mdx",
    "# Own",
    undefined,
    await shownBase(session, own),
  );
  const mine = await row(own);
  expect(mine?.author?.recipientId).toBe(w.device.recipientId);
  // Over a view it can't place, the device's own unchanged note would be rewritten unsigned.
  await session.saveNote(own, "Own.mdx", "# Own", undefined, unplaced);
  expect(await row(own)).toEqual(mine);
  expect(losses).toEqual([]);
});

test("a device's save over a view it can't place, or over none, is unsigned and reports the admin code it replaces", async () => {
  const w = await world();
  const pds = remote(
    [
      await w.entryBy(w.admin, { id: "page", name: "Page.mdx" }, "# v1"),
      await w.entryBy(w.admin, { id: "moved", name: "Moved.mdx" }, "# m"),
    ],
    w.access,
  );
  const session = w.open(w.device, w.access, [w.admin]);
  await pds.sync(session);
  const losses: TrustLoss[] = [];
  session.subscribeTrustLoss((loss) => losses.push(loss));
  const signer = async (id: string) =>
    (await session.database.items.get(id))?.author?.recipientId ?? null;
  const unplaced = { revision: "gone", digest: "0".repeat(64) };

  await session.saveNote("page", "Page.mdx", "# stale", undefined, unplaced);
  expect(await signer("page")).toBeNull();
  expect(losses).toEqual([{ unsigned: ["Page.mdx"], stale: [] }]);
  await pds.sync(session);
  pds.replace([
    ...pds.entries.filter((entry) => entry.id !== "page"),
    await w.entryBy(
      w.admin,
      { id: "page", name: "Page.mdx", revisionCounter: 3 },
      "# v3",
      "page-3",
    ),
  ]);
  await pds.sync(session);
  await session.saveNote("page", "Page.mdx", "# stale again");
  expect(await signer("page")).toBeNull();
  expect(losses.at(-1)).toEqual({ unsigned: ["Page.mdx"], stale: [] });
  await session.saveNote("moved", "Sub/Moved.mdx", "# m", undefined, unplaced);
  expect(await signer("moved")).toBeNull();
  expect(losses.at(-1)).toEqual({ unsigned: ["Moved.mdx"], stale: [] });

  const own = await session.create("Own.mdx");
  await session.saveNote(own, "Own.mdx", "# Own", undefined, unplaced);
  expect(await signer(own)).toBeNull();
  expect(losses).toHaveLength(3);
});

test("a vault that gains signed access mid-session starts signing", async () => {
  const w = await world();
  const legacy = await legacyHeader(
    key,
    {
      vault: w.vault,
      epoch: 1,
      recipients: [
        await createAccessRecipient(new Uint8Array(32).fill(1), "admin", owner),
      ],
    },
    owner,
  );
  const { metadata } = await readVerifiedVaultRoot(key, owner, legacy);
  const pds = remote([], metadata);
  const session = w.open(w.admin, metadata);
  await pds.sync(session);
  pds.replace([], w.access);
  await pds.sync(session);
  const id = await session.create("Signed.mdx");
  await session.saveNote(id, "Signed.mdx", "# Now signed");
  expect((await session.database.items.get(id))?.author?.recipientId).toBe(
    w.admin.recipientId,
  );
  expect((await originOf(session, "Signed.mdx")).origin?.runs).toBe(true);
});

test("locking wipes the session's copy of the signing key", async () => {
  const w = await world();
  const session = w.open(w.admin);
  // biome-ignore lint/complexity/useLiteralKeys: The held key is private by design; the test reads it to prove the wipe.
  const held = session["signer"]?.privateKey;
  expect(held?.some((byte) => byte !== 0)).toBe(true);
  expect(held).not.toBe(w.admin.privateKey);
  session.lock();
  expect(held?.every((byte) => byte === 0)).toBe(true);
  expect(w.admin.privateKey.some((byte) => byte !== 0)).toBe(true);
});

test("a move whose link repair rewrites the moved note itself still doesn't sign it", async () => {
  const w = await world();
  const source = "Read [the target](Target.md)\n\nexport const z = 3";
  const pds = remote(
    [await w.entryBy(w.agent, { id: "mover", name: "Mover.md" }, source)],
    w.access,
  );
  const session = w.open(w.admin);
  await pds.sync(session);
  const target = await session.create("Target.md");
  await session.saveNote(target, "Target.md", "# Target");
  await session.saveNote("mover", "Sub/Mover.mdx", source);
  const moved = await originOf(session, "Sub/Mover.mdx");
  expect(moved.source).not.toBe(source);
  expect(moved.source).toContain("Target.md");
  expect(moved.origin).toEqual({ runs: false, author: "Not signed" });
});

test("a sync lock-out wipes the signing key within the flush limit, even if a listener hangs", async () => {
  const w = await world();
  const session = w.open(w.admin);
  // biome-ignore lint/complexity/useLiteralKeys: The held key is private by design; the test reads it to prove the wipe.
  const held = session["signer"]?.privateKey;
  let lost = false;
  const transport: VaultSnapshotTransport = {
    version: 2,
    async readSnapshot() {
      if (lost) throw new VaultAccessError("Access removed");
      return { cid: "initial", entries: [], access: w.access };
    },
    async writeSnapshot() {
      throw new Error("Must not publish after access loss");
    },
  };
  const runtime = synchronizedRuntime(session, async () => transport, 50);
  await runtime.sync?.();
  let notified = false;
  runtime.subscribe?.((status) => {
    if (status !== SYNC_LOCKED) return;
    notified = true;
    return new Promise<void>(() => {});
  });
  lost = true;
  const locking = runtime.sync?.();
  while (!notified) await new Promise((resolve) => setTimeout(resolve, 0));
  expect(held?.some((byte) => byte !== 0)).toBe(true);
  await locking;
  expect(held?.every((byte) => byte === 0)).toBe(true);
  // biome-ignore lint/complexity/useLiteralKeys: The held key is private by design; the test reads it to prove the wipe.
  expect(session["signer"]).toBeNull();
});
