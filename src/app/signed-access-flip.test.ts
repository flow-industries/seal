import { afterEach, describe, expect, test } from "bun:test";
import Dexie from "dexie";
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { noteEntry } from "../../tests/entry-fixture.ts";
import { managedPds } from "../../tests/managed-pds-fixture.ts";
import { passkeyPort } from "../../tests/passkey-port.ts";
import { planPreviewAssets } from "../../tests/preview-planner.ts";
import { createSearchIndex } from "../../tests/search-index.ts";
import { memoryPds } from "../../tests/unlock-fixture.ts";
import {
  accessHeaderCommitment,
  createAccessHeader,
  createAccessRecipient,
  unwrapAccessKey,
} from "../crypto/access-v2.ts";
import {
  acceptAccess,
  createAccess,
  createSeedRecipient,
  nextSequence,
  passkeyAdmin,
  recipientsOf,
  UNTRUSTED_ACCESS,
} from "../crypto/access-v3.ts";
import {
  createRecoveryFile,
  createRecoverySeed,
  createVaultKey,
  type RecoveryFile,
} from "../crypto/index.ts";
import { createLinkSecret, linkCommitment } from "../crypto/link.ts";
import {
  AuthVaultTransport,
  readVerifiedVaultRoot,
} from "../sync/vault-transport.ts";
import { LINK_DEVICES } from "./flow-devices.ts";
import { flowPasskeys } from "./flow-passkeys.ts";
import { ENROLL_PASSKEYS } from "./passkey-request.ts";
import {
  AccessRemovedError,
  MigrationConfirmationError,
  MigrationInterruptedError,
  type NoteRuntime,
  PasskeysUnavailableError,
  RecoveryConfirmationError,
  UNTRUSTED_CHANGE,
  type UnlockResult,
} from "./runtime.ts";
import {
  addVaultRecipient,
  lastCheckpoint,
  refOf,
  signedState,
  UNTRUSTED_PIN,
  type UnlockPort,
  unlockVault,
  verifyHeader,
  WRITE_SIGNED_ACCESS,
} from "./unlock.ts";

// A production v2 vault meeting the release that writes signed access: the
// migration, Flow ID's passkey list, recovery and re-keying, each through the
// passkey port an app builds, one IndexedDB per browser.
Dexie.dependencies.IDBKeyRange = IDBKeyRange;
const owner = "did:plc:flip";
const userId = "flip-user";
const passkey = { id: "ZmxpcA", publicKey: "c".repeat(128) };
const prf = new Uint8Array(32).fill(8);
const OLD_ID = "b2xk";
const row = (credentialId: string, createdAt = "2026-01-15T12:00:00.000Z") => ({
  credentialId,
  publicKey: `0x${"c".repeat(128)}`,
  createdAt,
});

const servers: ReturnType<typeof Bun.serve>[] = [];
afterEach(() => {
  for (const server of servers.splice(0)) server.stop(true);
});
/** Flow ID's `GET /api/account/passkeys`, answering as the test says. */
function flowId(initial: () => Response) {
  const state = { answer: initial, requests: 0 };
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch() {
      state.requests++;
      return state.answer();
    },
  });
  servers.push(server);
  return { state, host: `http://127.0.0.1:${server.port}` };
}
const listing =
  (...rows: ReturnType<typeof row>[]) =>
  () =>
    Response.json({ userId, passkeys: rows });

type Pds = Pick<ReturnType<typeof memoryPds>, "rpc" | "stored">;

/** Another passkey of the same account, on a browser of its own. */
const newPasskey = {
  passkey: { id: "bmV3", publicKey: "d".repeat(128) },
  prf: new Uint8Array(32).fill(9),
};
/** One browser: its own IndexedDB, the same PDS and Flow ID. */
function browser(pds: Pds, host: string, who = { passkey, prf }) {
  const indexedDB = new IDBFactory();
  const use = () => {
    Dexie.dependencies.indexedDB = indexedDB;
  };
  let connected = who;
  const port = (writeJournal?: boolean): UnlockPort => {
    use();
    const { passkey: credential, prf: secret } = connected;
    const opened = passkeyPort({
      userId,
      did: owner,
      credentialId: credential.id,
      rpc: pds.rpc,
      prf: () => secret.slice(),
      passkeys: {
        rpId: "id.flow.industries",
        origin: "https://note.flow.talk",
        registered: () =>
          flowPasskeys(
            { user: { id: userId }, getToken: async () => "fixture" },
            host,
          ),
      },
      writeJournal,
    });
    return { ...opened, services: { planPreviewAssets, createSearchIndex } };
  };
  /** The checkpoint this browser holds, with the trust this release reads in it. */
  async function checkpoint() {
    const opened = port();
    try {
      return lastCheckpoint(await opened.checkpoint()) ?? undefined;
    } finally {
      opened.dispose?.();
    }
  }
  return {
    use,
    /** The person signs in here with another passkey. */
    connect(next: typeof who) {
      connected = next;
    },
    port: async (writeJournal?: boolean) => port(writeJournal),
    checkpoint,
    async trust() {
      const saved = await checkpoint();
      return saved && "trust" in saved ? saved.trust : undefined;
    },
    /** Puts back the unsigned checkpoint an earlier release saved for this vault. */
    async reset(vault: string) {
      const opened = port();
      await opened.saveCheckpoint({ vault, epoch: 1, pinned: null });
      opened.dispose?.();
    },
  };
}
type Browser = ReturnType<typeof browser>;

const sorted = <T extends { path: string }>(notes: T[]) =>
  notes.toSorted((a, b) => a.path.localeCompare(b.path));
/** Everything a person keeps in their notepad, as this runtime reads it. */
async function contents(runtime: NoteRuntime) {
  const { notes, folders } = await runtime.read();
  const attachments = await Promise.all(
    notes.map(async (note) =>
      (await runtime.assets(note)).map((asset) =>
        Array.from(asset.bytes).join(),
      ),
    ),
  );
  return {
    notes: sorted(notes).map(({ id, path, source, kind }) => ({
      id,
      path,
      source,
      kind,
    })),
    attachments: attachments.flat().toSorted(),
    folders: folders.toSorted(),
    trash: sorted(await runtime.trash()).map(({ path }) => path),
  };
}
/** The history a note keeps on this browser: it never leaves the device, so a migration must leave it alone. */
const historyOf = async (runtime: NoteRuntime, id: string) =>
  (await runtime.history(id)).map(({ source }) => source);
const originOf = async (runtime: NoteRuntime, path: string) =>
  (await runtime.list()).find((note) => note.path === path)?.origin;
async function trust(runtime: NoteRuntime, path: string) {
  const note = (await runtime.list()).find((value) => value.path === path);
  await runtime.trust([{ id: note?.id ?? "", digest: note?.digest ?? "" }]);
}
/** A v1 recovery file as the person downloaded it. */
async function exportedRecovery(runtime: NoteRuntime): Promise<RecoveryFile> {
  const exported = await runtime.recovery?.();
  if (!exported) throw new Error("No recovery file");
  return JSON.parse(await exported.text());
}

const LARGE = "A note big enough to live in its own blobs.\n".repeat(2000);
/** A vault as the previous release left it: v2 access, every kind of item, history, and one edit that never reached the PDS. */
async function productionVault(
  pds: ReturnType<typeof memoryPds>,
  b: Browser,
  writeJournal: boolean,
) {
  const { runtime } = await unlockVault(
    await b.port(writeJournal),
    { setup: true },
    false,
  );
  await runtime.sync?.();
  await runtime.createFolder("Empty");
  const plain = { id: "plain", path: "Plain.md", kind: "md" as const };
  await runtime.save({ ...plain, source: "# First" });
  await runtime.save({ ...plain, source: "# Second" });
  await runtime.save({ ...plain, source: "# Third" });
  await runtime.save({
    id: "deep",
    path: "Folder/Deep.md",
    kind: "md",
    source: "# In a folder",
  });
  await runtime.save({
    id: "large",
    path: "Large.md",
    kind: "md",
    source: LARGE,
  });
  await runtime.save({
    id: "chart",
    path: "Chart.mdx",
    kind: "mdx",
    source: "export const answer = 42\n\n# Chart",
  });
  const photo = {
    id: "photo",
    path: "Photo.md",
    kind: "md" as const,
    source: "# Photo",
  };
  await runtime.save(photo);
  const [attached] = await runtime.addAttachments(photo, [
    new File([new Uint8Array(4096).fill(7)], "photo.png", {
      type: "image/png",
    }),
  ]);
  await runtime.save({
    ...photo,
    source: `# Photo\n\n${attached?.markdown ?? ""}`,
  });
  await runtime.save({
    id: "gone",
    path: "Gone.md",
    kind: "md",
    source: "# Deleted",
  });
  await runtime.remove("gone");
  await runtime.sync?.();
  await runtime.save({
    id: "unsynced",
    path: "Unsynced.md",
    kind: "md",
    source: "# Never reached the PDS",
  });
  const held = await contents(runtime);
  const history = await historyOf(runtime, "plain");
  runtime.lock();
  const committed = pds.commits;
  expect(committed).toBeGreaterThan(0);
  return { held, history, committed };
}
async function rootOf(pds: Pds) {
  const record = pds.stored?.value;
  if (!record) throw new Error("Missing vault");
  const { key } = await unwrapAccessKey(
    { accessSalt: record.accessSalt, access: record.access },
    prf,
    passkey.id,
    owner,
  );
  const { metadata } = await readVerifiedVaultRoot(key, owner, record);
  key.fill(0);
  return metadata;
}

describe("a production v2 vault under the flipped release", () => {
  for (const seedJournal of [false, true])
    for (const writeJournal of [false, true])
      test(`migrates on its first passkey unlock, keeps everything, and opens normally after that (written with journal ${seedJournal}, flipped with journal ${writeJournal})`, async () => {
        const pds = memoryPds(owner);
        const { host, state } = flowId(listing(row(passkey.id)));
        const a = browser(pds, host);
        const before = await productionVault(pds, a, seedJournal);
        expect("version" in (await rootOf(pds))).toBe(false);
        expect(state.requests).toBe(0);

        // First unlock: signs one `migrate` listing only this passkey, in one write of the record alone.
        const blobs = pds.stored?.value.blobs;
        const uploaded = pds.uploads;
        const first = await unlockVault(await a.port(writeJournal), {}, true);
        expect(pds.commits).toBe(before.committed + 1);
        expect(pds.uploads).toBe(uploaded);
        expect(pds.stored?.value.blobs).toEqual(blobs);
        const admin = await passkeyAdmin(prf, passkey.id, owner);
        const signed = await rootOf(pds);
        if (!("version" in signed)) throw new Error("Expected signed access");
        expect(signed.statement).toMatchObject({
          kind: "migrate",
          signer: admin.recipient.id,
          sequence: 1,
        });
        expect(signed.recipients).toEqual([admin.recipient]);
        const pin = await a.checkpoint();
        expect(await a.trust()).toBe("created");
        expect(pin?.pinned?.admins).toHaveLength(1);
        expect(first.runtime.access?.()).toMatchObject({ canChange: true });

        // Nothing lost: notes, folders, trash, attachments and history, and the unsynced edit reaches the PDS.
        expect(await contents(first.runtime)).toEqual(before.held);
        expect(await historyOf(first.runtime, "plain")).toEqual(before.history);
        await first.runtime.sync?.();
        expect(await contents(first.runtime)).toEqual(before.held);
        expect(await historyOf(first.runtime, "plain")).toEqual(before.history);

        // The person's MDX waits for their word, once.
        expect(await originOf(first.runtime, "Chart.mdx")).toEqual({
          runs: false,
          author: "Not signed",
        });
        expect(first.runtime.canTrust()).toBe(true);
        await trust(first.runtime, "Chart.mdx");
        await first.runtime.sync?.();
        expect(await originOf(first.runtime, "Chart.mdx")).toEqual({
          runs: true,
          author: "Signed by a passkey",
        });
        first.runtime.lock();

        // Second unlock: no new statement, no ask, no write, and the same pin.
        const committed = pds.commits;
        const second = await unlockVault(await a.port(writeJournal), {}, true);
        await second.runtime.sync?.();
        expect(pds.commits).toBe(committed);
        expect((await a.checkpoint())?.pinned).toEqual(pin?.pinned);
        expect(await contents(second.runtime)).toEqual(before.held);
        expect(await historyOf(second.runtime, "plain")).toEqual(
          before.history,
        );
        expect(await originOf(second.runtime, "Chart.mdx")).toEqual({
          runs: true,
          author: "Signed by a passkey",
        });
        second.runtime.lock();

        // A fresh browser gets it all from the PDS, trusts the statement on first use, and writes nothing.
        const fresh = browser(pds, host);
        const other = await unlockVault(
          await fresh.port(writeJournal),
          {},
          true,
        );
        await other.runtime.sync?.();
        expect(await contents(other.runtime)).toEqual(before.held);
        expect(await originOf(other.runtime, "Chart.mdx")).toEqual({
          runs: true,
          author: "Signed by a passkey",
        });
        expect(other.runtime.access?.()).toMatchObject({ canChange: false });
        expect(await fresh.trust()).toBe("tofu");
        other.runtime.lock();
        expect(pds.commits).toBe(committed);
      });

  for (const writeJournal of [false, true])
    test(`a browser that used the vault before another one migrated it opens without writing, and a stale tab's edit still syncs (journal ${writeJournal})`, async () => {
      const pds = memoryPds(owner);
      const { host } = flowId(listing(row(passkey.id)));
      const a = browser(pds, host);
      const { held } = await productionVault(pds, a, writeJournal);
      const synced = await unlockVault(await a.port(writeJournal), {}, false);
      await synced.runtime.sync?.();
      synced.runtime.lock();
      const b = browser(pds, host);
      const stale = await unlockVault(await b.port(writeJournal), {}, false);
      await stale.runtime.sync?.();
      expect((await b.checkpoint())?.pinned).toBeNull();

      const migrated = await unlockVault(await a.port(writeJournal), {}, true);
      await migrated.runtime.sync?.();
      expect(await contents(migrated.runtime)).toEqual(held);

      await stale.runtime.save({
        id: "late",
        path: "Late.md",
        kind: "md",
        source: "# From the stale tab",
      });
      await stale.runtime.sync?.();
      stale.runtime.lock();
      const root = await rootOf(pds);
      if (!("version" in root))
        throw new Error("Stale tab downgraded the root");
      expect(root.statement.kind).toBe("migrate");
      await migrated.runtime.sync?.();
      const after = await contents(migrated.runtime);
      expect(after.notes.map(({ path }) => path)).toContain("Late.md");
      expect(after.notes.filter(({ id }) => id !== "late")).toEqual(held.notes);
      migrated.runtime.lock();

      const committed = pds.commits;
      const reopened = await unlockVault(await b.port(writeJournal), {}, true);
      await reopened.runtime.sync?.();
      expect(await contents(reopened.runtime)).toEqual(after);
      expect(pds.commits).toBe(committed);
      reopened.runtime.lock();
    });
});

/** A v2 vault listing this passkey and `others`, as a v1 `add` recovery leaves one, seeded directly so each test starts from one write. */
async function multiEntryVault(pds: Pds, others = [OLD_ID]) {
  const key = await createVaultKey();
  const vault = crypto.randomUUID();
  const context = { did: owner, vault };
  const recipients = await Promise.all(
    [passkey.id, ...others].map((id, index) =>
      createAccessRecipient(
        index === 0 ? prf : new Uint8Array(32).fill(index),
        id,
        owner,
      ),
    ),
  );
  const header = await createAccessHeader(
    key,
    recipients.map((recipient) => recipient.publicKey),
    owner,
  );
  const access = {
    header,
    metadata: {
      recipients,
      accessCommitment: await accessHeaderCommitment(header),
    },
  };
  const writer = new AuthVaultTransport(pds.rpc, {
    key,
    did: owner,
    vault,
    epoch: 1,
    access,
    pinned: null,
  });
  const entries = [
    await noteEntry(
      key,
      context,
      null,
      { id: "kept", name: "Kept.md" },
      "# Kept",
    ),
  ];
  await writer.writeSnapshot(entries, null);
  writer.stop();
  const recovery = await createRecoveryFile(key, {
    ...context,
    epoch: 1,
    item: "recovery",
    revision: "vault-key-v1",
    assets: [],
  });
  return { key, vault, context, access, entries, recovery };
}
/** The browser opens the vault as the previous release left it, so it holds a checkpoint for it from before signed access. */
async function usedBefore(b: Browser) {
  (await unlockVault(await b.port(), {}, false)).runtime.lock();
}
const failure = (result: Promise<UnlockResult>) =>
  result.then(
    ({ runtime }) => {
      runtime.lock();
      throw new Error("Expected the unlock to stop");
    },
    (error) => error,
  );

describe("no answer from Flow ID locks anyone out for good", () => {
  const answered: [string, () => Response][] = [
    [
      "a list that omits this passkey (a key row the route leaves out)",
      listing(row("c29tZW9uZQ")),
    ],
    ["an empty list", listing()],
    [
      "a credential id outside base64url",
      () => Response.json({ userId, passkeys: [row("not base64url")] }),
    ],
    [
      "more than 100 rows",
      () =>
        Response.json({
          userId,
          passkeys: Array.from({ length: 101 }, () => row(passkey.id)),
        }),
    ],
    ["a body that isn't JSON", () => new Response("<html>")],
    [
      "a refusal",
      () => Response.json({ code: "UNAUTHORIZED" }, { status: 401 }),
    ],
    ["a missing route", () => new Response("gone", { status: 404 })],
    [
      "another account's list",
      () => Response.json({ userId: "other", passkeys: [row(passkey.id)] }),
    ],
  ];
  for (const [name, answer] of answered) {
    test(`${name}: unlock asks, then migrates alone, and the next unlock just opens`, async () => {
      const pds = memoryPds(owner);
      const { host } = flowId(answer);
      await multiEntryVault(pds);
      const a = browser(pds, host);
      const asked = await failure(unlockVault(await a.port(), {}, true));
      expect(asked).toBeInstanceOf(MigrationConfirmationError);
      expect(asked.losing).toBe(
        "the other passkey listed on your notepad loses access",
      );
      expect(asked.message).toBe("Confirm who keeps access.");
      expect(pds.commits).toBe(1);
      expect(await a.checkpoint()).toBeUndefined();
      const { runtime } = await unlockVault(
        await a.port(),
        { confirmMigration: asked.confirmation },
        true,
      );
      expect(pds.commits).toBe(2);
      const admin = await passkeyAdmin(prf, passkey.id, owner);
      expect(recipientsOf(await rootOf(pds))).toEqual([admin.recipient]);
      expect(await a.trust()).toBe("tofu");
      await runtime.sync?.();
      expect((await runtime.list()).map(({ path }) => path)).toEqual([
        "Kept.md",
      ]);
      runtime.lock();
      const committed = pds.commits;
      const next = await unlockVault(await a.port(), {}, true);
      next.runtime.lock();
      expect(pds.commits).toBe(committed);
    });

    test(`${name}: a v1 recovery asks, then starts over, and keeps the notes`, async () => {
      const pds = memoryPds(owner);
      const { host } = flowId(answer);
      const { recovery } = await multiEntryVault(pds);
      const a = browser(pds, host);
      expect(
        await failure(unlockVault(await a.port(), { recovery }, true)),
      ).toBeInstanceOf(RecoveryConfirmationError);
      expect(pds.commits).toBe(1);
      const { runtime } = await unlockVault(
        await a.port(),
        { recovery, confirmRecovery: true },
        true,
      );
      await runtime.sync?.();
      const [kept] = await runtime.list();
      expect(kept?.source).toBe("# Kept");
      expect(await a.trust()).toBe("created");
      runtime.lock();
    });
  }

  const noAnswer: [string, () => Response][] = [
    ["a 500", () => Response.json({ code: "INTERNAL" }, { status: 500 })],
    ["a proxy's 502", () => new Response("<html>", { status: 502 })],
    ["a 503", () => new Response(null, { status: 503 })],
    [
      "a rate limit",
      () => Response.json({ code: "RATE_LIMITED" }, { status: 429 }),
    ],
  ];
  for (const [name, answer] of noAnswer)
    test(`${name} stays a retryable refusal that writes nothing, and the retry goes through`, async () => {
      const pds = memoryPds(owner);
      const { host, state } = flowId(answer);
      const { recovery } = await multiEntryVault(pds);
      const a = browser(pds, host);
      for (const options of [
        {},
        { recovery },
        { recovery, confirmRecovery: true },
      ])
        expect(
          await failure(unlockVault(await a.port(), options, true)),
        ).toBeInstanceOf(PasskeysUnavailableError);
      expect(pds.commits).toBe(1);
      expect(await a.checkpoint()).toBeUndefined();
      state.answer = listing(row(passkey.id));
      const { runtime } = await unlockVault(await a.port(), {}, true);
      runtime.lock();
      expect(pds.commits).toBe(2);
    });

  test("a failed request stays a retryable refusal", async () => {
    const pds = memoryPds(owner);
    const { host } = flowId(listing());
    servers.pop()?.stop(true);
    const { recovery } = await multiEntryVault(pds);
    const a = browser(pds, host);
    for (const options of [{}, { recovery }])
      expect(
        await failure(unlockVault(await a.port(), options, true)),
      ).toBeInstanceOf(PasskeysUnavailableError);
    expect(pds.commits).toBe(1);
  });

  test("an entry Flow ID doesn't list is dropped without asking when it names this passkey", async () => {
    const pds = memoryPds(owner);
    const { host, state } = flowId(listing(row(passkey.id)));
    await multiEntryVault(pds);
    const a = browser(pds, host);
    const { runtime } = await unlockVault(await a.port(), {}, true);
    runtime.lock();
    expect(state.requests).toBe(1);
    expect(pds.commits).toBe(2);
  });

  test("a vault that lists only this passkey never asks Flow ID", async () => {
    const pds = memoryPds(owner);
    const { host, state } = flowId(() => new Response(null, { status: 503 }));
    await multiEntryVault(pds, []);
    const a = browser(pds, host);
    (await unlockVault(await a.port(), {}, true)).runtime.lock();
    expect(state.requests).toBe(0);
    expect(pds.commits).toBe(2);
  });
});

describe("a confirmation holds only for what the person was shown", () => {
  test("names a passkey by when it was added, never by its credential id", async () => {
    const pds = memoryPds(owner);
    const added = "2026-03-02T12:00:00.000Z";
    const { host, state } = flowId(
      listing(row(passkey.id), row(OLD_ID, added)),
    );
    await multiEntryVault(pds);
    const a = browser(pds, host);
    const one = await failure(unlockVault(await a.port(), {}, true));
    expect(one.losing).toMatch(/^the passkey added on .*2026 loses access$/);
    expect(one.losing).not.toContain(OLD_ID.slice(0, 4));

    const two = memoryPds(owner);
    state.answer = listing(
      row(passkey.id),
      row(OLD_ID, added),
      row("dGhpcmQ", "2026-04-02T12:00:00.000Z"),
    );
    await multiEntryVault(two, [OLD_ID, "dGhpcmQ"]);
    const b = browser(two, host);
    const both = await failure(unlockVault(await b.port(), {}, true));
    expect(both.losing).toMatch(
      /^the passkeys added on .*2026 and .*2026 lose access$/,
    );

    // A row it can't place by date falls back on the count, rather than naming half of them.
    state.answer = listing(row(OLD_ID, added));
    const c = browser(two, host);
    const unplaced = await failure(unlockVault(await c.port(), {}, true));
    expect(unplaced.losing).toBe(
      "the 2 other passkeys listed on your notepad lose access",
    );
  });

  test("a root that moved since the ask asks again, for the root now there", async () => {
    const pds = memoryPds(owner);
    const { host } = flowId(listing(row(passkey.id), row(OLD_ID)));
    const { key, vault, access, entries } = await multiEntryVault(pds);
    const a = browser(pds, host);
    const asked = await failure(unlockVault(await a.port(), {}, true));
    const writer = new AuthVaultTransport(pds.rpc, {
      key,
      did: owner,
      vault,
      epoch: 1,
      access,
      pinned: null,
    });
    await writer.writeSnapshot(entries, pds.stored?.cid ?? null);
    writer.stop();
    const moved = pds.commits;
    const again = await failure(
      unlockVault(
        await a.port(),
        { confirmMigration: asked.confirmation },
        true,
      ),
    );
    expect(again).toBeInstanceOf(MigrationConfirmationError);
    expect(again.confirmation.cid).toBe(pds.stored?.cid);
    expect(again.confirmation.cid).not.toBe(asked.confirmation.cid);
    expect(pds.commits).toBe(moved);
    const { runtime } = await unlockVault(
      await a.port(),
      { confirmMigration: again.confirmation },
      true,
    );
    runtime.lock();
    expect(pds.commits).toBe(moved + 1);
  });

  test("a passkey added to the root after the ask is never dropped on the earlier confirmation", async () => {
    const pds = memoryPds(owner);
    const third = "dGhpcmQ";
    const { host } = flowId(listing(row(passkey.id), row(OLD_ID), row(third)));
    const { key, vault, context, entries } = await multiEntryVault(pds);
    const a = browser(pds, host);
    const asked = await failure(unlockVault(await a.port(), {}, true));
    expect(asked.confirmation.dropped).toHaveLength(1);
    const recipients = await Promise.all([
      createAccessRecipient(prf, passkey.id, owner),
      createAccessRecipient(new Uint8Array(32).fill(1), OLD_ID, owner),
      createAccessRecipient(new Uint8Array(32).fill(2), third, owner),
    ]);
    const header = await createAccessHeader(
      key,
      recipients.map((recipient) => recipient.publicKey),
      owner,
    );
    const writer = new AuthVaultTransport(pds.rpc, {
      key,
      did: owner,
      vault,
      epoch: 1,
      access: {
        header,
        metadata: {
          recipients,
          accessCommitment: await accessHeaderCommitment(header),
        },
      },
      pinned: null,
    });
    await writer.writeSnapshot(
      [
        ...entries,
        await noteEntry(
          key,
          context,
          null,
          { id: "more", name: "More.md" },
          "# More",
        ),
      ],
      pds.stored?.cid ?? null,
    );
    writer.stop();
    const again = await failure(
      unlockVault(
        await a.port(),
        { confirmMigration: asked.confirmation },
        true,
      ),
    );
    expect(again).toBeInstanceOf(MigrationConfirmationError);
    expect(again.confirmation.dropped).toHaveLength(2);
  });

  test("the same root with a different answer from Flow ID asks again", async () => {
    const pds = memoryPds(owner);
    const third = "dGhpcmQ";
    const { host, state } = flowId(listing(row(passkey.id), row(OLD_ID)));
    await multiEntryVault(pds, [OLD_ID, third]);
    const a = browser(pds, host);
    const asked = await failure(unlockVault(await a.port(), {}, true));
    expect(asked.confirmation.dropped).toHaveLength(1);
    state.answer = listing(row(passkey.id), row(OLD_ID), row(third));
    const again = await failure(
      unlockVault(
        await a.port(),
        { confirmMigration: asked.confirmation },
        true,
      ),
    );
    expect(again).toBeInstanceOf(MigrationConfirmationError);
    expect(again.confirmation.dropped).toHaveLength(2);
    expect(pds.commits).toBe(1);
  });
});

describe("a pin's trust", () => {
  test("survives what this release accepts: its own migration, and a change signed by a pinned admin", async () => {
    const pds = memoryPds(owner);
    const { host } = flowId(listing(row(passkey.id)));
    const { key, vault, entries } = await multiEntryVault(pds, []);
    const y = browser(pds, host);
    await usedBefore(y);
    const { runtime } = await unlockVault(await y.port(), {}, true);
    await runtime.sync?.();
    const admin = await passkeyAdmin(prf, passkey.id, owner);
    const device = await createSeedRecipient(
      new Uint8Array(32).fill(4),
      "device",
      "Laptop",
    );
    const access = await createAccess(
      key,
      { did: owner, vault, epoch: 1 },
      {
        kind: "change",
        sequence: 2,
        recipients: [admin.recipient, device],
        signer: admin,
      },
    );
    const writer = new AuthVaultTransport(pds.rpc, {
      key,
      did: owner,
      vault,
      epoch: 1,
      access,
      pinned: null,
    });
    await writer.writeSnapshot(entries, pds.stored?.cid ?? null);
    writer.stop();
    await runtime.sync?.();
    runtime.lock();
    expect((await y.checkpoint())?.pinned?.sequence).toBe(2);
    expect(await y.trust()).toBe("created");
    const reopened = await unlockVault(await y.port(), {}, true);
    expect(reopened.runtime.access?.()).toMatchObject({ canChange: true });
    reopened.runtime.lock();
  });

  test("never comes from a statement a key holder planted over the root", async () => {
    const pds = memoryPds(owner);
    const { host } = flowId(listing(row(passkey.id)));
    const { key, vault, entries } = await multiEntryVault(pds, []);
    const y = browser(pds, host);
    await usedBefore(y);
    (await unlockVault(await y.port(), {}, true)).runtime.lock();
    expect(await y.trust()).toBe("created");
    const admin = await passkeyAdmin(prf, passkey.id, owner);
    const planter = await passkeyAdmin(
      new Uint8Array(32).fill(3),
      "cGxhbnRlcg",
      owner,
    );
    const context = { did: owner, vault, epoch: 1 };
    const access = await createAccess(key, context, {
      kind: "migrate",
      sequence: 1,
      recipients: [admin.recipient, planter.recipient],
      signer: planter,
    });
    expect(await acceptAccess(access.metadata, context, null)).not.toBeNull();
    const writer = new AuthVaultTransport(pds.rpc, {
      key,
      ...context,
      access,
      pinned: null,
    });
    await writer.writeSnapshot(entries, pds.stored?.cid ?? null);
    writer.stop();
    // The pinned browser refuses it outright; it is no change any admin it trusts signed.
    await expect(unlockVault(await y.port(), {}, true)).rejects.toThrow(
      UNTRUSTED_ACCESS,
    );
    expect(await y.trust()).toBe("created");
  });
});

describe("a migration this browser didn't see finish", () => {
  /** The next PUT lands and its answer is lost; with `reread` false, so does the read that would have shown it. */
  function loseAnswer(pds: Pds, reread: boolean) {
    const records = pds.rpc.records.bind(pds.rpc);
    let lost = false;
    pds.rpc.records = async (operation) => {
      const result = await records(operation);
      if (lost) {
        pds.rpc.records = records;
        throw { code: "PDS_UNAVAILABLE", status: 502 };
      }
      if (operation.method === "put") {
        if (reread) pds.rpc.records = records;
        else lost = true;
        throw { code: "PDS_UNAVAILABLE", status: 502 };
      }
      return result;
    };
  }

  test("when the write's answer is lost, the retry records what it would have, and nothing more is written", async () => {
    const pds = memoryPds(owner);
    const { host } = flowId(listing(row(passkey.id)));
    const a = browser(pds, host);
    const { held } = await productionVault(pds, a, false);
    loseAnswer(pds, true);
    await expect(unlockVault(await a.port(), {}, true)).rejects.toBeInstanceOf(
      MigrationInterruptedError,
    );
    expect("version" in (await rootOf(pds))).toBe(true);
    expect((await a.checkpoint())?.pinned).toBeNull();
    const committed = pds.commits;
    const retry = await unlockVault(await a.port(), {}, true);
    expect(pds.commits).toBe(committed);
    expect(await a.trust()).toBe("created");
    expect(retry.runtime.access?.()).toMatchObject({ canChange: true });
    await retry.runtime.sync?.();
    expect(await contents(retry.runtime)).toEqual(held);
    retry.runtime.lock();
  });

  test("when even the re-read fails, the session opens closed, and the next unlock still records it", async () => {
    const pds = memoryPds(owner);
    const { host } = flowId(listing(row(passkey.id)));
    const a = browser(pds, host);
    await productionVault(pds, a, false);
    loseAnswer(pds, false);
    const stuck = await unlockVault(await a.port(), {}, true);
    expect(stuck.notice).toContain("Your notes are safe");
    await stuck.runtime.sync?.();
    expect((await a.checkpoint())?.pinned).toBeNull();
    stuck.runtime.lock();
    const next = await unlockVault(await a.port(), {}, true);
    expect(await a.trust()).toBe("created");
    next.runtime.lock();
  });

  test("another browser that held the vault follows this passkey's migration as its own", async () => {
    const pds = memoryPds(owner);
    const { host } = flowId(listing(row(passkey.id)));
    await multiEntryVault(pds, []);
    const a = browser(pds, host);
    const b = browser(pds, host);
    await usedBefore(a);
    await usedBefore(b);
    (await unlockVault(await a.port(), {}, true)).runtime.lock();
    const committed = pds.commits;
    (await unlockVault(await b.port(), {}, true)).runtime.lock();
    expect(pds.commits).toBe(committed);
    expect(await b.trust()).toBe("created");
  });

  test("a fresh browser reading the same statement stays on first use", async () => {
    const pds = memoryPds(owner);
    const { host } = flowId(listing(row(passkey.id)));
    await multiEntryVault(pds, []);
    const a = browser(pds, host);
    await usedBefore(a);
    (await unlockVault(await a.port(), {}, true)).runtime.lock();
    const fresh = browser(pds, host);
    (await unlockVault(await fresh.port(), {}, true)).runtime.lock();
    expect(await fresh.trust()).toBe("tofu");
  });

  test("anything but this passkey's own lone migrate stays first use", async () => {
    const pds = memoryPds(owner);
    const { host } = flowId(listing(row(passkey.id)));
    const { key, vault, entries } = await multiEntryVault(pds, []);
    const y = browser(pds, host);
    await usedBefore(y);
    const admin = await passkeyAdmin(prf, passkey.id, owner);
    const other = await passkeyAdmin(
      new Uint8Array(32).fill(3),
      "b3RoZXI",
      owner,
    );
    const context = { did: owner, vault, epoch: 1 };
    const statements = [
      // Signed by someone else, listing this passkey.
      {
        kind: "migrate" as const,
        sequence: 1,
        recipients: [admin.recipient, other.recipient],
        signer: other,
      },
      // This passkey's, but listing someone else too.
      {
        kind: "migrate" as const,
        sequence: 1,
        recipients: [admin.recipient, other.recipient],
        signer: admin,
      },
      // This passkey's and alone, but not a migration from unsigned.
      {
        kind: "change" as const,
        sequence: 2,
        recipients: [admin.recipient],
        signer: admin,
      },
    ];
    for (const statement of statements) {
      const access = await createAccess(key, context, statement);
      const writer = new AuthVaultTransport(pds.rpc, {
        key,
        ...context,
        access,
        pinned: null,
      });
      await writer.writeSnapshot(entries, pds.stored?.cid ?? null);
      writer.stop();
      const opened = await unlockVault(await y.port(), {}, true);
      expect(await y.trust()).toBe("tofu");
      opened.runtime.lock();
      await y.reset(vault);
    }
  });
});

describe("a migration write that keeps failing", () => {
  async function stuckVault(pds: ReturnType<typeof memoryPds>, a: Browser) {
    const before = await productionVault(pds, a, false);
    const synced = await unlockVault(await a.port(), {}, false);
    await synced.runtime.sync?.();
    await synced.runtime.lock();
    return before;
  }
  /** The PDS refuses to write the record, while still reading it; returns how to let it through again. */
  function refusePuts(pds: Pds, code = "QUOTA", status = 413) {
    const records = pds.rpc.records.bind(pds.rpc);
    pds.rpc.records = async (operation) => {
      if (operation.method === "put") throw { code, status };
      return records(operation);
    };
    return () => {
      pds.rpc.records = records;
    };
  }
  /** Opens through the failure, and proves the session is as promised: readable, running nothing, however it syncs. */
  async function opensClosed(pds: Pds, a: Browser) {
    const saved = await a.checkpoint();
    const stuck = await unlockVault(await a.port(), {}, true);
    expect(stuck.notice).toContain("Your notes are safe");
    expect("version" in (await rootOf(pds))).toBe(false);
    const closed = { runs: false, author: "Not signed" };
    expect(await originOf(stuck.runtime, "Chart.mdx")).toEqual(closed);
    await stuck.runtime.sync?.();
    expect(await originOf(stuck.runtime, "Chart.mdx")).toEqual(closed);
    expect(stuck.runtime.canTrust()).toBe(false);
    await expect(trust(stuck.runtime, "Chart.mdx")).rejects.toThrow();
    expect(await a.checkpoint()).toEqual(saved);
    return stuck;
  }

  test("a PDS that refuses the write doesn't stop the person reading, or editing; the next unlock migrates once it can", async () => {
    const pds = memoryPds(owner);
    const { host } = flowId(listing(row(passkey.id)));
    const a = browser(pds, host);
    const { held } = await stuckVault(pds, a);
    const letThrough = refusePuts(pds);
    const uploaded = pds.uploads;
    for (let attempt = 0; attempt < 2; attempt++) {
      const stuck = await opensClosed(pds, a);
      expect(await contents(stuck.runtime)).toEqual(held);
      stuck.runtime.lock();
    }
    // A failed attempt leaves nothing behind for the next one to pay for.
    expect(pds.uploads).toBe(uploaded);
    const edited = await unlockVault(await a.port(), {}, true);
    await edited.runtime.save({
      id: "plain",
      path: "Plain.md",
      kind: "md",
      source: "# Written while stuck",
    });
    const stillReadable = await contents(edited.runtime);
    edited.runtime.lock();

    letThrough();
    const healed = await unlockVault(await a.port(), {}, true);
    expect(healed.notice).toBeUndefined();
    expect("version" in (await rootOf(pds))).toBe(true);
    await healed.runtime.sync?.();
    expect(await contents(healed.runtime)).toEqual(stillReadable);
    healed.runtime.lock();
    expect(await a.trust()).toBe("created");
  });

  test("a fresh browser opens too, but saves no checkpoint that could later count as having held this vault", async () => {
    const pds = memoryPds(owner);
    const { host } = flowId(listing(row(passkey.id)));
    const a = browser(pds, host);
    const { held } = await stuckVault(pds, a);
    const fresh = browser(pds, host);
    refusePuts(pds);
    const stuck = await unlockVault(await fresh.port(), {}, true);
    expect(stuck.notice).toContain("Your notes are safe");
    await stuck.runtime.sync?.();
    expect((await contents(stuck.runtime)).notes).toEqual(held.notes);
    stuck.runtime.lock();
    expect(await fresh.checkpoint()).toBeUndefined();
  });

  test("a session opened this way keeps a signed statement it reads to itself, so the next unlock judges it", async () => {
    const pds = memoryPds(owner);
    const { host } = flowId(listing(row(passkey.id)));
    const a = browser(pds, host);
    await stuckVault(pds, a);
    const records = pds.rpc.records.bind(pds.rpc);
    const stuckAt = pds.commits;
    // The write lands, its answer is lost, and the re-read fails too, so this unlock can't tell.
    let lost = 2;
    pds.rpc.records = async (operation) => {
      const result = await records(operation);
      if (lost === 2 && operation.method === "put") lost--;
      else if (lost === 1) {
        lost--;
        throw { code: "PDS_UNAVAILABLE", status: 502 };
      }
      if (lost === 1) throw { code: "PDS_UNAVAILABLE", status: 502 };
      return result;
    };
    const saved = await a.checkpoint();
    const stuck = await unlockVault(await a.port(), {}, true);
    expect(stuck.notice).toContain("Your notes are safe");
    expect(pds.commits).toBe(stuckAt + 1);
    await stuck.runtime.sync?.();
    const chart = await originOf(stuck.runtime, "Chart.mdx");
    expect(chart).toEqual({ runs: false, author: "Not signed" });
    stuck.runtime.lock();
    expect(await a.checkpoint()).toEqual(saved);
  });

  test("a conflict isn't stuck: the root moved, so it says so, and the retry migrates once", async () => {
    const pds = memoryPds(owner);
    const { host } = flowId(listing(row(passkey.id)));
    const a = browser(pds, host);
    await stuckVault(pds, a);
    const other = await unlockVault(await a.port(), {}, false);
    // The race below must run its own sync, not join the one the runtime starts when it opens.
    await other.runtime.sync?.();
    const records = pds.rpc.records.bind(pds.rpc);
    let raced = false;
    pds.rpc.records = async (operation) => {
      if (operation.method === "put" && !raced) {
        raced = true;
        await other.runtime.save({
          id: "race",
          path: "Race.md",
          kind: "md",
          source: "# Raced",
        });
        await other.runtime.sync?.();
      }
      return records(operation);
    };
    await expect(unlockVault(await a.port(), {}, true)).rejects.toBeInstanceOf(
      MigrationInterruptedError,
    );
    expect("version" in (await rootOf(pds))).toBe(false);
    other.runtime.lock();
    const retried = await unlockVault(await a.port(), {}, true);
    expect(retried.notice).toBeUndefined();
    retried.runtime.lock();
    expect("version" in (await rootOf(pds))).toBe(true);
  });
});

/** A v2-format vault too large to rewrite beside itself on the managed PDS, as the release before journaling left it. */
async function vaultAt64(pds: ReturnType<typeof managedPds>, a: Browser) {
  const created = await unlockVault(
    await a.port(false),
    { setup: true },
    false,
  );
  await created.runtime.sync?.();
  const big = (name: string, bytes: number) =>
    new File(["x".repeat(bytes)], name);
  await created.runtime.import([
    big("Big-1.md", 30_000_000),
    big("Big-2.md", 30_000_000),
    big("Big-3.md", 30_000_000),
    big("Big-4.md", 10_000_000),
  ]);
  await created.runtime.save({
    id: "chart",
    path: "Chart.mdx",
    kind: "mdx",
    source: "# Chart",
  });
  await created.runtime.sync?.();
  created.runtime.lock();
  expect(pds.stored?.value.blobs).toHaveLength(64);
}
/**
 * The connected passkey lists a new v2 recovery file under the same key, as
 * an admin's access change does: a `change` it signs, published as a new
 * root over the same chunks.
 */
async function listRecovery(port: UnlockPort) {
  const remote = await port.readHeader();
  if (!remote) throw new Error("Missing vault");
  const { key } = await unwrapAccessKey(
    { accessSalt: remote.header.accessSalt, access: remote.header.access },
    prf,
    passkey.id,
    owner,
  );
  const admin = await passkeyAdmin(prf, passkey.id, owner);
  const verified = await verifyHeader(
    key,
    owner,
    remote.header,
    refOf(admin.recipient),
    await port.checkpoint(),
    { unlocker: admin.recipient },
  );
  const { metadata } = verified.access;
  if (!verified.pinned || !("version" in metadata))
    throw new Error("Expected signed access");
  const { seed, file } = await createRecoverySeed(owner, verified.vault);
  const recipient = await createSeedRecipient(seed, "recovery");
  seed.fill(0);
  const state = await signedState(
    key,
    { did: owner, vault: verified.vault, epoch: verified.epoch },
    {
      kind: "change",
      sequence: nextSequence(metadata, verified.pinned),
      recipients: [...metadata.recipients, recipient],
      signer: admin,
    },
    verified.trust,
  );
  await port.publish(key, state, remote.cid, "root");
  key.fill(0);
  port.dispose?.();
  return file;
}

describe("an access change that keeps the key moves no chunk", () => {
  test("listing a recovery file at 64 blobs uploads nothing and leaves no orphans, and the file then adds a passkey the same way", async () => {
    const pds = managedPds(owner);
    const { host } = flowId(listing(row(passkey.id)));
    const a = browser(pds, host);
    await vaultAt64(pds, a);
    const opened = await unlockVault(await a.port(), {}, true);
    expect(opened.runtime.access?.()).toMatchObject({ canChange: true });
    opened.runtime.lock();
    const blobs = pds.stored?.value.blobs;
    const uploaded = pds.uploads;
    let downloads = 0;
    const download = pds.rpc.download.bind(pds.rpc);
    pds.rpc.download = (cid) => {
      downloads++;
      return download(cid);
    };

    const file = await listRecovery(await a.port());
    expect(downloads).toBe(0);
    expect(pds.uploads).toBe(uploaded);
    expect(pds.count("orphan")).toBe(0);
    expect(pds.stored?.value.blobs).toEqual(blobs);
    const root = await rootOf(pds);
    if (!("version" in root)) throw new Error("Expected signed access");
    expect(root.statement.kind).toBe("change");
    expect(root.recipients.map(({ kind }) => kind).toSorted()).toEqual([
      "passkey",
      "recovery",
    ]);
    const added = await unlockVault(await a.port(), {}, true);
    expect(
      added.runtime
        .access?.()
        ?.recipients.map(({ kind }) => kind)
        .toSorted(),
    ).toEqual(["passkey", "recovery"]);
    added.runtime.lock();

    // The file adds a passkey on this browser under the same key, the same way.
    a.connect(newPasskey);
    const recovered = await unlockVault(
      await a.port(),
      { recovery: file },
      true,
    );
    expect(pds.uploads).toBe(uploaded);
    expect(pds.count("orphan")).toBe(0);
    expect(pds.stored?.value.blobs).toEqual(blobs);
    await recovered.runtime.sync?.();
    expect(
      (await recovered.runtime.list()).map(({ path }) => path).toSorted(),
    ).toEqual(["Big-1.md", "Big-2.md", "Big-3.md", "Big-4.md", "Chart.mdx"]);
    recovered.runtime.lock();
  }, 300_000);
});

describe("a migration moves no chunk", () => {
  test("a chunk the PDS can no longer serve doesn't stand in its way", async () => {
    const pds = memoryPds(owner);
    const { host } = flowId(listing(row(passkey.id)));
    const a = browser(pds, host);
    await productionVault(pds, a, false);
    const download = pds.rpc.download.bind(pds.rpc);
    pds.rpc.download = async () => {
      throw { code: "NOT_FOUND", status: 404 };
    };
    const opened = await unlockVault(await a.port(), {}, true);
    expect(opened.notice).toBeUndefined();
    expect("version" in (await rootOf(pds))).toBe(true);
    opened.runtime.lock();
    pds.rpc.download = download;
  });

  test("a root that moved after unlock read it is a conflict, and writes nothing", async () => {
    const pds = memoryPds(owner);
    const { host } = flowId(listing(row(passkey.id)));
    const a = browser(pds, host);
    await productionVault(pds, a, false);
    const port = await a.port();
    const records = pds.rpc.records.bind(pds.rpc);
    let reads = 0;
    pds.rpc.records = async (operation) => {
      // The port's first read is the unlock's; the next is the one the migration checks against.
      if (operation.method === "read" && ++reads === 2) {
        const stale = await unlockVault(await a.port(), {}, false);
        await stale.runtime.save({
          id: "race",
          path: "Race.md",
          kind: "md",
          source: "# Raced",
        });
        pds.rpc.records = records;
        await stale.runtime.sync?.();
        stale.runtime.lock();
        pds.rpc.records = records;
      }
      return records(operation);
    };
    const committed = pds.commits;
    await expect(unlockVault(port, {}, true)).rejects.toBeInstanceOf(
      MigrationInterruptedError,
    );
    expect(pds.commits).toBe(committed + 1);
    expect("version" in (await rootOf(pds))).toBe(false);
    (await unlockVault(await a.port(), {}, true)).runtime.lock();
    expect("version" in (await rootOf(pds))).toBe(true);
  });

  test("a v1 recovery that migrates moves none either", async () => {
    const pds = memoryPds(owner);
    const { host } = flowId(listing(row(passkey.id)));
    const a = browser(pds, host);
    await productionVault(pds, a, false);
    const seeded = await unlockVault(await a.port(), {}, false);
    await seeded.runtime.sync?.();
    const recovery = await exportedRecovery(seeded.runtime);
    seeded.runtime.lock();
    const uploaded = pds.uploads;
    const blobs = pds.stored?.value.blobs;
    const recovered = await unlockVault(
      await browser(pds, host).port(),
      { recovery },
      true,
    );
    recovered.runtime.lock();
    expect(pds.uploads).toBe(uploaded);
    expect(pds.stored?.value.blobs).toEqual(blobs);
    expect("version" in (await rootOf(pds))).toBe(true);
  });

  test("a vault too large to rewrite beside itself takes signed access with no uploads, stays whole, and a delete then lands", async () => {
    const pds = managedPds(owner);
    const { host } = flowId(listing(row(passkey.id)));
    const a = browser(pds, host);
    await vaultAt64(pds, a);
    const record = pds.stored;
    if (!record) throw new Error("Missing vault");
    const uploaded = pds.uploads;
    let downloads = 0;
    const download = pds.rpc.download.bind(pds.rpc);
    pds.rpc.download = (cid) => {
      downloads++;
      return download(cid);
    };

    const opened = await unlockVault(await a.port(), {}, true);
    expect(opened.notice).toBeUndefined();
    expect(pds.uploads).toBe(uploaded);
    expect(downloads).toBe(0);
    expect(pds.count("orphan")).toBe(0);
    expect(pds.stored?.value.blobs).toEqual(record.value.blobs);
    const root = await rootOf(pds);
    if (!("version" in root)) throw new Error("Expected signed access");
    expect(root.statement.kind).toBe("migrate");
    expect(await a.trust()).toBe("created");

    // Every note reads back from the same chunks, on a browser that holds nothing.
    await opened.runtime.sync?.();
    const notes = await opened.runtime.list();
    expect(notes.map(({ path }) => path).toSorted()).toEqual([
      "Big-1.md",
      "Big-2.md",
      "Big-3.md",
      "Big-4.md",
      "Chart.mdx",
    ]);

    // The person can delete their way out.
    const target = notes.find(({ path }) => path === "Big-1.md");
    if (!target) throw new Error("Missing note");
    await opened.runtime.remove(target.id);
    await opened.runtime.permanentRemove(target.id);
    await opened.runtime.sync?.();
    opened.runtime.lock();
    expect(pds.stored?.value.blobs.length).toBeLessThan(64);
    expect("version" in (await rootOf(pds))).toBe(true);
    const fresh = browser(pds, host);
    const other = await unlockVault(await fresh.port(), {}, true);
    await other.runtime.sync?.();
    expect((await other.runtime.list()).map(({ path }) => path)).not.toContain(
      "Big-1.md",
    );
    other.runtime.lock();
  }, 300_000);
});

describe("starting over with a v1 file", () => {
  /** The vault on a browser that migrated it and on one still unsigned, with a v1 file from before the flip. */
  async function twoBrowsers(pds: ReturnType<typeof memoryPds>, host: string) {
    const b = browser(pds, host);
    await productionVault(pds, b, false);
    const seeded = await unlockVault(await b.port(), {}, false);
    await seeded.runtime.sync?.();
    const recovery = await exportedRecovery(seeded.runtime);
    const held = await contents(seeded.runtime);
    seeded.runtime.lock();
    const y = browser(pds, host);
    const used = await unlockVault(await y.port(), {}, false);
    await used.runtime.sync?.();
    used.runtime.lock();
    (await unlockVault(await b.port(), {}, true)).runtime.lock();
    return { b, y, held, recovery };
  }

  test("by this passkey: its other browsers follow, keeping what they trust", async () => {
    const pds = memoryPds(owner);
    const { host } = flowId(listing(row(passkey.id)));
    const { b, y, held, recovery } = await twoBrowsers(pds, host);
    const z = browser(pds, host);
    const over = await unlockVault(
      await z.port(),
      { recovery, confirmRecovery: true },
      true,
    );
    await over.runtime.sync?.();
    over.runtime.lock();
    const root = await rootOf(pds);
    if (!("version" in root)) throw new Error("Expected signed access");
    expect(root.statement.kind).toBe("change");
    expect(root.epoch).toBe(2);
    const committed = pds.commits;
    for (const follower of [b, y]) {
      const opened = await unlockVault(await follower.port(), {}, true);
      await opened.runtime.sync?.();
      expect((await contents(opened.runtime)).notes).toEqual(held.notes);
      opened.runtime.lock();
    }
    expect(pds.commits).toBe(committed);
    expect(await b.trust()).toBe("created");
    expect(await y.trust()).toBe("tofu");
  });

  test("by another passkey: browsers pinned to this one refuse, say why, and clearing site data is the way back", async () => {
    const pds = memoryPds(owner);
    const { host } = flowId(listing(row(passkey.id)));
    const { b, held, recovery } = await twoBrowsers(pds, host);
    const z = browser(pds, host, newPasskey);
    const over = await unlockVault(
      await z.port(),
      { recovery, confirmRecovery: true },
      true,
    );
    over.runtime.lock();
    // The old passkey has no way in, and is told so.
    await expect(unlockVault(await b.port(), {}, true)).rejects.toBeInstanceOf(
      AccessRemovedError,
    );
    // Signed in with the new passkey, this browser's pin still refuses a change no admin it knows signed.
    b.connect(newPasskey);
    await expect(unlockVault(await b.port(), {}, true)).rejects.toThrow(
      UNTRUSTED_ACCESS,
    );
    expect(UNTRUSTED_CHANGE).toContain("clearing this site’s data");
    expect(UNTRUSTED_CHANGE).toContain("If you didn’t");
    // With no pin, as after clearing site data, it opens.
    const cleared = browser(pds, host, newPasskey);
    const opened = await unlockVault(await cleared.port(), {}, true);
    await opened.runtime.sync?.();
    expect((await contents(opened.runtime)).notes).toEqual(held.notes);
    opened.runtime.lock();
  });
});

describe("a browser that trusted the vault on first use", () => {
  test("a fresh browser's migration of a planted root is first use, so it can't carry the planter's key into a pinned browser", async () => {
    const pds = memoryPds(owner);
    const { host } = flowId(listing(row(passkey.id)));
    const x = browser(pds, host);
    await productionVault(pds, x, false);
    (await unlockVault(await x.port(), {}, true)).runtime.lock();
    expect(await x.trust()).toBe("created");
    const record = pds.stored;
    if (!record) throw new Error("Missing vault");
    const { manifest } = await readVerifiedVaultRoot(
      (
        await unwrapAccessKey(
          { accessSalt: record.value.accessSalt, access: record.value.access },
          prf,
          passkey.id,
          owner,
        )
      ).key,
      owner,
      record.value,
    );
    // Someone who knows the victim's public box key plants a v2 root under a key of their own.
    const planted = await createVaultKey();
    const admin = await passkeyAdmin(prf, passkey.id, owner);
    const own = {
      credentialHash: admin.recipient.id,
      publicKey: admin.recipient.boxPublicKey,
    };
    const header = await createAccessHeader(planted, [own.publicKey], owner);
    const planter = new AuthVaultTransport(pds.rpc, {
      key: planted,
      did: owner,
      vault: manifest.vault,
      epoch: manifest.epoch + 1,
      access: {
        header,
        metadata: {
          recipients: [own],
          accessCommitment: await accessHeaderCommitment(header),
        },
      },
      pinned: null,
    });
    await planter.writeSnapshot([], record.cid);
    planter.stop();
    await expect(unlockVault(await x.port(), {}, true)).rejects.toThrow(
      UNTRUSTED_ACCESS,
    );

    const y = browser(pds, host);
    const opened = await unlockVault(await y.port(), {}, true);
    expect(await y.trust()).toBe("tofu");
    expect(opened.runtime.access?.()).toMatchObject({ canChange: false });
    // It can still read, write and trust; only access is out of reach.
    await opened.runtime.save({
      id: "typed",
      path: "Typed.mdx",
      kind: "mdx",
      source: "# Typed here",
    });
    expect(await originOf(opened.runtime, "Typed.mdx")).toEqual({
      runs: true,
      author: "Signed by a passkey",
    });
    opened.runtime.lock();
    const seed = new Uint8Array(32).fill(6);
    const device = await createSeedRecipient(seed, "device", "Laptop");
    const secret = createLinkSecret();
    let approved = false;
    await expect(
      addVaultRecipient(await y.port(), {
        recipient: device,
        link: {
          secret,
          commitment: await linkCommitment(secret, {
            kind: "device",
            label: "Laptop",
            boxPublicKey: device.boxPublicKey,
            signPublicKey: device.signPublicKey ?? "",
          }),
          approve: async () => {
            approved = true;
            return "device";
          },
          revoke: async () => {},
        },
        confirm: async () => {},
      }),
    ).rejects.toThrow(UNTRUSTED_PIN);
    expect(approved).toBe(false);
    await expect(unlockVault(await x.port(), {}, true)).rejects.toThrow(
      UNTRUSTED_ACCESS,
    );
  });

  test("a browser that already held the vault keeps what it would have recorded", async () => {
    const pds = memoryPds(owner);
    const { host } = flowId(listing(row(passkey.id)));
    await multiEntryVault(pds, []);
    const y = browser(pds, host);
    await usedBefore(y);
    (await unlockVault(await y.port(), {}, true)).runtime.lock();
    expect(await y.trust()).toBe("created");
  });

  test("can export a recovery file, and that file brings every note back on a new passkey", async () => {
    const pds = memoryPds(owner);
    const { host } = flowId(listing(row(passkey.id)));
    const a = browser(pds, host);
    await productionVault(pds, a, false);
    (await unlockVault(await a.port(), {}, true)).runtime.lock();
    const fresh = browser(pds, host);
    const opened = await unlockVault(await fresh.port(), {}, true);
    expect(opened.runtime.access?.()).toMatchObject({ canChange: false });
    await opened.runtime.sync?.();
    const held = await contents(opened.runtime);
    const recovery = await exportedRecovery(opened.runtime);
    opened.runtime.lock();
    expect(recovery.version).toBe(1);
    const back = await unlockVault(
      await browser(pds, host, newPasskey).port(),
      { recovery, confirmRecovery: true },
      true,
    );
    await back.runtime.sync?.();
    expect(await contents(back.runtime)).toEqual(held);
    back.runtime.lock();
  });
});

describe("the release", () => {
  test("ships signed access, device linking and passkey enrollment on", () => {
    expect(WRITE_SIGNED_ACCESS).toBe(true);
    expect(LINK_DEVICES).toBe(true);
    expect(ENROLL_PASSKEYS).toBe(true);
  });

  test("by default migrates a v2 vault, and the next unlock writes nothing", async () => {
    const pds = memoryPds(owner);
    const { host } = flowId(listing(row(passkey.id)));
    const a = browser(pds, host);
    const { held } = await productionVault(pds, a, false);
    const { runtime } = await unlockVault(await a.port());
    expect(await contents(runtime)).toEqual(held);
    expect("version" in (await rootOf(pds))).toBe(true);
    runtime.lock();
    expect(await a.trust()).toBe("created");
    const committed = pds.commits;
    (await unlockVault(await a.port())).runtime.lock();
    expect(pds.commits).toBe(committed);
  });
});
