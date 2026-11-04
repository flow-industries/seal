import Dexie, { type ObservabilitySet, type Table } from "dexie";
import { z } from "zod";
import type { EntryAuthor } from "../crypto/authorship.ts";
import type { Envelope } from "../crypto/index.ts";
import { encodeBlob } from "../sync/vault-snapshot.ts";
export interface StoredRevision {
  id: string;
  envelope: Envelope;
  sequence: number;
  baseCid: string | null;
  revision: string;
  recordType?: "game.flow.note.item" | "game.flow.note.tombstone";
  encryptedBlobs?: Uint8Array[];
  chunkHashes?: string[];
  blobs?: import("../sync/records.ts").BlobRef[];
  localVersion?: string;
  author?: EntryAuthor;
}
export type ItemVersion = Pick<
  StoredRevision,
  "id" | "sequence" | "revision"
> & {
  localVersion: string;
};
const ITEM_VERSION_INDEX = "[id+sequence+revision+localVersion]";
const itemVersionKey = z.tuple([
  z.string(),
  z.number(),
  z.string(),
  z.string(),
]);
export interface PendingWrite extends StoredRevision {
  queuedAt: number;
  baseRevision?: RevisionProof & { cid: string };
}
type RevisionProof = Pick<
  StoredRevision,
  "revision" | "envelope" | "chunkHashes"
>;
function encryptedBase(value: RevisionProof, cid: string) {
  return {
    cid,
    revision: value.revision,
    envelope: { ...value.envelope },
    chunkHashes: value.chunkHashes?.slice(),
  };
}
interface HistoryRevision extends StoredRevision {
  historyId: string;
  order: number;
  retainedBytes: number;
}
interface HistoryState {
  id: "budget";
  bytes: number;
  order: number;
}
const HISTORY_BYTES = 20_000_000;
function encryptedBytes(entry: StoredRevision) {
  return (
    entry.envelope.ciphertext.length +
    (entry.encryptedBlobs ?? []).reduce((sum, blob) => sum + blob.byteLength, 0)
  );
}

/** Where a holder's local databases live, when not under the defaults. */
export interface VaultStorage {
  /**
   * Keeps holders that share an origin, such as two plugin vaults in one
   * app, from sharing one outbox: a linked device's recipient id. Passkey
   * and recovery sessions never set it, so their databases keep the names
   * browsers already hold.
   */
  namespace?: string;
  /** The IndexedDB to keep them in, instead of Dexie's default. */
  indexedDB?: { factory: IDBFactory; keyRange: typeof IDBKeyRange };
}
/** A write that would land on another row than the one it was planned on: read again, then retry. */
export class StaleWriteError extends Error {}
/**
 * Each epoch's ciphertext lives in its own database, so a session never reads
 * or publishes an envelope sealed under another epoch's key. Epoch 1 keeps the
 * name every vault had before rotation existed, and a `namespace` is appended
 * only for the holders that set one (`VaultStorage`). No part may hold `#`,
 * which sets the namespace apart for `deleteDeviceStorage` to match on.
 */
export function databaseName(
  owner: string,
  vault: string,
  epoch: number,
  namespace?: string,
): string {
  if ([owner, vault, namespace ?? ""].some((part) => part.includes("#")))
    throw new Error("Invalid vault database name");
  const name =
    epoch > 1
      ? `flow-note:${owner}:${vault}:${epoch}`
      : `flow-note:${owner}:${vault}`;
  return namespace ? `${name}#${namespace}` : name;
}
const dexieDependencies = (storage?: VaultStorage) =>
  storage?.indexedDB && {
    indexedDB: storage.indexedDB.factory,
    IDBKeyRange: storage.indexedDB.keyRange,
  };
async function databaseExists(
  owner: string,
  vault: string,
  epoch: number,
  storage?: VaultStorage,
): Promise<boolean> {
  const name = databaseName(owner, vault, epoch, storage?.namespace);
  const factory = storage?.indexedDB?.factory;
  if (!factory) return Dexie.exists(name);
  return (await factory.databases()).some((info) => info.name === name);
}
/** Names of the vault databases in `storage`'s IndexedDB, or Dexie's default one. */
export async function vaultDatabaseNames(
  storage?: VaultStorage,
): Promise<string[]> {
  const factory = storage?.indexedDB?.factory;
  const names = factory
    ? (await factory.databases()).flatMap((info) =>
        info.name ? [info.name] : [],
      )
    : await Dexie.getDatabaseNames();
  return names.filter((name) => name.startsWith("flow-note:"));
}
/** Deletes one vault database by name from `storage`'s IndexedDB, or Dexie's default one. */
export async function deleteVaultDatabase(
  name: string,
  storage?: VaultStorage,
): Promise<void> {
  const dependencies = dexieDependencies(storage);
  if (dependencies) await new Dexie(name, dependencies).delete();
  else await Dexie.delete(name);
}
/**
 * Clears an earlier epoch's database once nothing in it waits to sync, and
 * returns how many edits still do. The check and the clear share one
 * transaction, so an edit another tab queues meanwhile is never cleared. One
 * with pending edits is kept whole: they are sealed under a key this session
 * no longer holds, and clearing them would lose them.
 */
export async function retireVaultDatabase(
  owner: string,
  vault: string,
  epoch: number,
  storage?: VaultStorage,
): Promise<number> {
  if (!(await databaseExists(owner, vault, epoch, storage))) return 0;
  const database = new VaultDatabase(owner, vault, epoch, storage);
  try {
    return await database.transaction(
      "rw",
      [
        database.items,
        database.outbox,
        database.history,
        database.historyState,
      ],
      async () => {
        const pending = await database.outbox.count();
        if (pending) return pending;
        await Promise.all([
          database.items.clear(),
          database.history.clear(),
          database.historyState.clear(),
        ]);
        return 0;
      },
    );
  } finally {
    database.close();
  }
}
/** Local edits in one epoch's database that haven't reached the PDS yet. */
export async function pendingWrites(
  owner: string,
  vault: string,
  epoch: number,
  storage?: VaultStorage,
): Promise<number> {
  if (!(await databaseExists(owner, vault, epoch, storage))) return 0;
  const database = new VaultDatabase(owner, vault, epoch, storage);
  try {
    return await database.outbox.count();
  } finally {
    database.close();
  }
}
/** An earlier epoch's unsynced edits, still encrypted, as a JSON file to keep until they can be opened again. */
export async function strandedEdits(
  owner: string,
  vault: string,
  epoch: number,
  storage?: VaultStorage,
): Promise<Blob> {
  const database = new VaultDatabase(owner, vault, epoch, storage);
  try {
    const rows = await database.outbox.toArray();
    return new Blob(
      [
        JSON.stringify({
          format: "flow-note-unsynced",
          did: owner,
          vault,
          epoch,
          edits: rows.map((row) => ({
            id: row.id,
            revision: row.revision,
            recordType: row.recordType ?? "game.flow.note.item",
            envelope: row.envelope,
            chunkHashes: row.chunkHashes ?? [],
            encryptedBlobs: (row.encryptedBlobs ?? []).map(encodeBlob),
          })),
        }),
      ],
      { type: "application/json" },
    );
  } finally {
    database.close();
  }
}
/** One revision's exact ciphertext: its id, revision, item envelope and chunk hashes. */
export async function revisionDigest(entry: {
  id: string;
  revision: string;
  envelope: Envelope;
  chunkHashes?: readonly string[];
}): Promise<string> {
  const bytes = new TextEncoder().encode(
    JSON.stringify([
      entry.id,
      entry.revision,
      entry.envelope.version,
      entry.envelope.nonce,
      entry.envelope.ciphertext,
      entry.chunkHashes ?? [],
    ]),
  );
  return Array.from(
    new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)),
    (value) => value.toString(16).padStart(2, "0"),
  ).join("");
}

export class VaultDatabase extends Dexie {
  items!: Table<StoredRevision, string>;
  outbox!: Table<PendingWrite, string>;
  history!: Table<HistoryRevision, string>;
  historyState!: Table<HistoryState, string>;
  constructor(owner: string, vault: string, epoch = 1, storage?: VaultStorage) {
    super(
      databaseName(owner, vault, epoch, storage?.namespace),
      dexieDependencies(storage),
    );
    this.version(1).stores({
      items: "id",
      outbox: "id",
      history: "historyId,id,sequence",
    });
    this.version(2)
      .stores({
        items: "id",
        outbox: "id",
        history: "historyId,id,sequence,order,[id+sequence]",
        historyState: "id",
      })
      .upgrade(async (transaction) => {
        const history = transaction.table<HistoryRevision>("history");
        const entries = await history.toArray();
        // Old rows have no global timestamp; numeric sequence is a deterministic best-effort order.
        entries.sort(
          (a, b) =>
            a.sequence - b.sequence || a.historyId.localeCompare(b.historyId),
        );
        let bytes = 0;
        for (const [index, entry] of entries.entries()) {
          entry.order = index + 1;
          entry.retainedBytes = encryptedBytes(entry);
          bytes += entry.retainedBytes;
        }
        await history.bulkPut(entries);
        await transaction
          .table<HistoryState>("historyState")
          .put({ id: "budget", bytes, order: entries.length });
      });
    this.version(3)
      .stores({ items: `id,${ITEM_VERSION_INDEX}` })
      .upgrade((transaction) =>
        transaction
          .table<StoredRevision>("items")
          .toCollection()
          .modify((item) => {
            item.localVersion = crypto.randomUUID();
          }),
      );
    // Ciphertext can change without a new revision (repair), as can baseCid (acknowledgement).
    this.items.hook("creating", (_key, item) => {
      item.localVersion = crypto.randomUUID();
    });
    this.items.hook("updating", () => ({ localVersion: crypto.randomUUID() }));
  }
  async itemVersions(): Promise<ItemVersion[]> {
    const keys = await this.items.orderBy(ITEM_VERSION_INDEX).keys();
    if (keys.length !== (await this.items.count()))
      throw new Error("Incomplete item version index");
    return keys.map((key): ItemVersion => {
      const parsed = itemVersionKey.safeParse(key);
      if (!parsed.success) throw new Error("Invalid item version index");
      const [id, sequence, revision, localVersion] = parsed.data;
      return { id, sequence, revision, localVersion };
    });
  }
  /** A consistent encrypted snapshot that transfers payloads only for rows changed since the caller's last read. */
  async readItems(
    cached: ReadonlyMap<string, StoredRevision>,
  ): Promise<StoredRevision[]> {
    return this.transaction("r", this.items, async () => {
      const versions = await this.itemVersions();
      const changed = versions.filter(
        (item) => cached.get(item.id)?.localVersion !== item.localVersion,
      );
      const loaded = new Map(
        (await this.items.bulkGet(changed.map((item) => item.id))).flatMap(
          (item) => (item ? [[item.id, item] as const] : []),
        ),
      );
      return versions.map((version) => {
        const item = loaded.get(version.id) ?? cached.get(version.id);
        if (!item || item.localVersion !== version.localVersion)
          throw new Error("Inconsistent item snapshot");
        return item;
      });
    });
  }
  subscribe(table: "items" | "outbox", listener: () => void): () => void {
    const changed = (parts: ObservabilitySet) => {
      if (
        "all" in parts ||
        Object.keys(parts).some((part) =>
          part.startsWith(`idb://${this.name}/${table}/`),
        )
      )
        listener();
    };
    Dexie.on("storagemutated", changed);
    return () => Dexie.on("storagemutated").unsubscribe(changed);
  }
  async save(
    value: Omit<StoredRevision, "sequence">,
    expectedSequence: number | null,
    retainHistory = true,
    rebase?: { fromCid: string | null; revision: RevisionProof },
  ): Promise<StoredRevision> {
    return this.transaction(
      "rw",
      this.items,
      this.outbox,
      this.history,
      this.historyState,
      async () => {
        const previous = await this.items.get(value.id);
        if ((previous?.sequence ?? null) !== expectedSequence)
          throw new StaleWriteError("Concurrent local edit");
        const pending = await this.outbox.get(value.id);
        const expectedCid = rebase ? rebase.fromCid : value.baseCid;
        if (previous && previous.baseCid !== expectedCid)
          throw new StaleWriteError("Concurrent local edit during sync");
        let base: PendingWrite["baseRevision"];
        if (value.baseCid !== null) {
          if (rebase) base = encryptedBase(rebase.revision, value.baseCid);
          else if (pending?.baseCid === value.baseCid)
            base = pending.baseRevision;
          else if (!pending && previous?.baseCid === value.baseCid)
            base = encryptedBase(previous, value.baseCid);
        }
        const next = { ...value, sequence: (previous?.sequence ?? 0) + 1 };
        await this.items.put({ ...next });
        await this.outbox.put({
          ...next,
          queuedAt: Date.now(),
          baseRevision: base,
        });
        if (previous && retainHistory) await this.retainHistory(previous);
        return next;
      },
    );
  }
  /** Keeps `previous` in the note's history, within the history budget. Call inside a transaction over items, history and historyState. */
  async retainHistory(previous: StoredRevision) {
    const state = (await this.historyState.get("budget")) ?? {
      id: "budget" as const,
      bytes: 0,
      order: 0,
    };
    const entry: HistoryRevision = {
      ...previous,
      historyId: `${previous.id}:${previous.sequence}`,
      order: ++state.order,
      retainedBytes: encryptedBytes(previous),
    };
    const replaced = await this.history.get(entry.historyId);
    state.bytes += entry.retainedBytes - (replaced?.retainedBytes ?? 0);
    await this.history.put(entry);
    const excess = await this.history
      .where("[id+sequence]")
      .between([previous.id, Dexie.minKey], [previous.id, Dexie.maxKey])
      .reverse()
      .offset(30)
      .toArray();
    for (const revision of excess) state.bytes -= revision.retainedBytes;
    await this.history.bulkDelete(excess.map((revision) => revision.historyId));
    while (state.bytes > HISTORY_BYTES) {
      const oldest = await this.history.orderBy("order").limit(32).toArray();
      if (!oldest.length) throw new Error("History accounting mismatch");
      const remove: string[] = [];
      for (const revision of oldest) {
        if (state.bytes <= HISTORY_BYTES) break;
        state.bytes -= revision.retainedBytes;
        remove.push(revision.historyId);
      }
      await this.history.bulkDelete(remove);
    }
    await this.historyState.put(state);
  }
  async acknowledge(
    id: string,
    revision: string,
    cid: string,
    published?: RevisionProof,
  ): Promise<void> {
    await this.transaction("rw", this.items, this.outbox, async () => {
      const pending = await this.outbox.get(id);
      const item = await this.items.get(id);
      if (!pending || !item) return;
      if (pending.revision === revision) {
        await this.outbox.delete(id);
      } else {
        if (!published || published.revision !== revision)
          throw new Error(
            "Published revision proof required for pending edits",
          );
        await this.outbox.update(id, {
          baseCid: cid,
          baseRevision: encryptedBase(published, cid),
        });
      }
      await this.items.update(id, { baseCid: cid });
    });
  }
}
