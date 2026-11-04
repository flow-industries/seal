import Dexie, { type ObservabilitySet } from "dexie";
import type { RootMetadata } from "../crypto/access-v3.ts";
import {
  authorityOf,
  type EntryAuthority,
  type EntrySigner,
  entrySigner,
  type RevisionOrigin,
  type RunPolicy,
  revisionOrigin,
  revisionWriter,
  signEntry,
} from "../crypto/authorship.ts";
import {
  type CryptoContext,
  decrypt,
  encrypt,
  createRecoveryFile as generateRecoveryFile,
  parseEnvelope,
} from "../crypto/index.ts";
import { repairMovedNoteLinks } from "../links/rename.ts";
import { conflictName, draftAfterTombstone } from "../sync/conflicts.ts";
import type { EncryptedRecord, RemoteRecord } from "../sync/records.ts";
import {
  type AttachmentFile,
  type AttachmentInsertion,
  planAttachments,
} from "../writing/attachments.ts";
import {
  type ComposeRequest,
  extractNote,
  mergeNotes,
} from "../writing/composer.ts";
import { isInternalWritingPath } from "../writing/preferences.ts";
import { type GraphRepair, repairGraph as repairItemGraph } from "./graph.ts";
import { linkRanges, linkResolver } from "./links.ts";
import {
  canonicalLinkKey,
  exportFiles,
  type ItemKind,
  importFiles,
  mediaMime,
  newId,
  obsidianExport,
  type PortableFile,
  paths,
  safeSegment,
  type VaultItem,
} from "./model.ts";
import {
  revisionDigest,
  type StoredRevision,
  VaultDatabase,
} from "./storage.ts";

interface PathPlan {
  name: string;
  parent: string | null;
  folders: VaultItem[];
}
/** An attachment a preview reads, as the planner selected it. */
export type SelectedAsset = {
  id: string;
  mime: string;
  bytes: Uint8Array;
  path?: string;
  paths?: string[];
  canonicalPath?: string;
  /** Whether this module's revision may run by itself, and that exact stored revision's digest; set on modules only. */
  runs?: boolean;
  digest?: string;
};
/**
 * Picks the attachments a preview of `note` reads, reading each through
 * `read` within `limit` bytes. Modules carry a `canonicalPath`, and the
 * session then marks whether each may run. Planning never evaluates note code.
 */
export type PlanPreviewAssets = (
  note: VaultItem,
  source: string,
  items: readonly VaultItem[],
  read: (id: string, limit: number) => Promise<Uint8Array | null>,
) => Promise<SelectedAsset[]>;
/** The longest query `search` passes on; an index refuses longer ones. */
export const MAX_SEARCH_QUERY = 256;
/** A full-text index over decrypted notes, held only until the session locks. */
export interface NoteSearchIndex {
  update(delta: {
    upsert: { id: string; path: string; source: string }[];
    remove: string[];
  }): Promise<void>;
  search(query: string): Promise<{ id: string; line?: number }[]>;
  lock(): void;
}
/**
 * What a session borrows from the app hosting it. A device or agent needs
 * neither: without a planner `assetsForNote` refuses, and without an index
 * `search` does.
 */
export interface SessionServices {
  planPreviewAssets?: PlanPreviewAssets;
  /** A fresh, empty index; the session fills it on its first search. */
  createSearchIndex?: () => NoteSearchIndex;
}
export interface SessionOptions extends SessionServices {
  owner: string;
  vault: string;
  key: Uint8Array;
  epoch?: number;
  /** Separates this holder's local database from others for the same vault on one origin (`databaseName`). */
  storage?: string;
  /**
   * Who signs this session's writes, which recipients verify signatures and
   * whose admin signatures run by themselves (the unlock decides, knowing how
   * the device came to trust its access). Without it nothing is signed and
   * every note may run, as in an unsigned vault.
   */
  authorship?: {
    signer?: EntrySigner;
    access: RootMetadata;
    runners: RunPolicy;
  };
}
/**
 * Code another admin signed that a write here left unsigned, so it now needs
 * trust on every device, or whose links were left stale rather than rewritten.
 */
export interface TrustLoss {
  unsigned: string[];
  stale: string[];
}
const noLoss = (): TrustLoss => ({ unsigned: [], stale: [] });
/**
 * Content a write copies in: a note's current revision, or the row
 * `historyId` from its local history. A history row is named by its own
 * unique id, never by revision, which any key holder can reuse.
 */
export interface ContentSource {
  id: string;
  historyId?: string;
}
/** The revision a change was made on, and the digest of that exact row, by which it is looked up. */
export interface RevisionBase {
  revision: string;
  digest: string;
}
/**
 * One exact stored revision of an item, as the person was shown it: its
 * `revisionDigest`, which binds the ciphertext, since a revision id alone
 * can be reused for other content.
 */
export interface RevisionRef {
  id: string;
  digest: string;
}
/**
 * Where a write's content came from: the note itself plus any `sources`.
 * Every write, typed or not, is signed only when each source may run by
 * itself or the person `endorsed` it, so a note whose code they haven't
 * trusted stays unsigned however much they edit around it.
 */
export interface Provenance {
  sources?: readonly ContentSource[];
  endorsed?: boolean;
  /** The note's current content is discarded, as by restoring a version, so only `sources` vouch. */
  replaces?: boolean;
}
const runnable = (path: string) => /\.(mdx|[jt]sx?)$/iu.test(path);
/**
 * Whom a session over an unsigned root can check signatures against. That root
 * vouches for nobody, and any key holder could have written it, so such a
 * session runs nothing, signs nothing, and shows everything as not signed. A
 * later sync of an unsigned root doesn't change that.
 */
const NOBODY: EntryAuthority = [];
export interface NoteSummary {
  id: string;
  name: string;
  path: string;
  format: "md" | "mdx";
}
export interface ListedNote extends NoteSummary {
  created: string;
  modified: string;
}
/** An attachment outside the trash, without its bytes. */
export interface AssetSummary {
  id: string;
  path: string;
  mime: string;
  /** Plaintext bytes, read from the encrypted chunks' lengths without decrypting them. */
  size: number;
  revision: string;
  digest: string;
}
/** XChaCha20-Poly1305's tag, which each encrypted attachment chunk carries. */
const CHUNK_TAG_BYTES = 16;
const MIME = /^[a-z0-9!#$&^_.+-]{1,127}\/[a-z0-9!#$&^_.+-]{1,127}$/iu;
export interface NoteSearchHit extends NoteSummary {
  /** The one-based line of the task the query matched. */
  line?: number;
}
const encode = (item: VaultItem) =>
  new TextEncoder().encode(
    JSON.stringify({ ...item, bytes: Array.from(item.bytes) }),
  );
function decode(bytes: Uint8Array): VaultItem {
  const item = JSON.parse(new TextDecoder().decode(bytes));
  if (
    !item ||
    !["note", "folder", "asset"].includes(item.kind) ||
    // biome-ignore lint/plugin: Authenticated JSON still requires boundary validation.
    typeof item.name !== "string" ||
    // biome-ignore lint/plugin: Authenticated JSON still requires boundary validation.
    typeof item.id !== "string" ||
    !Array.isArray(item.bytes) ||
    item.bytes.some(
      // biome-ignore lint/plugin: Validate untrusted JSON numeric bytes at the boundary.
      (byte: unknown) =>
        // biome-ignore lint/plugin: Validate untrusted JSON numeric bytes at the boundary.
        typeof byte !== "number" ||
        !Number.isInteger(byte) ||
        byte < 0 ||
        byte > 255,
    )
  )
    throw new Error("Invalid encrypted item");
  return { ...item, bytes: Uint8Array.from(item.bytes) };
}
/**
 * Committed writes to each vault's `items` table, from this tab or another, so
 * a search can skip re-reading a vault that hasn't changed. Keyed by database
 * name so no session is kept alive by the listener. Dexie reports `all` when it
 * may have missed changes, such as a page restored from the back/forward cache.
 */
const itemWrites = new Map<string, number>();
let unknownWrites = 0;
const writeStamp = (name: string) =>
  `${unknownWrites}:${itemWrites.get(name) ?? 0}`;
Dexie.on("storagemutated", (parts: ObservabilitySet) => {
  if ("all" in parts) unknownWrites++;
  const touched = new Set<string>();
  for (const part of Object.keys(parts)) {
    const table = part.lastIndexOf("/items/");
    if (part.startsWith("idb://") && table > 6)
      touched.add(part.slice(6, table));
  }
  for (const name of touched)
    itemWrites.set(name, (itemWrites.get(name) ?? 0) + 1);
});
/** Reading renders at most this many embeds, so a note download holds no more. */
const MAX_EMBEDDED_NOTES = 30;
function* linkedItems(
  source: string,
  noteId: string,
  items: readonly VaultItem[],
  kind: ItemKind,
): Generator<{ item: VaultItem; target: string; embed: boolean }> {
  const resolveLink = linkResolver(items);
  for (const link of linkRanges(source)) {
    const target = link.target.split("#")[0] ?? "";
    if (!target || target.length > 1024 || /[?\\:]/u.test(target)) continue;
    const resolved = resolveLink(target, noteId, link.syntax);
    const item = items.find(
      (candidate) => candidate.id === resolved && candidate.kind === kind,
    );
    if (item) yield { item, target, embed: link.embed === true };
  }
}
const ASSET_CHUNK_BYTES = 256_000;
const sameBytes = (a: Uint8Array, b: Uint8Array) =>
  a.length === b.length && a.every((byte, index) => byte === b[index]);
/** Items whose content the person wrote in this operation, so their writes are signed. */
const authored = (items: readonly VaultItem[]) =>
  new Map(items.map((item) => [item.id, true]));
/** Bounds the attachment plaintext a session keeps decrypted between preview reloads. */
const ATTACHMENT_CACHE_ITEMS = 64;
const ATTACHMENT_CACHE_BYTES = 32_000_000;
const STORED_CACHE_BYTES = 32_000_000;
export class VaultSession {
  readonly database: VaultDatabase;
  private key: Uint8Array | null;
  private generation = 0;
  private storedCache = new Map<string, StoredRevision>();
  private searchWorker: NoteSearchIndex | null = null;
  /**
   * Plaintext caches are keyed by the stored ciphertext itself, never by
   * revision: any key holder can reuse a revision id for other content, and
   * what NOTE shows or runs must be what its trust decisions checked.
   */
  private metadataCache = new Map<
    string,
    { ciphertext: string; item: VaultItem }
  >();
  private sourceCache = new Map<
    string,
    { ciphertext: string; source: string }
  >();
  /** Decrypted attachment bytes, least recently used first; plaintext that lives only until lock. */
  private attachmentCache = new Map<
    string,
    { ciphertext: string; bytes: Uint8Array }
  >();
  private attachmentCacheBytes = 0;
  private indexedNotes = new Map<
    string,
    { ciphertext: string; path: string }
  >();
  private indexedSummaries = new Map<string, NoteSummary>();
  private indexedWrites = "";
  private searchQueue: Promise<void> = Promise.resolve();
  /** Held, like the vault key, only until lock; code that runs in the page can reach both. */
  private signer: EntrySigner | null;
  private authority: EntryAuthority;
  private readonly runners: RunPolicy;
  private trustLosses = new Set<(loss: TrustLoss) => void>();
  /** Verdicts by item, valid while the stored row and the recipients stay the same. */
  private origins = new Map<
    string,
    { version: string; origin: RevisionOrigin }
  >();
  private authorityListeners = new Set<() => void>();
  /**
   * The revisions this session wrote to each note, each with the revision it
   * was made on (null when it was made on nothing the person saw, as a
   * restore is), so typing ahead of a refresh still builds on its own writes.
   */
  private written = new Map<string, Map<string, string | null>>();
  /** Row digests by item, valid while the stored ciphertext stays the same. */
  private digests = new Map<string, { ciphertext: string; digest: string }>();
  private readonly options: Omit<SessionOptions, "key" | "authorship">;
  constructor(options: SessionOptions) {
    this.options = {
      owner: options.owner,
      vault: options.vault,
      epoch: options.epoch,
      planPreviewAssets: options.planPreviewAssets,
      createSearchIndex: options.createSearchIndex,
      storage: options.storage,
    };
    this.key = options.key.slice();
    const signer = options.authorship?.signer;
    this.signer = signer
      ? { ...signer, privateKey: signer.privateKey.slice() }
      : null;
    this.authority = options.authorship
      ? (authorityOf(options.authorship.access) ?? NOBODY)
      : null;
    const runners = options.authorship?.runners ?? [];
    this.runners =
      runners === "every-admin"
        ? runners
        : runners.map(({ recipientId, signPublicKey }) => ({
            recipientId,
            signPublicKey,
          }));
    this.database = new VaultDatabase(
      options.owner,
      options.vault,
      options.epoch,
      options.storage,
    );
  }
  /** Adopts the access a sync verified, against which every signature is checked from now on. */
  authorize(access: RootMetadata): void {
    const authority = authorityOf(access) ?? (this.authority && NOBODY);
    if (JSON.stringify(authority) === JSON.stringify(this.authority)) return;
    this.authority = authority;
    this.origins.clear();
    for (const listener of this.authorityListeners) listener();
  }
  /** Calls `listener` whenever verdicts may have changed without any item changing. */
  subscribeAuthority(listener: () => void): () => void {
    this.authorityListeners.add(listener);
    return () => this.authorityListeners.delete(listener);
  }
  /** Whether this revision may run by itself, checked against the current recipients. */
  async origin(stored: StoredRevision): Promise<RevisionOrigin> {
    const version =
      stored.localVersion &&
      JSON.stringify([
        stored.localVersion,
        stored.revision,
        stored.author?.signature,
      ]);
    const cached = this.origins.get(stored.id);
    if (version && cached?.version === version) return cached.origin;
    let authority: EntryAuthority;
    let origin: RevisionOrigin;
    // A sync may adopt new access while this verifies; a verdict against the old recipients is never returned.
    do {
      authority = this.authority;
      origin = await revisionOrigin(
        stored,
        this.entryContext(),
        authority,
        this.runners,
      );
    } while (authority !== this.authority);
    // Callers get the cached verdict itself, which `heldCode` also reads; frozen, nobody can rewrite it.
    Object.freeze(origin);
    // A history row shares its note's id, so caching it would evict the current revision's verdict.
    if (version && this.key && !Object.hasOwn(stored, "historyId"))
      this.origins.set(stored.id, { version, origin });
    return origin;
  }
  /**
   * Whether a write may carry this session's signature. Content the person
   * didn't write here (a move, link repair, restore or conflict copy) keeps
   * the trust its sources had, so re-encrypting it never vouches for it.
   */
  private async vouches(
    ...sources: (StoredRevision | undefined)[]
  ): Promise<boolean> {
    if (!this.signsAsAdmin() && sources.some(Boolean)) return false;
    for (const source of sources)
      if (source && !(await this.origin(source)).runs) return false;
    return true;
  }
  /**
   * Whether rewriting `item` from `source` here would drop an admin's
   * signature: one this session can't confirm, or any that runs here when
   * this session signs as a device or agent.
   */
  private async heldCode(
    item: VaultItem,
    source: StoredRevision | undefined,
  ): Promise<boolean> {
    if (!runnable(item.name) || !source) return false;
    const origin = await this.origin(source);
    return !!origin.reason || (origin.runs && !this.signsAsAdmin());
  }
  /**
   * `vouches` for a direct action that writes `item`, noting in `lost` code it
   * leaves unsigned that another admin had signed.
   */
  private async carries(
    lost: TrustLoss,
    item: VaultItem,
    ...sources: (StoredRevision | undefined)[]
  ): Promise<boolean> {
    if (await this.vouches(...sources)) return true;
    for (const source of sources)
      if (await this.heldCode(item, source)) {
        lost.unsigned.push(item.name);
        break;
      }
    return false;
  }
  /** Hears about every write that left another admin's code unsigned or unrepaired. */
  subscribeTrustLoss(listener: (loss: TrustLoss) => void): () => void {
    this.trustLosses.add(listener);
    return () => this.trustLosses.delete(listener);
  }
  /**
   * Whether rewriting this item here would drop the signature of an admin
   * this session can't confirm, so a direct action can ask first.
   */
  async holdsCode(id: string): Promise<string | null> {
    const stored = await this.database.items.get(id);
    return stored &&
      (await this.heldCode(await this.read(stored, false), stored))
      ? revisionDigest(stored)
      : null;
  }
  /** Reports what nobody was asked about: repairs, conflict copies, declined prompts and stale links. */
  private reportTrustLoss(loss: TrustLoss): void {
    if (!loss.unsigned.length && !loss.stale.length) return;
    for (const listener of this.trustLosses) listener(loss);
  }
  /**
   * What a device's or agent's typed save changed, judged against the
   * revision the person was shown: `typed` content is signed as this session,
   * whose signature never lets code run and so only names who changed the
   * note; an `unchanged` save writes nothing; content over a view this session
   * can't place, or over no view at all, is `unplaced` and saved unsigned.
   * The stored row's own bytes are `unchanged` whatever base the caller
   * names: rewriting them here could only swap or drop the signature they
   * carry.
   */
  private async typedHere(
    item: VaultItem,
    stored: StoredRevision | undefined,
    base: RevisionBase | undefined,
  ): Promise<"typed" | "unchanged" | "unplaced"> {
    if (stored && sameBytes(item.bytes, (await this.read(stored)).bytes))
      return "unchanged";
    if (stored && !base) return "unplaced";
    const shown = await this.staleBase(item.id, stored, base);
    if (shown === null) return "unplaced";
    if (!shown) return "typed";
    return sameBytes(item.bytes, (await this.read(shown)).bytes)
      ? "unchanged"
      : "typed";
  }
  /**
   * Whether a write may be signed: only if the person endorsed it, or every
   * source it came from (the note itself unless replaced, plus `sources`)
   * may run by itself. A source that is gone vouches for nothing.
   */
  private async vouchesDerived(
    lost: TrustLoss,
    item: VaultItem,
    stored: StoredRevision | undefined,
    provenance: Provenance,
    base?: RevisionBase,
  ): Promise<boolean> {
    if (provenance.endorsed && this.signsAsAdmin()) return true;
    const based = await this.staleBase(item.id, stored, base);
    if (based === null) {
      // Content over a view this session can't place may be a stale copy, so another admin's code it replaces is reported.
      if (await this.heldCode(item, stored)) lost.unsigned.push(item.name);
      return false;
    }
    const sources = await this.sourceRevisions(provenance.sources ?? []);
    const found = sources.filter((source) => source !== null);
    // A replacing write with nothing to vouch for it vouches for nothing.
    if (provenance.replaces && !found.length) return false;
    return (
      found.length === sources.length &&
      this.carries(
        lost,
        item,
        provenance.replaces ? undefined : (based ?? stored),
        ...found,
      )
    );
  }
  /**
   * The row an edit was made on, when it isn't the stored one and isn't one
   * this session wrote since. The change carries that row's content, not the
   * newer row's, so it alone vouches; within an epoch a revision id names one
   * ciphertext (see `reusesRevision`). Null when that row is gone; undefined
   * when the edit builds on the stored row.
   */
  private async staleBase(
    id: string,
    stored: StoredRevision | undefined,
    base: RevisionBase | undefined,
  ): Promise<StoredRevision | null | undefined> {
    if (!base || !stored) return undefined;
    const matches = async (row: StoredRevision) =>
      (await this.digestOf(row)) === base.digest;
    if (await matches(stored)) return undefined;
    if (this.continues(id, stored.revision, base.revision)) return undefined;
    for (const row of await this.database.history
      .where("id")
      .equals(id)
      .toArray())
      if (await matches(row)) return row;
    return null;
  }
  /**
   * Whether a save of `id` made on `base` can be judged against what the
   * person was shown: the item is new, or `base` is a row this session can
   * place (see `staleBase`).
   */
  async places(id: string, base?: RevisionBase): Promise<boolean> {
    if (!this.key) throw new Error("Vault locked");
    const stored = await this.database.items.get(id);
    if (!stored) return true;
    return !!base && (await this.staleBase(id, stored, base)) !== null;
  }
  /** Whether `revision` descends, through this session's own writes alone, from `base`. */
  private continues(id: string, revision: string, base: string): boolean {
    const line = this.written.get(id);
    let current: string | null | undefined = revision;
    for (let step = 0; line && current && step < line.size; step++) {
      current = line.get(current);
      if (current === base) return true;
    }
    return false;
  }
  private wrote(id: string, parent: string | undefined, revision?: string) {
    if (!revision) return;
    const line = this.written.get(id) ?? new Map<string, string | null>();
    line.set(revision, parent ?? null);
    this.written.set(id, line);
  }
  /** `revisionDigest`, cached for current rows; a history row shares its item's id, so it is never cached. */
  private async digestOf(row: StoredRevision): Promise<string> {
    const ciphertext = row.envelope.ciphertext;
    const cached = this.digests.get(row.id);
    if (cached?.ciphertext === ciphertext) return cached.digest;
    const digest = await revisionDigest(row);
    if (!Object.hasOwn(row, "historyId"))
      this.digests.set(row.id, { ciphertext, digest });
    return digest;
  }
  private async sourceRevisions(
    sources: readonly ContentSource[],
  ): Promise<(StoredRevision | null)[]> {
    return Promise.all(
      sources.map(async ({ id, historyId }) => {
        const row = historyId
          ? await this.database.history.get(historyId)
          : await this.database.items.get(id);
        return row?.id === id ? row : null;
      }),
    );
  }
  /**
   * Who wrote code that a write to `target` from `sources` would sign as
   * this session's admin and so let run by itself; null when it would
   * promote nothing.
   */
  async writerToEndorse(
    target: { id?: string; path: string },
    sources: readonly ContentSource[] = [],
  ): Promise<string | null> {
    if (!runnable(target.path) || !this.signsAsAdmin()) return null;
    const current = target.id && (await this.database.items.get(target.id));
    for (const source of [
      ...(current ? [current] : []),
      ...(await this.sourceRevisions(sources)),
    ]) {
      if (!source) return "an unknown writer";
      if (!(await this.origin(source)).runs)
        return revisionWriter(
          source,
          this.entryContext(),
          this.authority,
          this.runners,
        );
    }
    return null;
  }
  /**
   * Signs these exact revisions as this session's own, so their code runs by
   * itself: the person trusted them after seeing who wrote them. A revision
   * that changed since is refused, so trust never moves to unseen content.
   */
  async trust(revisions: readonly RevisionRef[]): Promise<void> {
    if (!this.signsAsAdmin())
      throw new Error("This notepad can’t record your trust from here.");
    const stored = await Promise.all(
      revisions.map(({ id, digest }) => this.shown(id, digest)),
    );
    // Typing that follows on the trusted view builds on what the person just trusted.
    for (const current of stored)
      this.wrote(
        current.id,
        current.revision,
        await this.persist(await this.read(current), true, current),
      );
  }
  /** The stored row of `id`, only while it is still exactly the one shown as `digest`. */
  private async shown(id: string, digest: string): Promise<StoredRevision> {
    const current = await this.database.items.get(id);
    if (!current || (await revisionDigest(current)) !== digest)
      throw new Error("This note changed. Review it again before trusting it.");
    return current;
  }
  /**
   * Only an admin's signature carries an admin's trust, so a device or agent
   * session never vouches for, endorses or trusts what it didn't write. A
   * session that wasn't told its vault's access has none to go by, so it counts.
   */
  signsAsAdmin(): boolean {
    const signer = this.listedSigner();
    return (
      !this.authority ||
      (!!signer &&
        this.authority.some(
          (recipient) =>
            recipient.id === signer.recipientId && recipient.role === "admin",
        ))
    );
  }
  private entryContext() {
    return { did: this.options.owner, vault: this.options.vault };
  }
  /** This session signs only once the verified recipients list its key. */
  private listedSigner(): EntrySigner | null {
    const signer = this.signer;
    return signer &&
      this.authority?.some(
        (recipient) =>
          recipient.id === signer.recipientId &&
          recipient.signPublicKey === signer.signPublicKey,
      )
      ? signer
      : null;
  }
  private context(id: string, revision: string): CryptoContext {
    return {
      did: this.options.owner,
      vault: this.options.vault,
      item: id,
      revision,
      epoch: this.options.epoch ?? 1,
      assets: [],
    };
  }
  private async digest(bytes: Uint8Array): Promise<string> {
    const hash = await crypto.subtle.digest("SHA-256", new Uint8Array(bytes));
    return Array.from(new Uint8Array(hash), (value) =>
      value.toString(16).padStart(2, "0"),
    ).join("");
  }
  private async prepare(
    item: VaultItem,
    revision: string,
    vouched: boolean,
  ): Promise<Omit<StoredRevision, "sequence" | "baseCid">> {
    if (!this.key) throw new Error("Vault locked");
    const encryptedBlobs: Uint8Array[] = [];
    const chunkHashes: string[] = [];
    const useBlobs = item.kind === "asset" || item.bytes.length > 64_000;
    if (useBlobs) {
      const count = Math.max(
        1,
        Math.ceil(item.bytes.length / ASSET_CHUNK_BYTES),
      );
      for (let index = 0; index < count; index++) {
        const chunk = await encrypt(
          item.bytes.slice(
            index * ASSET_CHUNK_BYTES,
            (index + 1) * ASSET_CHUNK_BYTES,
          ),
          this.key,
          {
            ...this.context(item.id, revision),
            chunkIndex: index,
            chunkCount: count,
          },
        );
        const bytes = new TextEncoder().encode(JSON.stringify(chunk));
        encryptedBlobs.push(bytes);
        chunkHashes.push(await this.digest(bytes));
      }
    }
    const envelope = await encrypt(
      encode(useBlobs ? { ...item, bytes: new Uint8Array() } : item),
      this.key,
      { ...this.context(item.id, revision), assets: chunkHashes },
    );
    const prepared = {
      id: item.id,
      revision,
      envelope,
      encryptedBlobs,
      chunkHashes,
    };
    const signer = vouched ? this.listedSigner() : null;
    if (!signer) return prepared;
    const author = await signEntry(prepared, this.entryContext(), signer);
    if (!this.key) throw new Error("Vault locked");
    return { ...prepared, author };
  }
  private async read(
    stored: StoredRevision,
    includeBytes = true,
  ): Promise<VaultItem> {
    const generation = this.generation;
    if (!this.key) throw new Error("Vault locked");
    const item = decode(
      await decrypt(stored.envelope, this.key, {
        ...this.context(stored.id, stored.revision),
        assets: stored.chunkHashes ?? [],
      }),
    );
    if (!this.key || generation !== this.generation)
      throw new Error("Vault locked");
    if (includeBytes && stored.chunkHashes?.length) {
      if (stored.encryptedBlobs?.length !== stored.chunkHashes.length)
        throw new Error("Missing encrypted chunks");
      const chunks: Uint8Array[] = [];
      for (let index = 0; index < stored.chunkHashes.length; index++) {
        const bytes = stored.encryptedBlobs[index];
        if ((await this.digest(bytes)) !== stored.chunkHashes[index])
          throw new Error("Encrypted chunk mapping mismatch");
        chunks.push(
          await decrypt(parseEnvelope(bytes), this.key, {
            ...this.context(stored.id, stored.revision),
            chunkIndex: index,
            chunkCount: stored.chunkHashes.length,
          }),
        );
      }
      const combined = new Uint8Array(
        chunks.reduce((sum, chunk) => sum + chunk.length, 0),
      );
      let offset = 0;
      for (const chunk of chunks) {
        combined.set(chunk, offset);
        offset += chunk.length;
      }
      item.bytes = combined;
    }
    if (!this.key || generation !== this.generation)
      throw new Error("Vault locked");
    if (item.id !== stored.id) throw new Error("Item identity mismatch");
    if (!includeBytes) item.bytes = new Uint8Array();
    return item;
  }
  private async items(): Promise<VaultItem[]> {
    return Promise.all(
      (await this.database.items.toArray()).map((value) => this.read(value)),
    );
  }
  private async metadata(
    baseline: readonly StoredRevision[],
  ): Promise<VaultItem[]> {
    const generation = this.generation;
    if (!this.key) throw new Error("Vault locked");
    const ids = new Set(baseline.map((item) => item.id));
    for (const id of this.metadataCache.keys())
      if (!ids.has(id)) this.metadataCache.delete(id);
    for (const id of this.sourceCache.keys())
      if (!ids.has(id)) this.sourceCache.delete(id);
    return Promise.all(
      baseline.map(async (stored) => {
        const ciphertext = stored.envelope.ciphertext;
        const cached = this.metadataCache.get(stored.id);
        if (cached?.ciphertext === ciphertext) return cached.item;
        if (this.sourceCache.get(stored.id)?.ciphertext !== ciphertext)
          this.sourceCache.delete(stored.id);
        const item = await this.read(stored, false);
        if (!this.key || generation !== this.generation)
          throw new Error("Vault locked");
        this.metadataCache.set(stored.id, { ciphertext, item });
        return item;
      }),
    );
  }
  private async storedItems(): Promise<StoredRevision[]> {
    const generation = this.generation;
    if (!this.key) throw new Error("Vault locked");
    const items = await this.database.readItems(this.storedCache);
    if (!this.key || generation !== this.generation)
      throw new Error("Vault locked");
    const cached = new Map<string, StoredRevision>();
    let bytes = 0;
    for (const item of items) {
      const size =
        item.envelope.ciphertext.length * 2 +
        (item.encryptedBlobs ?? []).reduce(
          (sum, chunk) => sum + chunk.length,
          0,
        );
      if (bytes + size > STORED_CACHE_BYTES) continue;
      cached.set(item.id, item);
      bytes += size;
    }
    this.storedCache = cached;
    return items;
  }
  async readMetadata() {
    const generation = this.generation;
    const baseline = await this.storedItems();
    const items = await this.metadata(baseline);
    const check = () => {
      if (!this.key || generation !== this.generation)
        throw new Error("Vault locked");
    };
    check();
    const active = items.filter((item) => !item.trashed);
    const index = paths(active);
    const folders = paths(items.filter((item) => item.kind === "folder"));
    const summarize = (item: VaultItem, path: string): ListedNote => ({
      id: item.id,
      name: item.name,
      path,
      format: item.format ?? "md",
      created: item.createdAt,
      modified: item.updatedAt,
    });
    const stored = new Map(baseline.map((value) => [value.id, value]));
    const executable = new Set(
      items
        .filter((item) => item.kind === "note" && /\.mdx$/iu.test(item.name))
        .map((item) => item.id),
    );
    return {
      notes: active
        .filter((item) => item.kind === "note")
        .map((item) => summarize(item, index.get(item.id)!)),
      folders: active
        .filter((item) => item.kind === "folder")
        .map((item) => index.get(item.id)!),
      trash: items
        .filter(
          (item) => item.kind === "note" && item.trashed && !item.permanent,
        )
        .map((item) =>
          summarize(
            item,
            `${item.parent ? `${folders.get(item.parent) ?? ""}/` : ""}${item.name}`,
          ),
        ),
      read: async (id: string) => {
        check();
        const revision = stored.get(id);
        if (!revision) throw new Error("Missing note");
        const source = await this.openStored(revision);
        const digest = await this.digestOf(revision);
        check();
        if (!executable.has(id))
          return { source, revision: revision.revision, digest };
        const origin = await this.origin(revision);
        check();
        return { source, revision: revision.revision, origin, digest };
      },
    };
  }
  /**
   * One attachment's plaintext, decrypted once per revision and returned as a
   * copy the caller may zero, or null when it alone exceeds `limit` bytes.
   * An attachment over the limit is never cached, and when its chunk count
   * already proves it too large, never decrypted.
   */
  private async attachmentBytes(
    stored: StoredRevision,
    limit: number,
  ): Promise<Uint8Array | null> {
    const chunks = stored.chunkHashes?.length ?? 0;
    if (chunks > 1 && (chunks - 1) * ASSET_CHUNK_BYTES >= limit) return null;
    const cached = this.attachmentCache.get(stored.id);
    if (cached?.ciphertext === stored.envelope.ciphertext) {
      if (cached.bytes.length > limit) return null;
      this.attachmentCache.delete(stored.id);
      this.attachmentCache.set(stored.id, cached);
      return cached.bytes.slice();
    }
    const generation = this.generation;
    const { bytes } = await this.read(stored);
    if (!this.key || generation !== this.generation)
      throw new Error("Vault locked");
    this.forgetAttachment(stored.id);
    if (bytes.length > limit) {
      bytes.fill(0);
      return null;
    }
    this.attachmentCache.set(stored.id, {
      ciphertext: stored.envelope.ciphertext,
      bytes,
    });
    this.attachmentCacheBytes += bytes.length;
    for (const [id] of this.attachmentCache) {
      if (
        this.attachmentCache.size <= ATTACHMENT_CACHE_ITEMS &&
        this.attachmentCacheBytes <= ATTACHMENT_CACHE_BYTES
      )
        break;
      if (id !== stored.id) this.forgetAttachment(id);
    }
    return bytes.slice();
  }
  private forgetAttachment(id: string) {
    const cached = this.attachmentCache.get(id);
    if (!cached) return;
    cached.bytes.fill(0);
    this.attachmentCacheBytes -= cached.bytes.length;
    this.attachmentCache.delete(id);
  }
  /** Wipes cached plaintext whose attachment is gone, trashed or stored as other ciphertext. */
  private pruneAttachments(
    records: ReadonlyMap<string, StoredRevision>,
    live: ReadonlySet<string>,
  ) {
    for (const [id, cached] of this.attachmentCache)
      if (
        !live.has(id) ||
        records.get(id)?.envelope.ciphertext !== cached.ciphertext
      )
        this.forgetAttachment(id);
  }
  private clearAttachments() {
    for (const cached of this.attachmentCache.values()) cached.bytes.fill(0);
    this.attachmentCache.clear();
    this.attachmentCacheBytes = 0;
  }
  async listNotes(): Promise<ListedNote[]> {
    return (await this.readMetadata()).notes;
  }
  async listAssets(): Promise<AssetSummary[]> {
    const generation = this.generation;
    const baseline = await this.storedItems();
    const active = (await this.metadata(baseline)).filter(
      (item) => !item.trashed,
    );
    const index = paths(active);
    const rows = new Map(baseline.map((row) => [row.id, row]));
    const assets: AssetSummary[] = [];
    for (const item of active) {
      const row = rows.get(item.id);
      const path = index.get(item.id);
      if (item.kind !== "asset" || !row || !path || isInternalWritingPath(path))
        continue;
      assets.push({
        id: item.id,
        path,
        mime: item.mime ?? "application/octet-stream",
        size: await this.plaintextLength(row),
        ...(await this.baseOf(row)),
      });
    }
    if (!this.key || generation !== this.generation)
      throw new Error("Vault locked");
    return assets;
  }
  /** An attachment's length; a chunked one's from each chunk's ciphertext, which is its plaintext and tag. */
  private async plaintextLength(row: StoredRevision): Promise<number> {
    if (!row.chunkHashes?.length) {
      const { bytes } = await this.read(row);
      bytes.fill(0);
      return bytes.length;
    }
    return (row.encryptedBlobs ?? []).reduce(
      (sum, blob) =>
        sum +
        Math.floor((parseEnvelope(blob).ciphertext.length * 3) / 4) -
        CHUNK_TAG_BYTES,
      0,
    );
  }
  /** An attachment's bytes, as a copy the caller may zero. */
  async openAsset(id: string): Promise<Uint8Array> {
    const stored = await this.database.items.get(id);
    if (!stored) throw new Error("Missing attachment");
    const item = await this.read(stored);
    if (item.kind !== "asset" || item.trashed) {
      item.bytes.fill(0);
      throw new Error("Item is not an active attachment");
    }
    return item.bytes;
  }
  async open(id: string): Promise<string> {
    const stored = await this.database.items.get(id);
    if (!stored) throw new Error("Missing note");
    return this.openStored(stored);
  }
  private async openStored(stored: StoredRevision): Promise<string> {
    const generation = this.generation;
    const id = stored.id;
    if (!this.key) throw new Error("Vault locked");
    const cached = this.sourceCache.get(id);
    if (cached?.ciphertext === stored.envelope.ciphertext) return cached.source;
    const source = new TextDecoder("utf-8", {
      fatal: true,
      ignoreBOM: true,
    }).decode((await this.read(stored)).bytes);
    if (!this.key || generation !== this.generation)
      throw new Error("Vault locked");
    this.sourceCache.set(id, {
      ciphertext: stored.envelope.ciphertext,
      source,
    });
    return source;
  }

  async readView() {
    const snapshot = await this.readMetadata();
    const notes = await Promise.all(
      snapshot.notes.map(async ({ name: _name, ...note }) => ({
        ...note,
        ...(await snapshot.read(note.id)),
      })),
    );
    return { notes, folders: snapshot.folders };
  }
  private async persist(
    item: VaultItem,
    vouched: boolean,
    previous?: StoredRevision,
    baseRevision?: StoredRevision,
  ): Promise<string> {
    const generation = this.generation;
    if (!this.key) throw new Error("Vault locked");
    const revision = newId();
    const counter = previous
      ? ((await this.read(previous)).revisionCounter ?? 1)
      : 0;
    const prepared = await this.prepare(
      { ...item, revisionCounter: counter + 1 },
      revision,
      vouched,
    );
    if (!this.key || generation !== this.generation)
      throw new Error("Vault locked");
    await this.database.save(
      {
        ...prepared,
        baseCid: baseRevision?.baseCid ?? previous?.baseCid ?? null,
        recordType: previous?.recordType,
      },
      previous?.sequence ?? null,
      item.kind === "note",
      baseRevision
        ? { fromCid: previous?.baseCid ?? null, revision: baseRevision }
        : undefined,
    );
    return revision;
  }

  async save(id: string, source: string): Promise<void> {
    const stored = await this.database.items.get(id);
    if (!stored) throw new Error("Missing note");
    const item = await this.read(stored);
    if (item.kind !== "note") throw new Error("Item is not a note");
    const bytes = new TextEncoder().encode(source);
    const edited = !sameBytes(bytes, item.bytes);
    // An unchanged save would only drop the signature of code another admin signed.
    if (!edited && (await this.heldCode(item, stored))) return;
    const lost = noLoss();
    await this.persist(
      { ...item, bytes, updatedAt: new Date().toISOString() },
      await this.carries(lost, item, stored),
      stored,
    );
    this.reportTrustLoss(lost);
  }
  private folderForPath(path: string, items: readonly VaultItem[]): PathPlan {
    if (path.length > 4096) throw new Error("Path exceeds bounds");
    const segments = path.split("/").map(safeSegment);
    if (segments.length > 64) throw new Error("Path depth exceeds bounds");
    const name = segments.pop();
    if (!name) throw new Error("Missing file name");
    const folders: VaultItem[] = [];
    let parent: string | null = null;
    for (const segment of segments) {
      const existing = [...items, ...folders].find(
        (item) =>
          item.parent === parent &&
          this.pathName(item.name) === this.pathName(segment),
      );
      if (existing && existing.kind !== "folder")
        throw new Error("Path is not a folder");
      if (existing) {
        parent = existing.id;
        continue;
      }
      const timestamp = new Date().toISOString();
      const folder: VaultItem = {
        id: newId(),
        kind: "folder",
        name: segment,
        parent,
        createdAt: timestamp,
        updatedAt: timestamp,
        bytes: new Uint8Array(),
      };
      folders.push(folder);
      parent = folder.id;
    }
    return { name, parent, folders };
  }
  private pathName(name: string): string {
    return canonicalLinkKey(name);
  }
  /** `vouched` decides, for every changed id, whether its write is signed (see `vouches`). */
  private async commitPathChanges(
    baseline: StoredRevision[],
    prospective: VaultItem[],
    changed: VaultItem[],
    vouched: ReadonlyMap<string, boolean>,
  ): Promise<Map<string, RevisionBase>> {
    const generation = this.generation;
    paths(prospective);
    const byId = new Map(baseline.map((item) => [item.id, item]));
    const encrypted = await Promise.all(
      changed.map(async (item) => {
        const previous = byId.get(item.id);
        const signs = vouched.get(item.id);
        if (signs === undefined) throw new Error("Unvouched item write");
        const prepared = await this.prepare(
          {
            ...item,
            revisionCounter: (previous ? (item.revisionCounter ?? 1) : 0) + 1,
          },
          newId(),
          signs,
        );
        return {
          item,
          previous,
          prepared: {
            ...prepared,
            baseCid: previous?.baseCid ?? null,
            recordType: previous?.recordType,
          },
          digest: await revisionDigest(prepared),
        };
      }),
    );
    if (!this.key || generation !== this.generation)
      throw new Error("Vault locked");
    await this.database.transaction(
      "rw",
      this.database.items,
      this.database.outbox,
      this.database.history,
      this.database.historyState,
      async () => {
        const current = await this.database.itemVersions();
        if (
          current.length !== baseline.length ||
          current.some(
            (item) =>
              byId.get(item.id)?.sequence !== item.sequence ||
              byId.get(item.id)?.revision !== item.revision,
          )
        )
          throw new Error("Concurrent local path edit");
        for (const update of encrypted) {
          if (!this.key || generation !== this.generation)
            throw new Error("Vault locked");
          const currentItem = await this.database.items.get(update.item.id);
          await this.database.save(
            {
              ...update.prepared,
              baseCid: currentItem?.baseCid ?? null,
            },
            update.previous?.sequence ?? null,
            update.item.kind === "note",
          );
        }
        if (!this.key || generation !== this.generation)
          throw new Error("Vault locked");
      },
    );
    return new Map(
      encrypted.map(({ item, prepared, digest }) => [
        item.id,
        { revision: prepared.revision, digest },
      ]),
    );
  }
  /**
   * Reads need a sound graph, so a repair rewrites even code another admin
   * signed, and reports it, rather than leaving the vault unreadable.
   */
  async repairGraph(): Promise<GraphRepair[]> {
    const stored = await this.database.items.toArray();
    const lost = noLoss();
    const decoded = await Promise.all(stored.map((item) => this.read(item)));
    const result = repairItemGraph(decoded);
    const repaired = new Set(result.repairs.map((repair) => repair.id));
    const updates = await Promise.all(
      result.items
        .filter((item) => repaired.has(item.id))
        .map(async (item) => {
          const previous = stored.find((stored) => stored.id === item.id);
          if (!previous) throw new Error("Missing repair baseline");
          return {
            previous,
            item,
            prepared: await this.prepare(
              { ...item, revisionCounter: (item.revisionCounter ?? 1) + 1 },
              newId(),
              await this.carries(lost, item, previous),
            ),
          };
        }),
    );
    if (!this.key) throw new Error("Vault locked");
    if (updates.length)
      await this.database.transaction(
        "rw",
        this.database.items,
        this.database.outbox,
        this.database.history,
        this.database.historyState,
        async () => {
          const current = await this.database.items.toArray();
          if (
            current.length !== stored.length ||
            current.some(
              (item) =>
                stored.find((value) => value.id === item.id)?.sequence !==
                item.sequence,
            )
          )
            throw new Error("Concurrent graph repair");
          for (const update of updates)
            await this.database.save(
              { ...update.prepared, baseCid: update.previous.baseCid },
              update.previous.sequence,
              update.item.kind === "note",
            );
        },
      );
    this.reportTrustLoss(lost);
    return result.repairs;
  }
  async assetsForNote(id: string, sourceOverride?: string) {
    const { planPreviewAssets } = this.options;
    if (!planPreviewAssets) throw new Error("Preview unavailable");
    const generation = this.generation;
    const check = () => {
      if (!this.key || generation !== this.generation)
        throw new Error("Vault locked");
    };
    const baseline = await this.storedItems();
    const records = new Map(baseline.map((record) => [record.id, record]));
    const items = (await this.metadata(baseline)).filter(
      (item) => !item.trashed,
    );
    this.pruneAttachments(records, new Set(items.map((item) => item.id)));
    const note = items.find((item) => item.id === id && item.kind === "note");
    const stored = records.get(id);
    if (!note || !stored) throw new Error("Missing note");
    const source = sourceOverride ?? (await this.openStored(stored));
    check();
    const assets = await planPreviewAssets(
      note,
      source,
      items,
      async (id, limit) => {
        check();
        const stored = records.get(id);
        if (!stored) throw new Error("Missing attachment");
        return this.attachmentBytes(stored, limit);
      },
    );
    try {
      for (const asset of assets) {
        if (!asset.canonicalPath) continue;
        const stored = records.get(asset.id);
        asset.runs = !!stored && (await this.origin(stored)).runs;
        asset.digest = stored && (await revisionDigest(stored));
      }
      check();
    } catch (error) {
      for (const asset of assets) asset.bytes.fill(0);
      throw error;
    }
    return assets;
  }
  async listFolders(): Promise<string[]> {
    return (await this.readMetadata()).folders;
  }
  async createFolder(path: string): Promise<void> {
    const baseline = await this.database.items.toArray();
    const items = (
      await Promise.all(baseline.map((item) => this.read(item)))
    ).filter((item) => !item.trashed);
    const { folders } = this.folderForPath(
      `${path}/.folder-placeholder`,
      items,
    );
    await this.commitPathChanges(
      baseline,
      [...items, ...folders],
      folders,
      authored(folders),
    );
  }
  async listTrash(): Promise<NoteSummary[]> {
    return (await this.readMetadata()).trash;
  }
  /** `endorsed`: as for `remove`. */
  async restore(id: string, endorsed?: string): Promise<string> {
    const stored = endorsed
      ? await this.shown(id, endorsed)
      : await this.database.items.get(id);
    if (!stored) throw new Error("Missing trashed note");
    const item = await this.read(stored);
    if (!item.trashed || item.permanent)
      throw new Error("Item is not recoverable trash");
    const restored = {
      ...item,
      id: newId(),
      parent: null,
      trashed: false,
      permanent: false,
      revisionCounter: 1,
    };
    paths([...(await this.items()).filter((item) => !item.trashed), restored]);
    const lost = noLoss();
    const vouched =
      (!!endorsed && this.signsAsAdmin()) ||
      (await this.carries(lost, restored, stored));
    const replacement = await this.prepare(restored, newId(), vouched);
    const tombstone = await this.prepare(
      {
        ...item,
        permanent: true,
        bytes: new Uint8Array(),
        revisionCounter: (item.revisionCounter ?? 1) + 1,
      },
      newId(),
      vouched,
    );
    if (!this.key) throw new Error("Vault locked");
    await this.database.transaction(
      "rw",
      this.database.items,
      this.database.outbox,
      this.database.history,
      this.database.historyState,
      async () => {
        await this.database.save({ ...replacement, baseCid: null }, null);
        await this.database.save(
          {
            ...tombstone,
            baseCid: stored.baseCid,
            recordType: "game.flow.note.tombstone",
          },
          stored.sequence,
        );
      },
    );
    this.reportTrustLoss(lost);
    return restored.id;
  }
  async create(path = "Untitled.md", id: string = newId()): Promise<string> {
    await this.writeNote(id, path, "", "create");
    return id;
  }
  /** The revision and digest of a stored row, to name it as a later save's base. */
  private async baseOf(row: StoredRevision): Promise<RevisionBase> {
    return { revision: row.revision, digest: await this.digestOf(row) };
  }
  /** Moves a note, repairing links to it, or an attachment, whose links stay as written. */
  async rename(id: string, path: string): Promise<RevisionBase> {
    const stored = await this.database.items.get(id);
    if (stored && (await this.read(stored, false)).kind === "asset")
      return this.writeAsset(id, path, undefined);
    return this.writeNote(id, path, undefined, "rename");
  }
  /**
   * Writes an attachment's bytes at `path`, as `saveNote` writes a note's
   * source: `base` names the revision the caller's copy came from, a device
   * or agent signs only bytes it changed, and an unedited older copy saved
   * to a new path only moves it. `mime` defaults to what the bytes show,
   * else the attachment's earlier type.
   */
  async saveAsset(
    id: string,
    path: string,
    bytes: Uint8Array,
    base?: RevisionBase,
    mime?: string,
  ): Promise<RevisionBase> {
    if (mime !== undefined && !MIME.test(mime))
      throw new Error("Invalid attachment type");
    return this.writeAsset(id, path, bytes, base, mime);
  }
  private async writeAsset(
    id: string,
    path: string,
    bytes: Uint8Array | undefined,
    base?: RevisionBase,
    mime?: string,
  ): Promise<RevisionBase> {
    if (/\.mdx?$/iu.test(path) || isInternalWritingPath(path))
      throw new Error("This path is reserved for notes and preferences.");
    const baseline = await this.storedItems();
    const visible = (await this.metadata(baseline)).filter(
      (item) => !item.trashed,
    );
    const stored = baseline.find((row) => row.id === id);
    const previous = stored && (await this.read(stored));
    if (previous && (previous.kind !== "asset" || previous.trashed))
      throw new Error("Item is not an active attachment");
    if (!previous && !bytes) throw new Error("Missing attachment");
    const samePath = !!previous && paths(visible).get(id) === path;
    const lost = noLoss();
    let content = bytes;
    let view: RevisionBase | undefined;
    let vouched: boolean;
    if (!previous || !stored) vouched = true;
    else if (!content) vouched = await this.carries(lost, previous, stored);
    else if (this.signsAsAdmin()) {
      const edited = { ...previous, bytes: content };
      vouched = await this.vouchesDerived(lost, edited, stored, {}, base);
      // Unchanged bytes rewritten unsigned would only drop the signature they carry.
      if (
        !vouched &&
        samePath &&
        sameBytes(content, previous.bytes) &&
        (await this.heldCode(previous, stored))
      )
        return this.baseOf(stored);
    } else {
      const edited = { ...previous, bytes: content };
      const typed = await this.typedHere(edited, stored, base);
      if (typed === "unchanged") {
        if (samePath) return this.unchangedBase(edited, stored, base);
        // A device's move of a copy it didn't edit, made before a newer revision arrived, keeps that revision's bytes.
        if (!sameBytes(content, previous.bytes)) view = base;
        content = undefined;
        vouched = await this.carries(lost, previous, stored);
      } else {
        vouched = typed === "typed";
        if (!vouched && (await this.heldCode(previous, stored)))
          lost.unsigned.push(previous.name);
      }
    }
    const { name, parent, folders } = this.folderForPath(path, visible);
    const timestamp = new Date().toISOString();
    const item: VaultItem = {
      ...(previous ?? {
        id,
        kind: "asset" as const,
        createdAt: timestamp,
        bytes: new Uint8Array(),
      }),
      name,
      parent,
      updatedAt: timestamp,
    };
    if (content) {
      const sniffed = mediaMime(content);
      item.bytes = content.slice();
      item.mime =
        mime ??
        (sniffed === "application/octet-stream" && previous?.mime
          ? previous.mime
          : sniffed);
    }
    const written = await this.commitPathChanges(
      baseline,
      [...visible.filter((value) => value.id !== id), ...folders, item],
      [...folders, item],
      new Map([...authored(folders), [id, vouched]]),
    );
    const row = written.get(id);
    if (!row) throw new Error("Missing written attachment");
    this.wrote(id, view ? undefined : base?.revision, row.revision);
    this.reportTrustLoss(lost);
    return view ?? row;
  }
  /** Without `provenance` the person typed `source`; the note keeps the trust it had. */
  /**
   * `base` is the revision the person's view of the note had when they made
   * the change; a change made on content that has since been replaced is
   * vouched for by that content alone. Resolves with the revision the saved
   * content now has, which names the next save's base: the row written, the
   * stored row when nothing needed writing, or `base` itself when the view's
   * content isn't what is stored (an unedited older view, or a move of one).
   */
  async saveNote(
    id: string,
    path: string,
    source: string,
    provenance?: Provenance,
    base?: RevisionBase,
  ): Promise<RevisionBase> {
    return this.writeNote(id, path, source, "upsert", provenance, base);
  }
  private async writeNote(
    id: string,
    path: string,
    source: string | undefined,
    mode: "create" | "rename" | "upsert",
    provenance?: Provenance,
    base?: RevisionBase,
  ): Promise<RevisionBase> {
    if (!/\.mdx?$/iu.test(path))
      throw new Error("Note path must end in .md or .mdx");
    const baseline = await this.storedItems();
    if (mode === "upsert" && baseline.some((item) => item.id === id)) {
      const metadata = await this.metadata(baseline);
      const previous = metadata.find((item) => item.id === id);
      if (!previous || previous.kind !== "note" || previous.trashed)
        throw new Error("Item is not an active note");
      const visible = metadata.filter((item) => !item.trashed);
      if (paths(visible).get(id) === path) {
        const item: VaultItem = {
          ...previous,
          format: previous.name.toLowerCase().endsWith(".mdx") ? "mdx" : "md",
          bytes: new TextEncoder().encode(source),
          updatedAt: new Date().toISOString(),
        };
        const stored = baseline.find((value) => value.id === id);
        const lost = noLoss();
        let vouched: boolean;
        if (!provenance && !this.signsAsAdmin()) {
          const typed = await this.typedHere(item, stored, base);
          if (typed === "unchanged")
            return this.unchangedBase(item, stored, base);
          vouched = typed === "typed";
          if (typed === "unplaced" && (await this.heldCode(item, stored)))
            lost.unsigned.push(item.name);
        } else
          vouched = await this.vouchesDerived(
            lost,
            item,
            stored,
            provenance ?? {},
            base,
          );
        // An unchanged save would only drop the signature of code another admin signed.
        if (
          !vouched &&
          stored &&
          (await this.heldCode(item, stored)) &&
          (await this.openStored(stored)) === source
        )
          return this.baseOf(stored);
        const written = await this.commitPathChanges(
          baseline,
          visible,
          [item],
          new Map([[id, vouched]]),
        );
        const row = written.get(id);
        if (!row) throw new Error("Missing written note");
        this.wrote(id, base?.revision, row.revision);
        this.reportTrustLoss(lost);
        return row;
      }
    }
    const decoded = await Promise.all(baseline.map((item) => this.read(item)));
    const previous = decoded.find((item) => item.id === id);
    if (mode === "create" && previous)
      throw new Error("Duplicate item identifier");
    if (mode === "rename" && !previous) throw new Error("Missing note");
    if (previous && (previous.kind !== "note" || previous.trashed))
      throw new Error("Item is not an active note");
    const visible = decoded.filter((item) => !item.trashed);
    // A device's move of a view it didn't edit, made before a newer revision arrived, keeps that revision's text.
    const view = base;
    const renamesOnly =
      !!previous &&
      source !== undefined &&
      !provenance &&
      !this.signsAsAdmin() &&
      (await this.movesUneditedView(
        previous,
        baseline.find((value) => value.id === id),
        source,
        base,
      ));
    if (renamesOnly) {
      source = undefined;
      base = undefined;
    }
    const { name, parent, folders } = this.folderForPath(path, visible);
    const timestamp = new Date().toISOString();
    const item: VaultItem = {
      ...(previous ?? {
        id,
        kind: "note",
        createdAt: timestamp,
        bytes: new Uint8Array(),
      }),
      name,
      parent,
      format: name.toLowerCase().endsWith(".mdx") ? "mdx" : "md",
      updatedAt: timestamp,
    };
    if (source !== undefined) item.bytes = new TextEncoder().encode(source);
    const prospective = [
      ...visible.filter((value) => value.id !== id),
      ...folders,
      item,
    ];
    const changed = new Map(
      [...folders, item].map((value) => [value.id, value]),
    );
    const stored = new Map(baseline.map((value) => [value.id, value]));
    const lost = noLoss();
    if (previous && (previous.name !== name || previous.parent !== parent)) {
      const beforePaths = paths(visible);
      const afterPaths = paths(prospective);
      const snapshots = (items: VaultItem[], index: Map<string, string>) =>
        items
          .filter(
            (value) =>
              value.kind === "note" &&
              !isInternalWritingPath(index.get(value.id) ?? value.name),
          )
          .map((value) => ({
            id: value.id,
            path: index.get(value.id)!,
            source: new TextDecoder("utf-8", {
              fatal: true,
              ignoreBOM: true,
            }).decode(value.bytes),
            kind: value.format ?? ("md" as const),
          }));
      const repairs = repairMovedNoteLinks(
        snapshots(visible, beforePaths),
        snapshots(prospective, afterPaths),
        visible
          .filter((value) => value.kind === "asset")
          .map((value) => ({ id: value.id, path: beforePaths.get(value.id)! })),
      );
      for (const value of prospective) {
        const repaired = repairs.get(value.id);
        if (repaired === undefined) continue;
        if (
          value.id !== id &&
          (await this.heldCode(value, stored.get(value.id)))
        ) {
          lost.stale.push(value.name);
          continue;
        }
        value.bytes = new TextEncoder().encode(repaired);
        value.updatedAt = timestamp;
        changed.set(value.id, value);
      }
    }
    const vouchedSelf = await this.vouchesDerived(
      lost,
      item,
      stored.get(id),
      provenance ?? {},
      base,
    );
    const vouched = authored(folders);
    for (const value of changed.values())
      if (!vouched.has(value.id))
        vouched.set(
          value.id,
          value.id === id
            ? vouchedSelf
            : await this.carries(lost, value, stored.get(value.id)),
        );
    const written = await this.commitPathChanges(
      baseline,
      prospective,
      [...changed.values()],
      vouched,
    );
    const row = written.get(id);
    if (!row) throw new Error("Missing written note");
    this.wrote(id, base?.revision, row.revision);
    this.reportTrustLoss(lost);
    return renamesOnly && view ? view : row;
  }
  /**
   * After a typed save that wrote nothing, the revision the caller's view
   * matches: the stored row when it holds the same bytes, else the older row
   * the view was made on.
   */
  private async unchangedBase(
    item: VaultItem,
    stored: StoredRevision | undefined,
    base: RevisionBase | undefined,
  ): Promise<RevisionBase> {
    if (!stored) throw new Error("Missing note");
    if (base && !sameBytes(item.bytes, (await this.read(stored)).bytes))
      return base;
    return this.baseOf(stored);
  }
  /**
   * Whether a typed save to a new path carries, unedited, an older view than
   * the stored row: writing its bytes would revert the newer text, so the
   * save is only a rename.
   */
  private async movesUneditedView(
    previous: VaultItem,
    stored: StoredRevision | undefined,
    source: string,
    base: RevisionBase | undefined,
  ): Promise<boolean> {
    const bytes = new TextEncoder().encode(source);
    if (!base || sameBytes(bytes, previous.bytes)) return false;
    return (
      (await this.typedHere({ ...previous, bytes }, stored, base)) ===
      "unchanged"
    );
  }
  /** `endorsed` lets the person sign the note they compose into, and the note an extract rewrites, whatever their sources. */
  async compose(
    request: ComposeRequest,
    endorsed = false,
  ): Promise<{ selectedId: string }> {
    const baseline = await this.database.items.toArray();
    const visible = (
      await Promise.all(baseline.map((item) => this.read(item)))
    ).filter((item) => !item.trashed);
    const index = paths(visible);
    const notes = visible
      .filter(
        (item) =>
          item.kind === "note" && !isInternalWritingPath(index.get(item.id)!),
      )
      .map((item) => ({
        id: item.id,
        path: index.get(item.id)!,
        source: new TextDecoder("utf-8", {
          fatal: true,
          ignoreBOM: true,
        }).decode(item.bytes),
        kind: item.format ?? ("md" as const),
      }));
    const assets = visible
      .filter((item) => item.kind === "asset")
      .map((item) => ({ id: item.id, path: index.get(item.id)! }));
    const origin = visible.find(
      (item) => item.id === request.originId && item.kind === "note",
    );
    if (!origin) throw new Error("Missing source note");
    const timestamp = new Date().toISOString();
    const changed = new Map<string, VaultItem>();
    const stored = new Map(baseline.map((value) => [value.id, value]));
    const lost = noLoss();
    let selectedId: string;
    let prospective = visible;
    if (request.kind === "extract") {
      if (isInternalWritingPath(request.path))
        throw new Error("Choose a note path outside internal settings");
      const { name, parent, folders } = this.folderForPath(
        request.path,
        visible,
      );
      const id = newId();
      const item: VaultItem = {
        id,
        name,
        parent,
        kind: "note",
        format: name.toLowerCase().endsWith(".mdx") ? "mdx" : "md",
        bytes: new Uint8Array(),
        createdAt: timestamp,
        updatedAt: timestamp,
      };
      prospective = [...visible, ...folders, item];
      paths(prospective);
      const result = extractNote(request, notes, assets);
      item.bytes = new TextEncoder().encode(result.extracted);
      for (const folder of folders) changed.set(folder.id, folder);
      changed.set(id, item);
      changed.set(origin.id, {
        ...origin,
        bytes: new TextEncoder().encode(result.origin),
        updatedAt: timestamp,
      });
      selectedId = id;
    } else {
      const updates = mergeNotes(request, notes, assets);
      for (const item of visible) {
        const source = updates.get(item.id);
        if (source === undefined) continue;
        if (
          item.id !== request.targetId &&
          item.id !== origin.id &&
          (await this.heldCode(item, stored.get(item.id)))
        ) {
          lost.stale.push(item.name);
          continue;
        }
        changed.set(item.id, {
          ...item,
          bytes: new TextEncoder().encode(source),
          updatedAt: timestamp,
        });
      }
      changed.set(origin.id, {
        ...origin,
        trashed: true,
        updatedAt: timestamp,
      });
      prospective = visible.filter((item) => item.id !== origin.id);
      selectedId = request.targetId;
    }
    const vouched = new Map<string, boolean>();
    for (const item of changed.values())
      vouched.set(
        item.id,
        (item.kind === "folder" && !stored.has(item.id)) ||
          (endorsed &&
            this.signsAsAdmin() &&
            (item.id === selectedId ||
              (request.kind === "extract" && item.id === origin.id))) ||
          (await this.carries(
            lost,
            item,
            stored.get(item.id),
            item.id === selectedId ? stored.get(origin.id) : undefined,
          )),
      );
    await this.commitPathChanges(
      baseline,
      prospective,
      [...changed.values()],
      vouched,
    );
    this.reportTrustLoss(lost);
    return { selectedId };
  }
  /**
   * `endorsed` is the digest `holdsCode` gave for the row the person chose to
   * sign as theirs rather than drop another admin's signature; it signs only
   * that exact row.
   */
  async remove(id: string, endorsed?: string): Promise<void> {
    const stored = endorsed
      ? await this.shown(id, endorsed)
      : await this.database.items.get(id);
    if (!stored) return;
    const trashed = { ...(await this.read(stored)), trashed: true };
    const lost = noLoss();
    await this.persist(
      trashed,
      (!!endorsed && this.signsAsAdmin()) ||
        (await this.carries(lost, trashed, stored)),
      stored,
    );
    this.reportTrustLoss(lost);
  }
  async addAttachments(
    noteId: string,
    notePath: string,
    files: readonly AttachmentFile[],
  ): Promise<AttachmentInsertion[]> {
    const generation = this.generation;
    if (!this.key) throw new Error("Vault locked");
    const baseline = await this.database.items.toArray();
    const items = (
      await Promise.all(baseline.map((item) => this.read(item)))
    ).filter((item) => !item.trashed);
    const index = paths(items);
    if (
      !items.some((item) => item.id === noteId && item.kind === "note") ||
      index.get(noteId) !== notePath
    )
      throw new Error(
        "The note moved or closed. Insert the attachments again.",
      );
    const plan = planAttachments(notePath, files, [...index.values()]);
    const changed: VaultItem[] = [];
    const inserted: AttachmentInsertion[] = [];
    for (const file of plan) {
      const { name, parent, folders } = this.folderForPath(file.path, items);
      const timestamp = new Date().toISOString();
      const item: VaultItem = {
        id: newId(),
        kind: "asset",
        name,
        parent,
        createdAt: timestamp,
        updatedAt: timestamp,
        mime: file.mime,
        bytes: file.bytes,
      };
      items.push(...folders, item);
      changed.push(...folders, item);
      inserted.push({
        id: item.id,
        path: file.path,
        name,
        mime: file.mime,
        markdown: file.markdown,
      });
    }
    if (!this.key || generation !== this.generation)
      throw new Error("Vault locked");
    await this.commitPathChanges(baseline, items, changed, authored(changed));
    return inserted;
  }
  /**
   * Imported files are signed only if the person endorses their code; it
   * came from outside NOTE, so `endorse` is asked only when an admin's
   * signature would let some of it run.
   */
  async import(
    files: readonly PortableFile[],
    endorse?: (code: readonly string[]) => Promise<boolean>,
  ): Promise<void> {
    const imported = importFiles(files);
    const index = paths(imported);
    const code = imported
      .filter((item) => item.kind !== "folder" && runnable(item.name))
      .map((item) => index.get(item.id) ?? item.name);
    const endorsed =
      !!endorse &&
      !!code.length &&
      !!this.authority &&
      this.signsAsAdmin() &&
      (await endorse(code));
    const baseline = await this.database.items.toArray();
    const items = (
      await Promise.all(baseline.map((item) => this.read(item)))
    ).filter((item) => !item.trashed);
    const changed: VaultItem[] = [];
    const remapped = new Map<string, string>();
    for (const original of imported) {
      const item = {
        ...original,
        parent: original.parent
          ? (remapped.get(original.parent) ?? original.parent)
          : null,
      };
      if (item.kind === "folder") {
        const existing = items.find(
          (value) =>
            value.parent === item.parent &&
            this.pathName(value.name) === this.pathName(item.name),
        );
        if (existing && existing.kind !== "folder")
          throw new Error("Path is not a folder");
        if (existing) {
          remapped.set(item.id, existing.id);
          continue;
        }
      }
      items.push(item);
      changed.push(item);
      remapped.set(item.id, item.id);
    }
    await this.commitPathChanges(
      baseline,
      items,
      changed,
      new Map(
        changed.map((item) => [item.id, endorsed || item.kind === "folder"]),
      ),
    );
  }
  async permanentRemove(id: string): Promise<void> {
    const stored = await this.database.items.get(id);
    if (!stored) return;
    const item = await this.read(stored);
    const revision = newId();
    const prepared = await this.prepare(
      {
        ...item,
        trashed: true,
        permanent: true,
        revisionCounter: (item.revisionCounter ?? 1) + 1,
        bytes: new Uint8Array(),
      },
      revision,
      await this.vouches(stored),
    );
    await this.database.save(
      {
        ...prepared,
        recordType: "game.flow.note.tombstone",
        baseCid: stored.baseCid,
      },
      stored.sequence,
    );
  }
  async validateRemote(
    remote: RemoteRecord,
    blobs?: Uint8Array[],
  ): Promise<void> {
    if (!this.key) throw new Error("Vault locked");
    const record = remote.record;
    const hashes = record.chunkHashes ?? [];
    if (
      hashes.length !== record.blobs.length ||
      hashes.length > 128 ||
      record.blobs.some(
        (blob) =>
          !Number.isSafeInteger(blob.size) ||
          blob.size < 0 ||
          blob.size > 400_000,
      ) ||
      record.blobs.reduce((sum, blob) => sum + blob.size, 0) > 43_000_000
    )
      throw new Error("Remote chunks exceed bounds");
    await decrypt(record.envelope, this.key, {
      ...this.context(record.id, record.revision),
      assets: hashes,
    });
    if (blobs) {
      const item = await this.read({
        id: record.id,
        revision: record.revision,
        envelope: record.envelope,
        sequence: 0,
        baseCid: remote.cid,
        chunkHashes: hashes,
        encryptedBlobs: blobs,
      });
      if (
        !Number.isSafeInteger(item.revisionCounter) ||
        (item.revisionCounter ?? 0) < 1 ||
        (record.$type === "game.flow.note.tombstone") !==
          (item.permanent === true)
      )
        throw new Error("Invalid authenticated snapshot item");
    }
  }
  /**
   * Sets aside this device's pending edit to an item whose remote revision it
   * can't read, which sync carries untouched: the edit becomes a conflict
   * copy, and the item's own pending write is dropped so it never replaces
   * that revision. The item keeps showing what this device last read.
   */
  async keepEditBeside(id: string): Promise<void> {
    const pending = await this.database.outbox.get(id);
    if (!pending) return;
    const local = await this.read(pending);
    if (!local.permanent) {
      const draft = {
        ...local,
        id: newId(),
        parent: null,
        name: conflictName(local),
      };
      const lost = noLoss();
      await this.persist(draft, await this.carries(lost, draft, pending));
      this.reportTrustLoss(lost);
    }
    await this.database.transaction("rw", this.database.outbox, async () => {
      const current = await this.database.outbox.get(id);
      if (current?.revision !== pending.revision)
        throw new Error("Concurrent local edit during sync");
      await this.database.outbox.delete(id);
    });
  }
  /**
   * Whether `record` reuses a revision id this epoch's database already holds
   * for the item as other ciphertext. Within an epoch every write takes a new
   * revision id, so a revision id names exactly one ciphertext, and only a
   * key holder rewriting history would reuse one.
   */
  async reusesRevision(
    record: EncryptedRecord,
    local?: StoredRevision,
  ): Promise<boolean> {
    const differs = (row: StoredRevision) =>
      row.revision === record.revision &&
      (row.envelope.ciphertext !== record.envelope.ciphertext ||
        row.envelope.nonce !== record.envelope.nonce);
    if (local?.revision === record.revision) return differs(local);
    return (
      await this.database.history.where("id").equals(record.id).toArray()
    ).some(differs);
  }
  /**
   * Takes a signature another device added to a revision this one already
   * holds, as Trust does; without it, this device's next write would publish
   * the revision unsigned again. A signature never replaces another, so
   * stripping one remotely can't spread from here. It must verify over this
   * device's own ciphertext, since any key holder can pair a valid signature
   * with other content under the same revision.
   */
  async adoptAuthor(record: EncryptedRecord): Promise<void> {
    const author = record.author;
    const authority = this.authority;
    if (!author || !authority) return;
    const item = await this.database.items.get(record.id);
    if (
      item?.revision !== record.revision ||
      item.author ||
      !(await entrySigner(
        { ...item, author },
        { did: this.options.owner, vault: this.options.vault },
        authority,
      ))
    )
      return;
    await this.database.transaction("rw", this.database.items, async () => {
      const current = await this.database.items.get(record.id);
      if (current?.localVersion === item.localVersion && !current?.author)
        await this.database.items.update(record.id, { author });
    });
  }
  async applyRemote(
    remote: RemoteRecord,
    blobs: Uint8Array[] = [],
  ): Promise<void> {
    const record = remote.record;
    const stored: StoredRevision = {
      id: record.id,
      revision: record.revision,
      envelope: record.envelope,
      baseCid: remote.cid,
      sequence: 0,
      recordType: record.$type,
      blobs: record.blobs,
      chunkHashes: record.chunkHashes,
      encryptedBlobs: blobs,
    };
    if (record.author) stored.author = record.author;
    const remoteItem = await this.read(stored);
    if (
      !Number.isSafeInteger(remoteItem.revisionCounter) ||
      (remoteItem.revisionCounter ?? 0) < 1
    )
      throw new Error("Invalid authenticated revision counter");
    if (
      (record.$type === "game.flow.note.tombstone") !==
      (remoteItem.permanent === true)
    )
      throw new Error("Invalid tombstone");
    const observed = await this.database.items.get(record.id);
    const pending = await this.database.outbox.get(record.id);
    if (pending?.baseCid === remote.cid) return;
    if (observed && observed.revision !== record.revision) {
      const current = await this.read(observed);
      let minimumCounter = current.revisionCounter ?? 1;
      if (pending?.baseCid === null) minimumCounter = 0;
      else if (pending?.baseRevision) {
        if (pending.baseRevision.cid !== pending.baseCid)
          throw new Error("Pending revision base mismatch");
        const base = await this.read(
          { ...pending, ...pending.baseRevision },
          false,
        );
        minimumCounter = base.revisionCounter ?? 1;
      }
      if ((remoteItem.revisionCounter ?? 0) < minimumCounter) {
        throw new Error("Authenticated stale revision rejected");
      }
      if (
        (remoteItem.revisionCounter ?? 0) <= (current.revisionCounter ?? 1) &&
        !remoteItem.permanent
      ) {
        const copy = {
          ...remoteItem,
          id: newId(),
          parent: null,
          trashed: false,
          permanent: false,
          name: conflictName(remoteItem),
        };
        const lost = noLoss();
        await this.persist(copy, await this.carries(lost, copy, stored));
        await this.persist(
          current,
          await this.carries(lost, current, observed),
          observed,
          stored,
        );
        this.reportTrustLoss(lost);
        return;
      }
    }
    const conflictingLocal =
      pending ?? (observed && remoteItem.permanent ? observed : null);
    if (conflictingLocal && conflictingLocal.revision !== record.revision) {
      const local = await this.read(conflictingLocal);
      const draft =
        record.$type === "game.flow.note.tombstone"
          ? draftAfterTombstone(local)
          : {
              ...local,
              id: newId(),
              parent: null,
              name: conflictName(local),
            };
      if (!local.permanent) {
        const lost = noLoss();
        await this.persist(
          draft,
          await this.carries(lost, draft, conflictingLocal),
        );
        this.reportTrustLoss(lost);
      }
    }

    await this.database.transaction(
      "rw",
      this.database.items,
      this.database.outbox,
      this.database.history,
      this.database.historyState,
      async () => {
        const current = await this.database.items.get(record.id);
        const currentPending = await this.database.outbox.get(record.id);
        if (
          current?.sequence !== observed?.sequence ||
          current?.baseCid !== observed?.baseCid ||
          currentPending?.revision !== pending?.revision
        )
          throw new Error("Concurrent local edit during sync");
        await this.database.items.put({
          ...stored,
          sequence: (current?.sequence ?? 0) + 1,
        });
        await this.database.outbox.delete(record.id);
        // The replaced row stays restorable, and a later reuse of its revision id stays detectable.
        if (current && remoteItem.kind === "note")
          await this.database.retainHistory(current);
      },
    );
  }
  async export(): Promise<PortableFile[]> {
    return exportFiles((await this.items()).filter((item) => !item.trashed));
  }
  /**
   * One note as `source` encoded, followed by every attachment it links or
   * embeds and every note it embeds directly with that note's attachments,
   * each at its vault path so the links resolve unchanged.
   */
  async exportNote(id: string, source: string): Promise<PortableFile[]> {
    const items = (await this.items()).filter((item) => !item.trashed);
    const index = paths(items);
    const notePath = index.get(id);
    if (
      !notePath ||
      !items.some((item) => item.id === id && item.kind === "note")
    )
      throw new Error("Missing note");
    const files: PortableFile[] = [
      { path: notePath, bytes: new TextEncoder().encode(source) },
    ];
    const include = (item: VaultItem) => {
      const path = index.get(item.id);
      if (path && !files.some((file) => file.path === path))
        files.push({ path, bytes: item.bytes.slice() });
    };
    for (const { item } of linkedItems(source, id, items, "asset"))
      include(item);
    let embeds = 0;
    for (const { item: embedded, embed } of linkedItems(
      source,
      id,
      items,
      "note",
    )) {
      if (!embed) continue;
      if (++embeds > MAX_EMBEDDED_NOTES) break;
      include(embedded);
      const embeddedSource = new TextDecoder().decode(embedded.bytes);
      for (const { item } of linkedItems(
        embeddedSource,
        embedded.id,
        items,
        "asset",
      ))
        include(item);
    }
    return files;
  }
  async exportObsidian(): Promise<{ files: PortableFile[]; losses: string[] }> {
    return obsidianExport((await this.items()).filter((item) => !item.trashed));
  }
  /**
   * Restores the history row `historyId` of note `id`: its exact bytes,
   * vouched for by that same row alone, since the restore discards the
   * current content. Unless `endorsed`, someone else's version stays
   * unsigned, so the person never signs content they were shown under
   * another revision's name.
   */
  async restoreVersion(
    id: string,
    historyId: string,
    endorsed = false,
  ): Promise<void> {
    const row = await this.database.history.get(historyId);
    if (row?.id !== id) throw new Error("This version is no longer available.");
    const source = new TextDecoder("utf-8", {
      fatal: true,
      ignoreBOM: true,
    }).decode((await this.read(row)).bytes);
    const visible = (await this.metadata(await this.storedItems())).filter(
      (item) => !item.trashed,
    );
    const path = paths(visible).get(id);
    if (!path) throw new Error("Missing note");
    await this.writeNote(id, path, source, "upsert", {
      sources: [{ id, historyId }],
      endorsed,
      replaces: true,
    });
  }
  async history(
    id: string,
  ): Promise<{ historyId: string; revision: string; source: string }[]> {
    return Promise.all(
      (await this.database.history.where("id").equals(id).toArray()).map(
        async (value) => ({
          historyId: value.historyId,
          revision: value.revision,
          source: new TextDecoder("utf-8", { ignoreBOM: true }).decode(
            (await this.read(value)).bytes,
          ),
        }),
      ),
    );
  }
  search(query: string): Promise<NoteSearchHit[]> {
    const { createSearchIndex } = this.options;
    if (!createSearchIndex)
      return Promise.reject(new Error("Search unavailable"));
    // The worker would refuse it, and its refusal reads as a failure that discards the index.
    if (query.length > MAX_SEARCH_QUERY)
      return Promise.reject(new Error("Search query too long"));
    const generation = this.generation;
    const result = this.searchQueue.then(() => {
      if (!this.key || generation !== this.generation)
        throw new Error("Vault locked");
      return this.searchIndex(query, createSearchIndex).catch((error) => {
        this.searchWorker?.lock();
        this.searchWorker = null;
        this.metadataCache.clear();
        this.sourceCache.clear();
        this.indexedNotes.clear();
        this.indexedSummaries.clear();
        this.indexedWrites = "";
        throw error;
      });
    });
    this.searchQueue = result.then(
      () => {},
      () => {},
    );
    return result;
  }
  private async searchIndex(
    query: string,
    createSearchIndex: () => NoteSearchIndex,
  ): Promise<NoteSearchHit[]> {
    const generation = this.generation;
    const writes = writeStamp(this.database.name);
    if (this.searchWorker && this.indexedWrites === writes)
      return this.searchHits(query, generation);
    const stored = await this.database.items.toArray();
    const byId = new Map(stored.map((item) => [item.id, item]));
    const items = (await this.metadata(stored)).filter((item) => !item.trashed);
    const index = paths(items);
    const notes: NoteSummary[] = items
      .filter(
        (item) =>
          item.kind === "note" &&
          !isInternalWritingPath(index.get(item.id) ?? item.name),
      )
      .map((item) => ({
        id: item.id,
        name: item.name,
        path: index.get(item.id) ?? item.name,
        format: item.format ?? "md",
      }));
    const currentIds = new Set(notes.map((note) => note.id));
    const remove = Array.from(this.indexedNotes.keys()).filter(
      (id) => !currentIds.has(id),
    );
    const upsert = [];
    for (const note of notes) {
      const record = byId.get(note.id);
      if (!record) throw new Error("Missing indexed record");
      const previous = this.indexedNotes.get(note.id);
      if (
        previous?.ciphertext === record.envelope.ciphertext &&
        previous.path === note.path
      )
        continue;
      const item = await this.read(record);
      upsert.push({
        id: note.id,
        path: note.path,
        source: new TextDecoder("utf-8", {
          fatal: true,
          ignoreBOM: true,
        }).decode(item.bytes),
      });
    }
    if (!this.key || generation !== this.generation)
      throw new Error("Vault locked");
    this.searchWorker ??= createSearchIndex();
    if (upsert.length || remove.length)
      await this.searchWorker.update({ upsert, remove });
    if (!this.key || generation !== this.generation)
      throw new Error("Vault locked");
    this.indexedNotes = new Map(
      notes.map((note) => [
        note.id,
        {
          ciphertext: byId.get(note.id)?.envelope.ciphertext ?? "",
          path: note.path,
        },
      ]),
    );
    this.indexedSummaries = new Map(notes.map((note) => [note.id, note]));
    this.indexedWrites = writes;
    return this.searchHits(query, generation);
  }
  private async searchHits(
    query: string,
    generation: number,
  ): Promise<NoteSearchHit[]> {
    if (!this.searchWorker) throw new Error("Search locked");
    const hits = await this.searchWorker.search(query);
    if (!this.key || generation !== this.generation)
      throw new Error("Vault locked");
    return hits.flatMap((hit) => {
      const note = this.indexedSummaries.get(hit.id);
      return note ? [{ ...note, line: hit.line }] : [];
    });
  }
  async createRecoveryFile() {
    if (!this.key) throw new Error("Vault locked");
    const generation = this.generation;
    const file = await generateRecoveryFile(
      this.key,
      this.context("recovery", "vault-key-v1"),
    );
    if (!this.key || generation !== this.generation)
      throw new Error("Vault locked");
    return file;
  }
  lock(): void {
    this.generation++;
    this.storedCache.clear();
    this.searchWorker?.lock();
    this.searchWorker = null;
    this.metadataCache.clear();
    this.sourceCache.clear();
    this.clearAttachments();
    this.indexedNotes.clear();
    this.indexedSummaries.clear();
    this.indexedWrites = "";
    this.searchQueue = Promise.resolve();
    this.key?.fill(0);
    this.key = null;
    this.signer?.privateKey.fill(0);
    this.signer = null;
    this.trustLosses.clear();
    this.origins.clear();
    this.authorityListeners.clear();
    this.written.clear();
    this.digests.clear();
    this.database.close();
  }
}
export const createSession = (options: SessionOptions) =>
  new VaultSession(options);
