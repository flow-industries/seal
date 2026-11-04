import { z } from "zod";
import {
  accessHeaderCommitment,
  accessSlotsSchema,
} from "../crypto/access-v2.ts";
import {
  acceptAccess,
  accessSaltFor,
  listsRecipient,
  type PinnedAccess,
  type RecipientRef,
  rootMetadataSchema,
  type VaultAccess,
} from "../crypto/access-v3.ts";
import {
  baseChunkCount,
  CHUNK_BYTES,
  type ContainerBase,
  type ContainerManifest,
  containerBlobCount,
  containerChunkCount,
  decryptContainerChunks,
  decryptContainerJournal,
  decryptContainerRoot,
  encryptContainer,
  encryptContainerBase,
  encryptContainerJournal,
  JOURNAL_PLAINTEXT_BYTES,
  type JsonValue,
  MAX_CHUNKS,
  ROOT_BYTES,
  resealContainerRoot,
} from "../crypto/container.ts";
import { SyncFailure } from "./records.ts";
import {
  applyJournal,
  decodeJournal,
  decodeSnapshot,
  type EntryStamp,
  encodeJournal,
  encodeSnapshot,
  entryStamps,
  type JournalFootprint,
  journalFootprint,
  journalSince,
  MAX_SNAPSHOT_BYTES,
  type SnapshotEntry,
  VaultAccessError,
  type VaultSnapshotTransport,
} from "./vault-snapshot.ts";

/**
 * Every reader of journaled (v3) roots shipped before this writer, so rolling
 * back to the release before it lands on a client that reads them and writes v2.
 */
const WRITE_JOURNAL = true;
const MIN_SUPERSEDED_BYTES = 1024 * 1024;
/**
 * A new base is charged beside the record it replaces until the `put`, and the
 * managed PDS counts both against this quota. It copies `STORAGE_LIMIT_BYTES` in
 * auth's managed-pds, so raising that means raising this.
 */
export const MANAGED_QUOTA_BYTES = 512_000_000;
const TOO_LARGE = "Notepad too large to sync";

const opaque = z.string().min(1).max(512);
export const vaultBlobSchema = z
  .object({
    $type: z.literal("blob"),
    ref: z.object({ $link: opaque }).strict(),
    mimeType: z.literal("application/octet-stream"),
    size: z.literal(CHUNK_BYTES),
  })
  .strict();
export const vaultRecordSchema = z
  .object({
    $type: z.literal("industries.flow.note.vault"),
    version: z.literal(2),
    accessSalt: z.string().length(43),
    access: accessSlotsSchema,
    root: z
      .object({
        version: z.literal(2),
        nonce: z.string().length(16),
        ciphertext: z.string().length(Math.ceil(((ROOT_BYTES - 12) * 4) / 3)),
      })
      .strict(),
    blobs: z.array(vaultBlobSchema).min(1).max(MAX_CHUNKS),
  })
  .strict()
  .refine((record) => (record.blobs.length & (record.blobs.length - 1)) === 0);
export type VaultRecordV2 = z.infer<typeof vaultRecordSchema>;
/**
 * Two independent "version 3" formats meet in the root, and either may appear
 * without the other: `manifest.version` 3 is a journaled container (base plus
 * journal chunk), and `metadata.version` 3 is signed access (a statement whose
 * salt the header must carry; unsigned metadata has no version).
 */
export async function readVerifiedVaultRoot(
  key: Uint8Array,
  did: string,
  record: VaultRecordV2,
) {
  const manifest = await decryptContainerRoot(key, { did }, record.root);
  const metadata = rootMetadataSchema.parse(manifest.metadata);
  const signedAccess = "version" in metadata;
  if (
    metadata.accessCommitment !==
      (await accessHeaderCommitment({
        accessSalt: record.accessSalt,
        access: record.access,
      })) ||
    containerBlobCount(manifest) !== record.blobs.length ||
    metadata.recipients.length > record.access.length ||
    (signedAccess &&
      (metadata.epoch !== manifest.epoch ||
        (await accessSaltFor(metadata, {
          did,
          vault: manifest.vault,
          epoch: manifest.epoch,
        })) !== record.accessSalt))
  )
    throw new Error("Vault header authentication failed");
  return { manifest, metadata };
}
/** The verified base a journal write may reuse. */
export interface JournalBase {
  base: ContainerBase;
  blobs: VaultRecordV2["blobs"];
  stamps: ReadonlyMap<string, EntryStamp>;
  compactAt: number;
}
/** A verified record's base, for a writer publishing over that record under the same key. */
export interface VerifiedBase {
  cid: string;
  base: JournalBase;
}
/**
 * The last record this transport verified or wrote, keyed by its CID so a
 * write never pairs one read's access header or base with another read's
 * record. A fresh writer holds an access change that no record carries yet:
 * `cid` is null until its first read or write, unless a reader handed it the
 * record that change replaces.
 */
interface VerifiedRecord {
  cid: string | null;
  access: VaultAccess;
  /** The statement this device accepted; it moves only after `onPinned` persists it. */
  pinned: PinnedAccess | null;
  base: JournalBase | null;
  /** How many blobs the record at `cid` holds. */
  blobs: number;
}
async function openVaultSnapshot(
  key: Uint8Array,
  did: string,
  manifest: ContainerManifest,
  chunks: Uint8Array[],
): Promise<{ base: SnapshotEntry[]; entries: SnapshotEntry[] }> {
  if (chunks.length !== containerBlobCount(manifest))
    throw new Error("Incomplete vault chunks");
  const plaintext = await decryptContainerChunks(
    key,
    { did },
    manifest,
    chunks.slice(0, manifest.chunkCount),
  );
  let journal: Uint8Array | undefined;
  try {
    const journaled = manifest.version === 3;
    const base =
      journaled && manifest.byteLength === 0 ? [] : decodeSnapshot(plaintext);
    if (!journaled) return { base, entries: base };
    journal = await decryptContainerJournal(
      key,
      { did },
      manifest,
      chunks[manifest.chunkCount],
    );
    const changes = decodeJournal(journal);
    if (
      changes.entries.length + changes.removed.length !==
      manifest.journal.entries
    )
      throw new Error("Vault journal count mismatch");
    return { base, entries: applyJournal(base, changes) };
  } finally {
    plaintext.fill(0);
    journal?.fill(0);
  }
}
/** Uniform in the journal chunk's upper half. It varies when one compaction lands; over many compactions the average change rate still shows. */
function compactionPoint(): number {
  const [sample = 0] = crypto.getRandomValues(new Uint32Array(1));
  const half = JOURNAL_PLAINTEXT_BYTES / 2;
  return half + Math.floor((sample / 2 ** 32) * half);
}
/**
 * Whether a write over `base` may stay journal-only. It compacts once the
 * journal outgrows `compactAt`, once it deletes an entry holding blobs, once
 * the base holds more than a quarter of dead bytes, or whenever compacting
 * would drop to a smaller blob count, so deleted blobs and their quota never
 * wait on journal growth alone; a deleted note short enough to inline does wait.
 * While the change fits, a vault keeps journaling if compacting would leave it
 * too large to decode, or if its record fits the managed quota but a new base
 * beside it wouldn't: one delete must not stop sync there. A record past that
 * quota can only be on a self-hosted PDS, so it compacts as usual.
 */
export function staysJournal(
  base: Pick<JournalBase, "base" | "compactAt">,
  journalBytes: number,
  footprint: JournalFootprint,
  limit = MAX_SNAPSHOT_BYTES,
): boolean {
  if (journalBytes > JOURNAL_PLAINTEXT_BYTES) return false;
  if (footprint.snapshotBytes > limit) return true;
  const blobs = base.base.chunkCount + 1;
  const compacted = baseChunkCount(footprint.snapshotBytes);
  if (
    blobs * CHUNK_BYTES <= MANAGED_QUOTA_BYTES &&
    (blobs + compacted + 1) * CHUNK_BYTES > MANAGED_QUOTA_BYTES
  )
    return true;
  return !(
    footprint.erasesBlobs ||
    journalBytes > base.compactAt ||
    footprint.superseded >
      Math.max(base.base.byteLength / 4, MIN_SUPERSEDED_BYTES) ||
    footprint.snapshotBytes <= JOURNAL_PLAINTEXT_BYTES ||
    compacted < base.base.chunkCount
  );
}
function encodeWritableSnapshot(entries: SnapshotEntry[]): Uint8Array {
  const plaintext = encodeSnapshot(entries);
  if (plaintext.length <= MAX_SNAPSHOT_BYTES) return plaintext;
  plaintext.fill(0);
  throw new SyncFailure("too-large", TOO_LARGE);
}
/** Needing exactly 32 chunks, a journaled base couldn't compact beside itself on the managed PDS, while a v2 container can rewrite beside itself. */
function keepsContainer(bytes: number): boolean {
  return (
    2 * (baseChunkCount(bytes) + 1) * CHUNK_BYTES > MANAGED_QUOTA_BYTES &&
    2 * containerChunkCount(bytes) * CHUNK_BYTES <= MANAGED_QUOTA_BYTES
  );
}
/** The blobs a compaction of a snapshot this size uploads. */
function compactionBlobs(bytes: number): number {
  if (keepsContainer(bytes)) return containerChunkCount(bytes);
  if (bytes <= JOURNAL_PLAINTEXT_BYTES) return 1;
  return baseChunkCount(bytes) + 1;
}
export type VaultOperation =
  | { method: "read"; collection: "industries.flow.note.vault"; rkey: "vault" }
  | {
      method: "put";
      collection: "industries.flow.note.vault";
      rkey: "vault";
      record: VaultRecordV2;
      swapRecord: string | null;
    };
export interface VaultTransportRpc {
  // biome-ignore lint/plugin: SDK values are validated at this boundary.
  records(operation: VaultOperation): Promise<unknown>;
  // biome-ignore lint/plugin: SDK values are validated at this boundary.
  upload(bytes: Uint8Array): Promise<unknown>;
  // biome-ignore lint/plugin: SDK values are validated at this boundary.
  download(cid: string): Promise<unknown>;
}
export interface VaultTransportOptions {
  key: Uint8Array;
  did: string;
  vault: string;
  epoch: number;
  /** Written verbatim by every content write; only an unlock-time access change replaces it. */
  access: VaultAccess;
  /** Null only before a device has accepted any signed statement. */
  pinned: PinnedAccess | null;
  ownRecipient?: RecipientRef;
  /** Overrides the release-wide journal switch; tests exercise both formats with it. */
  writeJournal?: boolean;
  /** What a reader verified at the record this writer's access change replaces. */
  over?: VerifiedBase | null;
  /** The account's quota when Flow hosts this PDS; any other PDS has its own limits. */
  quotaBytes?: number;
  onCommitted?: (value: {
    record: VaultRecordV2;
    cid: string;
  }) => Promise<void> | void;
  /** Persists a newly accepted statement before the transport adopts it; the read fails if this throws. */
  onPinned?: (value: {
    pinned: PinnedAccess;
    record: VaultRecordV2;
    cid: string;
  }) => Promise<void> | void;
}
const failureReasons = new Map<string, SyncFailure["reason"]>([
  ["CONFLICT", "conflict"],
  ["QUOTA", "quota"],
  ["RATE_LIMITED", "rate-limited"],
  ["CONSENT_REQUIRED", "consent"],
  ["RECONNECT_REQUIRED", "consent"],
  ["ACCOUNT_CHANGED", "consent"],
]);
export class AuthVaultTransport implements VaultSnapshotTransport {
  readonly version = 2;
  private key: Uint8Array;
  private verified: VerifiedRecord;
  private writesJournal: boolean;
  private stopped = false;
  private rpc: VaultTransportRpc;
  private options: VaultTransportOptions;
  constructor(rpc: VaultTransportRpc, options: VaultTransportOptions) {
    this.rpc = rpc;
    this.options = { ...options, key: new Uint8Array(), over: null };
    this.key = options.key.slice();
    this.verified = {
      cid: options.over?.cid ?? null,
      access: structuredClone(options.access),
      pinned: structuredClone(options.pinned),
      base: options.over?.base ?? null,
      blobs: options.over ? options.over.base.blobs.length + 1 : 0,
    };
    this.writesJournal = options.writeJournal ?? WRITE_JOURNAL;
  }
  stop(): void {
    this.stopped = true;
    this.key.fill(0);
    this.verified = { ...this.verified, base: null };
  }
  private active(): void {
    if (this.stopped) throw new Error("Vault locked");
  }
  /** The access this transport last verified or wrote. */
  currentAccess(): VaultAccess {
    return structuredClone(this.verified.access);
  }
  /** What a writer may reuse over the record last verified here, when one has a base and the writer holds the same key. */
  verifiedBase(): VerifiedBase | null {
    const { cid, base } = this.verified;
    return cid !== null && base ? { cid, base } : null;
  }
  private async verifyRemote<T>(verify: () => T | Promise<T>): Promise<T> {
    try {
      const result = await verify();
      this.active();
      return result;
    } catch {
      this.stop();
      throw new VaultAccessError("Couldn’t verify your notepad. Unlock again.");
    }
  }
  private async request(
    // biome-ignore lint/plugin: The SDK response is parsed by its operation-specific caller.
    run: () => Promise<unknown>,
    missing = false,
    // biome-ignore lint/plugin: The operation-specific caller parses this SDK boundary response.
  ): Promise<unknown> {
    this.active();
    try {
      const value = await run();
      const failure = z.object({ code: z.string() }).safeParse(value);
      if (failure.success) throw failure.data;
      this.active();
      return value;
    } catch (error) {
      const code = z.object({ code: z.string() }).safeParse(error);
      if (
        missing &&
        code.success &&
        ["NOTE_NOT_FOUND", "NOT_FOUND", "RECORD_NOT_FOUND"].includes(
          code.data.code,
        )
      )
        return null;
      if (!code.success) throw error;
      // Flow ID refuses a revoked device's refresh with INVALID_GRANT; retrying can't help.
      if (
        code.data.code === "INVALID_RESPONSE" ||
        code.data.code === "INVALID_GRANT"
      ) {
        this.stop();
        throw new VaultAccessError(
          "Couldn’t verify your notepad. Unlock again.",
        );
      }
      throw new SyncFailure(
        failureReasons.get(code.data.code) ?? "offline",
        "Encrypted sync unavailable",
      );
    }
  }
  /** The current record and its verified root, for this vault at this epoch. */
  private async readRoot() {
    const value = await this.request(
      () =>
        this.rpc.records({
          method: "read",
          collection: "industries.flow.note.vault",
          rkey: "vault",
        }),
      true,
    );
    if (value === null) {
      this.stop();
      throw new VaultAccessError(
        "Your notepad is no longer available. Unlock again.",
      );
    }
    const stored = await this.verifyRemote(() =>
      z
        .object({ cid: opaque, uri: opaque, value: vaultRecordSchema })
        .parse(value),
    );
    const { manifest, metadata } = await this.verifyRemote(async () => {
      if (
        stored.uri !==
        `at://${this.options.did}/industries.flow.note.vault/vault`
      )
        throw new Error("Vault identity mismatch");
      return readVerifiedVaultRoot(this.key, this.options.did, stored.value);
    });
    if (
      manifest.vault !== this.options.vault ||
      manifest.epoch !== this.options.epoch
    ) {
      this.stop();
      throw new VaultAccessError("Your notepad changed. Unlock again.");
    }
    return { stored, manifest, metadata };
  }
  async readSnapshot() {
    const { stored, manifest, metadata } = await this.readRoot();
    const pinned = await this.verifyRemote(() =>
      acceptAccess(
        metadata,
        { did: this.options.did, vault: manifest.vault, epoch: manifest.epoch },
        this.verified.pinned,
      ),
    );
    const own = this.options.ownRecipient;
    if (own && !listsRecipient(metadata, own)) {
      this.stop();
      throw new VaultAccessError("Your notepad access changed. Unlock again.");
    }
    const chunks: Uint8Array[] = [];
    for (const blob of stored.value.blobs) {
      const response = await this.request(() =>
        this.rpc.download(blob.ref.$link),
      );
      const bytes = await this.verifyRemote(() => {
        const bytes = z.instanceof(Uint8Array).parse(response);
        if (bytes.length !== CHUNK_BYTES)
          throw new Error("Vault chunk size mismatch");
        return bytes;
      });
      chunks.push(bytes);
    }
    const snapshot = await this.verifyRemote(() =>
      openVaultSnapshot(this.key, this.options.did, manifest, chunks),
    );
    this.active();
    if (pinned && pinned.statement !== this.verified.pinned?.statement) {
      await this.options.onPinned?.({
        pinned,
        record: stored.value,
        cid: stored.cid,
      });
      this.active();
    }
    this.verified = {
      cid: stored.cid,
      access: {
        header: {
          accessSalt: stored.value.accessSalt,
          access: stored.value.access,
        },
        metadata,
      },
      pinned: pinned ?? this.verified.pinned,
      base:
        manifest.version === 3 && this.writesJournal
          ? {
              base: {
                generation: manifest.generation,
                byteLength: manifest.byteLength,
                chunkCount: manifest.chunkCount,
                chunkHashes: manifest.chunkHashes,
              },
              blobs: stored.value.blobs.slice(0, manifest.chunkCount),
              stamps: entryStamps(snapshot.base),
              compactAt: manifest.journal.compactAt,
            }
          : null,
      blobs: stored.value.blobs.length,
    };
    await this.options.onCommitted?.({
      record: stored.value,
      cid: stored.cid,
    });
    this.active();
    return { cid: stored.cid, entries: snapshot.entries, access: metadata };
  }
  private async uploadChunk(chunk: Uint8Array) {
    const response = await this.request(() => this.rpc.upload(chunk));
    const uploaded = await this.verifyRemote(() =>
      z.object({ blob: vaultBlobSchema }).parse(response),
    );
    return uploaded.blob;
  }
  private async publishJournal(
    target: JournalBase,
    baseChunks: Uint8Array[],
    journal: { plaintext: Uint8Array; entries: number },
    metadata: JsonValue,
  ) {
    const sealed = await encryptContainerJournal(
      this.key,
      this.options,
      target.base,
      { ...journal, compactAt: target.compactAt },
      metadata,
    );
    const blobs = [...target.blobs];
    for (const chunk of [...baseChunks, sealed.chunk])
      blobs.push(await this.uploadChunk(chunk));
    return {
      root: sealed.root,
      blobs,
      base: { ...target, blobs: blobs.slice(0, target.base.chunkCount) },
    };
  }
  private async publishContainer(
    entries: SnapshotEntry[],
    metadata: JsonValue,
  ) {
    const plaintext = encodeWritableSnapshot(entries);
    let container: Awaited<ReturnType<typeof encryptContainer>>;
    try {
      container = await encryptContainer(
        this.key,
        this.options,
        plaintext,
        metadata,
      );
    } finally {
      plaintext.fill(0);
    }
    const blobs = [];
    for (const chunk of container.chunks)
      blobs.push(await this.uploadChunk(chunk));
    return { root: container.root, blobs, base: null };
  }
  /**
   * Uploads only a journal chunk over the base last verified at
   * `expectedCid`, unless `staysJournal` says to compact: everything then
   * moves into a fresh base, or into the journal alone when it fits one chunk.
   */
  private async publishSnapshot(
    entries: SnapshotEntry[],
    expectedCid: string | null,
    metadata: JsonValue,
  ): Promise<{
    root: VaultRecordV2["root"];
    blobs: VaultRecordV2["blobs"];
    base: JournalBase | null;
  }> {
    if (!this.writesJournal) return this.publishContainer(entries, metadata);
    const previous =
      this.verified.cid === expectedCid ? this.verified.base : null;
    if (previous?.base.chunkCount) {
      const changes = journalSince(previous.stamps, entries);
      const plaintext = encodeJournal(changes);
      try {
        if (
          staysJournal(
            previous,
            plaintext.length,
            journalFootprint(previous.stamps, changes),
          )
        )
          return await this.publishJournal(
            previous,
            [],
            {
              plaintext,
              entries: changes.entries.length + changes.removed.length,
            },
            metadata,
          );
      } finally {
        plaintext.fill(0);
      }
    }
    const whole = encodeWritableSnapshot(entries);
    try {
      const live = this.verified.cid === expectedCid ? this.verified.blobs : 0;
      const { quotaBytes } = this.options;
      // A write that can't fit beside the record it replaces would only leave its uploads charged for a day, holding the space a delete needs.
      if (
        quotaBytes &&
        (live + compactionBlobs(whole.length)) * CHUNK_BYTES > quotaBytes
      )
        throw new SyncFailure("too-large", TOO_LARGE);
      if (keepsContainer(whole.length))
        return await this.publishContainer(entries, metadata);
      const inline = whole.length <= JOURNAL_PLAINTEXT_BYTES;
      const fresh = await encryptContainerBase(
        this.key,
        this.options,
        inline ? new Uint8Array() : whole,
      );
      return await this.publishJournal(
        {
          base: fresh.base,
          blobs: [],
          stamps: entryStamps(inline ? [] : entries),
          compactAt: compactionPoint(),
        },
        fresh.chunks,
        inline
          ? { plaintext: whole, entries: entries.length }
          : { plaintext: encodeSnapshot([]), entries: 0 },
        metadata,
      );
    } finally {
      whole.fill(0);
    }
  }
  async writeSnapshot(
    entries: SnapshotEntry[],
    expectedCid: string | null,
  ): Promise<{ cid: string }> {
    this.active();
    if (this.verified.cid !== null && this.verified.cid !== expectedCid)
      throw new SyncFailure("conflict", "Encrypted sync unavailable");
    const { header, metadata } = this.verified.access;
    const published = await this.publishSnapshot(
      entries,
      expectedCid,
      metadata,
    );
    return this.putRecord(
      {
        $type: "industries.flow.note.vault",
        version: 2,
        ...header,
        root: published.root,
        blobs: published.blobs,
      },
      expectedCid,
      published.base,
    );
  }
  /**
   * Publishes this transport's access over the record at `expectedCid`, keeping
   * its chunks and so everything in them. Nothing is read but the record and
   * nothing uploaded, so a vault too large to rewrite beside itself can still
   * change access, a chunk the PDS can't serve doesn't stand in the way, and a
   * failure leaves no blob behind. The caller must not be changing the key.
   */
  async resealRoot(expectedCid: string): Promise<{ cid: string }> {
    this.active();
    if (this.verified.cid !== null && this.verified.cid !== expectedCid)
      throw new SyncFailure("conflict", "Encrypted sync unavailable");
    const { stored, manifest } = await this.readRoot();
    if (stored.cid !== expectedCid)
      throw new SyncFailure("conflict", "Encrypted sync unavailable");
    const { header, metadata } = this.verified.access;
    return this.putRecord(
      {
        ...stored.value,
        ...header,
        root: await resealContainerRoot(
          this.key,
          this.options.did,
          manifest,
          metadata,
        ),
      },
      expectedCid,
      null,
    );
  }
  private async putRecord(
    next: VaultRecordV2,
    expectedCid: string | null,
    base: JournalBase | null,
  ): Promise<{ cid: string }> {
    const record = vaultRecordSchema.parse(next);
    this.active();
    const response = await this.request(() =>
      this.rpc.records({
        method: "put",
        collection: "industries.flow.note.vault",
        rkey: "vault",
        record,
        swapRecord: expectedCid,
      }),
    );
    const result = await this.verifyRemote(() => {
      const result = z.object({ cid: opaque, uri: opaque }).parse(response);
      if (
        result.uri !==
        `at://${this.options.did}/industries.flow.note.vault/vault`
      )
        throw new Error("Vault write identity mismatch");
      return result;
    });
    this.active();
    this.verified = {
      ...this.verified,
      cid: result.cid,
      base,
      blobs: record.blobs.length,
    };
    await this.options.onCommitted?.({ record, cid: result.cid });
    this.active();
    return { cid: result.cid };
  }
}
