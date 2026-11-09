import {
  authorizeNoteDevice,
  createNoteDeviceTransport,
  type NoteDeviceCredentialStore,
  type NoteDeviceFetch,
  type NoteDeviceKind,
  type NoteDeviceRequest,
  NoteTransportError,
  pollNoteDeviceToken,
} from "@flow-industries/id";
import sodium from "libsodium-wrappers-sumo";
import { z } from "zod";
import type {
  NoteView,
  StrandedEdits,
  SyncListener,
  SyncReport,
} from "../app/runtime.ts";
import { synchronizedRuntime } from "../app/synchronized-runtime.ts";
import {
  type Checkpoint,
  type SeedUnlockPort,
  unlockVaultWithSeed,
} from "../app/unlock.ts";
import {
  acceptAccess,
  createSeedRecipient,
  listsRecipient,
  openWithSeed,
  pinnedAccessSchema,
  seedSigningKey,
} from "../crypto/access-v3.ts";
import type { EntryRunner } from "../crypto/authorship.ts";
import {
  createLinkSecret,
  deviceAuthorizeMessage,
  formatPairingCode,
  type LinkedCheckpoint,
  linkCommitment,
  normalizeUserCode,
  verifyLinkHandoff,
} from "../crypto/link.ts";
import {
  AuthVaultTransport,
  readVerifiedVaultRoot,
  type VaultRecordV2,
  vaultRecordSchema,
} from "../sync/vault-transport.ts";
import type {
  AssetSummary,
  MoveOptions,
  RevisionBase,
  TrustLoss,
  VaultSession,
} from "../vault/session.ts";
import {
  deleteVaultDatabase,
  StaleWriteError,
  type VaultStorage,
  vaultDatabaseNames,
} from "../vault/storage.ts";
import type { ComposeRequest } from "../writing/composer.ts";
import { isInternalWritingPath } from "../writing/preferences.ts";

/**
 * The pin a linked device accepted, with the provenance the approving browser
 * handed over, and the one admin whose MDX it runs by itself: the passkey
 * whose change linked it. Any other admin needs an explicit Run.
 */
export interface DeviceCheckpoint extends LinkedCheckpoint {
  runners: readonly EntryRunner[];
}
/** Where a linked device keeps the pin it accepted; the pin is public, but replacing it resets the device's trust. */
export interface DeviceCheckpointStore {
  read(): Promise<DeviceCheckpoint | null>;
  write(checkpoint: DeviceCheckpoint): Promise<void>;
}
export interface DeviceOptions {
  /** Flow ID's origin, e.g. `https://id.flow.industries`. */
  host: string;
  credentials: NoteDeviceCredentialStore;
  checkpoints: DeviceCheckpointStore;
  fetch?: NoteDeviceFetch;
  /**
   * Flow ID refused the device token, the vault dropped this device, or a
   * link couldn't be verified: wipe its tokens, and its seed unless it will
   * link again. Keep the checkpoint, so a relinked seed can't be walked back
   * to an older statement. The person should also remove the device from
   * the access list, where an unverified link shows as approved but not added.
   */
  onRemoved?(reason: "removed" | "revoked" | "unverified"): Promise<void>;
  /**
   * The IndexedDB this device's local databases live in, for a test or an
   * app that brings its own; Dexie's default otherwise.
   */
  indexedDB?: VaultStorage["indexedDB"];
}
/** What the device shows while the user approves it in a browser. */
export interface LinkPrompt {
  userCode: string;
  verificationUri: string;
  /**
   * The device secret the user types on the link page. Show it, never send
   * it anywhere: Flow ID holds only a slow hash of it, so it can't vouch for
   * keys or a vault of its own choosing.
   */
  pairingCode: string;
  expiresIn: number;
}
export interface LinkOptions extends DeviceOptions {
  label: string;
  kind?: NoteDeviceKind;
  onPrompt(prompt: LinkPrompt): void;
  signal?: AbortSignal;
  /** How long to wait for the approving tab's change once Flow ID has issued the token; at most `PUBLISH_WAIT_MS`. */
  publishTimeoutMs?: number;
}
/** A note as `DeviceVault.read` returned it, or a new one; an existing note's `revision` and `digest` name the revision the person edited. */
export type DeviceNote = Pick<
  NoteView,
  "id" | "path" | "source" | "revision" | "digest"
>;
/**
 * `current`: compare-and-swap. The write is refused with `NoteChangedError`
 * unless its `revision` and `digest` name the stored revision itself, and
 * also when a sync lands mid-write, even one that changed another note: read
 * again and retry. Without it, a base this device can place on an older
 * revision is an edit of that revision, and the write replaces whatever
 * landed since, such as another device's edit a sync brought in after the
 * caller read.
 */
export interface WriteOptions extends MoveOptions {
  current?: boolean;
}

/** An attachment as `DeviceVault.listAttachments` lists it: everything but its bytes. */
export type DeviceAttachment = AssetSummary;
/** An attachment to save; an existing one's `revision` and `digest` name the revision the device's copy came from. */
export interface DeviceAttachmentWrite {
  id: string;
  path: string;
  bytes: Uint8Array;
  /** Defaults to the type the bytes show, else the attachment's earlier type. */
  mime?: string;
  revision?: string;
  digest?: string;
}
/**
 * The linked notepad, through a seed session's own operations only. Every
 * write is signed as this device only when it is the device's own typing,
 * and code another admin signed that a write can't keep signed is left
 * unsigned and reported, never re-signed (`signsAsAdmin` in
 * `src/vault/session.ts`). Nothing here writes or signs a raw entry.
 */
export interface DeviceVault {
  /** Every note with its source; `.mdx` notes carry `origin`, whether their code runs here by itself. */
  read(): Promise<{ notes: NoteView[]; folders: string[] }>;
  /**
   * Saves what the person typed, judged against the revision they edited,
   * and resolves with the revision the saved content now has: pass it as the
   * next save's `revision` and `digest`, with no `read` in between. A new
   * `id` creates the note and a new `path` moves it; a save that changes
   * nothing writes nothing. A move of an older view the person didn't edit
   * keeps the newer text and only renames, so it resolves with that older
   * revision: read the note again to see the text it kept. An edited save of
   * an older view replaces the newer text, unless `options.current` refuses
   * it. An existing note saved without a revision this device can place
   * throws `NoteChangedError`.
   */
  saveNote(note: DeviceNote, options?: WriteOptions): Promise<RevisionBase>;
  /** Every attachment outside the trash, without its bytes. */
  listAttachments(): Promise<DeviceAttachment[]>;
  /** An attachment's bytes, as a copy the caller may zero. */
  readAttachment(id: string): Promise<Uint8Array>;
  /**
   * Saves an attachment's bytes at `path` under the same rules as
   * `saveNote`: it resolves with the revision the bytes now have, a move of
   * an older copy the device didn't change only moves it, and an existing
   * attachment saved without a revision this device can place throws
   * `NoteChangedError`. Paths ending in `.md` or `.mdx` are notes.
   */
  saveAttachment(
    attachment: DeviceAttachmentWrite,
    options?: WriteOptions,
  ): Promise<RevisionBase>;
  /**
   * Moves a note or an attachment and resolves with its new revision. A
   * note's move rewrites the links to it, in the notes `options.repairLinks`
   * selects (every one by default); an attachment's leaves them as written,
   * so save the notes that link to it. A move to the path it already has writes nothing and
   * resolves with its current revision. With `base`, it is refused with
   * `NoteChangedError` unless `base` names the stored revision.
   */
  rename(
    id: string,
    path: string,
    base?: RevisionBase,
    options?: MoveOptions,
  ): Promise<RevisionBase>;
  /** Moves a note or an attachment to the trash; with `base`, only while it names the stored revision. */
  remove(id: string, base?: RevisionBase): Promise<void>;
  compose(request: ComposeRequest): Promise<{ selectedId: string }>;
  /**
   * Writes sync on their own; this syncs now. When a sync is already
   * running, it also waits for one more run after it, so the run it reports
   * holds every save that resolved before the call. Unless something stays
   * queued, such as a run the PDS refused (the status listener then hears
   * something other than `SYNCED`), those saves are on the PDS when it
   * resolves. `read` says whether the run read the vault from the PDS:
   * until one has, what `read()` returns may be only this device's local
   * copy.
   */
  sync(): Promise<SyncReport>;
  /** `SYNC_LOCKED` means the device lost access and the keys are gone: open it again to learn why. */
  subscribe(listener: SyncListener): () => void;
  subscribeChanges(listener: () => void): () => void;
  /** Hears about every write that left another admin's code unsigned, or its links stale. */
  subscribeTrustLoss(listener: (loss: TrustLoss) => void): () => void;
  /** Edits a rotation left in the earlier epoch's local database; `download` is refused once `stop()` began, like every other operation. */
  stranded?: StrandedEdits;
  /**
   * Refuses new operations, lets those already running finish, then wipes
   * the vault and signing keys and stops syncing. Resolves once nothing
   * touches the local database or the PDS any more, so `deleteDeviceStorage`
   * may follow. It never uploads anything itself: writes not yet synced
   * wait in the local database for the next open, so call `sync()` first to
   * send them.
   */
  stop(): Promise<void>;
}
/**
 * Deletes every local database this seed's vault sessions wrote, in every
 * epoch, with any edits not yet synced. Call it after `await vault.stop()`
 * when the device is unlinked; it never touches the PDS or another seed's databases,
 * which `openDeviceVault` names by each seed's recipient id.
 */
export async function deleteDeviceStorage(
  seed: Uint8Array,
  options: Pick<DeviceOptions, "indexedDB"> = {},
): Promise<void> {
  const storage = await deviceStorage(seed, options);
  const suffix = `#${storage.namespace}`;
  for (const name of await vaultDatabaseNames(storage))
    if (name.endsWith(suffix)) await deleteVaultDatabase(name, storage);
}
/** A seed's own databases, named by its recipient id; passkey sessions never carry one. */
async function deviceStorage(
  seed: Uint8Array,
  options: Pick<DeviceOptions, "indexedDB">,
): Promise<VaultStorage & { namespace: string }> {
  return {
    namespace: (await createSeedRecipient(seed, "device")).id,
    ...(options.indexedDB && { indexedDB: options.indexedDB }),
  };
}
/**
 * A save named no revision of an existing note that this device can place,
 * so it can't tell the person's edit from a stale copy: read the note again
 * and reapply the edit.
 */
export class NoteChangedError extends Error {
  constructor() {
    super("This note changed. Read it again.");
  }
}
export const LINK_UNVERIFIED =
  "This device's link couldn't be verified. Link it again.";
/**
 * How long a link may take, on this device's own clock: Flow ID's code
 * lifetime, and never longer whatever Flow ID answers. The secret has only
 * about 2^40 values, so its commitment resists a search only for so long.
 */
export const LINK_WINDOW_MS = 10 * 60_000;
/** The longest a device waits for the approving tab's change once it has its tokens, whatever the caller asks. */
export const PUBLISH_WAIT_MS = 60_000;
/**
 * Milliseconds since it was started, on whichever clock has moved further:
 * the monotonic clock can pause while the machine sleeps, and the wall clock
 * can be stepped back, so neither alone may stretch the link's window.
 */
function stopwatch() {
  const monotonic = performance.now();
  const wall = Date.now();
  return () => Math.max(performance.now() - monotonic, Date.now() - wall);
}
export const LINK_EXPIRED =
  "This device's link wasn't approved within ten minutes. Link it again.";
/** Aborts at `deadline` on the `stopwatch` clock, rounded down because Node's timers refuse fractional milliseconds. */
const abortAt = (deadline: number, elapsed: () => number) =>
  AbortSignal.timeout(Math.max(0, Math.floor(deadline - elapsed())));

/** A fresh seed for one device; the caller keeps it outside the vault, e.g. in the OS keychain. */
export function createDeviceSeed(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

const savedRecord = z
  .object({
    uri: z.string(),
    cid: z.string().min(1).max(512),
    value: vaultRecordSchema,
  })
  .strict();
const missing = z.object({ code: z.literal("NOTE_NOT_FOUND") });
async function readRecord(
  rpc: Pick<ReturnType<typeof createNoteDeviceTransport>, "records">,
  did: string,
  signal?: AbortSignal,
): Promise<{ header: VaultRecordV2; cid: string } | null> {
  try {
    const saved = savedRecord.parse(
      await rpc.records(
        {
          method: "read",
          collection: "industries.flow.note.vault",
          rkey: "vault",
        },
        signal,
      ),
    );
    if (saved.uri !== `at://${did}/industries.flow.note.vault/vault`)
      throw new Error("Vault identity mismatch");
    return { header: saved.value, cid: saved.cid };
  } catch (error) {
    if (missing.safeParse(error).success) return null;
    throw error;
  }
}
function wait(ms: number, signal?: AbortSignal) {
  return new Promise<void>((resolve, reject) => {
    signal?.throwIfAborted();
    const abort = () => {
      clearTimeout(timer);
      reject(signal?.reason);
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", abort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", abort, { once: true });
  });
}

/**
 * The pin the approving admin handed this seed's holder in the change that
 * listed it, or null while that change hasn't landed. Anything else that
 * lists this device without a valid handoff is refused, never trusted.
 */
export async function handedCheckpoint(
  record: { header: VaultRecordV2 },
  seed: Uint8Array,
  did: string,
  secret: string,
): Promise<DeviceCheckpoint | null> {
  const own = await createSeedRecipient(seed, "device");
  let key: Uint8Array;
  try {
    key = (
      await openWithSeed(
        { accessSalt: record.header.accessSalt, access: record.header.access },
        seed,
        did,
      )
    ).key;
  } catch {
    return null;
  }
  try {
    const { manifest, metadata } = await readVerifiedVaultRoot(
      key,
      did,
      record.header,
    );
    if (
      !("version" in metadata) ||
      !metadata.link ||
      !listsRecipient(metadata, own)
    )
      throw new Error(LINK_UNVERIFIED);
    const context = { did, vault: manifest.vault, epoch: manifest.epoch };
    const candidate = {
      vault: manifest.vault,
      epoch: manifest.epoch,
      pinned: await acceptAccess(metadata, context, null),
      trust: metadata.link.trust,
    };
    if (
      !(await verifyLinkHandoff(
        metadata.link,
        seed,
        { secret, did, recipient: own },
        candidate,
      ))
    )
      throw new Error(LINK_UNVERIFIED);
    const linker = metadata.recipients.find(
      (recipient) => recipient.id === metadata.statement.signer,
    );
    if (!linker?.signPublicKey) throw new Error(LINK_UNVERIFIED);
    return {
      ...candidate,
      runners: [
        { recipientId: linker.id, signPublicKey: linker.signPublicKey },
      ],
    };
  } finally {
    key.fill(0);
  }
}

/** What this device asks Flow ID to link: its public keys, the commitment to its secret, and its signature over both. */
async function authorizeRequest(
  seed: Uint8Array,
  kind: NoteDeviceKind,
  label: string,
  secret: string,
): Promise<NoteDeviceRequest> {
  const recipient = await createSeedRecipient(seed, kind, label);
  const keys = {
    kind,
    boxPublicKey: recipient.boxPublicKey,
    signPublicKey: recipient.signPublicKey ?? "",
  };
  const commitment = await linkCommitment(secret, { ...keys, label });
  const signingKey = await seedSigningKey(seed);
  try {
    return {
      ...keys,
      label,
      commitment,
      proof: sodium.to_base64(
        sodium.crypto_sign_detached(
          deviceAuthorizeMessage({ ...keys, commitment }),
          signingKey,
        ),
        sodium.base64_variants.URLSAFE_NO_PADDING,
      ),
    };
  } finally {
    signingKey.fill(0);
  }
}

/**
 * Polls for the device's tokens until `deadline` on this device's clock,
 * however long Flow ID says its code lasts, and refuses tokens that arrive
 * after it, as they can through a `fetch` that ignores the abort.
 */
async function tokensBy(
  deadline: number,
  elapsed: () => number,
  authorization: Awaited<ReturnType<typeof authorizeNoteDevice>>,
  options: LinkOptions,
) {
  const window = abortAt(deadline, elapsed);
  let tokens: Awaited<ReturnType<typeof pollNoteDeviceToken>>;
  try {
    tokens = await pollNoteDeviceToken(
      options.host,
      {
        ...authorization,
        expiresIn: Math.max(0, deadline - elapsed()) / 1000,
      },
      {
        ...(options.fetch && { fetch: options.fetch }),
        signal: options.signal
          ? AbortSignal.any([options.signal, window])
          : window,
      },
    );
  } catch (error) {
    if (
      (window.aborted && !options.signal?.aborted) ||
      (error instanceof NoteTransportError && error.code === "EXPIRED_TOKEN")
    )
      throw new Error(LINK_EXPIRED);
    throw error;
  }
  if (elapsed() >= deadline) throw new Error(LINK_EXPIRED);
  return tokens;
}

/**
 * Links this device to the account the user approves it from: asks Flow ID
 * for a code, shows the user a fresh secret to type in the approving tab,
 * waits for the approval, then accepts only the pin that tab sealed under
 * that secret to this seed. Saves the device's credentials and checkpoint.
 * A user code outside Flow ID's user-code alphabet is refused with
 * `LINK_UNVERIFIED` before the secret is shown, since it could be a secret
 * Flow ID committed its own keys to.
 * The whole link runs on this device's clock: a code Flow ID says lasts
 * longer than `LINK_WINDOW_MS` is refused before the secret is shown, and no
 * token or handoff is taken once that window (plus up to `PUBLISH_WAIT_MS`
 * for the handoff) has passed, however long a read Flow ID holds open: each
 * read is aborted at the deadline, and whatever arrives is checked against
 * it again before it is kept.
 */
export async function linkDevice(
  seed: Uint8Array,
  options: LinkOptions,
): Promise<DeviceCheckpoint> {
  const elapsed = stopwatch();
  const secret = createLinkSecret();
  const transportOptions = options.fetch ? { fetch: options.fetch } : {};
  const authorization = await authorizeNoteDevice(
    options.host,
    await authorizeRequest(
      seed,
      options.kind ?? "device",
      options.label.trim(),
      secret,
    ),
    { ...transportOptions, signal: options.signal },
  );
  if (authorization.expiresIn * 1000 > LINK_WINDOW_MS)
    throw new Error(LINK_EXPIRED);
  // Flow ID picks the user code; one outside the user-code alphabet could be a secret it committed its own keys to, waiting to be typed.
  if (!normalizeUserCode(authorization.userCode))
    throw new Error(LINK_UNVERIFIED);
  options.onPrompt({
    userCode: authorization.userCode,
    verificationUri: authorization.verificationUri,
    pairingCode: formatPairingCode(secret),
    expiresIn: authorization.expiresIn,
  });
  const credentials = await tokensBy(
    LINK_WINDOW_MS,
    elapsed,
    authorization,
    options,
  );
  await options.credentials.write(credentials);
  const rpc = createNoteDeviceTransport(
    options.host,
    options.credentials,
    transportOptions,
  );
  const deadline =
    Math.min(elapsed(), LINK_WINDOW_MS) +
    Math.min(options.publishTimeoutMs ?? PUBLISH_WAIT_MS, PUBLISH_WAIT_MS);
  const readsEnd = abortAt(deadline, elapsed);
  const signal = options.signal
    ? AbortSignal.any([options.signal, readsEnd])
    : readsEnd;
  try {
    for (;;) {
      if (elapsed() >= deadline) throw new Error(LINK_UNVERIFIED);
      const record = await readRecord(rpc, credentials.did, signal);
      if (!record) throw new Error("Existing vault key unavailable");
      const checkpoint = await handedCheckpoint(
        record,
        seed,
        credentials.did,
        secret,
      );
      // A read Flow ID held open past the deadline may carry a handoff it only now could seal.
      if (elapsed() >= deadline) throw new Error(LINK_UNVERIFIED);
      if (checkpoint) {
        await options.checkpoints.write(checkpoint);
        return checkpoint;
      }
      await wait(
        Math.max(
          0,
          Math.min(authorization.interval * 1000, deadline - elapsed()),
        ),
        signal,
      );
    }
  } catch (error) {
    const late = readsEnd.aborted && !options.signal?.aborted;
    // A token without a verified pin opens nothing, but could still overwrite content.
    if (late || (error instanceof Error && error.message === LINK_UNVERIFIED))
      await options.onRemoved?.("unverified");
    if (late) throw new Error(LINK_UNVERIFIED);
    throw error;
  }
}

/**
 * Opens the vault this device was linked to, verified against its saved pin,
 * as a local session that syncs over Flow ID's device token. A newer
 * statement the pin trusts moves the saved checkpoint forward. The local
 * database is IndexedDB, which Node needs installed (e.g. `fake-indexeddb`).
 */
export async function openDeviceVault(
  seed: Uint8Array,
  options: DeviceOptions,
): Promise<DeviceVault> {
  const credentials = await options.credentials.read();
  if (!credentials) throw new Error("This device isn't linked");
  const rpc = createNoteDeviceTransport(
    options.host,
    options.credentials,
    options.fetch ? { fetch: options.fetch } : {},
  );
  const own = await createSeedRecipient(seed, "device");
  const runners = (await options.checkpoints.read())?.runners ?? [];
  // The pin moves with newer statements; who may run MDX here stays the passkey that linked it.
  const save = async (value: Checkpoint) => {
    if (!value.pinned)
      throw new Error("Vault access isn't pinned on this device");
    await options.checkpoints.write({
      vault: value.vault,
      epoch: value.epoch,
      pinned: pinnedAccessSchema.parse(value.pinned),
      trust: value.trust === "handed" ? "handed" : "tofu",
      runners,
    });
  };
  let opened: FencedVault | undefined;
  const port: SeedUnlockPort = {
    current: () => ({
      userId: credentials.userId,
      did: credentials.did,
      recipientId: own.id,
      sessionVersion: 0,
    }),
    checkpoint: () => options.checkpoints.read(),
    saveCheckpoint: save,
    resolve: async () => ({
      did: credentials.did,
      active: true,
      authorized: true,
    }),
    readHeader: () => readRecord(rpc, credentials.did),
    forget: async (reason) => {
      await options.onRemoved?.(reason);
    },
    runners,
    storage: await deviceStorage(seed, options),
    runtime(session, key, state) {
      const transport = new AuthVaultTransport(rpc, {
        key,
        did: credentials.did,
        ...state,
        onPinned: ({ pinned }) =>
          save({
            vault: state.vault,
            epoch: state.epoch,
            pinned,
            trust: state.trust,
          }),
      });
      const runtime = synchronizedRuntime(session, async () => transport);
      opened = sessionVault(session, runtime, transport);
      return runtime;
    },
  };
  const { stranded } = await unlockVaultWithSeed(port, seed);
  if (!opened) throw new Error("Vault locked");
  const { vault, tracked } = opened;
  if (!stranded) return vault;
  // The earlier epoch's database is opened on demand, so after `stop()` and `deleteDeviceStorage` a read would create it again.
  const download = () => tracked(() => stranded.download());
  return { ...vault, stranded: { count: stranded.count, download } };
}

const baseOf = (
  { revision, digest }: { revision?: string; digest?: string },
  { current }: WriteOptions,
) => (revision && digest ? { revision, digest, current } : undefined);
/** A compare-and-swap write that lost its race reads, to the caller, as any other changed note. */
async function swapped<T>(current: boolean, write: () => Promise<T>) {
  try {
    return await write();
  } catch (error) {
    if (current && error instanceof StaleWriteError)
      throw new NoteChangedError();
    throw error;
  }
}
/** A device vault, and the fence its operations run through: refused once `stop()` began, and awaited by it. */
interface FencedVault {
  vault: DeviceVault;
  tracked<T>(operation: () => Promise<T>): Promise<T>;
}
/** Only these closures leave the client: the session, its keys and the transport stay behind them. */
function sessionVault(
  session: VaultSession,
  runtime: ReturnType<typeof synchronizedRuntime>,
  transport: AuthVaultTransport,
): FencedVault {
  let stopped = false;
  let stopping: Promise<void> | undefined;
  const inFlight = new Set<Promise<unknown>>();
  /** Runs one operation on the session, refused once `stop()` began, and tracked so `stop()` can wait for it. */
  function tracked<T>(operation: () => Promise<T>): Promise<T> {
    if (stopped) return Promise.reject(new Error("Vault locked"));
    const work = operation();
    inFlight.add(work);
    const settle = () => inFlight.delete(work);
    work.then(settle, settle);
    return work;
  }
  /** Operations already running finish first, so a save made before `stop()` lands in the outbox rather than failing half-way. */
  async function shutDown() {
    stopped = true;
    if (inFlight.size) await Promise.allSettled(inFlight);
    transport.stop();
    runtime.lock();
    await runtime.settled();
  }
  const vault: DeviceVault = {
    read: () => tracked(() => runtime.read()),
    saveNote: (note, options = {}) =>
      tracked(async () => {
        if (isInternalWritingPath(note.path))
          throw new Error("This path is reserved for vault preferences.");
        const base = baseOf(note, options);
        if (!(await session.places(note.id, base)))
          throw new NoteChangedError();
        return swapped(!!base?.current, () =>
          session.saveNote(note.id, note.path, note.source, undefined, base, {
            repairLinks: options.repairLinks,
          }),
        );
      }),
    listAttachments: () => tracked(() => session.listAssets()),
    readAttachment: (id) => tracked(() => session.openAsset(id)),
    saveAttachment: (attachment, options = {}) =>
      tracked(async () => {
        const { id, path, bytes, mime } = attachment;
        const base = baseOf(attachment, options);
        if (!(await session.places(id, base))) throw new NoteChangedError();
        return swapped(!!base?.current, () =>
          session.saveAsset(id, path, bytes, base, mime),
        );
      }),
    rename: (id, path, base, options = {}) =>
      tracked(async () => {
        if (isInternalWritingPath(path))
          throw new Error("This path is reserved for vault preferences.");
        return swapped(!!base, () =>
          session.rename(id, path, base, { repairLinks: options.repairLinks }),
        );
      }),
    remove: (id, base) =>
      tracked(async () => {
        await swapped(!!base, () => session.remove(id, undefined, base));
      }),
    compose: (request) => tracked(() => runtime.compose(request)),
    sync: () => runtime.sync(),
    subscribe: (listener) => runtime.subscribe(listener),
    subscribeChanges: (listener) => runtime.subscribeChanges(listener),
    subscribeTrustLoss: (listener) => runtime.subscribeTrustLoss(listener),
    stop() {
      stopping ??= shutDown();
      return stopping;
    },
  };
  return { vault, tracked };
}
