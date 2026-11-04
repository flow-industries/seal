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
import type { NoteView, StrandedEdits, SyncListener } from "../app/runtime.ts";
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
  verifyLinkHandoff,
} from "../crypto/link.ts";
import {
  AuthVaultTransport,
  readVerifiedVaultRoot,
  type VaultRecordV2,
  vaultRecordSchema,
} from "../sync/vault-transport.ts";
import type { TrustLoss, VaultSession } from "../vault/session.ts";
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
   * Saves what the person typed, judged against the revision they edited.
   * A new `id` creates the note and a new `path` moves it; a save that
   * changes nothing writes nothing. An existing note saved without a
   * revision this device can place throws `NoteChangedError`.
   */
  saveNote(note: DeviceNote): Promise<void>;
  rename(id: string, path: string): Promise<void>;
  /** Moves the note to the trash. */
  remove(id: string): Promise<void>;
  compose(request: ComposeRequest): Promise<{ selectedId: string }>;
  /** Writes sync on their own; this syncs now. */
  sync(): Promise<void>;
  /** `SYNC_LOCKED` means the device lost access and the keys are gone: open it again to learn why. */
  subscribe(listener: SyncListener): () => void;
  subscribeChanges(listener: () => void): () => void;
  /** Hears about every write that left another admin's code unsigned, or its links stale. */
  subscribeTrustLoss(listener: (loss: TrustLoss) => void): () => void;
  /** Edits a rotation left in the earlier epoch's local database. */
  stranded?: StrandedEdits;
  /** Wipes the vault and signing keys; writes not yet synced wait in the local database for the next open. */
  stop(): void;
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

/**
 * What this device asks Flow ID to link: its public keys, the commitment to
 * its secret, and its signature over both. `NoteDeviceRequest` names the last
 * two from SDK 0.36.0; until NOTE moves to it they travel through the
 * request unchanged.
 */
type AuthorizeRequest = NoteDeviceRequest & {
  commitment: string;
  proof: string;
};
async function authorizeRequest(
  seed: Uint8Array,
  kind: NoteDeviceKind,
  label: string,
  secret: string,
): Promise<AuthorizeRequest> {
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
  let vault: DeviceVault | undefined;
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
      vault = sessionVault(session, runtime, transport);
      return runtime;
    },
  };
  const { stranded } = await unlockVaultWithSeed(port, seed);
  if (!vault) throw new Error("Vault locked");
  return stranded ? { ...vault, stranded } : vault;
}

/** Only these closures leave the client: the session, its keys and the transport stay behind them. */
function sessionVault(
  session: VaultSession,
  runtime: ReturnType<typeof synchronizedRuntime>,
  transport: AuthVaultTransport,
): DeviceVault {
  let stopped = false;
  return {
    read: () => runtime.read(),
    async saveNote(note) {
      const { revision, digest } = note;
      const base = revision && digest ? { revision, digest } : undefined;
      if (!(await session.places(note.id, base))) throw new NoteChangedError();
      await runtime.save({
        ...note,
        kind: /\.mdx$/iu.test(note.path) ? "mdx" : "md",
      });
    },
    async rename(id, path) {
      if (stopped) throw new Error("Vault locked");
      if (isInternalWritingPath(path))
        throw new Error("This path is reserved for vault preferences.");
      await session.rename(id, path);
    },
    remove: (id) => runtime.remove(id),
    compose: (request) => runtime.compose(request),
    sync: () => runtime.sync(),
    subscribe: (listener) => runtime.subscribe(listener),
    subscribeChanges: (listener) => runtime.subscribeChanges(listener),
    subscribeTrustLoss: (listener) => runtime.subscribeTrustLoss(listener),
    stop() {
      stopped = true;
      transport.stop();
      runtime.lock();
    },
  };
}
