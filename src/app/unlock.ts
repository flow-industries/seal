import { z } from "zod";
import {
  createVaultKey,
  type RecoveryFile,
  type RecoveryFileV2,
  recoverVaultKey,
  recoverySeed,
} from "../crypto/index.ts";
import {
  ACCESS_SLOTS,
  type AccessRecipient,
  accessHeaderCommitment,
  createAccessHeader,
  credentialHash,
  NO_ACCESS_SLOT,
  type SlotVersion,
  unwrapAccessKey,
  v2PrfInput,
} from "../crypto/access-v2.ts";
import {
  type AccessContext,
  type AccessSigner,
  acceptAccess,
  createAccess,
  createSeedRecipient,
  isPinnedAdmin,
  type LegacyBinding,
  listsRecipient,
  nextSequence,
  openWithSeed,
  type PinnedAccess,
  passkeyAdmin,
  passkeyBinding,
  pinnedRecipients,
  type RecipientRef,
  type RootMetadata,
  recipientsOf,
  type StatementKind,
  seedRecipientId,
  seedSigner,
  seedSigningKey,
  UNTRUSTED_ACCESS,
  type VaultAccess,
  type VaultRecipient,
} from "../crypto/access-v3.ts";
import type { EntryRunner, EntrySigner, RunPolicy } from "../crypto/authorship.ts";
import { decryptContainerRoot } from "../crypto/container.ts";
import { matchesLinkCommitment, sealLinkHandoff } from "../crypto/link.ts";
import {
  PASSKEY_REQUEST_SKEW_MS,
  PASSKEY_REQUEST_TTL_MS,
  type PasskeyAssertion,
  passkeyRequestChallenge,
  type RegisteredPasskey,
  verifiesPasskeyAssertion,
} from "../crypto/passkey-proof.ts";
import { SyncFailure } from "../sync/records.ts";
import { rekeySnapshot } from "../sync/rekey.ts";
import { type SnapshotEntry, snapshotRemote } from "../sync/vault-snapshot.ts";
import {
  readVerifiedVaultRoot,
  type VaultRecordV2,
  vaultRecordSchema,
} from "../sync/vault-transport.ts";
import { createSession } from "../vault/session.ts";
import { retireVaultDatabase, strandedEdits } from "../vault/storage.ts";
import { LINK_DEVICES } from "./flow-devices.ts";
import { flowIdAnswered } from "./flow-passkeys.ts";
import { localRuntime } from "./local-runtime.ts";
import { ENROLL_PASSKEYS } from "./passkey-request.ts";
import { unconfirmed } from "./recipients.ts";
import {
  AccessRemovedError,
  type DroppedPasskey,
  MIGRATION_PENDING,
  type MigrationConfirmation,
  MigrationConfirmationError,
  MigrationInterruptedError,
  type NoteRuntime,
  PasskeysUnavailableError,
  RecoveryConfirmationError,
  type RecoveryScope,
  RelinkRequiredError,
  SYNC_PENDING,
  type UnlockOptions,
  type UnlockResult,
} from "./runtime.ts";

/**
 * Whether unlock may introduce signed (v3) access into a vault that has none:
 * on create, and when a v2 root migrates, on unlock or recovery, listing only
 * the unlocking passkey (`passkeysToDrop`). A session opens over an unsigned
 * root only when it can't publish: the offline shell, and a migrating write
 * that keeps failing. Such a session runs nothing and vouches for nothing
 * (`NOBODY`), and saves no checkpoint a later migration could count as having
 * held the vault. It shipped off first, so every reader
 * understood v3 before any writer produced it; an image rollback past that
 * reader would lock migrated vaults out. A vault already signed is always
 * re-signed. Device and agent enrollment must not ship while any client still
 * writes v2, since an unsigned root lets any key holder list itself.
 */
export const WRITE_SIGNED_ACCESS = true;
/**
 * The highest root sequence an unpinned recovery continues from. That
 * sequence is unverified, so a hostile one near `MAX_SAFE_INTEGER` must not
 * push the recovery statement past the schema; honest vaults never get near.
 */
const UNPINNED_SEQUENCE_CAP = 2 ** 32;
/** A recovery file whose key no longer opens the vault's root: v1 files bind one epoch, and a rotation retires them. */
export const RECOVERY_SUPERSEDED = "Recovery file superseded";
export interface VaultIdentity {
  userId: string;
  did: string;
  credentialId: string;
  sessionVersion: number;
}
/** A device, agent or recovery holder, known by its recipient id rather than a credential. */
export interface SeedIdentity {
  userId: string;
  did: string;
  recipientId: string;
  sessionVersion: number;
}
export type VaultHeader = VaultRecordV2;
/**
 * How this browser came to trust its pin. A pin accepted from an earlier pin
 * keeps that pin's provenance, so one rooted in first use stays `tofu`.
 * - `created`: this browser made the vault or the epoch, a re-keying recovery
 *   included, or migrated a vault it already held (`migratedState`, `ownMigration`);
 * - `handed`: an admin handed it over (`linkedCheckpoint`);
 * - `tofu`: trusted on first use, as is every pin saved before provenance was
 *   recorded.
 * Only a created or handed pin may sign a change to access.
 */
export type PinTrust = "created" | "handed" | "tofu";
export interface VerifiedVault {
  vault: string;
  epoch: number;
  access: VaultAccess;
  trust: PinTrust;
  /** Null only for an unsigned v2 root. */
  pinned: PinnedAccess | null;
  ownRecipient: RecipientRef;
}
export type PinnedVault = VerifiedVault & { pinned: PinnedAccess };
/** The last vault a device accepted; `pinned` is null or absent until it accepts a signed statement. */
export interface Checkpoint {
  vault: string;
  epoch: number;
  pinned?: PinnedAccess | null;
  /** Absent on checkpoints saved before provenance was recorded, which count as `tofu`. */
  trust?: PinTrust;
}
/** A checkpoint as saved: `trust` only beside a pin, so an unsigned one stays the row earlier releases wrote. */
export type SavedCheckpoint = Checkpoint & { pinned: PinnedAccess | null };
export const savedCheckpoint = (state: VerifiedVault): SavedCheckpoint =>
  state.pinned
    ? {
        vault: state.vault,
        epoch: state.epoch,
        pinned: state.pinned,
        trust: state.trust,
      }
    : { vault: state.vault, epoch: state.epoch, pinned: null };
export type CheckpointPolicy =
  | Checkpoint
  | { resetCandidates: { vault: string; epoch: number }[] };
function matchesCheckpoint(
  value: { vault: string; epoch: number },
  checkpoint: CheckpointPolicy,
) {
  const candidates =
    "resetCandidates" in checkpoint ? checkpoint.resetCandidates : [checkpoint];
  return candidates.some(
    (candidate) =>
      value.vault === candidate.vault && value.epoch >= candidate.epoch,
  );
}
export const lastCheckpoint = (checkpoint: CheckpointPolicy | null) =>
  checkpoint && !("resetCandidates" in checkpoint) ? checkpoint : null;
interface VaultPort<Identity> {
  current(): Identity | null;
  dispose?(): void;
  /**
   * Drops what this device cached about a vault it can no longer open:
   * `removed` when its slot is gone, `revoked` when Flow ID also refused its
   * device credential. Neither may touch the checkpoint, which stays the trust
   * anchor if the device is added again.
   */
  forget?(reason: "removed" | "revoked"): Promise<void>;
  runtime?(
    session: ReturnType<typeof createSession>,
    key: Uint8Array,
    state: VerifiedVault,
  ): NoteRuntime;
  checkpoint(): Promise<CheckpointPolicy | null>;
  saveCheckpoint(value: SavedCheckpoint): Promise<void>;
  resolve(): Promise<{ did: string; active: boolean; authorized: boolean }>;
  readHeader(): Promise<{ header: VaultHeader; cid: string } | null>;
}
export interface UnlockPort extends VaultPort<VaultIdentity> {
  /** `root`: only access changes, under the same key, so only the record is rewritten and no chunk moves. */
  publish(
    key: Uint8Array,
    state: VerifiedVault,
    expectedCid: string | null,
    scope?: "root",
  ): Promise<void>;
  evaluatePrf(input: Uint8Array): Promise<Uint8Array>;
  /**
   * Reads the record verified at `expectedCid` with `from`, re-encrypts its
   * entries and writes them under `to` in one CAS put, returning what it
   * wrote. A record that moved since raises a sync conflict and writes nothing.
   */
  rekey?(
    from: { key: Uint8Array; state: VerifiedVault },
    to: { key: Uint8Array; state: VerifiedVault },
    expectedCid: string,
    reencrypt: (entries: SnapshotEntry[]) => Promise<SnapshotEntry[]>,
  ): Promise<SnapshotEntry[]>;
  /**
   * Flow ID's list of this account's passkeys, and the origin and rpId their
   * assertions must carry. A passkey request is enrolled only when its
   * assertion verifies against a key on that list.
   */
  passkeys?: {
    rpId: string;
    origin: string;
    registered(): Promise<RegisteredPasskey[]>;
  };
  /** Revokes Flow ID's device tokens for these recipients, or for every linked device but those listed in `except`, so none can write once access changes. */
  revokeDevices?(
    recipientIds: readonly string[] | { except: readonly string[] },
  ): Promise<void>;
  prepareLegacyReset?(): Promise<{
    publish(key: Uint8Array, state: VerifiedVault): Promise<void>;
  }>;
}
/**
 * Opens a vault with a holder's seed instead of a PRF; it has no way to change
 * access. `checkpoint()` must return the pin its enrolling admin handed over
 * (`linkedCheckpoint`): a seed holder never trusts on first use.
 */
export type SeedUnlockPort = VaultPort<SeedIdentity> & {
  /** The admins whose MDX this seed's sessions run by itself: for a linked device, the passkey its handoff named. Absent, they run none. */
  runners?: readonly EntryRunner[];
};
/**
 * What an enrolling admin hands a newly linked seed holder, after publishing
 * the change that lists it. A pin is only as trusted as the browser handing
 * it over, so a first-use pin hands over a first-use pin.
 */
export function linkedCheckpoint(state: VerifiedVault): Required<Checkpoint> & {
  pinned: PinnedAccess;
  trust: "handed" | "tofu";
} {
  if (!state.pinned) throw new Error(UNTRUSTED_ACCESS);
  return {
    vault: state.vault,
    epoch: state.epoch,
    pinned: state.pinned,
    trust: state.trust === "tofu" ? "tofu" : "handed",
  };
}
export const FIRST_USE_PIN = "Vault access trusted on first use";
export const UNSIGNED_ACCESS = "Vault access is unsigned";
export const ACCESS_ADMIN_REQUIRED = "Vault access admin required";
export const ALREADY_LISTED = "Vault recipient already listed";
/**
 * The one precondition every access change shares: it is signed only from a
 * pin this browser held before the change began. A pin taken on first use in
 * the same call would let a planted root, which only that pin trusts, be
 * re-signed into every pinned device.
 */
export function earlierPin(checkpoint: CheckpointPolicy | null): PinnedAccess {
  const last = lastCheckpoint(checkpoint);
  if (!last) throw new Error(FIRST_USE_PIN);
  if (!last.pinned) throw new Error(UNSIGNED_ACCESS);
  return last.pinned;
}
export const UNTRUSTED_PIN = "Vault pin trusted on first use";
/** The pin, when this browser created it or was handed it, directly or through the pins it accepted since. */
export function trustedPin(
  checkpoint: CheckpointPolicy | null,
): PinnedAccess | null {
  const last = lastCheckpoint(checkpoint);
  return last?.pinned && last.trust && last.trust !== "tofu"
    ? last.pinned
    : null;
}
/**
 * The precondition for signing any change to access (a removal, a link, an
 * upgrade, a recovery that re-signs over the pin): a pin from before the
 * change that this browser didn't take on first use. A first-use pin may be a
 * planted root's, and signing from it would carry the planter into every
 * pinned device.
 */
export function assertTrustedPin(
  checkpoint: CheckpointPolicy | null,
): PinnedAccess {
  earlierPin(checkpoint);
  const pin = trustedPin(checkpoint);
  if (!pin) throw new Error(UNTRUSTED_PIN);
  return pin;
}
const holder = (identity: VaultIdentity | SeedIdentity) =>
  "credentialId" in identity ? identity.credentialId : identity.recipientId;
export function identityGuard<Identity extends VaultIdentity | SeedIdentity>(
  port: Pick<VaultPort<Identity>, "current">,
  identity: Identity,
) {
  return () => {
    const next = port.current();
    if (
      !next ||
      next.userId !== identity.userId ||
      next.did !== identity.did ||
      holder(next) !== holder(identity) ||
      next.sessionVersion !== identity.sessionVersion
    )
      throw new Error("Account changed");
  };
}
/**
 * Authenticates the root against the header, then accepts its access
 * statement against the device's pin. An epoch above the checkpoint is a
 * re-key. A v3 slot proves the vault was signed, so an unsigned root over it
 * is a downgrade.
 */
export async function verifyHeader(
  key: Uint8Array,
  did: string,
  header: VaultHeader,
  ownRecipient: RecipientRef,
  checkpoint: CheckpointPolicy | null,
  opened: { slotVersion?: SlotVersion; unlocker?: VaultRecipient } = {},
): Promise<VerifiedVault> {
  const { manifest, metadata } = await readVerifiedVaultRoot(key, did, header);
  if (checkpoint && !matchesCheckpoint(manifest, checkpoint))
    throw new Error("Vault rollback or key loss detected");
  if (opened.slotVersion === 3 && !("version" in metadata))
    throw new Error(UNTRUSTED_ACCESS);
  const last = lastCheckpoint(checkpoint);
  const pinned = await acceptAccess(
    metadata,
    { did, vault: manifest.vault, epoch: manifest.epoch },
    last?.pinned ?? null,
    {
      rekeyed: !!last && manifest.epoch > last.epoch,
      unlocker: opened.unlocker,
    },
  );
  if (!listsRecipient(metadata, ownRecipient))
    throw new Error(
      "This connected credential cannot unlock the vault. Use an unlocked device or recovery file.",
    );
  return {
    vault: manifest.vault,
    epoch: manifest.epoch,
    access: {
      header: { accessSalt: header.accessSalt, access: header.access },
      metadata,
    },
    pinned,
    ownRecipient,
    trust: (last?.pinned && last.trust) || "tofu",
  };
}
export const refOf = (recipient: VaultRecipient): RecipientRef => ({
  id: recipient.id,
  boxPublicKey: recipient.boxPublicKey,
});
export const signerOf = (
  recipient: VaultRecipient,
  privateKey: Uint8Array,
): EntrySigner | undefined =>
  recipient.signPublicKey
    ? {
        recipientId: recipient.id,
        signPublicKey: recipient.signPublicKey,
        privateKey,
      }
    : undefined;
export async function signedState(
  key: Uint8Array,
  context: AccessContext,
  statement: {
    kind: StatementKind;
    sequence: number;
    recipients: readonly VaultRecipient[];
    signer: AccessSigner;
    binding?: LegacyBinding;
  },
  trust: PinTrust,
): Promise<PinnedVault> {
  if (statement.recipients.length > ACCESS_SLOTS)
    throw new Error("Vault credential limit reached");
  const access = await createAccess(key, context, statement);
  return {
    vault: context.vault,
    epoch: context.epoch,
    access,
    pinned: await acceptAccess(access.metadata, context, null),
    ownRecipient: refOf(statement.signer.recipient),
    trust,
  };
}
async function unsignedState(
  key: Uint8Array,
  context: AccessContext,
  recipients: AccessRecipient[],
  ownRecipient: RecipientRef,
): Promise<VerifiedVault> {
  if (recipients.length > ACCESS_SLOTS)
    throw new Error("Vault credential limit reached");
  const header = await createAccessHeader(
    key,
    recipients.map((recipient) => recipient.publicKey),
    context.did,
  );
  return {
    vault: context.vault,
    epoch: context.epoch,
    access: {
      header,
      metadata: {
        recipients,
        accessCommitment: await accessHeaderCommitment(header),
      },
    },
    pinned: null,
    ownRecipient,
    trust: "tofu",
  };
}
/** The statement a legacy passkey signs to add its own signing key, and nothing else. */
async function upgradedState(
  key: Uint8Array,
  context: AccessContext,
  metadata: RootMetadata,
  pinned: PinnedAccess | null,
  admin: AccessSigner,
  prf: Uint8Array,
  credentialId: string,
  trust: PinTrust,
) {
  const listed = recipientsOf(metadata).find(
    (recipient) => recipient.id === admin.recipient.id,
  );
  if (!listed) throw new Error(UNTRUSTED_ACCESS);
  const upgraded: VaultRecipient = {
    ...listed,
    signPublicKey: admin.recipient.signPublicKey,
  };
  return signedState(
    key,
    context,
    {
      kind: "upgrade",
      sequence: nextSequence(metadata, pinned),
      recipients: recipientsOf(metadata).map((recipient) =>
        recipient.id === upgraded.id ? upgraded : recipient,
      ),
      signer: { recipient: upgraded, privateKey: admin.privateKey },
      binding: await passkeyBinding(prf, credentialId, context, upgraded),
    },
    trust,
  );
}
/** This passkey's entry; without `signPublicKey` it is a legacy entry that may upgrade itself. */
export const listedSelf = (metadata: RootMetadata, signer: VaultRecipient) =>
  recipientsOf(metadata).find(
    (recipient) =>
      recipient.id === signer.id &&
      recipient.boxPublicKey === signer.boxPublicKey,
  );
/**
 * Re-keys a recovered vault: a new key at the next epoch under `statement`.
 * Whoever changed the root may hold the old key, so, as a rotation does, the
 * entries are re-sealed first, then every linked device the new statement
 * doesn't list loses its Flow ID token, then one CAS put publishes it.
 * Entries come across unsigned, so MDX needs trust once, and entries that won't
 * re-seal are dropped: no reader would accept them either. This browser made
 * the new epoch, so its pin is `created`.
 */
async function rekeyRecovered(
  port: UnlockPort,
  context: AccessContext,
  from: { key: Uint8Array; state: VerifiedVault },
  expectedCid: string,
  statement: Parameters<typeof signedState>[2],
  guard: () => void,
): Promise<{ key: Uint8Array; state: PinnedVault; entries: SnapshotEntry[] }> {
  const revokeDevices = port.revokeDevices?.bind(port);
  if (!port.rekey || !revokeDevices)
    throw new Error("Vault re-key unavailable");
  const next = await createVaultKey();
  try {
    const to = { key: next, epoch: context.epoch + 1 };
    const state = await signedState(
      next,
      { ...context, epoch: to.epoch },
      statement,
      "created",
    );
    const listed = recipientsOf(state.access.metadata).map(
      (recipient) => recipient.id,
    );
    const owner = { did: context.did, vault: context.vault };
    const entries = await port.rekey(
      from,
      { key: next, state },
      expectedCid,
      async (current) => {
        const sealed = await rekeySnapshot(
          current,
          owner,
          { key: from.key, epoch: context.epoch },
          to,
        );
        await revokeDevices({ except: listed });
        guard();
        return sealed.entries;
      },
    );
    return { key: next, state, entries };
  } catch (error) {
    next.fill(0);
    throw error;
  }
}
/**
 * The entries an unsigned root lists that the person must agree to drop before
 * it migrates. A migration lists only this passkey (`ownId`), the one entry it
 * can verify by deriving its keys: credential ids are public, so any key holder
 * could have listed another under a registered id with its own keys. That makes
 * migrating safe whatever Flow ID says, so its answer decides only whether to
 * ask, and no answer can lock anyone out:
 * - it names this passkey: the other entries it names; one it doesn't name
 *   belongs to no passkey that can sign in, and is dropped without asking;
 * - it doesn't, or NOTE can't read it (`flowIdAnswered`): it says nothing about
 *   any other entry, so all of them.
 * Only no answer at all, which trying again can fix, refuses.
 */
async function passkeysToDrop(
  port: Pick<UnlockPort, "passkeys">,
  metadata: RootMetadata,
  ownId: string,
  guard: () => void,
): Promise<DroppedPasskey[]> {
  const others = recipientsOf(metadata)
    .map((recipient) => recipient.id)
    .filter((id) => id !== ownId);
  if (!others.length) return [];
  if (!port.passkeys) throw new PasskeysUnavailableError();
  const answer = await port.passkeys.registered().catch((error) => {
    guard();
    if (!flowIdAnswered(error)) throw new PasskeysUnavailableError();
    return [];
  });
  const registered = new Map(
    await Promise.all(
      answer.map(
        async (passkey) =>
          [await credentialHash(passkey.credentialId), passkey] as const,
      ),
    ),
  );
  guard();
  const named = (id: string): DroppedPasskey => {
    const createdAt = registered.get(id)?.createdAt;
    return createdAt ? { id, createdAt } : { id };
  };
  return registered.has(ownId)
    ? others.filter((id) => registered.has(id)).map(named)
    : others.map(named);
}
/** Whether the person accepted dropping exactly these entries from exactly this root. */
const confirmsMigration = (
  given: MigrationConfirmation | undefined,
  cid: string,
  dropped: readonly DroppedPasskey[],
) =>
  given?.cid === cid &&
  given.dropped.length === dropped.length &&
  dropped.every(({ id }, index) => given.dropped[index] === id);
/**
 * Whether the root a migrating write failed on has moved, perhaps by this very
 * write with its answer lost: then the next unlock can simply look again. Any
 * other failure may keep happening, and must not keep the person from opening
 * their notepad (`MIGRATION_PENDING`).
 */
async function rootMoved(
  port: Pick<UnlockPort, "readHeader">,
  cid: string,
  guard: () => void,
): Promise<boolean> {
  const now = await readRemoteHeader(port, guard).catch(() => null);
  guard();
  return !!now && now.cid !== cid;
}
/**
 * A v2 root's first signed statement, listing only the passkey that signs it
 * (`passkeysToDrop`), so its pin holds nothing it didn't derive. The key under
 * it may still be a planter's: only a browser that already held this vault
 * knows it isn't new, so a fresh browser's pin stays first use. It reads,
 * writes, trusts code and can export a recovery file, but can't change access.
 */
const migratedState = (
  key: Uint8Array,
  context: AccessContext,
  admin: AccessSigner,
  last: Checkpoint | null,
) =>
  signedState(
    key,
    context,
    {
      kind: "migrate",
      sequence: 1,
      recipients: [admin.recipient],
      signer: admin,
    },
    last?.vault === context.vault ? "created" : "tofu",
  );
/**
 * Whether this root is the `migrate` this passkey signed over the unsigned
 * vault this browser holds, at the same epoch, listing only itself. That is
 * what this browser records when it migrates (`migratedState`), and nobody
 * without this passkey's PRF can produce it. So a browser whose own write lost
 * its answer, or whose other browser got there first, isn't left on first use.
 */
function ownMigration(
  { access: { metadata }, vault, epoch }: VerifiedVault,
  last: Checkpoint | null,
  signer: VaultRecipient,
): boolean {
  return (
    !!last &&
    !last.pinned &&
    last.vault === vault &&
    last.epoch === epoch &&
    "version" in metadata &&
    metadata.statement.kind === "migrate" &&
    metadata.statement.sequence === 1 &&
    metadata.statement.signer === signer.id &&
    metadata.recipients.length === 1 &&
    listedSelf(metadata, signer)?.signPublicKey === signer.signPublicKey
  );
}
/**
 * What a v1 recovery does, decided before the passkey prompt from this
 * passkey's id alone, so a re-key is confirmed before anyone is asked for it:
 * - `add`: an unsigned vault this browser never pinned gains this passkey
 *   under the same key, as before signed access;
 * - `migrate`: with `signAccess`, a signed `migrate` listing this passkey
 *   alone, when dropping the rest needs nobody's word (`passkeysToDrop`);
 * - `adopt`: this browser's trusted pin accepts the current statement, and it
 *   lists this passkey;
 * - `rekey`: anything else. A lookalike of this passkey under its id passes
 *   as `adopt` here, and falls back to asking after the prompt.
 */
type LegacyRecoveryPlan =
  | { path: "add"; listed: AccessRecipient[] }
  | { path: "migrate" }
  | { path: "adopt" | "rekey"; accepted: PinnedAccess | null };
async function planLegacyRecovery(
  port: Pick<UnlockPort, "passkeys">,
  metadata: RootMetadata,
  context: AccessContext,
  checkpoint: CheckpointPolicy | null,
  ownId: string,
  signAccess: boolean,
  guard: () => void,
): Promise<LegacyRecoveryPlan> {
  const last = lastCheckpoint(checkpoint);
  if (!("version" in metadata) && !last?.pinned) {
    if (!signAccess) return { path: "add", listed: metadata.recipients };
    const dropped = await passkeysToDrop(port, metadata, ownId, guard);
    return dropped.length
      ? { path: "rekey", accepted: null }
      : { path: "migrate" };
  }
  const pin = trustedPin(checkpoint);
  const accepted =
    pin && last
      ? await acceptAccess(metadata, context, pin, {
          rekeyed: context.epoch > last.epoch,
        }).catch(() => null)
      : null;
  return {
    path:
      accepted &&
      recipientsOf(metadata).some((recipient) => recipient.id === ownId)
        ? "adopt"
        : "rekey",
    accepted,
  };
}
/** What confirming a re-keying recovery gives up, for its prompt: see `RecoveryScope`. */
const recoveryScope = (
  accepted: PinnedAccess | null,
  checkpoint: CheckpointPolicy | null,
): RecoveryScope =>
  accepted ? "replace" : trustedPin(checkpoint) ? "repair" : "fresh";
/**
 * Recovery with a v1 file proves only possession of the vault key, which
 * every writer also holds, and carries no admin key, so it never lists a
 * passkey under a statement other devices refuse. It follows `plan`: `add`,
 * `migrate` and `adopt` keep the key (`adopt` adopts the statement, or
 * upgrades this passkey's legacy entry). Anything else re-keys
 * (`rekeyRecovered`) once the person confirms: a pinned admin of a trusted
 * pin keeps the recipients that pin knew, and any other passkey starts over
 * alone. Either way this passkey signs a `change`, which only it can produce,
 * so its own other browsers follow; a browser pinned to other admins refuses.
 */
async function recoverWithKey(
  port: UnlockPort,
  key: Uint8Array,
  context: AccessContext,
  remote: { access: VaultAccess; cid: string },
  checkpoint: CheckpointPolicy | null,
  admin: AccessSigner,
  passkey: { prf: Uint8Array; credentialId: string },
  plan: LegacyRecoveryPlan,
  confirmed: boolean,
  guard: () => void,
): Promise<{
  key: Uint8Array;
  state: VerifiedVault;
  entries: SnapshotEntry[];
  publish: boolean;
}> {
  const { metadata } = remote.access;
  const signer = admin.recipient;
  const sameKey = (state: VerifiedVault, publish = true) => ({
    key,
    state,
    entries: [],
    publish,
  });
  if (plan.path === "add")
    return sameKey(
      await unsignedState(
        key,
        context,
        [
          ...plan.listed.filter(
            (recipient) => recipient.credentialHash !== signer.id,
          ),
          { credentialHash: signer.id, publicKey: signer.boxPublicKey },
        ],
        refOf(signer),
      ),
    );
  if (plan.path === "migrate")
    return sameKey(
      await migratedState(key, context, admin, lastCheckpoint(checkpoint)),
    );
  const { accepted } = plan;
  const trust = lastCheckpoint(checkpoint)?.trust ?? "tofu";
  const self = accepted && listedSelf(metadata, signer);
  if (accepted && self && !self.signPublicKey)
    return sameKey(
      await upgradedState(
        key,
        context,
        metadata,
        accepted,
        admin,
        passkey.prf,
        passkey.credentialId,
        trust,
      ),
    );
  if (accepted && self?.signPublicKey === signer.signPublicKey)
    return sameKey(
      {
        ...context,
        access: remote.access,
        pinned: accepted,
        ownRecipient: refOf(signer),
        trust,
      },
      false,
    );
  if (!confirmed)
    throw new RecoveryConfirmationError(recoveryScope(accepted, checkpoint));
  const pin = trustedPin(checkpoint);
  // Only an admin the pin already trusted signs what other devices accept; a `recover` by anyone else is refused by all of them, so it can't keep them.
  const repairs = !accepted && pin && (await isPinnedAdmin(signer, pin));
  const kept = repairs ? await pinnedRecipients(metadata, pin) : [];
  return {
    ...(await rekeyRecovered(
      port,
      context,
      {
        key,
        state: {
          ...context,
          access: remote.access,
          pinned: null,
          ownRecipient: refOf(signer),
          trust: "tofu",
        },
      },
      remote.cid,
      {
        kind: "change",
        // An untrusted root's own sequence is attacker-chosen: a pin alone advances it, and with no pin it is capped.
        sequence: pin
          ? pin.sequence + 1
          : Math.min(nextSequence(metadata, null), UNPINNED_SEQUENCE_CAP + 1),
        recipients: [
          ...kept.filter(
            (recipient) =>
              recipient.id !== signer.id && !unconfirmed(recipient),
          ),
          signer,
        ],
        signer: admin,
      },
      guard,
    )),
    publish: false,
  };
}
/** Opens the root a v1 recovery file's key decrypts, at that file's epoch; the caller wipes `key`. */
async function openLegacyRecovery(
  file: RecoveryFile,
  did: string,
  header: VaultHeader,
  checkpoint: CheckpointPolicy | null,
  guard: () => void,
): Promise<{
  key: Uint8Array;
  metadata: RootMetadata;
  context: AccessContext;
}> {
  if (file.context.did !== did)
    throw new Error("Recovery belongs to another vault");
  const key = await recoverVaultKey(file, file.context);
  try {
    guard();
    await decryptContainerRoot(key, { did }, header.root).catch(() => {
      throw new Error(RECOVERY_SUPERSEDED);
    });
    const { manifest, metadata } = await readVerifiedVaultRoot(
      key,
      did,
      header,
    );
    guard();
    if (
      manifest.vault !== file.context.vault ||
      manifest.epoch !== file.context.epoch ||
      (checkpoint && !matchesCheckpoint(manifest, checkpoint))
    )
      throw new Error("Recovery belongs to another vault");
    return {
      key,
      metadata,
      context: { did, vault: manifest.vault, epoch: manifest.epoch },
    };
  } catch (error) {
    key.fill(0);
    throw error;
  }
}
/** Flow ID refuses a revoked device's refresh token with this code; removal always revokes it first. */
const deviceRevoked = z.object({ code: z.literal("INVALID_GRANT") });
/**
 * Opens a vault through a v2 recovery file's own slot, the one its `recovery`
 * admin recipient keeps across rotations, and checks that recipient is listed
 * as a signing admin. The caller wipes `key` and `signer.privateKey`.
 */
async function openRecovery(
  did: string,
  header: VaultHeader,
  checkpoint: CheckpointPolicy | null,
  file: RecoveryFileV2,
  guard: () => void,
): Promise<{ key: Uint8Array; verified: VerifiedVault; signer: AccessSigner }> {
  if (file.did !== did) throw new Error("Recovery belongs to another vault");
  const seed = await recoverySeed(file);
  let signingKey: Uint8Array | undefined;
  let key: Uint8Array | undefined;
  try {
    const recovery = await seedSigner(seed);
    signingKey = recovery.privateKey;
    const opened = await openWithSeed(
      { accessSalt: header.accessSalt, access: header.access },
      seed,
      did,
    ).catch((error) => {
      throw error instanceof Error && error.message === NO_ACCESS_SLOT
        ? new Error(RECOVERY_SUPERSEDED)
        : error;
    });
    key = opened.key;
    guard();
    const verified = await verifyHeader(
      key,
      did,
      header,
      refOf(recovery.recipient),
      checkpoint,
      { slotVersion: opened.version },
    );
    guard();
    if (verified.vault !== file.vault)
      throw new Error("Recovery belongs to another vault");
    const listed = recipientsOf(verified.access.metadata).find(
      (recipient) => recipient.id === recovery.recipient.id,
    );
    if (
      !verified.pinned ||
      listed?.role !== "admin" ||
      listed.signPublicKey !== recovery.recipient.signPublicKey
    )
      throw new Error(UNTRUSTED_ACCESS);
    return {
      key,
      verified,
      signer: { recipient: listed, privateKey: recovery.privateKey },
    };
  } catch (error) {
    key?.fill(0);
    signingKey?.fill(0);
    throw error;
  } finally {
    seed.fill(0);
  }
}
/**
 * Recovers with a v2 file, then signs a `change`, as the recovery admin, that
 * lists the connected passkey.
 * - A device with a trusted pin (`trustedPin`) judges the current statement
 *   by it, keeps the key, and adds this passkey. Devices pinned to the
 *   recovery admin accept it.
 * - A device with no pin, or one it took on first use, can't tell a planted
 *   root from a real one, and a planted root's key is known to whoever
 *   planted it. Nor can it tell a real recipient from a lookalike a planter
 *   listed with its own keys under the real id and label. So, once the person
 *   confirms, it re-keys (`rekeyRecovered`) and lists only the recovery
 *   recipient and this passkey, so every linked device loses its token. Other
 *   passkeys re-add themselves with the recovery file on their own pinned
 *   device, and devices link again.
 */
async function recoverWithSeed(
  port: UnlockPort,
  did: string,
  remote: { header: VaultHeader; cid: string },
  checkpoint: CheckpointPolicy | null,
  file: RecoveryFileV2,
  confirmed: boolean,
  admin: AccessSigner,
  guard: () => void,
): Promise<{
  key: Uint8Array;
  state: VerifiedVault;
  entries: SnapshotEntry[];
  publish: boolean;
}> {
  const opened = await openRecovery(
    did,
    remote.header,
    checkpoint,
    file,
    guard,
  );
  const { verified, signer } = opened;
  let key: Uint8Array | null = opened.key;
  try {
    const { metadata } = verified.access;
    const own = admin.recipient;
    const ownRecipient = refOf(own);
    const context = { did, vault: verified.vault, epoch: verified.epoch };
    if (trustedPin(checkpoint)) {
      const listedOwn =
        listedSelf(metadata, own)?.signPublicKey === own.signPublicKey;
      const state = listedOwn
        ? verified
        : await signedState(
            key,
            context,
            {
              kind: "change",
              sequence: nextSequence(metadata, verified.pinned),
              recipients: [
                ...recipientsOf(metadata).filter(
                  (recipient) => recipient.id !== own.id,
                ),
                own,
              ],
              signer,
            },
            verified.trust,
          );
      const result = {
        key,
        state: { ...state, ownRecipient },
        entries: [],
        publish: !listedOwn,
      };
      key = null;
      return result;
    }
    if (!confirmed) throw new RecoveryConfirmationError();
    const rekeyed = await rekeyRecovered(
      port,
      context,
      { key, state: verified },
      remote.cid,
      {
        kind: "change",
        // This root is unverified, so its sequence is attacker-chosen; it is capped, as in recoverWithKey.
        sequence: Math.min(
          nextSequence(metadata, null),
          UNPINNED_SEQUENCE_CAP + 1,
        ),
        recipients: [signer.recipient, own],
        signer,
      },
      guard,
    );
    return {
      ...rekeyed,
      state: { ...rekeyed.state, ownRecipient },
      publish: false,
    };
  } finally {
    key?.fill(0);
    signer.privateKey.fill(0);
  }
}
/** Publishes `state` and returns the CID of the record that now carries it, for a change that follows. */
async function republished(
  port: Pick<UnlockPort, "publish" | "readHeader">,
  key: Uint8Array,
  did: string,
  state: VerifiedVault,
  expectedCid: string,
  guard: () => void,
): Promise<string> {
  await port.publish(key, state, expectedCid, "root");
  guard();
  const next = await readRemoteHeader(port, guard);
  if (!next) throw new Error("Vault rollback or key loss detected");
  if (next.header.accessSalt !== state.access.header.accessSalt)
    throw new Error("Vault changed during access change");
  await verifyHeader(
    key,
    did,
    next.header,
    state.ownRecipient,
    savedCheckpoint(state),
  );
  guard();
  return next.cid;
}
/** A recipient an admin is adding: a device approved at Flow ID, or a passkey enrolled from its own browser. */
export interface RecipientRequest {
  recipient: VaultRecipient;
  /** Required for a device, absent for a passkey. */
  link?: {
    /**
     * The device secret the user typed from the device. It must match the
     * device's `commitment` to the recipient's kind, label and keys, and it
     * keys the pin handoff; Flow ID never sees it.
     */
    secret: string;
    /** The device's commitment, as Flow ID's `lookup` relayed it. */
    commitment: string;
    /** Approves the device at Flow ID and returns its device id. */
    approve(): Promise<string>;
    /**
     * Revokes whatever Flow ID approved for this recipient: the device id when
     * approve answered, otherwise every device listed with its recipient id.
     * It must throw when it can't confirm the revocation.
     */
    revoke(device: { deviceId?: string; recipientId: string }): Promise<void>;
  };
  /**
   * Required for a passkey, absent for a device: the new passkey's own
   * assertion over its keys (`passkeyRequestChallenge`) at `issuedAt`.
   */
  passkey?: {
    credentialId: string;
    issuedAt: number;
    assertion: PasskeyAssertion;
  };
  /**
   * Shown everyone the change will carry, each marked by whether this
   * browser's earlier pin already trusted it; rejects to cancel. It runs
   * after the vault is verified and before anything is approved or written,
   * and expires after `CONFIRM_WITHIN_MS` so the unlocked keys don't linger.
   */
  confirm(carried: CarriedRecipient[]): Promise<void>;
}
export interface CarriedRecipient {
  recipient: VaultRecipient;
  /** Listed in the statement this browser pinned before this change. */
  trusted: boolean;
  /** The passkey approving this change. */
  self: boolean;
}
/** Flow ID still holds an approval this browser couldn't undo; the person must remove it. */
export class LinkCleanupError extends Error {
  constructor() {
    super("Device approval not undone");
  }
}
/** The change listing the recipient was published, so it stays approved; only this browser's own follow-up failed. */
export class LinkedWithCleanupError extends Error {
  readonly deviceId: string | undefined;
  constructor(deviceId: string | undefined) {
    super("Linked; some cleanup failed");
    this.deviceId = deviceId;
  }
}
export const CONFIRM_EXPIRED = "Vault change confirmation expired";
/** How long `confirm` may keep the vault key, the PRF output and the admin's signing key in memory. */
export const CONFIRM_WITHIN_MS = 120_000;
async function confirmedWithin(confirmation: Promise<void>, ms: number) {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      confirmation,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(CONFIRM_EXPIRED)), ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
export const LINK_SECRET_MISMATCH = "Link secret does not match the device";
export const LINK_CHECK_FAILED = "Link secret could not be checked";
export const PASSKEY_REQUEST_EXPIRED = "Passkey request expired";
export const UNANCHORED_PASSKEY =
  "Passkey request not made by a passkey on this account";
async function checkedRequest({ recipient, link, passkey }: RecipientRequest) {
  if (
    recipient.kind === "passkey" &&
    recipient.signPublicKey &&
    passkey &&
    !link &&
    recipient.id === (await credentialHash(passkey.credentialId))
  )
    return;
  if (
    recipient.kind === "device" &&
    link &&
    !passkey &&
    recipient.id === (await seedRecipientId(recipient.signPublicKey ?? ""))
  ) {
    let matches: boolean;
    try {
      matches = await matchesLinkCommitment(
        link.secret,
        {
          kind: recipient.kind,
          label: recipient.label ?? "",
          boxPublicKey: recipient.boxPublicKey,
          signPublicKey: recipient.signPublicKey ?? "",
        },
        link.commitment,
      );
    } catch {
      throw new Error(LINK_CHECK_FAILED);
    }
    if (!matches) throw new Error(LINK_SECRET_MISMATCH);
    return;
  }
  throw new Error("Invalid vault recipient request");
}
/**
 * A passkey request counts only when the passkey it names is registered to
 * this account at Flow ID and asserted over exactly these keys, for this DID,
 * on NOTE's origin, within the last ten minutes. Without that, a link carries
 * nothing a phisher can't make up.
 */
export async function anchoredPasskey(
  port: Pick<UnlockPort, "passkeys">,
  { recipient, passkey }: RecipientRequest,
  did: string,
  guard: () => void,
) {
  if (!passkey || !port.passkeys || !recipient.signPublicKey)
    throw new Error(UNANCHORED_PASSKEY);
  const age = Date.now() - passkey.issuedAt;
  if (
    !Number.isSafeInteger(passkey.issuedAt) ||
    age > PASSKEY_REQUEST_TTL_MS ||
    age < -PASSKEY_REQUEST_SKEW_MS
  )
    throw new Error(PASSKEY_REQUEST_EXPIRED);
  const registered = (await port.passkeys.registered()).find(
    (listed) => listed.credentialId === passkey.credentialId,
  );
  guard();
  if (
    !registered ||
    !(await verifiesPasskeyAssertion(passkey.assertion, {
      challenge: await passkeyRequestChallenge({
        did,
        boxPublicKey: recipient.boxPublicKey,
        signPublicKey: recipient.signPublicKey,
        issuedAt: passkey.issuedAt,
      }),
      publicKey: registered.publicKey,
      origin: port.passkeys.origin,
      rpId: port.passkeys.rpId,
    }))
  )
    throw new Error(UNANCHORED_PASSKEY);
}
/** Retries a revoke a few times; a lingering approval is worse than a slow one. */
async function undoApproval(
  link: NonNullable<RecipientRequest["link"]>,
  device: { deviceId?: string; recipientId: string },
) {
  for (let attempt = 1; ; attempt++)
    try {
      return await link.revoke(device);
    } catch {
      if (attempt === 3) throw new LinkCleanupError();
      await new Promise((resolve) => setTimeout(resolve, 500 * attempt));
    }
}
/**
 * Adds a device or passkey to a signed vault after one fresh passkey unlock
 * in this call, with a `change` signed by that passkey. The browser's pin
 * must be one it created or was handed (`assertTrustedPin`), never one it
 * trusted on first use; the passkey must be one of its pinned admins, and
 * `confirm` sees everyone the change carries before anything is approved or
 * written, within `confirmWithin`. Before any of that, a device's typed
 * secret must match the commitment it registered for this kind, label and
 * these keys, and a
 * passkey's own assertion must verify against Flow ID's list for this
 * account (`anchoredPasskey`). A device is approved at Flow ID only after
 * confirmation, is revoked again if the publish fails, and gets its pin
 * through the change, sealed under its secret (`sealLinkHandoff`).
 */
export async function addVaultRecipient(
  port: UnlockPort,
  request: RecipientRequest,
  allowed = { devices: LINK_DEVICES, passkeys: ENROLL_PASSKEYS },
  confirmWithin = CONFIRM_WITHIN_MS,
): Promise<{ deviceId?: string }> {
  let key: Uint8Array | undefined;
  let prf: Uint8Array | undefined;
  let admin: AccessSigner | undefined;
  const input = await v2PrfInput();
  try {
    const { recipient, link } = request;
    if (!(recipient.kind === "passkey" ? allowed.passkeys : allowed.devices))
      throw new Error("Vault linking is off");
    await checkedRequest(request);
    const current = port.current();
    if (!current?.credentialId) throw new Error("Connected passkey required");
    const identity = { ...current };
    const { did } = identity;
    const guard = identityGuard(port, identity);
    await requireAuthorizedPds(port, did, guard);
    if (recipient.kind === "passkey")
      await anchoredPasskey(port, request, did, guard);
    const remote = await readRemoteHeader(port, guard);
    const checkpoint = await port.checkpoint();
    guard();
    if (!remote) throw new Error("Existing vault key unavailable");
    const earlier = assertTrustedPin(checkpoint);
    prf = await port.evaluatePrf(input);
    guard();
    if (prf.length !== 32) throw new Error("Actual successful PRF required");
    admin = await passkeyAdmin(prf, identity.credentialId, did);
    guard();
    const signer = admin.recipient;
    const opened = await unwrapAccessKey(
      { accessSalt: remote.header.accessSalt, access: remote.header.access },
      prf,
      identity.credentialId,
      did,
    );
    key = opened.key;
    guard();
    const verified = await verifyHeader(
      key,
      did,
      remote.header,
      refOf(signer),
      checkpoint,
      { slotVersion: opened.version, unlocker: signer },
    );
    guard();
    const { metadata } = verified.access;
    if (!verified.pinned || !("version" in metadata))
      throw new Error(UNTRUSTED_ACCESS);
    if (listsRecipient(metadata, recipient)) throw new Error(ALREADY_LISTED);
    if (
      metadata.recipients.some(
        (listed) =>
          listed.id === recipient.id ||
          listed.boxPublicKey === recipient.boxPublicKey,
      )
    )
      throw new Error("Vault recipient conflict");
    const self = listedSelf(metadata, signer);
    if (!self) throw new Error(ACCESS_ADMIN_REQUIRED);
    const trusted = new Set(
      (await pinnedRecipients(metadata, earlier)).map((listed) => listed.id),
    );
    await confirmedWithin(
      request.confirm(
        metadata.recipients.map((listed) => ({
          recipient: listed,
          trusted: trusted.has(listed.id),
          self: listed.id === signer.id,
        })),
      ),
      confirmWithin,
    );
    guard();
    const context = { did, vault: verified.vault, epoch: verified.epoch };
    let base: VerifiedVault = verified;
    let cid = remote.cid;
    if (!self.signPublicKey) {
      base = await upgradedState(
        key,
        context,
        metadata,
        verified.pinned,
        admin,
        prf,
        identity.credentialId,
        verified.trust,
      );
      cid = await republished(port, key, did, base, cid, guard);
    }
    if (!base.pinned || !(await isPinnedAdmin(signer, base.pinned)))
      throw new Error(ACCESS_ADMIN_REQUIRED);
    const added = await signedState(
      key,
      context,
      {
        kind: "change",
        sequence: nextSequence(base.access.metadata, base.pinned),
        recipients: [...recipientsOf(base.access.metadata), recipient],
        signer: admin,
      },
      base.trust,
    );
    const state: VerifiedVault = link
      ? {
          ...added,
          access: {
            ...added.access,
            metadata: {
              ...added.access.metadata,
              link: await sealLinkHandoff(
                { secret: link.secret, did, recipient },
                linkedCheckpoint(added),
              ),
            },
          },
        }
      : added;
    guard();
    let deviceId: string | undefined;
    try {
      deviceId = await link?.approve();
      guard();
      await port.publish(key, state, cid, "root");
    } catch (error) {
      // Flow ID may have committed an approval whose answer never arrived, so a failed approve is undone by recipient too.
      if (link)
        await undoApproval(link, { deviceId, recipientId: recipient.id });
      throw error;
    }
    // The vault lists the recipient now; undoing its approval would leave a listed device without a token.
    try {
      guard();
      await port.saveCheckpoint(savedCheckpoint(state));
      guard();
    } catch {
      throw new LinkedWithCleanupError(deviceId);
    }
    return { deviceId };
  } finally {
    key?.fill(0);
    prf?.fill(0);
    admin?.privateKey.fill(0);
    input.fill(0);
    port.dispose?.();
  }
}
export async function requireAuthorizedPds(
  port: Pick<VaultPort<unknown>, "resolve">,
  did: string,
  guard: () => void,
) {
  const resolved = await port.resolve();
  guard();
  if (!resolved.active || !resolved.authorized || resolved.did !== did)
    throw new Error("Authorized active PDS required");
}
export async function readRemoteHeader(
  port: Pick<VaultPort<unknown>, "readHeader">,
  guard: () => void,
) {
  const remote = await port.readHeader();
  guard();
  if (remote) {
    remote.header = vaultRecordSchema.parse(remote.header);
    if (!remote.cid || remote.cid.length > 512)
      throw new Error("Invalid vault header CID");
  }
  return remote;
}
/**
 * Pins `state` and opens its epoch's local database. The session copies
 * `signer`'s key and wipes it on lock, so it signs what it writes without the
 * key being stored. `runners` is decided by the caller, which knows whether
 * the device's pin was trusted on first use. After a re-key the last epoch's
 * database is retired, and `entries` (the snapshot the caller just wrote)
 * seed the new one so the notepad isn't empty until the first sync.
 */
export async function openSession<Identity>(
  port: VaultPort<Identity>,
  did: string,
  key: Uint8Array,
  state: VerifiedVault,
  guard: () => void,
  signer: EntrySigner | undefined,
  runners: RunPolicy,
  last: Checkpoint | null,
  entries: readonly SnapshotEntry[] = [],
): Promise<UnlockResult> {
  await port.saveCheckpoint(savedCheckpoint(state));
  guard();
  let stranded: UnlockResult["stranded"];
  if (last?.vault === state.vault && last.epoch < state.epoch) {
    const { epoch } = last;
    const count = await retireVaultDatabase(did, state.vault, epoch).catch(
      () => 0,
    );
    if (count)
      stranded = {
        count,
        download: () => strandedEdits(did, state.vault, epoch),
      };
  }
  const session = createSession({
    owner: did,
    vault: state.vault,
    key,
    epoch: state.epoch,
    authorship: { signer, access: state.access.metadata, runners },
  });
  try {
    for (const entry of entries) {
      const { remote, blobs } = snapshotRemote(entry);
      await session.applyRemote(remote, blobs);
    }
    guard();
    const result: UnlockResult = {
      runtime: port.runtime?.(session, key, state) ?? localRuntime(session),
      status: SYNC_PENDING,
    };
    if (stranded) result.stranded = stranded;
    return result;
  } catch (error) {
    session.lock();
    throw error;
  }
}
/** `signAccess` decides only whether an unsigned vault gains signed access; see `WRITE_SIGNED_ACCESS`. */
export async function unlockVault(
  port: UnlockPort,
  options: UnlockOptions = {},
  signAccess = WRITE_SIGNED_ACCESS,
): Promise<UnlockResult> {
  let key: Uint8Array | undefined;
  let prf: Uint8Array | undefined;
  let admin: AccessSigner | undefined;
  const input = await v2PrfInput();
  try {
    if (options.resetLegacy && (options.setup || options.recovery))
      throw new Error("Choose either reset, setup or recovery");
    const current = port.current();
    if (!current?.credentialId) throw new Error("Connected passkey required");
    const identity = { ...current };
    const guard = identityGuard(port, identity);
    await requireAuthorizedPds(port, identity.did, guard);
    const reset = options.resetLegacy
      ? await port.prepareLegacyReset?.()
      : undefined;
    guard();
    if (options.resetLegacy && !reset)
      throw new Error("Legacy reset unavailable");
    const remote = reset ? null : await readRemoteHeader(port, guard);
    const checkpoint = reset ? null : await port.checkpoint();
    guard();
    if (!remote && checkpoint)
      throw new Error("Vault rollback or key loss detected");
    if (!remote && !reset && (!options.setup || options.recovery))
      throw new Error("Existing vault key unavailable");
    if (
      remote &&
      options.recovery?.version === 2 &&
      !options.confirmRecovery &&
      !trustedPin(checkpoint)
    ) {
      // Asked before the passkey prompt, once the file is known to open this vault.
      const preview = await openRecovery(
        identity.did,
        remote.header,
        checkpoint,
        options.recovery,
        guard,
      );
      preview.key.fill(0);
      preview.signer.privateKey.fill(0);
      throw new RecoveryConfirmationError();
    }
    const legacy =
      remote && options.recovery && options.recovery.version !== 2
        ? await openLegacyRecovery(
            options.recovery,
            identity.did,
            remote.header,
            checkpoint,
            guard,
          )
        : null;
    key = legacy?.key;
    const plan =
      legacy &&
      (await planLegacyRecovery(
        port,
        legacy.metadata,
        legacy.context,
        checkpoint,
        await credentialHash(identity.credentialId),
        signAccess,
        guard,
      ));
    if (plan?.path === "rekey" && !options.confirmRecovery)
      throw new RecoveryConfirmationError(
        recoveryScope(plan.accepted, checkpoint),
      );
    prf = await port.evaluatePrf(input);
    guard();
    if (prf.length !== 32) throw new Error("Actual successful PRF required");
    admin = await passkeyAdmin(prf, identity.credentialId, identity.did);
    guard();
    const signer = admin.recipient;
    const endorser = signerOf(signer, admin.privateKey);
    let state: VerifiedVault;
    let entries: SnapshotEntry[] = [];
    let migrationStuck = false;
    if (!remote) {
      key = await createVaultKey();
      const context = {
        did: identity.did,
        vault: crypto.randomUUID(),
        epoch: 1,
      };
      state = signAccess
        ? await signedState(
            key,
            context,
            {
              kind: "create",
              sequence: 1,
              recipients: [signer],
              signer: admin,
            },
            "created",
          )
        : await unsignedState(
            key,
            context,
            [{ credentialHash: signer.id, publicKey: signer.boxPublicKey }],
            refOf(signer),
          );
      guard();
      if (reset) await reset.publish(key, state);
      else await port.publish(key, state, null);
      guard();
    } else if (options.recovery?.version === 2) {
      const recovered = await recoverWithSeed(
        port,
        identity.did,
        remote,
        checkpoint,
        options.recovery,
        options.confirmRecovery === true,
        admin,
        guard,
      );
      key = recovered.key;
      state = recovered.state;
      entries = recovered.entries;
      guard();
      if (recovered.publish) {
        await port.publish(key, state, remote.cid, "root");
        guard();
      }
    } else if (legacy && plan) {
      const { metadata, context } = legacy;
      // As verifyHeader does: a v3 slot proves the vault was signed, so unsigned metadata over it is a downgrade. Only this passkey's own slot can show it. A pinned device instead re-keys over what its pin trusted (recoverWithKey), which repairs the vault.
      if (!("version" in metadata) && !lastCheckpoint(checkpoint)?.pinned) {
        const own = await unwrapAccessKey(
          {
            accessSalt: remote.header.accessSalt,
            access: remote.header.access,
          },
          prf,
          identity.credentialId,
          identity.did,
        ).catch(() => null);
        own?.key.fill(0);
        if (own?.version === 3) throw new Error(UNTRUSTED_ACCESS);
      }
      const recovered = await recoverWithKey(
        port,
        legacy.key,
        context,
        {
          access: {
            header: {
              accessSalt: remote.header.accessSalt,
              access: remote.header.access,
            },
            metadata,
          },
          cid: remote.cid,
        },
        checkpoint,
        admin,
        { prf, credentialId: identity.credentialId },
        plan,
        options.confirmRecovery === true,
        guard,
      );
      if (recovered.key !== legacy.key) legacy.key.fill(0);
      key = recovered.key;
      state = recovered.state;
      entries = recovered.entries;
      guard();
      if (recovered.publish) {
        await port.publish(key, state, remote.cid, "root");
        guard();
      }
    } else {
      const pin = lastCheckpoint(checkpoint)?.pinned;
      const opened = await unwrapAccessKey(
        { accessSalt: remote.header.accessSalt, access: remote.header.access },
        prf,
        identity.credentialId,
        identity.did,
      ).catch(async (error) => {
        // A pinned admin's slot gone means it was removed, or the header was replaced by someone who can't sign; neither is retried. A seed device learns it from Flow ID instead.
        if (
          error instanceof Error &&
          error.message === NO_ACCESS_SLOT &&
          pin &&
          (await isPinnedAdmin(signer, pin))
        ) {
          await port.forget?.("removed");
          throw new AccessRemovedError();
        }
        throw error;
      });
      key = opened.key;
      guard();
      const read = await verifyHeader(
        key,
        identity.did,
        remote.header,
        refOf(signer),
        checkpoint,
        { slotVersion: opened.version, unlocker: signer },
      );
      guard();
      const verified: VerifiedVault = ownMigration(
        read,
        lastCheckpoint(checkpoint),
        signer,
      )
        ? { ...read, trust: "created" }
        : read;
      const { metadata } = verified.access;
      const context = {
        did: identity.did,
        vault: verified.vault,
        epoch: verified.epoch,
      };
      const self = listedSelf(metadata, signer);
      // An unsigned root would open as a session that runs every MDX in it, so with signed access on it migrates or stays locked.
      const migrates = !verified.pinned && signAccess;
      if (migrates) {
        const dropped = await passkeysToDrop(port, metadata, signer.id, guard);
        if (
          dropped.length &&
          !confirmsMigration(options.confirmMigration, remote.cid, dropped)
        )
          throw new MigrationConfirmationError(remote.cid, dropped);
      }
      // An upgrade is an access change too, so a first-use pin leaves this passkey's entry legacy until the pin is trusted.
      if (
        verified.pinned &&
        self &&
        !self.signPublicKey &&
        verified.trust !== "tofu"
      )
        state = await upgradedState(
          key,
          context,
          metadata,
          verified.pinned,
          admin,
          prf,
          identity.credentialId,
          verified.trust,
        );
      else if (migrates)
        state = await migratedState(
          key,
          context,
          admin,
          lastCheckpoint(checkpoint),
        );
      else state = verified;
      if (state !== verified) {
        guard();
        try {
          await port.publish(key, state, remote.cid, "root");
        } catch (error) {
          guard();
          if (!migrates) throw error;
          if (
            (error instanceof SyncFailure && error.reason === "conflict") ||
            (await rootMoved(port, remote.cid, guard))
          )
            throw new MigrationInterruptedError();
          state = verified;
          migrationStuck = true;
        }
        guard();
      }
    }
    // A passkey device may have trusted its pin on first use, so only this passkey's own signatures run.
    const result = await openSession(
      // A browser that never read this root mustn't later count as having held it; one that did already has its row.
      migrationStuck ? { ...port, saveCheckpoint: async () => {} } : port,
      identity.did,
      key,
      state,
      guard,
      endorser,
      endorser ? [endorser] : [],
      lastCheckpoint(checkpoint),
      entries,
    );
    if (migrationStuck) result.notice = MIGRATION_PENDING;
    return result;
  } finally {
    key?.fill(0);
    prf?.fill(0);
    admin?.privateKey.fill(0);
    input.fill(0);
    port.dispose?.();
  }
}

async function seedVault(port: SeedUnlockPort, seed: Uint8Array) {
  const current = port.current();
  if (!current?.recipientId) throw new Error("Vault recipient required");
  const identity = { ...current };
  const guard = identityGuard(port, identity);
  let remote: Awaited<ReturnType<typeof readRemoteHeader>>;
  try {
    await requireAuthorizedPds(port, identity.did, guard);
    remote = await readRemoteHeader(port, guard);
  } catch (error) {
    if (!deviceRevoked.safeParse(error).success) throw error;
    await port.forget?.("revoked");
    throw new AccessRemovedError("token");
  }
  const checkpoint = await port.checkpoint();
  guard();
  if (!remote)
    throw new Error(
      checkpoint
        ? "Vault rollback or key loss detected"
        : "Existing vault key unavailable",
    );
  const last = lastCheckpoint(checkpoint);
  if (!last?.pinned)
    throw new Error("Vault access isn't pinned on this device");
  // Only the id and box key locate this holder's slot, so any seed kind yields the same reference.
  const own = await createSeedRecipient(seed, "device");
  if (own.id !== identity.recipientId)
    throw new Error("Vault recipient changed");
  const opened = await openWithSeed(
    { accessSalt: remote.header.accessSalt, access: remote.header.access },
    seed,
    identity.did,
  ).catch(async (error) => {
    if (!(error instanceof Error && error.message === NO_ACCESS_SLOT))
      throw error;
    await port.forget?.("removed");
    throw new AccessRemovedError();
  });
  try {
    guard();
    // A seed device has no recovery path: a change it can't verify (one signed by a recovery admin its pin predates, or a planted one) leaves linking again as the remedy.
    const state = await verifyHeader(
      opened.key,
      identity.did,
      remote.header,
      refOf(own),
      checkpoint,
      { slotVersion: opened.version },
    ).catch((error) => {
      throw error instanceof Error && error.message === UNTRUSTED_ACCESS
        ? new RelinkRequiredError()
        : error;
    });
    guard();
    return { did: identity.did, guard, key: opened.key, state, own, last };
  } catch (error) {
    opened.key.fill(0);
    throw error;
  }
}

/**
 * Opens an existing vault with a device, agent or recovery seed as a local
 * session that signs what it writes as the seed, and saves the checkpoint it
 * verified against. The device must already hold the pin its enrolling admin
 * handed over, and the root must carry a statement that pin trusts.
 */
export async function unlockVaultWithSeed(
  port: SeedUnlockPort,
  seed: Uint8Array,
): Promise<UnlockResult> {
  let key: Uint8Array | undefined;
  let signingKey: Uint8Array | undefined;
  try {
    const opened = await seedVault(port, seed);
    key = opened.key;
    signingKey = await seedSigningKey(seed);
    // Fails closed: a seed holder runs MDX by itself only from the admins it was handed, a linked device the passkey that linked it.
    return await openSession(
      port,
      opened.did,
      key,
      opened.state,
      opened.guard,
      signerOf(opened.own, signingKey),
      port.runners ?? [],
      opened.last,
    );
  } finally {
    key?.fill(0);
    signingKey?.fill(0);
    port.dispose?.();
  }
}
