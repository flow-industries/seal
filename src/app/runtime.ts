import type { VaultRecipient } from "../crypto/access-v3.ts";
import type { RevisionOrigin } from "../crypto/authorship.ts";
import type { RecoveryFile, RecoveryFileV2 } from "../crypto/index.ts";
import type { UnsealedEntry } from "../sync/rekey.ts";
import type {
  ContentSource,
  Provenance,
  RevisionRef,
  SelectedAsset,
  TrustLoss,
} from "../vault/session.ts";
import type { AttachmentInsertion } from "../writing/attachments.ts";
import type { ComposeRequest } from "../writing/composer.ts";
import type { WritingPreferences } from "../writing/preferences.ts";
export interface NoteView {
  id: string;
  path: string;
  source: string;
  kind: "md" | "mdx";
  revision?: string;
  /** Set on versions from `history`: the unique row a restore names. */
  historyId?: string;
  /** The shown revision's digest, which trusting it and saving on it bind to (see `RevisionRef`, `RevisionBase`). */
  digest?: string;
  /** ISO 8601 times from the encrypted item; absent on notes created since the vault was last listed. */
  created?: string;
  modified?: string;
  /** Set on `.mdx` notes: whether this revision may run by itself, and who signed it. */
  origin?: RevisionOrigin;
}

/** A note matching a search, with the line of the task it matched when the query names tasks. */
export interface NoteSearchResult {
  id: string;
  line?: number;
}
/** Asked, with their paths, before imported code would be signed to run by itself. */
export type Endorse = (code: readonly string[]) => Promise<boolean>;
export interface NoteRuntime {
  read(): Promise<{ notes: NoteView[]; folders: string[] }>;
  list(): Promise<NoteView[]>;
  preferences(): Promise<WritingPreferences>;
  savePreferences(value: WritingPreferences): Promise<void>;
  assets(note: NoteView): Promise<SelectedAsset[]>;
  addAttachments(
    note: Pick<NoteView, "id" | "path">,
    files: File[],
  ): Promise<AttachmentInsertion[]>;
  folders(): Promise<string[]>;
  createFolder(path: string): Promise<void>;
  trash(): Promise<NoteView[]>;
  /** `endorsed`: the `holdsCode` digest of the row to sign as the person's own rather than drop another admin's signature. */
  restore(id: string, endorsed?: string): Promise<void>;
  permanentRemove(id: string): Promise<void>;
  /** `provenance` marks content the person didn't type in the editor (see `Provenance`). */
  save(note: NoteView, provenance?: Provenance): Promise<void>;
  /**
   * Who wrote code that saving `note` from `sources` would sign and so let
   * run by itself; ask the person first. Null when it would promote nothing.
   */
  writerToEndorse(
    note: Pick<NoteView, "path"> & { id?: string },
    sources?: readonly ContentSource[],
  ): Promise<string | null>;
  /** Whether `trust` can record anything here: not in a session over an unsigned root, which vouches for nobody. */
  canTrust(): boolean;
  /** Signs exactly these revisions as the person's own after they chose to trust them; refuses any that changed. */
  trust(revisions: readonly RevisionRef[]): Promise<void>;
  compose(
    request: ComposeRequest,
    endorsed?: boolean,
  ): Promise<{ selectedId: string }>;
  /** `endorsed`: as for `restore`. */
  remove(id: string, endorsed?: string): Promise<void>;
  /** The digest of this item's row when rewriting it here would drop the signature of an admin this browser can't confirm, so a direct action asks first; null otherwise. */
  holdsCode(id: string): Promise<string | null>;
  import(files: File[], endorse?: Endorse): Promise<NoteView[]>;
  export(mode?: "exact" | "obsidian"): Promise<Blob>;
  /** The note's exact source file, or a ZIP of it with the attachments it links and the notes it embeds. */
  exportNote(note: Pick<NoteView, "id" | "source">): Promise<File>;
  history(id: string): Promise<NoteView[]>;
  /** Restores the history row `historyId` itself, vouched for by that row alone; `endorsed` signs it regardless. Resolves with the note as restored. */
  restoreVersion(
    id: string,
    historyId: string,
    endorsed?: boolean,
  ): Promise<NoteView>;
  search(query: string): Promise<NoteSearchResult[]>;
  subscribeChanges(listener: () => void): () => void;
  /** Writes that left another admin's code unsigned, or its links stale (see `TrustLoss`). */
  subscribeTrustLoss?(listener: (loss: TrustLoss) => void): () => void;
  subscribe?(listener: SyncListener): () => void;
  sync?(): Promise<void>;
  recovery?(): Promise<Blob>;
  /** Who can open a signed vault, as this runtime last verified it; absent or null while access is unsigned. */
  access?(): VaultAccessView | null;
  /** Entries the last sync couldn't read; they stay out of this device until a re-key drops them. */
  unreadable?(): number;
  lock(): void;
}
export interface VaultAccessView {
  did: string;
  vault: string;
  /** The recipient id this runtime unlocked as. */
  self: string;
  /** False while this browser's pin was trusted on first use: it reads and writes, but can't sign access changes. */
  canChange: boolean;
  recipients: VaultRecipient[];
}

export const SYNC_LOCKED = "Your notepad changed. Unlock again.";
export const SYNCED = "Synced";
export const SYNC_PENDING = "Saved locally · Sync pending";
export const SYNC_BLOCKED = "Saved locally · Sync blocked";
export const SYNC_QUOTA_REACHED = "Saved locally · PDS quota reached";
export const SYNC_RATE_LIMITED = "Saved locally · PDS upload limit reached";
export const SYNC_TOO_LARGE = "Saved locally · Notepad too large to sync";
export const SYNC_AUTHORIZATION_REQUIRED =
  "Saved locally · Sync needs authorization";

/** A refusal that sync waits out before trying on its own again. */
export type SyncRefusal =
  | typeof SYNC_QUOTA_REACHED
  | typeof SYNC_RATE_LIMITED
  | typeof SYNC_TOO_LARGE;
const NEXT_SYNC = " · Next sync ";
export type SyncBackoffStatus = `${SyncRefusal}${typeof NEXT_SYNC}${string}`;

/** Names the local minute by which the next automatic sync has started. */
export function syncBackoffStatus(
  refusal: SyncRefusal,
  retryAt: number,
): SyncBackoffStatus {
  const minute = Math.ceil(retryAt / 60_000) * 60_000;
  const time = new Date(minute).toLocaleTimeString([], {
    hour: "numeric",
    minute: "2-digit",
  });
  return `${refusal}${NEXT_SYNC}${time}`;
}

export function parseSyncBackoff(
  status: string,
): { refusal: SyncRefusal; time: string } | undefined {
  for (const refusal of [
    SYNC_QUOTA_REACHED,
    SYNC_RATE_LIMITED,
    SYNC_TOO_LARGE,
  ] as const)
    if (status.startsWith(`${refusal}${NEXT_SYNC}`))
      return { refusal, time: status.slice(refusal.length + NEXT_SYNC.length) };
  return undefined;
}

/**
 * On `SYNC_LOCKED`, sync has already stopped and the vault stays open only
 * until a returned promise settles, so queued edits can still be saved, and
 * never longer than `LOCK_FLUSH_TIMEOUT_MS`.
 */
export type SyncListener = (status: SyncStatus) => void | Promise<void>;
/** Bounds how long the key outlives revoked access while queued edits save locally. */
export const LOCK_FLUSH_TIMEOUT_MS = 10_000;

/** Waits until `work` settles or `limit` ms pass, whichever comes first; never rejects. */
export async function waitAtMost(work: Promise<unknown>, limit: number) {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      work.catch(() => {}),
      new Promise((resolve) => {
        timer = setTimeout(resolve, limit);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
export type SyncStatus =
  | typeof SYNC_LOCKED
  | typeof SYNCED
  | typeof SYNC_PENDING
  | typeof SYNC_BLOCKED
  | SyncBackoffStatus
  | typeof SYNC_AUTHORIZATION_REQUIRED;

/** An unlock failure whose message is written for the person unlocking. */
export class UnlockError extends Error {}
export class VaultMigrationRequiredError extends UnlockError {
  constructor() {
    super(
      "Your notepad needs its storage update before sync. Your stored notes haven’t been changed.",
    );
  }
}
export class LegacyVaultError extends UnlockError {
  constructor() {
    super(
      "This notepad uses an older format. You can discard it and start fresh.",
    );
  }
}

/**
 * This holder's slot is gone from a vault it had pinned (`slot`), or Flow ID
 * refused its device token (`token`). A missing slot can't be told apart from
 * a header someone rewrote, so that copy doesn't claim a removal happened.
 */
export class AccessRemovedError extends UnlockError {
  readonly reason: "slot" | "token";
  constructor(reason: "slot" | "token" = "slot") {
    super(
      reason === "token"
        ? "This device was unlinked from your notepad. Link it again to keep using it."
        : "This passkey or device isn’t in your notepad’s access any more. If you didn’t remove it, open your notepad on another device and check Access.",
    );
    this.reason = reason;
  }
}
/**
 * A device pinned before the recovery recipient that just signed a change
 * existed can't verify it: its pin has no path to that admin. Linking again
 * hands it the current pin.
 */
export class RelinkRequiredError extends UnlockError {
  constructor() {
    super(
      "This device can’t confirm the latest change to who can open your notepad. Link it again to keep using it.",
    );
  }
}
/**
 * Who a recovery that re-keys keeps:
 * - `fresh`: no trusted pin, so nobody but this passkey (and a v2 file's own
 *   recovery recipient);
 * - `replace`: this browser trusts the current list, but a v1 file can't add
 *   this passkey to it, so nobody else;
 * - `repair`: this browser's trusted pin refuses the current list, so whom it
 *   trusted, provided this passkey was one of its admins, else nobody else.
 */
export type RecoveryScope = "fresh" | "replace" | "repair";
/**
 * A recovery that re-keys, and so drops everyone this browser can't confirm,
 * waits for the person to accept that. With no trusted pin it can't tell a
 * planted access list, or a lookalike recipient, from a real one, so it
 * carries nobody over; a v1 file also carries no admin key, so a passkey it
 * adds can't be listed under a statement other devices accept.
 */
export class RecoveryConfirmationError extends UnlockError {
  readonly scope: RecoveryScope;
  constructor(scope: RecoveryScope = "fresh") {
    super("Confirm recovery with a new key.");
    this.scope = scope;
  }
}
/**
 * Flow ID gave no answer about this account's passkeys (`flowIdAnswered`), so
 * an unsigned list can't be replaced yet; opening it unsigned instead would run
 * any MDX a key holder planted. Nothing was written, so trying again is safe.
 */
export class PasskeysUnavailableError extends UnlockError {
  constructor() {
    super(
      "Couldn’t check your passkeys with Flow ID, so your notepad stayed locked. Nothing was changed. Try again.",
    );
  }
}
/** An entry on an unsigned list that turning on signed access drops; `createdAt` when Flow ID's list named it. */
export interface DroppedPasskey {
  id: string;
  createdAt?: string;
}
/** The root the person was asked about and the entries they accepted dropping from it; it holds for exactly these. */
export interface MigrationConfirmation {
  cid: string;
  dropped: readonly string[];
}
/** Names only what a person can match to something: when Flow ID says a passkey was added. */
function losingAccess(dropped: readonly DroppedPasskey[]) {
  const added = dropped.flatMap(({ createdAt }) =>
    createdAt
      ? [
          new Date(createdAt).toLocaleDateString(undefined, {
            dateStyle: "long",
          }),
        ]
      : [],
  );
  if (added.length < dropped.length)
    return dropped.length === 1
      ? "the other passkey listed on your notepad loses access"
      : `the ${dropped.length} other passkeys listed on your notepad lose access`;
  const dates = new Intl.ListFormat(undefined).format(added);
  return added.length === 1
    ? `the passkey added on ${dates} loses access`
    : `the passkeys added on ${dates} lose access`;
}
/**
 * Turning on signed access lists only the passkey unlocking now: another
 * passkey's entry can't be verified without that passkey. The person confirms
 * dropping the ones Flow ID still lists, or all of them when its answer can't
 * tell; with enrollment off, a dropped passkey's only way back is a recovery file.
 */
export class MigrationConfirmationError extends UnlockError {
  readonly confirmation: MigrationConfirmation;
  /** Finishes "NOTE can vouch only for this passkey, so …". */
  readonly losing: string;
  constructor(cid: string, dropped: readonly DroppedPasskey[]) {
    super("Confirm who keeps access.");
    this.confirmation = { cid, dropped: dropped.map(({ id }) => id) };
    this.losing = losingAccess(dropped);
  }
}
/**
 * The root moved while an unlock was signing it, or the write landed and its
 * answer was lost. Nothing was lost either way, and the next unlock sees which.
 */
export class MigrationInterruptedError extends UnlockError {
  constructor() {
    super(
      "Your notepad changed while it was opening. Your notes are safe. Unlock again.",
    );
  }
}
/**
 * Shown when a pin refuses the root. A start-over with a recovery file under
 * another passkey looks exactly like a planted change, so this says both, and
 * what each means. A browser opens the new root again once it has no pin.
 */
export const UNTRUSTED_CHANGE =
  "NOTE detected an untrusted change to who can open your notepad and stopped to protect it. If you started over with a recovery file on another device, that change is yours: clearing this site’s data in your browser lets this browser open it, and discards any edits it hasn’t synced. If you didn’t, leave this browser as it is and open your notepad on a device you trust.";
/** Why a notepad opened with signed access still off: its migrating write failed, and the next unlock tries it again. */
export const MIGRATION_PENDING =
  "Your notes are safe, but syncing with your PDS is failing, so NOTE couldn’t finish signing who can open your notepad. Notes with code show their source until it can. NOTE tries again the next time you unlock.";
/**
 * Entries that couldn't be re-sealed; dropping them lets the removal finish.
 * `revoked` says the removed devices' tokens were already revoked on an
 * earlier attempt, though the key wasn't rotated.
 */
export class RekeyBlockedError extends UnlockError {
  readonly failed: UnsealedEntry[];
  constructor(failed: UnsealedEntry[], revoked = false) {
    const items = failed.length === 1 ? "one item" : `${failed.length} items`;
    super(
      revoked
        ? `NOTE couldn’t re-encrypt ${items}, so the removal didn’t finish. Whoever you removed can still read new notes until it does. Remove the items to finish.`
        : `NOTE couldn’t re-encrypt ${items}, so nobody was removed. They may have been written by the device you’re removing. Remove them to finish.`,
    );
    this.failed = failed;
  }
}
/** A removal that didn't publish: the removed holders still open the vault's current key. */
export class AccessChangeIncompleteError extends UnlockError {
  constructor(names: string, plural: boolean) {
    super(
      `Removing ${names} didn’t finish. ${plural ? "They" : "It"} can still read new notes until you try again.`,
    );
  }
}

export type VaultPresence = "present" | "absent";
/** What the locked screen may offer: one path per known state, none while checking. */
export type VaultState = VaultPresence | "checking" | "unavailable";

export interface UnlockResult {
  runtime: NoteRuntime;
  status: typeof SYNC_PENDING | typeof SYNCED;
  /**
   * Present when the notepad opened before the PDS confirmed its header. It
   * rejects with the reason once that check fails and the runtime is locked.
   */
  verified?: Promise<void>;
  /** Edits left in an earlier epoch's local database, sealed under a key this session doesn't hold. */
  stranded?: StrandedEdits;
  /** Something the person should know about how this unlock went. */
  notice?: string;
}
export interface StrandedEdits {
  count: number;
  /** The encrypted edits as JSON, to keep until they can be opened again. */
  download(): Promise<Blob>;
}

/** An admin's change to who can open a signed vault. */
export interface AccessChange {
  /** Recipient ids to remove. Any removal re-keys the whole vault under a new epoch. */
  revoke: string[];
  /** A recovery file the person already saved, whose recipient this change lists. */
  recovery?: RecoveryFileV2;
  /** `digest`s of entries a re-key couldn't re-seal (`RekeyBlockedError`) that the person chose to delete. */
  drop?: string[];
}
export interface UnlockOptions {
  setup?: boolean;
  recovery?: RecoveryFile | RecoveryFileV2;
  /** The person accepted recovering with a new key (`RecoveryConfirmationError`). */
  confirmRecovery?: boolean;
  /** The person accepted that turning on signed access drops these entries from this root (`MigrationConfirmationError`). */
  confirmMigration?: MigrationConfirmation;
  resetLegacy?: boolean;
  change?: AccessChange;
}
export type UnlockVault = (options?: UnlockOptions) => Promise<UnlockResult>;
