/**
 * The device client: link a plugin or agent to a vault through the browser,
 * then open it as a local session that syncs over Flow ID's device token.
 * Everything else in the package is under its module's own subpath.
 */
export type {
  NoteDeviceCredentialStore,
  NoteDeviceCredentials,
  NoteDeviceFetch,
  NoteDeviceKind,
} from "@flow-industries/id";
export {
  AccessRemovedError,
  type NoteView,
  parseSyncBackoff,
  RelinkRequiredError,
  type StrandedEdits,
  SYNC_AUTHORIZATION_REQUIRED,
  SYNC_BLOCKED,
  SYNC_LOCKED,
  SYNC_PENDING,
  SYNC_QUOTA_REACHED,
  SYNC_RATE_LIMITED,
  SYNC_TOO_LARGE,
  SYNCED,
  type SyncListener,
  type SyncStatus,
  UnlockError,
} from "./app/runtime.ts";
export type { EntryRunner, RevisionOrigin } from "./crypto/authorship.ts";
export {
  createDeviceSeed,
  type DeviceCheckpoint,
  type DeviceCheckpointStore,
  type DeviceNote,
  type DeviceOptions,
  type DeviceVault,
  handedCheckpoint,
  LINK_EXPIRED,
  LINK_UNVERIFIED,
  LINK_WINDOW_MS,
  type LinkOptions,
  type LinkPrompt,
  linkDevice,
  NoteChangedError,
  openDeviceVault,
  PUBLISH_WAIT_MS,
} from "./device/client.ts";
export type { RevisionBase, TrustLoss } from "./vault/session.ts";
export type { ComposeRequest } from "./writing/composer.ts";
