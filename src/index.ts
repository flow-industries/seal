/**
 * The device client: link a plugin or agent to a vault through the browser,
 * then open it as a local session that syncs over Flow ID's device token.
 * `@flow-industries/seal/testing` runs a link without a server; the
 * `internal/*` subpaths are the app's, with no stability promise.
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
  type SyncReport,
  type SyncStatus,
  UnlockError,
} from "./app/runtime.ts";
export type { EntryRunner, RevisionOrigin } from "./crypto/authorship.ts";
export {
  createDeviceSeed,
  type DeviceAttachment,
  type DeviceAttachmentWrite,
  type DeviceCheckpoint,
  type DeviceCheckpointStore,
  type DeviceNote,
  type DeviceOptions,
  type DeviceVault,
  deleteDeviceStorage,
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
  type WriteOptions,
} from "./device/client.ts";
export type { RevisionBase, TrustLoss } from "./vault/session.ts";
export type { ComposeRequest } from "./writing/composer.ts";
