import type { EntryAuthor } from "../crypto/authorship.ts";
import type { Envelope } from "../crypto/index.ts";
export interface BlobRef {
  $type: "blob";
  ref: { $link: string };
  mimeType: "application/octet-stream";
  size: number;
}
export interface EncryptedRecord {
  $type: "game.flow.note.item" | "game.flow.note.tombstone";
  id: string;
  revision: string;
  envelope: Envelope;
  blobs: BlobRef[];
  chunkHashes?: string[];
  author?: EntryAuthor;
}
export interface RemoteRecord {
  cid: string;
  record: EncryptedRecord;
}
/**
 * Why a sync stopped. `connection`: no complete answer came back, or Flow ID
 * stopped receiving the request, so a write may or may not have landed.
 * `busy`: too many uploads in flight for this account or device, which clears
 * in seconds.
 */
export class SyncFailure extends Error {
  readonly reason:
    | "conflict"
    | "quota"
    | "rate-limited"
    | "too-large"
    | "consent"
    | "connection"
    | "busy"
    | "offline";
  /** Seconds Flow ID asked the caller to wait, from a 429's `Retry-After`, when it said. */
  readonly retryAfter?: number;
  constructor(
    reason: SyncFailure["reason"],
    message: string,
    retryAfter?: number,
  ) {
    super(message);
    this.reason = reason;
    this.retryAfter = retryAfter;
  }
}
