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
 * Why a sync stopped short. `connection`: no complete answer came back, and a
 * write may still have landed. `busy`: Flow ID had too many uploads in flight,
 * which clears in seconds. `offline`: any other failure worth retrying.
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
  /** Seconds Flow ID asked to wait before retrying a `busy` refusal, when it said. */
  readonly retryAfter: number | undefined;
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
export type SyncFailureReason = SyncFailure["reason"];
