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
export class SyncFailure extends Error {
  readonly reason:
    | "conflict"
    | "quota"
    | "rate-limited"
    | "too-large"
    | "consent"
    | "offline";
  constructor(reason: SyncFailure["reason"], message: string) {
    super(message);
    this.reason = reason;
  }
}
