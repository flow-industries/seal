import {
  accessHeaderCommitment,
  createAccessHeader,
  createAccessRecipient,
} from "../src/crypto/access-v2.ts";
import type { VaultAccess } from "../src/crypto/access-v3.ts";
import { createVaultKey } from "../src/crypto/index.ts";
import type { SnapshotEntry } from "../src/sync/vault-snapshot.ts";
import type {
  VaultRecordV2,
  VaultTransportRpc,
} from "../src/sync/vault-transport.ts";

const LIMIT = 512_000_000;
const ORPHAN_GRACE = 24 * 3600_000;
const CHURN_GRACE = 10 * 60_000;

/**
 * A model of the Flow-hosted PDS's storage accounting, with an upload charged
 * until it is referenced or 24 h pass, and a dropped blob free for 10 minutes.
 * Pass `Infinity` for a self-hosted PDS.
 */
export function managedPds(did: string, limit = LIMIT) {
  const uri = `at://${did}/industries.flow.note.vault/vault`;
  type Row = {
    bytes: Uint8Array | null;
    size: number;
    state: "orphan" | "live" | "churn";
    due: number;
  };
  const rows = new Map<string, Row>();
  let stored: { cid: string; value: VaultRecordV2 } | null = null;
  let commits = 0;
  let now = 0;
  let uploads = 0;
  let retainBytes = true;
  const count = (state: Row["state"]) => {
    let total = 0;
    for (const row of rows.values()) if (row.state === state) total++;
    return total;
  };
  const sum = (state: Row["state"]) => {
    let total = 0;
    for (const row of rows.values()) if (row.state === state) total += row.size;
    return total;
  };
  const usage = () =>
    sum("live") + sum("orphan") + sum("churn") - Math.min(sum("churn"), limit);
  const rpc: VaultTransportRpc = {
    async records(operation) {
      if (operation.method === "read") {
        if (!stored) throw { code: "NOTE_NOT_FOUND", status: 404 };
        return structuredClone({ uri, ...stored });
      }
      if ((stored?.cid ?? null) !== operation.swapRecord)
        throw { code: "CONFLICT", status: 409 };
      const next = new Set(operation.record.blobs.map((b) => b.ref.$link));
      for (const blob of stored?.value.blobs ?? [])
        if (!next.has(blob.ref.$link)) {
          const row = rows.get(blob.ref.$link);
          if (row) {
            row.state = "churn";
            row.due = now + CHURN_GRACE;
          }
        }
      for (const cid of next) {
        const row = rows.get(cid);
        if (!row) throw { code: "BLOB_NOT_FOUND", status: 400 };
        row.state = "live";
      }
      stored = {
        cid: `cid-${++commits}`,
        value: structuredClone(operation.record),
      };
      return { cid: stored.cid, uri };
    },
    async upload(bytes) {
      if (limit - usage() < bytes.length) throw { code: "QUOTA", status: 413 };
      uploads++;
      const cid = crypto.randomUUID();
      rows.set(cid, {
        bytes: retainBytes ? bytes.slice() : null,
        size: bytes.length,
        state: "orphan",
        due: now + ORPHAN_GRACE,
      });
      return {
        blob: {
          $type: "blob",
          ref: { $link: cid },
          mimeType: "application/octet-stream",
          size: bytes.length,
        },
      };
    },
    async download(cid) {
      const row = rows.get(cid);
      if (!row?.bytes) throw { code: "PDS_UNAVAILABLE", status: 502 };
      return row.bytes.slice();
    },
  };
  return {
    rpc,
    count,
    get stored() {
      return stored;
    },
    get uploads() {
      return uploads;
    },
    /** Counts uploads without keeping their bytes, for a write nothing reads back. */
    discardBytes(discard: boolean) {
      retainBytes = !discard;
    },
    advance(ms: number) {
      now += ms;
      for (const [cid, row] of rows)
        if (row.state !== "live" && row.due <= now) rows.delete(cid);
    },
  };
}

/** An unsigned (v2) vault's key and access, as the previous release holds them. */
export async function legacyWorld(did: string, prf: Uint8Array, id: string) {
  const key = await createVaultKey();
  const vault = crypto.randomUUID();
  const recipient = await createAccessRecipient(prf, id, did);
  const header = await createAccessHeader(key, [recipient.publicKey], did);
  const access: VaultAccess = {
    header,
    metadata: {
      recipients: [recipient],
      accessCommitment: await accessHeaderCommitment(header),
    },
  };
  return {
    key,
    vault,
    options: { key, did, vault, epoch: 1, access, pinned: null },
  };
}

const HEX = "a".repeat(64);
const SEGMENT = "x".repeat(540_000);
let counter = 0;
/** A blob-holding entry of about `chars` encoded characters; the transport never opens it. */
export function attachment(id: string, chars: number): SnapshotEntry {
  const count = Math.max(1, Math.ceil(chars / 540_000));
  return {
    id,
    revision: `r${++counter}`,
    recordType: "game.flow.note.item",
    envelope: { version: 1, nonce: `n${counter}`, ciphertext: "c" },
    chunkHashes: Array(count).fill(HEX),
    encryptedBlobs: [
      ...Array(count - 1).fill(SEGMENT),
      "x".repeat(chars - (count - 1) * 540_000),
    ],
  };
}
/** An inline note of about `chars` encoded characters. */
export function note(id: string, chars: number): SnapshotEntry {
  return {
    id,
    revision: `r${++counter}`,
    recordType: "game.flow.note.item",
    envelope: {
      version: 1,
      nonce: `n${counter}`,
      ciphertext: "c".repeat(chars),
    },
    chunkHashes: [],
    encryptedBlobs: [],
  };
}
export function tombstone(id: string): SnapshotEntry {
  return {
    id,
    revision: `r${++counter}`,
    recordType: "game.flow.note.tombstone",
    envelope: { version: 1, nonce: `n${counter}`, ciphertext: "t" },
    chunkHashes: [],
    encryptedBlobs: [],
  };
}
export const encodedLength = (entries: SnapshotEntry[]) =>
  new TextEncoder().encode(JSON.stringify({ version: 2, entries })).length;
