import { z } from "zod";
import type { EntryAuthor } from "../crypto/authorship.ts";
import {
  type CryptoContext,
  decrypt,
  encrypt,
  parseEnvelope,
} from "../crypto/index.ts";
import { revisionDigest } from "../vault/storage.ts";
import {
  decodeBlob,
  encodeBlob,
  type SnapshotEntry,
} from "./vault-snapshot.ts";

export interface EpochKey {
  key: Uint8Array;
  epoch: number;
}
const encoder = new TextEncoder();
async function chunkHash(bytes: Uint8Array): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", new Uint8Array(bytes));
  return Array.from(new Uint8Array(hash), (value) =>
    value.toString(16).padStart(2, "0"),
  ).join("");
}

/**
 * Re-seals one entry under another key and epoch, exactly as `VaultSession`
 * seals items: same plaintext, id and revision; the attachment chunks get new
 * ciphertext, so their hashes change, and the item envelope binds the new ones.
 * Decryption authenticates every chunk and the envelope against `from`. The
 * result carries only these fields: anything bound to the old ciphertext,
 * such as an author's signature, would no longer verify.
 */
async function rekeyEntry(
  entry: SnapshotEntry,
  owner: { did: string; vault: string },
  from: EpochKey,
  to: EpochKey,
): Promise<SnapshotEntry> {
  const context = (epoch: number): CryptoContext => ({
    did: owner.did,
    vault: owner.vault,
    item: entry.id,
    revision: entry.revision,
    epoch,
    assets: [],
  });
  const count = entry.chunkHashes.length;
  if (entry.encryptedBlobs.length !== count)
    throw new Error("Incomplete snapshot item");
  const encryptedBlobs: string[] = [];
  const chunkHashes: string[] = [];
  for (let index = 0; index < count; index++) {
    const bytes = decodeBlob(entry.encryptedBlobs[index] ?? "");
    if ((await chunkHash(bytes)) !== entry.chunkHashes[index])
      throw new Error("Encrypted chunk mapping mismatch");
    const envelope = parseEnvelope(bytes);
    const chunk = { chunkIndex: index, chunkCount: count };
    const plaintext = await decrypt(envelope, from.key, {
      ...context(from.epoch),
      ...chunk,
    });
    try {
      const sealed = encoder.encode(
        JSON.stringify(
          await encrypt(plaintext, to.key, { ...context(to.epoch), ...chunk }),
        ),
      );
      encryptedBlobs.push(encodeBlob(sealed));
      chunkHashes.push(await chunkHash(sealed));
    } finally {
      plaintext.fill(0);
    }
  }
  const item = await decrypt(entry.envelope, from.key, {
    ...context(from.epoch),
    assets: entry.chunkHashes,
  });
  try {
    return {
      id: entry.id,
      revision: entry.revision,
      recordType: entry.recordType,
      envelope: await encrypt(item, to.key, {
        ...context(to.epoch),
        assets: chunkHashes,
      }),
      chunkHashes,
      encryptedBlobs,
    };
  } finally {
    item.fill(0);
  }
}

/** An entry that couldn't be re-sealed: its exact ciphertext (`digest`), so a drop never hits another revision, and its name when its envelope still opens. */
export interface UnsealedEntry {
  id: string;
  digest: string;
  name?: string;
}
async function unsealed(
  entry: SnapshotEntry,
  owner: { did: string; vault: string },
  from: EpochKey,
): Promise<UnsealedEntry> {
  const unnamed = { id: entry.id, digest: await revisionDigest(entry) };
  try {
    const item = await decrypt(entry.envelope, from.key, {
      did: owner.did,
      vault: owner.vault,
      item: entry.id,
      revision: entry.revision,
      epoch: from.epoch,
      assets: entry.chunkHashes,
    });
    try {
      const named = z
        .object({ name: z.string().max(255) })
        .safeParse(JSON.parse(new TextDecoder().decode(item)));
      return named.success ? { ...unnamed, name: named.data.name } : unnamed;
    } finally {
      item.fill(0);
    }
  } catch {
    return unnamed;
  }
}

/**
 * Re-seals every entry of a vault's snapshot from one epoch's key to the next.
 * An entry that doesn't open is reported in `failed` instead of aborting the
 * set, so content a removed holder planted can't veto its own removal; the
 * caller decides whether to drop it. `sign` sees each original beside its
 * re-sealed copy and returns the signature to attach, if any; without it every
 * entry is written unsigned.
 */
export async function rekeySnapshot(
  entries: readonly SnapshotEntry[],
  owner: { did: string; vault: string },
  from: EpochKey,
  to: EpochKey,
  sign?: (
    original: SnapshotEntry,
    rekeyed: SnapshotEntry,
  ) => Promise<EntryAuthor | undefined>,
): Promise<{ entries: SnapshotEntry[]; failed: UnsealedEntry[] }> {
  const rekeyed: SnapshotEntry[] = [];
  const failed: UnsealedEntry[] = [];
  for (const entry of entries) {
    let sealed: SnapshotEntry;
    try {
      sealed = await rekeyEntry(entry, owner, from, to);
    } catch {
      failed.push(await unsealed(entry, owner, from));
      continue;
    }
    const author = await sign?.(entry, sealed);
    rekeyed.push(author ? { ...sealed, author } : sealed);
  }
  return { entries: rekeyed, failed };
}
