import {
  type EntryContext,
  type EntrySigner,
  signEntry,
} from "../src/crypto/authorship.ts";
import { encrypt } from "../src/crypto/index.ts";
import type { SnapshotEntry } from "../src/sync/vault-snapshot.ts";
import type { VaultItem } from "../src/vault/model.ts";

const encoder = new TextEncoder();

/** A note revision encrypted, and optionally signed, outside NOTE's own client, as any key holder can write one. */
export async function noteEntry(
  key: Uint8Array,
  context: EntryContext,
  signer: EntrySigner | null,
  item: Partial<VaultItem> & Pick<VaultItem, "id" | "name">,
  source: string,
  revision: string = crypto.randomUUID(),
): Promise<SnapshotEntry> {
  const stamp = "2026-10-27T00:00:00.000Z";
  const plaintext = {
    kind: "note",
    parent: null,
    createdAt: stamp,
    updatedAt: stamp,
    format: item.name.endsWith(".mdx") ? "mdx" : "md",
    revisionCounter: 1,
    ...item,
    bytes: Array.from(encoder.encode(source)),
  };
  const envelope = await encrypt(
    encoder.encode(JSON.stringify(plaintext)),
    key,
    { ...context, item: item.id, revision, epoch: 1, assets: [] },
  );
  const entry: SnapshotEntry = {
    id: item.id,
    revision,
    recordType: "game.flow.note.item",
    envelope,
    chunkHashes: [],
    encryptedBlobs: [],
  };
  return signer
    ? { ...entry, author: await signEntry(entry, context, signer) }
    : entry;
}
