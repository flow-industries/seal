import sodium from "libsodium-wrappers-sumo";
import { z } from "zod";

export const CHUNK_BYTES = 4 * 1024 * 1024;
export const ROOT_BYTES = 64 * 1024;
export const MAX_CHUNKS = 128;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const LENGTH_BYTES = 4;
export const CHUNK_PLAINTEXT_BYTES = CHUNK_BYTES - NONCE_BYTES - TAG_BYTES;
export const MAX_CONTAINER_BYTES = MAX_CHUNKS * CHUNK_PLAINTEXT_BYTES;
export const MAX_BASE_BYTES = (MAX_CHUNKS - 1) * CHUNK_PLAINTEXT_BYTES;
export const JOURNAL_PLAINTEXT_BYTES = CHUNK_PLAINTEXT_BYTES - LENGTH_BYTES;
const ROOT_PLAINTEXT_BYTES = ROOT_BYTES - NONCE_BYTES - TAG_BYTES;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
export type JsonValue = z.infer<ReturnType<typeof z.json>>;
export interface ContainerContext {
  did: string;
  vault: string;
  epoch: number;
}
export interface ContainerEnvelope {
  version: 2;
  nonce: string;
  ciphertext: string;
}
const epochSchema = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const identifier = z.string().min(1).max(4096);
const digest = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const manifestSchema = z.discriminatedUnion("version", [
  z.strictObject({
    version: z.literal(2),
    vault: identifier,
    epoch: epochSchema,
    generation: digest,
    byteLength: z.number().int().min(0).max(MAX_CONTAINER_BYTES),
    chunkCount: z.number().int().min(1).max(MAX_CHUNKS),
    chunkHashes: z.array(digest).min(1).max(MAX_CHUNKS),
    metadata: z.json(),
  }),
  z.strictObject({
    version: z.literal(3),
    vault: identifier,
    epoch: epochSchema,
    generation: digest,
    byteLength: z.number().int().min(0).max(MAX_BASE_BYTES),
    chunkCount: z
      .number()
      .int()
      .min(0)
      .max(MAX_CHUNKS - 1),
    chunkHashes: z.array(digest).max(MAX_CHUNKS - 1),
    journal: z.strictObject({
      hash: digest,
      entries: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
      compactAt: z.number().int().min(0).max(JOURNAL_PLAINTEXT_BYTES),
    }),
    metadata: z.json(),
  }),
]);
export type ContainerManifest = z.infer<typeof manifestSchema>;
export type JournaledManifest = Extract<ContainerManifest, { version: 3 }>;
/** The immutable part of a journaled container that journal writes reuse. */
export type ContainerBase = Pick<
  JournaledManifest,
  "generation" | "byteLength" | "chunkCount" | "chunkHashes"
>;
type ChunkBinding = Pick<
  ContainerManifest,
  "vault" | "epoch" | "generation" | "chunkCount"
>;
const envelopeSchema = z.strictObject({
  version: z.literal(2),
  nonce: z.string().length(16),
  ciphertext: z
    .string()
    .length(Math.ceil(((ROOT_BYTES - NONCE_BYTES) * 4) / 3)),
});
function encode(bytes: Uint8Array): string {
  return sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING);
}
function decode(value: string, length: number): Uint8Array {
  const bytes = sodium.from_base64(
    value,
    sodium.base64_variants.URLSAFE_NO_PADDING,
  );
  if (bytes.length !== length || encode(bytes) !== value)
    throw new Error("Invalid container encoding");
  return bytes;
}
function random(length: number): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += 65536)
    crypto.getRandomValues(
      bytes.subarray(offset, Math.min(offset + 65536, length)),
    );
  return bytes;
}
export function containerChunkCount(byteLength: number): number {
  if (
    !Number.isSafeInteger(byteLength) ||
    byteLength < 0 ||
    byteLength > MAX_CONTAINER_BYTES
  )
    throw new Error("Container size exceeds limit");
  const needed = Math.max(1, Math.ceil(byteLength / CHUNK_PLAINTEXT_BYTES));
  return 2 ** Math.ceil(Math.log2(needed));
}
/** Base chunks of a journaled container: one less than a power of two, so the journal chunk completes the bucket. An empty base has none. */
export function baseChunkCount(byteLength: number): number {
  if (
    !Number.isSafeInteger(byteLength) ||
    byteLength < 0 ||
    byteLength > MAX_BASE_BYTES
  )
    throw new Error("Container size exceeds limit");
  const needed = Math.ceil(byteLength / CHUNK_PLAINTEXT_BYTES);
  return 2 ** Math.ceil(Math.log2(needed + 1)) - 1;
}
/** The record blobs a manifest authenticates: its base chunks, plus the journal chunk when it has one. */
export function containerBlobCount(manifest: ContainerManifest): number {
  return manifest.version === 3 ? manifest.chunkCount + 1 : manifest.chunkCount;
}
// biome-ignore lint/plugin: Decrypted JSON is untrusted until this schema boundary.
function validateManifest(value: unknown): ContainerManifest {
  const manifest = manifestSchema.parse(value);
  const journaled = manifest.version === 3;
  const hashes = journaled
    ? [...manifest.chunkHashes, manifest.journal.hash]
    : manifest.chunkHashes;
  const chunkCount = journaled
    ? baseChunkCount(manifest.byteLength)
    : containerChunkCount(manifest.byteLength);
  if (
    manifest.chunkCount !== chunkCount ||
    manifest.chunkHashes.length !== manifest.chunkCount ||
    new Set(hashes).size !== hashes.length
  )
    throw new Error("Invalid container manifest");
  decode(manifest.generation, 32);
  for (const hash of hashes) decode(hash, 32);
  return manifest;
}
function aad(
  did: string,
  purpose: string,
  manifest?: ChunkBinding,
  index?: number,
): Uint8Array<ArrayBuffer> {
  identifier.parse(did);
  return encoder.encode(
    JSON.stringify(
      manifest
        ? [
            "flow-note/v2",
            purpose,
            did,
            manifest.vault,
            manifest.epoch,
            manifest.generation,
            index,
            manifest.chunkCount,
          ]
        : ["flow-note/v2", purpose, did],
    ),
  );
}
async function encryptionKey(
  key: Uint8Array,
  did: string,
  purpose: string,
): Promise<CryptoKey> {
  if (key.length !== 32) throw new Error("Invalid key length");
  const copy = new Uint8Array(key);
  try {
    const material = await crypto.subtle.importKey("raw", copy, "HKDF", false, [
      "deriveKey",
    ]);
    return await crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(32),
        info: aad(did, purpose),
      },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  } finally {
    copy.fill(0);
  }
}
async function hash(bytes: Uint8Array): Promise<string> {
  return encode(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new Uint8Array(bytes)),
    ),
  );
}
async function seal(
  plaintext: Uint8Array<ArrayBuffer>,
  key: CryptoKey,
  additionalData: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array> {
  const nonce = random(NONCE_BYTES);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData, tagLength: 128 },
      key,
      plaintext,
    ),
  );
  const packed = new Uint8Array(nonce.length + ciphertext.length);
  packed.set(nonce);
  packed.set(ciphertext, nonce.length);
  return packed;
}
async function open(
  packed: Uint8Array,
  key: CryptoKey,
  additionalData: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: new Uint8Array(packed.subarray(0, NONCE_BYTES)),
        additionalData,
        tagLength: 128,
      },
      key,
      new Uint8Array(packed.subarray(NONCE_BYTES)),
    ),
  );
}

async function sealFramed(
  payload: Uint8Array,
  size: number,
  key: CryptoKey,
  additionalData: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array> {
  const framed = random(size);
  try {
    new DataView(framed.buffer).setUint32(0, payload.length, false);
    framed.set(payload, LENGTH_BYTES);
    return await seal(framed, key, additionalData);
  } finally {
    framed.fill(0);
  }
}
function unframe(framed: Uint8Array, error: string): Uint8Array {
  const length = new DataView(
    framed.buffer,
    framed.byteOffset,
    framed.byteLength,
  ).getUint32(0, false);
  if (length < 2 || length > framed.length - LENGTH_BYTES)
    throw new Error(error);
  return framed.subarray(LENGTH_BYTES, LENGTH_BYTES + length);
}
async function encryptChunks(
  key: Uint8Array,
  did: string,
  manifest: ChunkBinding,
  plaintext: Uint8Array,
): Promise<{ chunks: Uint8Array[]; chunkHashes: string[] }> {
  const chunkKey = await encryptionKey(key, did, "chunk-key");
  const chunks: Uint8Array[] = [];
  const chunkHashes: string[] = [];
  for (let index = 0; index < manifest.chunkCount; index++) {
    const padded = random(CHUNK_PLAINTEXT_BYTES);
    try {
      padded.set(
        plaintext.subarray(
          index * CHUNK_PLAINTEXT_BYTES,
          (index + 1) * CHUNK_PLAINTEXT_BYTES,
        ),
      );
      const chunk = await seal(
        padded,
        chunkKey,
        aad(did, "chunk", manifest, index),
      );
      chunks.push(chunk);
      chunkHashes.push(await hash(chunk));
    } finally {
      padded.fill(0);
    }
  }
  return { chunks, chunkHashes };
}
async function sealRoot(
  key: Uint8Array,
  did: string,
  manifest: ContainerManifest,
): Promise<ContainerEnvelope> {
  const serialized = encoder.encode(JSON.stringify(manifest));
  try {
    if (serialized.length > ROOT_PLAINTEXT_BYTES - LENGTH_BYTES)
      throw new Error("Container root exceeds limit");
    const packed = await sealFramed(
      serialized,
      ROOT_PLAINTEXT_BYTES,
      await encryptionKey(key, did, "root-key"),
      aad(did, "root"),
    );
    return {
      version: 2,
      nonce: encode(packed.subarray(0, NONCE_BYTES)),
      ciphertext: encode(packed.subarray(NONCE_BYTES)),
    };
  } finally {
    serialized.fill(0);
  }
}

/** A new root over the same chunks: they bind the vault, epoch, generation, index and count, never the metadata. */
export function resealContainerRoot(
  key: Uint8Array,
  did: string,
  manifest: ContainerManifest,
  metadata: JsonValue,
): Promise<ContainerEnvelope> {
  return sealRoot(key, did, {
    ...manifest,
    metadata: z.json().parse(metadata),
  });
}

/** Encrypts every bucket chunk afresh. Callers retain ownership of their plaintext and key buffers. */
export async function encryptContainer(
  key: Uint8Array,
  context: ContainerContext,
  plaintext: Uint8Array,
  metadata: JsonValue = {},
): Promise<{
  root: ContainerEnvelope;
  chunks: Uint8Array[];
  manifest: ContainerManifest;
}> {
  await sodium.ready;
  identifier.parse(context.vault);
  const chunkCount = containerChunkCount(plaintext.length);
  const manifest: ContainerManifest = {
    version: 2,
    vault: context.vault,
    epoch: context.epoch,
    generation: encode(random(32)),
    byteLength: plaintext.length,
    chunkCount,
    chunkHashes: [],
    metadata: z.json().parse(metadata),
  };
  epochSchema.parse(context.epoch);
  const { chunks, chunkHashes } = await encryptChunks(
    key,
    context.did,
    manifest,
    plaintext,
  );
  manifest.chunkHashes = chunkHashes;
  return { root: await sealRoot(key, context.did, manifest), chunks, manifest };
}

/** Encrypts a fresh base under a new generation, padded to 2^k − 1 chunks. Callers retain ownership of their plaintext and key buffers. */
export async function encryptContainerBase(
  key: Uint8Array,
  context: ContainerContext,
  plaintext: Uint8Array,
): Promise<{ base: ContainerBase; chunks: Uint8Array[] }> {
  await sodium.ready;
  identifier.parse(context.vault);
  epochSchema.parse(context.epoch);
  const base: ContainerBase = {
    generation: encode(random(32)),
    byteLength: plaintext.length,
    chunkCount: baseChunkCount(plaintext.length),
    chunkHashes: [],
  };
  const { chunks, chunkHashes } = await encryptChunks(
    key,
    context.did,
    { ...context, ...base },
    plaintext,
  );
  return { base: { ...base, chunkHashes }, chunks };
}

/**
 * Seals one padded journal chunk bound to `base`'s generation, and the root
 * that authenticates the base chunk hashes and the journal hash together.
 */
export async function encryptContainerJournal(
  key: Uint8Array,
  context: ContainerContext,
  base: ContainerBase,
  journal: { plaintext: Uint8Array; entries: number; compactAt: number },
  metadata: JsonValue,
): Promise<{
  root: ContainerEnvelope;
  chunk: Uint8Array;
  manifest: JournaledManifest;
}> {
  await sodium.ready;
  if (journal.plaintext.length > JOURNAL_PLAINTEXT_BYTES)
    throw new Error("Container journal exceeds limit");
  const binding: ChunkBinding = {
    vault: context.vault,
    epoch: context.epoch,
    generation: base.generation,
    chunkCount: base.chunkCount,
  };
  const chunk = await sealFramed(
    journal.plaintext,
    CHUNK_PLAINTEXT_BYTES,
    await encryptionKey(key, context.did, "journal-key"),
    aad(context.did, "journal", binding, base.chunkCount),
  );
  const manifest: JournaledManifest = {
    version: 3,
    ...binding,
    byteLength: base.byteLength,
    chunkHashes: base.chunkHashes,
    journal: {
      hash: await hash(chunk),
      entries: journal.entries,
      compactAt: journal.compactAt,
    },
    metadata: z.json().parse(metadata),
  };
  validateManifest(manifest);
  return { root: await sealRoot(key, context.did, manifest), chunk, manifest };
}

/** The caller must verify the authenticated access commitment before accepting an unlocked vault. */
export async function decryptContainerRoot(
  key: Uint8Array,
  context: Pick<ContainerContext, "did">,
  root: ContainerEnvelope,
): Promise<ContainerManifest> {
  await sodium.ready;
  envelopeSchema.parse(root);
  const packed = new Uint8Array(ROOT_BYTES);
  packed.set(decode(root.nonce, NONCE_BYTES));
  packed.set(decode(root.ciphertext, ROOT_BYTES - NONCE_BYTES), NONCE_BYTES);
  const rootKey = await encryptionKey(key, context.did, "root-key");
  const plaintext = await open(packed, rootKey, aad(context.did, "root"));
  try {
    return validateManifest(
      JSON.parse(
        decoder.decode(unframe(plaintext, "Invalid root payload length")),
      ),
    );
  } finally {
    plaintext.fill(0);
  }
}

/** Returns the caller-owned journal payload once its digest matches the authenticated root. */
export async function decryptContainerJournal(
  key: Uint8Array,
  context: Pick<ContainerContext, "did">,
  untrustedManifest: ContainerManifest,
  chunk: Uint8Array,
): Promise<Uint8Array> {
  await sodium.ready;
  const manifest = validateManifest(untrustedManifest);
  if (manifest.version !== 3 || chunk.length !== CHUNK_BYTES)
    throw new Error("Invalid container journal");
  if ((await hash(chunk)) !== manifest.journal.hash)
    throw new Error("Container journal digest mismatch");
  const framed = await open(
    chunk,
    await encryptionKey(key, context.did, "journal-key"),
    aad(context.did, "journal", manifest, manifest.chunkCount),
  );
  try {
    return unframe(framed, "Invalid journal payload length").slice();
  } finally {
    framed.fill(0);
  }
}

/** Returns caller-owned plaintext; authentication failures zero partial output before rejection. */
export async function decryptContainerChunks(
  key: Uint8Array,
  context: Pick<ContainerContext, "did">,
  untrustedManifest: ContainerManifest,
  chunks: readonly Uint8Array[],
): Promise<Uint8Array> {
  await sodium.ready;
  const manifest = validateManifest(untrustedManifest);
  if (
    chunks.length !== manifest.chunkCount ||
    chunks.some((chunk) => chunk.length !== CHUNK_BYTES)
  )
    throw new Error("Incomplete container chunks");
  const chunkKey = await encryptionKey(key, context.did, "chunk-key");
  const plaintext = new Uint8Array(manifest.byteLength);
  try {
    for (let index = 0; index < chunks.length; index++) {
      const chunk = chunks[index];
      if ((await hash(chunk)) !== manifest.chunkHashes[index])
        throw new Error("Container chunk digest mismatch");
      const padded = await open(
        chunk,
        chunkKey,
        aad(context.did, "chunk", manifest, index),
      );
      try {
        const offset = index * CHUNK_PLAINTEXT_BYTES;
        if (offset < plaintext.length)
          plaintext.set(
            padded.subarray(
              0,
              Math.min(padded.length, plaintext.length - offset),
            ),
            offset,
          );
      } finally {
        padded.fill(0);
      }
    }
    return plaintext;
  } catch (error) {
    plaintext.fill(0);
    throw error;
  }
}
