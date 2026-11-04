import sodium from "libsodium-wrappers-sumo";
import { z } from "zod";

export interface CryptoContext {
  did: string;
  vault: string;
  item: string;
  revision: string;
  epoch: number;
  assets: readonly string[];
  chunkIndex?: number;
  chunkCount?: number;
}
export interface Envelope {
  version: 1;
  nonce: string;
  ciphertext: string;
}
const envelopeSchema = z
  .object({
    version: z.literal(1),
    nonce: z.string().max(128),
    ciphertext: z.string().max(900_000),
  })
  .strict();
const strictUtf8 = new TextDecoder("utf-8", { fatal: true });
/**
 * An attachment chunk's stored envelope. Readers and the re-key both parse
 * chunks here, strictly, so a chunk one of them would refuse can't sit
 * unnoticed in a vault until a rotation trips over it.
 */
export function parseEnvelope(bytes: Uint8Array): Envelope {
  return envelopeSchema.parse(JSON.parse(strictUtf8.decode(bytes)));
}
export interface WrappedVaultKey {
  version: 1;
  salt: string;
  envelope: Envelope;
}
/** Wraps one epoch's vault key, so it stops opening the vault at its first rotation. */
export interface RecoveryFile {
  format: "flow-note-recovery";
  version: 1;
  context: CryptoContext;
  bearer: string;
  wrapped: WrappedVaultKey;
}
/** The seed of a `recovery` admin recipient; it opens its own slot in every epoch until that recipient is revoked. */
export interface RecoveryFileV2 {
  format: "flow-note-recovery";
  version: 2;
  did: string;
  vault: string;
  seed: string;
}
const encoder = new TextEncoder();
const domain = "flow-note/v1";
export const ready = sodium.ready;
const encode = (bytes: Uint8Array) =>
  sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING);
const decode = (value: string) =>
  sodium.from_base64(value, sodium.base64_variants.URLSAFE_NO_PADDING);
function keyCheck(key: Uint8Array): void {
  if (key.length !== 32) throw new Error("Invalid key length");
}
function validIdentifier(value: string): boolean {
  // biome-ignore lint/plugin: Persisted recovery context crosses a security boundary.
  return typeof value === "string" && value.length > 0 && value.length <= 4096;
}
function associatedData(context: CryptoContext, purpose: string): Uint8Array {
  const {
    did,
    vault,
    item,
    revision,
    epoch,
    assets,
    chunkIndex = 0,
    chunkCount = 1,
  } = context;
  if (
    ![did, vault, item, revision].every(validIdentifier) ||
    !Number.isSafeInteger(epoch) ||
    epoch < 0 ||
    !Number.isSafeInteger(chunkIndex) ||
    !Number.isSafeInteger(chunkCount) ||
    chunkCount < 1 ||
    chunkIndex < 0 ||
    chunkIndex >= chunkCount ||
    !Array.isArray(assets) ||
    assets.length > 10_000 ||
    !assets.every(validIdentifier) ||
    new Set(assets).size !== assets.length
  )
    throw new Error("Invalid encryption context");
  return encoder.encode(
    JSON.stringify([
      domain,
      purpose,
      did,
      vault,
      item,
      revision,
      epoch,
      assets,
      chunkIndex,
      chunkCount,
    ]),
  );
}
export async function createVaultKey(): Promise<Uint8Array> {
  await ready;
  return sodium.randombytes_buf(32);
}
async function seal(
  plaintext: Uint8Array,
  key: Uint8Array,
  context: CryptoContext,
  purpose: string,
): Promise<Envelope> {
  await ready;
  keyCheck(key);
  const nonce = sodium.randombytes_buf(24);
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    associatedData(context, purpose),
    null,
    nonce,
    key,
  );
  return { version: 1, nonce: encode(nonce), ciphertext: encode(ciphertext) };
}
async function open(
  envelope: Envelope,
  key: Uint8Array,
  context: CryptoContext,
  purpose: string,
): Promise<Uint8Array> {
  await ready;
  keyCheck(key);
  if (envelope.version !== 1) throw new Error("Unsupported encryption version");
  const nonce = decode(envelope.nonce);
  if (nonce.length !== 24) throw new Error("Invalid nonce");
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    decode(envelope.ciphertext),
    associatedData(context, purpose),
    nonce,
    key,
  );
}
export const encrypt = (
  plaintext: Uint8Array,
  key: Uint8Array,
  context: CryptoContext,
) => seal(plaintext, key, context, "item");
export const decrypt = (
  envelope: Envelope,
  key: Uint8Array,
  context: CryptoContext,
) => open(envelope, key, context, "item");
async function wrappingKey(
  secret: Uint8Array,
  salt: Uint8Array,
  context: CryptoContext,
  purpose: string,
): Promise<Uint8Array> {
  keyCheck(secret);
  if (salt.length !== 32) throw new Error("Invalid wrapping salt");
  const material = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(secret),
    "HKDF",
    false,
    ["deriveBits"],
  );
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(salt),
        info: new Uint8Array(associatedData(context, purpose)),
      },
      material,
      256,
    ),
  );
}
async function wrap(
  key: Uint8Array,
  secret: Uint8Array,
  context: CryptoContext,
  purpose: string,
): Promise<WrappedVaultKey> {
  await ready;
  keyCheck(key);
  const salt = sodium.randombytes_buf(32);
  const derived = await wrappingKey(secret, salt, context, purpose);
  try {
    return {
      version: 1,
      salt: encode(salt),
      envelope: await seal(key, derived, context, purpose),
    };
  } finally {
    sodium.memzero(derived);
  }
}
async function unwrap(
  wrapped: WrappedVaultKey,
  secret: Uint8Array,
  context: CryptoContext,
  purpose: string,
): Promise<Uint8Array> {
  await ready;
  if (wrapped.version !== 1) throw new Error("Unsupported wrapping version");
  const derived = await wrappingKey(
    secret,
    decode(wrapped.salt),
    context,
    purpose,
  );
  try {
    const key = await open(wrapped.envelope, derived, context, purpose);
    keyCheck(key);
    return key;
  } finally {
    sodium.memzero(derived);
  }
}
export async function createRecoveryFile(
  key: Uint8Array,
  context: CryptoContext,
): Promise<RecoveryFile> {
  const bearer = await createVaultKey();
  try {
    return {
      format: "flow-note-recovery",
      version: 1,
      context: structuredClone(context),
      bearer: encode(bearer),
      wrapped: await wrap(key, bearer, context, "recovery-wrap"),
    };
  } finally {
    sodium.memzero(bearer);
  }
}
/** A new recovery seed and the file that carries it; the caller wipes the seed once its recipient is derived. */
export async function createRecoverySeed(
  did: string,
  vault: string,
): Promise<{ seed: Uint8Array; file: RecoveryFileV2 }> {
  const seed = await createVaultKey();
  return {
    seed,
    file: {
      format: "flow-note-recovery",
      version: 2,
      did,
      vault,
      seed: encode(seed),
    },
  };
}
/** The caller wipes the returned seed. */
export async function recoverySeed(file: RecoveryFileV2): Promise<Uint8Array> {
  await ready;
  const seed = decode(file.seed);
  keyCheck(seed);
  return seed;
}
export async function recoverVaultKey(
  file: RecoveryFile,
  expectedContext: CryptoContext,
): Promise<Uint8Array> {
  await ready;
  if (
    file.format !== "flow-note-recovery" ||
    file.version !== 1 ||
    !sodium.memcmp(
      associatedData(file.context, "recovery-wrap"),
      associatedData(expectedContext, "recovery-wrap"),
    )
  )
    throw new Error("Recovery identity mismatch");
  const bearer = decode(file.bearer);
  try {
    return await unwrap(file.wrapped, bearer, expectedContext, "recovery-wrap");
  } finally {
    sodium.memzero(bearer);
  }
}
