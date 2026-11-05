import sodium from "libsodium-wrappers-sumo";
import { z } from "zod";

const encoder = new TextEncoder();
export const encoded32 = z
  .string()
  .regex(/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/);
const encoded112 = z.string().regex(/^[A-Za-z0-9_-]{149}[AQgw]$/);
/** Flow ID accepts only 16 access slots, so headers write 16 until it accepts 32. */
export const ACCESS_SLOTS: 16 | 32 = 16;
export const accessRecipientSchema = z
  .object({ credentialHash: encoded32, publicKey: encoded32 })
  .strict();
export const accessSlotSchema = z
  .object({ keyId: encoded32, wrapped: encoded112 })
  .strict();
export const accessSlotsSchema = z
  .array(accessSlotSchema)
  .refine((slots) => slots.length === 16 || slots.length === 32);
export const accessHeaderSchema = z
  .object({ accessSalt: encoded32, access: accessSlotsSchema })
  .strict()
  .refine(
    (header) =>
      new Set(header.access.map((slot) => slot.keyId)).size ===
      header.access.length,
  );
export type AccessRecipient = z.infer<typeof accessRecipientSchema>;
export type AccessSlot = z.infer<typeof accessSlotSchema>;
export type AccessHeader = z.infer<typeof accessHeaderSchema>;

function encode(bytes: Uint8Array): string {
  return sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING);
}
function decode(value: string): Uint8Array {
  return sodium.from_base64(value, sodium.base64_variants.URLSAFE_NO_PADDING);
}
function checkDid(did: string): void {
  if (!/^did:[a-z0-9]+:[A-Za-z0-9._:%-]+$/.test(did) || did.length > 4096)
    throw new Error("Invalid access identity");
}
async function digest(value: string): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.digest("SHA-256", encoder.encode(value)),
  );
}

/** All v2 slots share a domain-separated PRF input so inputs cannot identify real slots. */
export function v2PrfInput(): Promise<Uint8Array> {
  return digest("flow-note/v2/prf");
}
/** A passkey recipient's id; v3 keeps it so v2 recipients keep their identity. */
export async function credentialHash(credentialId: string): Promise<string> {
  if (!credentialId || credentialId.length > 4096)
    throw new Error("Invalid credential identifier");
  return encode(await digest(credentialId));
}
/** The caller owns and must wipe the returned 32 bytes. */
export async function deriveSeed(
  secret: Uint8Array,
  salt: Uint8Array,
  info: string,
): Promise<Uint8Array> {
  const copy = new Uint8Array(secret);
  let material: CryptoKey;
  try {
    material = await crypto.subtle.importKey("raw", copy, "HKDF", false, [
      "deriveBits",
    ]);
  } finally {
    copy.fill(0);
  }
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(salt),
        info: encoder.encode(info),
      },
      material,
      256,
    ),
  );
}
/** Every key a passkey holds derives from its PRF under this salt, separated by `info`. */
export async function passkeySeed(
  prf: Uint8Array,
  credentialId: string,
  did: string,
  info: string,
): Promise<Uint8Array> {
  await sodium.ready;
  checkDid(did);
  if (prf.length !== 32) throw new Error("Actual successful PRF required");
  return deriveSeed(
    prf,
    await digest(JSON.stringify([did, await credentialHash(credentialId)])),
    info,
  );
}
async function recipientKeyPair(
  prf: Uint8Array,
  credentialId: string,
  did: string,
) {
  const seed = await passkeySeed(
    prf,
    credentialId,
    did,
    "flow-note/v2/access-recipient",
  );
  try {
    return sodium.crypto_box_seed_keypair(seed);
  } finally {
    sodium.memzero(seed);
  }
}

/** Only the public recipient capability may be persisted inside the encrypted root. */
export async function createAccessRecipient(
  prf: Uint8Array,
  credentialId: string,
  did: string,
): Promise<AccessRecipient> {
  const pair = await recipientKeyPair(prf, credentialId, did);
  try {
    return {
      credentialHash: await credentialHash(credentialId),
      publicKey: encode(pair.publicKey),
    };
  } finally {
    sodium.memzero(pair.privateKey);
  }
}
/** A slot's format follows its root: v2 roots are unsigned, v3 roots carry a signed access statement. */
export type SlotVersion = 2 | 3;
function contextDigest(
  did: string,
  accessSalt: string,
  keyId: string,
  version: SlotVersion,
): Promise<Uint8Array> {
  return digest(
    JSON.stringify([
      `flow-note/v${version}/access-wrap`,
      did,
      accessSalt,
      keyId,
    ]),
  );
}

/**
 * Re-randomizes every slot, including real recipients, without retaining any
 * PRF-derived secret. A signed header takes the salt its statement derives and
 * seals v3 slots, so its root can never be swapped for an unsigned one.
 */
export async function createAccessHeader(
  key: Uint8Array,
  publicKeys: readonly string[],
  did: string,
  signedSalt?: Uint8Array,
): Promise<AccessHeader> {
  await sodium.ready;
  checkDid(did);
  if (key.length !== 32) throw new Error("Invalid vault key");
  const checked = z.array(encoded32).min(1).max(ACCESS_SLOTS).parse(publicKeys);
  if (new Set(checked).size !== checked.length)
    throw new Error("Duplicate access recipient");
  const version: SlotVersion = signedSalt ? 3 : 2;
  const accessSalt = encode(signedSalt ?? sodium.randombytes_buf(32));
  const access: AccessSlot[] = [];
  for (const publicKey of checked) {
    const keyId = encode(sodium.randombytes_buf(32));
    const payload = new Uint8Array(64);
    payload.set(key);
    payload.set(await contextDigest(did, accessSalt, keyId, version), 32);
    try {
      access.push({
        keyId,
        wrapped: encode(sodium.crypto_box_seal(payload, decode(publicKey))),
      });
    } finally {
      sodium.memzero(payload);
    }
  }
  while (access.length < ACCESS_SLOTS) {
    const dummy = sodium.crypto_box_keypair();
    try {
      access.push({
        keyId: encode(sodium.randombytes_buf(32)),
        wrapped: encode(
          sodium.crypto_box_seal(sodium.randombytes_buf(64), dummy.publicKey),
        ),
      });
    } finally {
      sodium.memzero(dummy.privateKey);
    }
  }
  for (let index = access.length - 1; index > 0; index--) {
    const other = sodium.randombytes_uniform(index + 1);
    [access[index], access[other]] = [access[other], access[index]];
  }
  return accessHeaderSchema.parse({ accessSalt, access });
}

/** The returned key must still authenticate the root and its header commitment before use. */
export async function unwrapAccessKey(
  header: AccessHeader,
  prf: Uint8Array,
  credentialId: string,
  did: string,
): Promise<{ key: Uint8Array; version: SlotVersion }> {
  const pair = await recipientKeyPair(prf, credentialId, did);
  try {
    return await openAccessSlot(header, pair, did);
  } finally {
    sodium.memzero(pair.privateKey);
  }
}

/** No slot in the header is sealed to the caller's key. */
export const NO_ACCESS_SLOT =
  "This connected credential cannot unlock the vault";
/** Opens the slot sealed to `pair`; the caller keeps ownership of the private key. */
export async function openAccessSlot(
  header: AccessHeader,
  pair: { publicKey: Uint8Array; privateKey: Uint8Array },
  did: string,
): Promise<{ key: Uint8Array; version: SlotVersion }> {
  await sodium.ready;
  checkDid(did);
  const checked = accessHeaderSchema.parse(header);
  for (const slot of checked.access) {
    let payload: Uint8Array;
    try {
      payload = sodium.crypto_box_seal_open(
        decode(slot.wrapped),
        pair.publicKey,
        pair.privateKey,
      );
    } catch {
      continue;
    }
    try {
      if (payload.length !== 64)
        throw new Error("Access context verification failed");
      for (const version of [2, 3] as const)
        if (
          sodium.memcmp(
            payload.subarray(32),
            await contextDigest(did, checked.accessSalt, slot.keyId, version),
          )
        )
          return { key: payload.slice(0, 32), version };
      throw new Error("Access context verification failed");
    } finally {
      sodium.memzero(payload);
    }
  }
  throw new Error(NO_ACCESS_SLOT);
}

/** Bind this digest inside the authenticated root and verify it before accepting an unlock. */
export async function accessHeaderCommitment(
  header: AccessHeader,
): Promise<string> {
  await sodium.ready;
  const checked = accessHeaderSchema.parse(header);
  return encode(
    await digest(
      JSON.stringify([
        "flow-note/v2/access-header",
        checked.accessSalt,
        checked.access.map(({ keyId, wrapped }) => [keyId, wrapped]),
      ]),
    ),
  );
}
