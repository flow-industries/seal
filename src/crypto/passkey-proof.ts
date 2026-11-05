import sodium from "libsodium-wrappers-sumo";
import { z } from "zod";

const encoder = new TextEncoder();
const base64url = z.string().regex(/^[A-Za-z0-9_-]+$/);
/** A WebAuthn assertion as `navigator.credentials.get` returns it, each part unpadded base64url. */
export const passkeyAssertionSchema = z
  .object({
    authenticatorData: base64url.min(50).max(1024),
    clientDataJSON: base64url.min(1).max(2048),
    signature: base64url.min(1).max(128),
  })
  .strict();
export type PasskeyAssertion = z.infer<typeof passkeyAssertionSchema>;
/** A passkey Flow ID lists for the account, its key in `FlowCredential`'s encoding (`0x` and x‖y). */
export interface RegisteredPasskey {
  credentialId: string;
  publicKey: string;
  /** When Flow ID registered it, so a passkey added just now can be called out. */
  createdAt?: string;
}
/** How long a passkey request may wait for its approval, like a device's code. */
export const PASSKEY_REQUEST_TTL_MS = 10 * 60_000;
/** How far ahead of this browser's clock the requesting browser's may run. */
export const PASSKEY_REQUEST_SKEW_MS = 2 * 60_000;
const clientDataSchema = z.object({
  type: z.string(),
  challenge: z.string(),
  origin: z.string(),
  crossOrigin: z.boolean().optional(),
});
const P256_POINT = /^0x([0-9a-f]{128})$/;
const USER_PRESENT = 0x01;
const USER_VERIFIED = 0x04;

const decode = (value: string) =>
  sodium.from_base64(value, sodium.base64_variants.URLSAFE_NO_PADDING);
async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.digest("SHA-256", new Uint8Array(bytes)),
  );
}
function sameBytes(a: Uint8Array, b: Uint8Array) {
  return a.length === b.length && a.every((byte, index) => byte === b[index]);
}

/**
 * What a new passkey's own browser asserts before an admin elsewhere adds it:
 * both public keys its PRF derived, for this DID, at this time. The domain
 * keeps a NOTE request from being any other Flow assertion.
 */
export async function passkeyRequestChallenge(request: {
  did: string;
  boxPublicKey: string;
  signPublicKey: string;
  issuedAt: number;
}): Promise<Uint8Array> {
  return sha256(
    encoder.encode(
      JSON.stringify([
        "flow-note/v3/passkey-request",
        request.did,
        request.boxPublicKey,
        request.signPublicKey,
        request.issuedAt,
      ]),
    ),
  );
}

/** A DER ECDSA signature's two 32-byte integers, r‖s, as WebCrypto verifies them; null when it isn't one. */
function rawSignature(der: Uint8Array): Uint8Array<ArrayBuffer> | null {
  if (der[0] !== 0x30 || der[1] !== der.length - 2) return null;
  const raw = new Uint8Array(64);
  let offset = 2;
  for (const half of [0, 32]) {
    const length = der[offset + 1] ?? 0;
    if (der[offset] !== 0x02 || length < 1 || length > 33) return null;
    let integer = der.subarray(offset + 2, offset + 2 + length);
    if (integer.length !== length) return null;
    if (integer.length === 33) {
      if (integer[0] !== 0) return null;
      integer = integer.subarray(1);
    }
    raw.set(integer, half + 32 - integer.length);
    offset += 2 + length;
  }
  return offset === der.length ? raw : null;
}

/**
 * Whether `assertion` is the registered passkey's WebAuthn signature over
 * `challenge`, made on `origin` under `rpId` with the user present and
 * verified. Anything malformed is simply not that.
 */
export async function verifiesPasskeyAssertion(
  assertion: PasskeyAssertion,
  expected: {
    challenge: Uint8Array;
    publicKey: string;
    origin: string;
    rpId: string;
  },
): Promise<boolean> {
  await sodium.ready;
  try {
    const point = P256_POINT.exec(expected.publicKey)?.[1];
    if (!point) return false;
    const clientDataBytes = decode(assertion.clientDataJSON);
    const clientData = clientDataSchema.parse(
      JSON.parse(new TextDecoder().decode(clientDataBytes)),
    );
    if (
      clientData.type !== "webauthn.get" ||
      clientData.challenge !==
        sodium.to_base64(
          expected.challenge,
          sodium.base64_variants.URLSAFE_NO_PADDING,
        ) ||
      clientData.origin !== expected.origin ||
      clientData.crossOrigin === true
    )
      return false;
    const authenticatorData = decode(assertion.authenticatorData);
    const flags = authenticatorData[32] ?? 0;
    if (
      authenticatorData.length < 37 ||
      !sameBytes(
        authenticatorData.subarray(0, 32),
        await sha256(encoder.encode(expected.rpId)),
      ) ||
      !(flags & USER_PRESENT) ||
      !(flags & USER_VERIFIED)
    )
      return false;
    const signature = rawSignature(decode(assertion.signature));
    if (!signature) return false;
    const key = await crypto.subtle.importKey(
      "raw",
      new Uint8Array([0x04, ...sodium.from_hex(point)]),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    const signed = new Uint8Array(authenticatorData.length + 32);
    signed.set(authenticatorData);
    signed.set(await sha256(clientDataBytes), authenticatorData.length);
    return await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      signature,
      signed,
    );
  } catch {
    return false;
  }
}
