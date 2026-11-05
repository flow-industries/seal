import { z } from "zod";
import { credentialHash, encoded32 } from "../crypto/access-v2.ts";
import {
  passkeyAdmin,
  type VaultRecipient,
  vaultRecipientSchema,
} from "../crypto/access-v3.ts";
import {
  type PasskeyAssertion,
  passkeyAssertionSchema,
  passkeyRequestChallenge,
} from "../crypto/passkey-proof.ts";

/**
 * A passkey can be added through another device's approval. A request carries
 * its own passkey's assertion, which the approving browser checks
 * against Flow ID's list of this account's passkeys before anything is
 * unlocked, so a link a phisher makes up enrolls nothing.
 */
export const ENROLL_PASSKEYS = true;

const keysSchema = z.object({
  credentialId: z
    .string()
    .min(1)
    .max(512)
    .regex(/^[A-Za-z0-9_-]+$/),
  boxPublicKey: encoded32,
  signPublicKey: encoded32,
});
/** The public half of the admin keys a passkey's PRF derives. */
export type PasskeyKeys = z.infer<typeof keysSchema>;
const requestSchema = keysSchema.extend({
  issuedAt: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  assertion: passkeyAssertionSchema,
});
/**
 * A new passkey's public keys, which an admin on another device approves on
 * `/link`, with that passkey's assertion over them (`passkeyRequestChallenge`)
 * made at `issuedAt`.
 */
export type PasskeyRequest = z.infer<typeof requestSchema>;

/** The link the new passkey's browser shows. Only public data travels, in the fragment, which no server receives. */
export function passkeyRequestLink(
  origin: string,
  request: PasskeyRequest,
): string {
  const { authenticatorData, clientDataJSON, signature } = request.assertion;
  return `${origin}/link#passkey=${[
    request.credentialId,
    request.boxPublicKey,
    request.signPublicKey,
    request.issuedAt,
    authenticatorData,
    clientDataJSON,
    signature,
  ].join(".")}`;
}
export function readPasskeyRequest(hash: string): PasskeyRequest | null {
  if (!hash.startsWith("#passkey=")) return null;
  const parts = hash.slice("#passkey=".length).split(".");
  const [
    credentialId,
    boxPublicKey,
    signPublicKey,
    issuedAt,
    authenticatorData,
    clientDataJSON,
    signature,
  ] = parts;
  if (parts.length !== 7 || !/^\d{1,16}$/.test(issuedAt ?? "")) return null;
  return (
    requestSchema.safeParse({
      credentialId,
      boxPublicKey,
      signPublicKey,
      issuedAt: Number(issuedAt),
      assertion: { authenticatorData, clientDataJSON, signature },
    }).data ?? null
  );
}
/** `label` tells this passkey apart from the owner's own in the access list; see `enrolledLabel`. */
export async function passkeyRecipient(
  request: PasskeyKeys,
  label?: string,
): Promise<VaultRecipient> {
  return vaultRecipientSchema.parse({
    id: await credentialHash(request.credentialId),
    kind: "passkey",
    role: "admin",
    boxPublicKey: request.boxPublicKey,
    signPublicKey: request.signPublicKey,
    ...(label && { label }),
  });
}
/** When it was added and the first digits its approver typed, so a phished one can't pass as the owner's. */
export const enrolledLabel = (pairing: string, added: Date) =>
  `Passkey ${pairing.slice(0, 4)}, added ${added.toISOString().slice(0, 10)}`;
/** The public half of the admin keys this passkey's PRF derives; the caller wipes `prf`. */
export async function connectedPasskeyRequest(
  prf: Uint8Array,
  credentialId: string,
  did: string,
): Promise<PasskeyKeys> {
  const admin = await passkeyAdmin(prf, credentialId, did);
  admin.privateKey.fill(0);
  return keysSchema.parse({
    credentialId,
    boxPublicKey: admin.recipient.boxPublicKey,
    signPublicKey: admin.recipient.signPublicKey,
  });
}
/** Has the passkey behind `keys` assert over them, so the approving admin can check they came from it. */
export async function signedPasskeyRequest(
  keys: PasskeyKeys,
  did: string,
  assert: (challenge: Uint8Array) => Promise<PasskeyAssertion>,
  issuedAt = Date.now(),
): Promise<PasskeyRequest> {
  return requestSchema.parse({
    ...keys,
    issuedAt,
    assertion: await assert(
      await passkeyRequestChallenge({ ...keys, did, issuedAt }),
    ),
  });
}
const encode = (bytes: ArrayBuffer) =>
  btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
/** A user-verified WebAuthn assertion by exactly this credential over `challenge`. */
export async function assertWithPasskey(
  credentialId: string,
  rpId: string,
  challenge: Uint8Array,
): Promise<PasskeyAssertion> {
  const id = Uint8Array.from(
    atob(credentialId.replace(/-/g, "+").replace(/_/g, "/")),
    (character) => character.charCodeAt(0),
  );
  const credential = await navigator.credentials.get({
    publicKey: {
      challenge: challenge.slice(),
      rpId,
      allowCredentials: [{ type: "public-key", id }],
      userVerification: "required",
      timeout: 60_000,
    },
  });
  if (
    !(credential instanceof PublicKeyCredential) ||
    !(credential.response instanceof AuthenticatorAssertionResponse) ||
    encode(credential.rawId) !== encode(id.buffer)
  )
    throw new Error("PRF_UNAVAILABLE");
  return passkeyAssertionSchema.parse({
    authenticatorData: encode(credential.response.authenticatorData),
    clientDataJSON: encode(credential.response.clientDataJSON),
    signature: encode(credential.response.signature),
  });
}
