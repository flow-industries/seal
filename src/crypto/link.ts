import sodium from "libsodium-wrappers-sumo";
import { deriveSeed } from "./access-v2.ts";
import {
  type LinkHandoff,
  openSealedToSeed,
  type PinnedAccess,
  type RecipientRef,
} from "./access-v3.ts";

const encoder = new TextEncoder();
const USER_CODE = /^[BCDFGHJKLMNPQRSTVWXZ]{8}$/;
const CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CODE_LENGTH = 8;
const LINK_SECRET = /^[0-9A-HJKMNP-TV-Z]{8}$/;
/** Every Flow ID user code as `typedPairingCode` reads it: its consonants, with L as 1. */
const TYPED_USER_CODE = /^[1BCDFGHJKMNPQRSTVWXZ]{8}$/;
/**
 * Argon2id cost of the link-secret commitment. Device and tab must agree on it
 * forever, so it never changes in place. The secret has only about 2^40
 * values, so the commitment is an offline oracle for it: at this cost a
 * search takes a GPU farm days, which is safe only because the device accepts
 * a handoff for ten minutes on its own clock (`LINK_WINDOW_MS`) and salts
 * every attempt with a fresh nonce, so no table outlives one link.
 */
const COMMITMENT_OPSLIMIT = 3;
const COMMITMENT_MEMLIMIT = 64 * 1024 * 1024;
const COMMITMENT_NONCE_BYTES = 16;

function decode(value: string): Uint8Array {
  return sodium.from_base64(value, sodium.base64_variants.URLSAFE_NO_PADDING);
}
async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  const joined = new Uint8Array(
    parts.reduce((length, part) => length + part.length, 0),
  );
  let offset = 0;
  for (const part of parts) {
    joined.set(part, offset);
    offset += part.length;
  }
  return new Uint8Array(await crypto.subtle.digest("SHA-256", joined));
}

/** A Flow ID user code as typed, with or without its hyphen; null when it can't be one. */
export function normalizeUserCode(input: string): string | null {
  const code = input.replace(/[\s-]/g, "").toUpperCase();
  return USER_CODE.test(code) ? code : null;
}

/**
 * Five bytes, exactly 40 bits, as eight Crockford base32 symbols, most
 * significant bits first. Each symbol takes five whole bits, so uniform bytes
 * give uniform symbols.
 */
export function codeSymbols(bytes: Uint8Array): string {
  if (bytes.length !== 5) throw new Error("A code takes exactly five bytes");
  const value = bytes.reduce((sum, byte) => (sum << 8n) | BigInt(byte), 0n);
  return Array.from(
    { length: CODE_LENGTH },
    (_, index) =>
      CODE_ALPHABET[Number((value >> BigInt(35 - 5 * index)) & 31n)],
  ).join("");
}

/**
 * Whether `code` can be a device secret or a pairing code: eight canonical
 * symbols that no Flow ID user code types as. Flow ID issues the user code,
 * so a code shaped like one is a code it may know, and could commit its own
 * keys to or grind a passkey toward.
 */
export const isLinkSecret = (code: string) =>
  LINK_SECRET.test(code) && !TYPED_USER_CODE.test(code);

/**
 * The code a linking device shows and the approving browser makes the user
 * type. It commits to both public keys, so a key swapped between the device
 * and the browser shows a different code; its 40 bits make grinding a
 * matching key within the code's ten minutes costly. It is the first of the
 * digest's six 5-byte windows that `isLinkSecret` accepts, and the digest is
 * hashed again if none is, so it never reads as a Flow ID user code and every
 * key pair still has one.
 */
export async function pairingCode(
  boxPublicKey: string,
  signPublicKey: string,
): Promise<string> {
  await sodium.ready;
  let digest = await sha256(
    encoder.encode("flow-note/v3/pairing"),
    decode(boxPublicKey),
    decode(signPublicKey),
  );
  for (;;) {
    for (let offset = 0; offset + 5 <= digest.length; offset += 5) {
      const code = codeSymbols(digest.subarray(offset, offset + 5));
      if (isLinkSecret(code)) return code;
    }
    digest = await sha256(digest);
  }
}
/** A code as shown: `XXXX XXXX`, spaced rather than hyphenated so it never reads as a Flow ID user code. */
export const formatPairingCode = (code: string) =>
  code.replace(/^(.{4})(?=.)/, "$1 ");
/**
 * A code as typed, in canonical form: uppercase, O read as 0 and I or L as 1,
 * everything outside `[0-9A-Z]` dropped. It is a code only when that leaves
 * eight symbols of the alphabet.
 */
export const typedPairingCode = (input: string) =>
  input
    .toUpperCase()
    .replace(/O/g, "0")
    .replace(/[IL]/g, "1")
    .replace(/[^0-9A-Z]/g, "");

/**
 * The device secret a linking device shows and the user types into the
 * approving tab: eight random symbols that never leave the device any other
 * way, so Flow ID, which relays everything else, never learns them. A draw
 * shaped like a user code (about one in 43) is drawn again, which leaves
 * about 2^39.97 secrets, all equally likely.
 */
export function createLinkSecret(): string {
  for (;;) {
    const secret = codeSymbols(crypto.getRandomValues(new Uint8Array(5)));
    if (isLinkSecret(secret)) return secret;
  }
}
/** What a link commitment covers besides the secret: everything the approving tab will enroll. */
export interface CommittedRequest {
  kind: string;
  label: string;
  boxPublicKey: string;
  signPublicKey: string;
}
async function commitmentHash(
  secret: string,
  request: CommittedRequest,
  nonce: Uint8Array,
): Promise<Uint8Array> {
  await sodium.ready;
  const salt = await sha256(
    encoder.encode(
      JSON.stringify([
        "flow-note/v3/link-commitment",
        sodium.to_base64(nonce, sodium.base64_variants.URLSAFE_NO_PADDING),
        request.kind,
        request.label,
        request.boxPublicKey,
        request.signPublicKey,
      ]),
    ),
  );
  return sodium.crypto_pwhash(
    32 - COMMITMENT_NONCE_BYTES,
    encoder.encode(secret),
    salt.slice(0, sodium.crypto_pwhash_SALTBYTES),
    COMMITMENT_OPSLIMIT,
    COMMITMENT_MEMLIMIT,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
}
/**
 * The slow-hash commitment the device registers at Flow ID: a fresh 16-byte
 * nonce, then Argon2id of the secret salted with that nonce, the device's
 * kind, label and both public keys. The approving tab recomputes it from the
 * code the user types and what Flow ID returned, so a kind, label or key
 * swapped in between, or a code mistyped, doesn't match; Flow ID can only find
 * the secret behind it by an Argon2id search that starts over with each link.
 */
export async function linkCommitment(
  secret: string,
  request: CommittedRequest,
  nonce = crypto.getRandomValues(new Uint8Array(COMMITMENT_NONCE_BYTES)),
): Promise<string> {
  if (!isLinkSecret(secret)) throw new Error("Invalid link secret");
  if (nonce.length !== COMMITMENT_NONCE_BYTES)
    throw new Error("Invalid link nonce");
  const hash = await commitmentHash(secret, request, nonce);
  const commitment = new Uint8Array(32);
  commitment.set(nonce);
  commitment.set(hash, COMMITMENT_NONCE_BYTES);
  return sodium.to_base64(
    commitment,
    sodium.base64_variants.URLSAFE_NO_PADDING,
  );
}
/**
 * Whether the typed `secret` reproduces `commitment` for exactly this request.
 * A malformed secret or commitment simply doesn't; it throws only when
 * Argon2id itself can't run, such as a browser out of memory.
 */
export async function matchesLinkCommitment(
  secret: string,
  request: CommittedRequest,
  commitment: string,
): Promise<boolean> {
  if (!isLinkSecret(secret)) return false;
  await sodium.ready;
  let bytes: Uint8Array;
  try {
    bytes = decode(commitment);
  } catch {
    return false;
  }
  if (bytes.length !== 32) return false;
  const expected = await commitmentHash(
    secret,
    request,
    bytes.subarray(0, COMMITMENT_NONCE_BYTES),
  );
  return sodium.memcmp(expected, bytes.subarray(COMMITMENT_NONCE_BYTES));
}
/**
 * What a device signs at Flow ID's `authorize` to prove it holds the private
 * half of `signPublicKey`, so a browser session can't register a device under
 * another device's public keys. Flow ID checks the same bytes.
 */
export function deviceAuthorizeMessage(request: {
  kind: string;
  boxPublicKey: string;
  signPublicKey: string;
  commitment: string;
}): Uint8Array {
  return encoder.encode(
    JSON.stringify([
      "flow-note/v3/device-authorize",
      request.kind,
      request.boxPublicKey,
      request.signPublicKey,
      request.commitment,
    ]),
  );
}

/** The checkpoint a linked device starts from: the statement that listed it, trusted as far as the approving browser trusted its own pin. */
export interface LinkedCheckpoint {
  vault: string;
  epoch: number;
  pinned: PinnedAccess;
  trust: LinkHandoff["trust"];
}
interface LinkContext {
  /** The device secret (`createLinkSecret`) the user typed into the approving tab. */
  secret: string;
  did: string;
  recipient: RecipientRef;
}
/**
 * Keyed by the device secret, which only the device and the approving tab
 * hold, the tag shows the device which statement the approving admin
 * published. Flow ID relays the request and the record but never sees the
 * secret, so within the ten minutes the device waits it can't hand a linking
 * device a vault of its own. Past that, only an Argon2id search of
 * the commitment would get it there, which the device's deadline outruns.
 */
async function linkTag(
  { secret, did, recipient }: LinkContext,
  checkpoint: LinkedCheckpoint,
): Promise<Uint8Array> {
  if (!isLinkSecret(secret)) throw new Error("Invalid link secret");
  const key = await deriveSeed(
    encoder.encode(secret),
    await sha256(
      encoder.encode(JSON.stringify(["flow-note/v3/link", did, recipient.id])),
    ),
    "flow-note/v3/link-secret-key",
  );
  try {
    return sodium.crypto_auth_hmacsha256(
      encoder.encode(
        JSON.stringify([
          "flow-note/v3/link",
          did,
          recipient.id,
          checkpoint.vault,
          checkpoint.epoch,
          checkpoint.pinned.statement,
          checkpoint.trust,
        ]),
      ),
      key,
    );
  } finally {
    sodium.memzero(key);
  }
}

/**
 * Seals the tag to the device's box key, so only that device reads it and no
 * other vault member can test guesses of the secret against it.
 */
export async function sealLinkHandoff(
  context: LinkContext,
  checkpoint: LinkedCheckpoint,
): Promise<LinkHandoff> {
  await sodium.ready;
  const tag = await linkTag(context, checkpoint);
  try {
    return {
      recipient: context.recipient.id,
      trust: checkpoint.trust,
      sealed: sodium.to_base64(
        sodium.crypto_box_seal(tag, decode(context.recipient.boxPublicKey)),
        sodium.base64_variants.URLSAFE_NO_PADDING,
      ),
    };
  } finally {
    sodium.memzero(tag);
  }
}

/** Whether `handoff` shows the approving admin published `candidate` for this seed's holder. */
export async function verifyLinkHandoff(
  handoff: LinkHandoff | undefined,
  seed: Uint8Array,
  context: LinkContext,
  candidate: LinkedCheckpoint,
): Promise<boolean> {
  await sodium.ready;
  if (handoff?.recipient !== context.recipient.id) return false;
  let sealed: Uint8Array;
  try {
    sealed = decode(handoff.sealed);
  } catch {
    return false;
  }
  const tag = await openSealedToSeed(sealed, seed);
  if (tag?.length !== 32) return false;
  const expected = await linkTag(context, candidate);
  try {
    return sodium.memcmp(tag, expected);
  } finally {
    sodium.memzero(tag);
    sodium.memzero(expected);
  }
}
