import sodium from "libsodium-wrappers-sumo";
import type { CommittedRequest } from "../src/crypto/link.ts";

/**
 * A link commitment laid out exactly as `linkCommitment` lays one out, but
 * for any secret at all: what a dishonest Flow ID can register, since it
 * needs no permission from `src/` to run Argon2id.
 */
export async function commitmentToAnySecret(
  secret: string,
  request: CommittedRequest,
  nonce = new Uint8Array(16).fill(9),
): Promise<string> {
  await sodium.ready;
  const encoder = new TextEncoder();
  const salt = new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
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
    ),
  );
  const commitment = new Uint8Array(32);
  commitment.set(nonce);
  commitment.set(
    sodium.crypto_pwhash(
      16,
      encoder.encode(secret),
      salt.slice(0, 16),
      3,
      64 * 1024 * 1024,
      sodium.crypto_pwhash_ALG_ARGON2ID13,
    ),
    16,
  );
  return sodium.to_base64(
    commitment,
    sodium.base64_variants.URLSAFE_NO_PADDING,
  );
}
