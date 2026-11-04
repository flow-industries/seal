import sodium from "libsodium-wrappers-sumo";
import type {
  PasskeyAssertion,
  RegisteredPasskey,
} from "../src/crypto/passkey-proof.ts";

export const PASSKEY_RP_ID = "id.flow.industries";
export const NOTE_ORIGIN = "https://note.flow.talk";
const encode = (bytes: Uint8Array) =>
  sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING);
async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.digest("SHA-256", new Uint8Array(bytes)),
  );
}
/** One DER INTEGER: minimal, and positive even when the top bit is set. */
function derInteger(half: Uint8Array): number[] {
  let start = 0;
  while (start < half.length - 1 && half[start] === 0) start++;
  const bytes = [...half.subarray(start)];
  if ((bytes[0] ?? 0) & 0x80) bytes.unshift(0);
  return [0x02, bytes.length, ...bytes];
}

/**
 * A software passkey that signs WebAuthn assertions the way a platform
 * authenticator does (DER ECDSA over authenticatorData ‖ SHA-256(clientData)),
 * with `options` to bend each part an attacker or a broken client might.
 */
export async function softwarePasskey(credentialId: string) {
  await sodium.ready;
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const raw = new Uint8Array(
    await crypto.subtle.exportKey("raw", pair.publicKey),
  );
  const registered: RegisteredPasskey = {
    credentialId,
    publicKey: `0x${sodium.to_hex(raw.subarray(1))}`,
  };
  async function assert(
    challenge: Uint8Array,
    options: {
      origin?: string;
      rpId?: string;
      flags?: number;
      type?: string;
      crossOrigin?: boolean;
    } = {},
  ): Promise<PasskeyAssertion> {
    const authenticatorData = new Uint8Array([
      ...(await sha256(
        new TextEncoder().encode(options.rpId ?? PASSKEY_RP_ID),
      )),
      options.flags ?? 0x05,
      0,
      0,
      0,
      1,
    ]);
    const clientData = new TextEncoder().encode(
      JSON.stringify({
        type: options.type ?? "webauthn.get",
        challenge: encode(challenge),
        origin: options.origin ?? NOTE_ORIGIN,
        crossOrigin: options.crossOrigin ?? false,
      }),
    );
    const signature = new Uint8Array(
      await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        pair.privateKey,
        new Uint8Array([...authenticatorData, ...(await sha256(clientData))]),
      ),
    );
    const body = [
      ...derInteger(signature.subarray(0, 32)),
      ...derInteger(signature.subarray(32)),
    ];
    return {
      authenticatorData: encode(authenticatorData),
      clientDataJSON: encode(clientData),
      signature: encode(new Uint8Array([0x30, body.length, ...body])),
    };
  }
  return { registered, assert };
}
export type SoftwarePasskey = Awaited<ReturnType<typeof softwarePasskey>>;
