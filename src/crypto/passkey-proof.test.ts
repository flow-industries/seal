import { describe, expect, test } from "bun:test";
import sodium from "libsodium-wrappers-sumo";
import {
  NOTE_ORIGIN,
  PASSKEY_RP_ID,
  softwarePasskey,
} from "../../tests/passkey-authenticator.ts";
import {
  type PasskeyAssertion,
  passkeyRequestChallenge,
  verifiesPasskeyAssertion,
} from "./passkey-proof.ts";

const request = {
  did: "did:plc:proof",
  boxPublicKey: `${"b".repeat(42)}A`,
  signPublicKey: `${"s".repeat(42)}A`,
  issuedAt: 1_800_000_000_000,
};
const decode = (value: string) =>
  sodium.from_base64(value, sodium.base64_variants.URLSAFE_NO_PADDING);
const encode = (bytes: Uint8Array) =>
  sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING);

describe("passkey request challenge", () => {
  test("commits to the DID, both keys and the time", async () => {
    const challenge = await passkeyRequestChallenge(request);
    expect(challenge).toHaveLength(32);
    expect(await passkeyRequestChallenge(request)).toEqual(challenge);
    for (const changed of [
      { ...request, did: "did:plc:other" },
      { ...request, boxPublicKey: request.signPublicKey },
      { ...request, signPublicKey: request.boxPublicKey },
      { ...request, issuedAt: request.issuedAt + 1 },
    ])
      expect(await passkeyRequestChallenge(changed)).not.toEqual(challenge);
  });
});

describe("passkey assertion", () => {
  test("verifies only the registered key's user-verified assertion over this challenge, origin and rpId", async () => {
    await sodium.ready;
    const passkey = await softwarePasskey("cred");
    const other = await softwarePasskey("other");
    const challenge = await passkeyRequestChallenge(request);
    const expected = {
      challenge,
      publicKey: passkey.registered.publicKey,
      origin: NOTE_ORIGIN,
      rpId: PASSKEY_RP_ID,
    };
    const genuine = await passkey.assert(challenge);
    expect(await verifiesPasskeyAssertion(genuine, expected)).toBe(true);

    const refused: [string, PasskeyAssertion | Promise<PasskeyAssertion>][] = [
      ["another passkey", other.assert(challenge)],
      [
        "another challenge",
        passkey.assert(
          await passkeyRequestChallenge({ ...request, did: "did:plc:x" }),
        ),
      ],
      ["another origin", passkey.assert(challenge, { origin: "https://x" })],
      [
        "another Flow app",
        passkey.assert(challenge, { origin: "https://other.example" }),
      ],
      ["another rpId", passkey.assert(challenge, { rpId: "evil.example" })],
      [
        "a registration",
        passkey.assert(challenge, { type: "webauthn.create" }),
      ],
      [
        "a cross-origin frame",
        passkey.assert(challenge, { crossOrigin: true }),
      ],
      ["no user verification", passkey.assert(challenge, { flags: 0x01 })],
      ["no user presence", passkey.assert(challenge, { flags: 0x04 })],
      [
        "tampered authenticator data",
        {
          ...genuine,
          authenticatorData: encode(
            decode(genuine.authenticatorData).map((byte, index) =>
              index === 36 ? byte ^ 1 : byte,
            ),
          ),
        },
      ],
      [
        "a signature with r and s swapped",
        (async () => {
          const der = decode(genuine.signature);
          const rLength = der[3] ?? 0;
          const r = der.subarray(2, 4 + rLength);
          const s = der.subarray(4 + rLength);
          return {
            ...genuine,
            signature: encode(new Uint8Array([0x30, der[1] ?? 0, ...s, ...r])),
          };
        })(),
      ],
      [
        "a raw signature",
        { ...genuine, signature: encode(new Uint8Array(64)) },
      ],
      ["undecodable data", { ...genuine, clientDataJSON: "%%%" }],
      [
        "client data that isn't JSON",
        { ...genuine, clientDataJSON: encode(new Uint8Array([1, 2, 3])) },
      ],
    ];
    for (const [name, assertion] of refused)
      expect([
        name,
        await verifiesPasskeyAssertion(await assertion, expected),
      ]).toEqual([name, false]);
    for (const publicKey of [
      `0x${"0".repeat(128)}`,
      passkey.registered.publicKey.slice(2),
      `0x04${passkey.registered.publicKey.slice(2)}`,
    ])
      expect(
        await verifiesPasskeyAssertion(genuine, { ...expected, publicKey }),
      ).toBe(false);
  });
});
