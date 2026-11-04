import { describe, expect, test } from "bun:test";
import { credentialHash } from "../crypto/access-v2.ts";
import {
  passkeyRequestChallenge,
  verifiesPasskeyAssertion,
} from "../crypto/passkey-proof.ts";
import {
  NOTE_ORIGIN,
  PASSKEY_RP_ID,
  softwarePasskey,
} from "../../tests/passkey-authenticator.ts";
import {
  connectedPasskeyRequest,
  passkeyRecipient,
  passkeyRequestLink,
  readPasskeyRequest,
  signedPasskeyRequest,
} from "./passkey-request.ts";

const did = "did:plc:request";
async function signedRequest() {
  const passkey = await softwarePasskey("Y3JlZGVudGlhbA");
  const keys = await connectedPasskeyRequest(
    new Uint8Array(32).fill(8),
    "Y3JlZGVudGlhbA",
    did,
  );
  return {
    passkey,
    request: await signedPasskeyRequest(
      keys,
      did,
      passkey.assert,
      1_800_000_000_000,
    ),
  };
}

describe("passkey requests", () => {
  test("travel as public keys and their passkey's assertion in a link fragment, and come back as an admin passkey recipient", async () => {
    const { passkey, request } = await signedRequest();
    const link = passkeyRequestLink("https://note.example", request);
    expect(link.startsWith("https://note.example/link#passkey=")).toBe(true);
    expect(new URL(link).search).toBe("");
    expect(readPasskeyRequest(new URL(link).hash)).toEqual(request);
    expect(request.issuedAt).toBe(1_800_000_000_000);
    expect(
      await verifiesPasskeyAssertion(request.assertion, {
        challenge: await passkeyRequestChallenge({ ...request, did }),
        publicKey: passkey.registered.publicKey,
        origin: NOTE_ORIGIN,
        rpId: PASSKEY_RP_ID,
      }),
    ).toBe(true);
    expect(await passkeyRecipient(request)).toEqual({
      id: await credentialHash("Y3JlZGVudGlhbA"),
      kind: "passkey",
      role: "admin",
      boxPublicKey: request.boxPublicKey,
      signPublicKey: request.signPublicKey,
    });
  });
  test("refuse anything but seven well-formed parts", async () => {
    const { request } = await signedRequest();
    const parts = new URL(
      passkeyRequestLink("https://note.example", request),
    ).hash
      .slice("#passkey=".length)
      .split(".");
    const replaced = (index: number, value: string) =>
      `#passkey=${parts.map((part, at) => (at === index ? value : part)).join(".")}`;
    for (const hash of [
      "",
      `#code=${parts.join(".")}`,
      `#passkey=${parts.slice(0, 3).join(".")}`,
      `#passkey=${parts.slice(0, 6).join(".")}`,
      `#passkey=${[...parts, "x"].join(".")}`,
      replaced(0, "bad id!"),
      replaced(1, "short"),
      replaced(3, "-1"),
      replaced(3, "1e12"),
      replaced(3, "12345678901234567"),
      replaced(6, ""),
      replaced(5, "not base64!"),
    ])
      expect(readPasskeyRequest(hash)).toBeNull();
  });
});
