import { describe, expect, spyOn, test } from "bun:test";
import sodium from "libsodium-wrappers-sumo";
import { createSeedRecipient } from "./access-v3.ts";
import {
  createLinkSecret,
  deviceAuthorizeMessage,
  formatPairingCode,
  type LinkedCheckpoint,
  linkCommitment,
  matchesLinkCommitment,
  normalizeUserCode,
  pairingCode,
  sealLinkHandoff,
  typedPairingCode,
  verifyLinkHandoff,
} from "./link.ts";

const did = "did:plc:link";
const seed = new Uint8Array(32).fill(3);
const checkpoint = {
  vault: "8f1b5a0e-4a37-4d9a-9a49-0c2b1c1f0a11",
  epoch: 1,
  pinned: {
    statement: "s".repeat(42).concat("A"),
    sequence: 2,
    admins: [],
    recipients: ["r".repeat(42).concat("A")],
  },
  trust: "handed",
} satisfies LinkedCheckpoint;

describe("pairing code", () => {
  test("is twelve digits fixed by both keys", async () => {
    const device = await createSeedRecipient(seed, "device");
    const other = await createSeedRecipient(
      new Uint8Array(32).fill(4),
      "device",
    );
    const code = await pairingCode(
      device.boxPublicKey,
      device.signPublicKey ?? "",
    );
    expect(code).toMatch(/^\d{12}$/);
    expect(
      await pairingCode(device.boxPublicKey, device.signPublicKey ?? ""),
    ).toBe(code);
    expect(
      await pairingCode(other.boxPublicKey, device.signPublicKey ?? ""),
    ).not.toBe(code);
    expect(
      await pairingCode(device.boxPublicKey, other.signPublicKey ?? ""),
    ).not.toBe(code);
    expect(formatPairingCode(code)).toMatch(/^\d{4} \d{4} \d{4}$/);
    expect(typedPairingCode(` ${formatPairingCode(code)}-`)).toBe(code);
  });
  test("user codes normalize as Flow ID's do", () => {
    expect(normalizeUserCode("bcdf-ghjk")).toBe("BCDFGHJK");
    expect(normalizeUserCode(" BCDF GHJK ")).toBe("BCDFGHJK");
    expect(normalizeUserCode("BCDF-GHJA")).toBeNull();
    expect(normalizeUserCode("BCDF-GHJ")).toBeNull();
  });
});

describe("link handoff", () => {
  test("verifies only for its seed, secret and statement", async () => {
    await sodium.ready;
    const recipient = await createSeedRecipient(seed, "device");
    const context = { secret: "123456789012", did, recipient };
    const handoff = await sealLinkHandoff(context, checkpoint);
    expect(handoff.recipient).toBe(recipient.id);
    expect(handoff.sealed).toHaveLength(107);
    expect(await verifyLinkHandoff(handoff, seed, context, checkpoint)).toBe(
      true,
    );
    expect(
      await verifyLinkHandoff(
        handoff,
        seed,
        { ...context, secret: "123456789013" },
        checkpoint,
      ),
    ).toBe(false);
    expect(
      await verifyLinkHandoff(
        handoff,
        seed,
        { ...context, did: "did:plc:other" },
        checkpoint,
      ),
    ).toBe(false);
    for (const changed of [
      { ...checkpoint, epoch: 2 },
      { ...checkpoint, vault: crypto.randomUUID() },
      { ...checkpoint, trust: "tofu" } satisfies LinkedCheckpoint,
      {
        ...checkpoint,
        pinned: { ...checkpoint.pinned, statement: "t".repeat(42).concat("A") },
      },
    ])
      expect(await verifyLinkHandoff(handoff, seed, context, changed)).toBe(
        false,
      );
    expect(await verifyLinkHandoff(undefined, seed, context, checkpoint)).toBe(
      false,
    );
    const otherSeed = new Uint8Array(32).fill(5);
    const other = await createSeedRecipient(otherSeed, "device");
    expect(
      await verifyLinkHandoff(
        handoff,
        otherSeed,
        { ...context, recipient: other },
        checkpoint,
      ),
    ).toBe(false);
    expect(
      await verifyLinkHandoff(
        { ...handoff, recipient: other.id },
        otherSeed,
        { ...context, recipient: other },
        checkpoint,
      ),
    ).toBe(false);
    const garbled = `${handoff.sealed.slice(0, 50)}${handoff.sealed[50] === "A" ? "B" : "A"}${handoff.sealed.slice(51)}`;
    expect(
      await verifyLinkHandoff(
        { ...handoff, sealed: garbled },
        seed,
        context,
        checkpoint,
      ),
    ).toBe(false);
  });
  test("refuses anything but a twelve-digit secret, Flow ID's user code included", async () => {
    const recipient = await createSeedRecipient(seed, "device");
    for (const secret of ["BCDF-GHJK", "BCDFGHJK", "12345678901", ""])
      await expect(
        sealLinkHandoff({ secret, did, recipient }, checkpoint),
      ).rejects.toThrow("Invalid link secret");
    const handoff = await sealLinkHandoff(
      { secret: "123456789012", did, recipient },
      checkpoint,
    );
    await expect(
      verifyLinkHandoff(
        handoff,
        seed,
        { secret: "BCDFGHJK", did, recipient },
        checkpoint,
      ),
    ).rejects.toThrow("Invalid link secret");
  });
});

describe("link secret", () => {
  test("is twelve uniform digits, fresh each time", () => {
    const secrets = Array.from({ length: 200 }, createLinkSecret);
    for (const secret of secrets) expect(secret).toMatch(/^\d{12}$/);
    expect(new Set(secrets).size).toBe(200);
    const leading = new Set(secrets.map((secret) => secret[0]));
    expect(leading.size).toBeGreaterThan(5);
  });
  test("the commitment binds the secret, kind, label and both keys under a fresh nonce, and only Argon2id reaches it", async () => {
    const device = await createSeedRecipient(seed, "device");
    const other = await createSeedRecipient(
      new Uint8Array(32).fill(4),
      "device",
    );
    const request = {
      kind: "device",
      label: "Laptop",
      boxPublicKey: device.boxPublicKey,
      signPublicKey: device.signPublicKey ?? "",
    };
    const commitment = await linkCommitment("123456789012", request);
    expect(commitment).toMatch(/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/);
    expect(
      await matchesLinkCommitment("123456789012", request, commitment),
    ).toBe(true);
    // Each attempt draws its own nonce, so the same secret and keys never commit the same way twice.
    expect(await linkCommitment("123456789012", request)).not.toBe(commitment);
    for (const [secret, changed] of [
      ["123456789013", request],
      ["123456789012", { ...request, kind: "agent" }],
      ["123456789012", { ...request, label: "Your MacBook" }],
      ["123456789012", { ...request, boxPublicKey: other.boxPublicKey }],
      [
        "123456789012",
        { ...request, signPublicKey: other.signPublicKey ?? "" },
      ],
      ["BCDFGHJK", request],
    ] as const)
      expect(await matchesLinkCommitment(secret, changed, commitment)).toBe(
        false,
      );
    for (const malformed of ["", "%%%", commitment.slice(0, 40)])
      expect(
        await matchesLinkCommitment("123456789012", request, malformed),
      ).toBe(false);
    await expect(linkCommitment("BCDFGHJK", request)).rejects.toThrow(
      "Invalid link secret",
    );
    const bytes = sodium.from_base64(
      commitment,
      sodium.base64_variants.URLSAFE_NO_PADDING,
    );
    const nonce = bytes.slice(0, 16);
    expect(await linkCommitment("123456789012", request, nonce)).toBe(
      commitment,
    );
    const salt = new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(
          JSON.stringify([
            "flow-note/v3/link-commitment",
            sodium.to_base64(nonce, sodium.base64_variants.URLSAFE_NO_PADDING),
            "device",
            "Laptop",
            request.boxPublicKey,
            request.signPublicKey,
          ]),
        ),
      ),
    );
    const argon = sodium.crypto_pwhash(
      16,
      new TextEncoder().encode("123456789012"),
      salt.slice(0, 16),
      3,
      64 * 1024 * 1024,
      sodium.crypto_pwhash_ALG_ARGON2ID13,
    );
    expect([...bytes.slice(16)]).toEqual([...argon]);
  });
  test("checking a commitment throws, rather than reading as a mismatch, when Argon2id can't run", async () => {
    const device = await createSeedRecipient(seed, "device");
    const request = {
      kind: "device",
      label: "Laptop",
      boxPublicKey: device.boxPublicKey,
      signPublicKey: device.signPublicKey ?? "",
    };
    const commitment = await linkCommitment("123456789012", request);
    const failing = spyOn(sodium, "crypto_pwhash").mockImplementation(() => {
      throw new Error("Cannot enlarge memory");
    });
    try {
      await expect(
        matchesLinkCommitment("123456789012", request, commitment),
      ).rejects.toThrow("Cannot enlarge memory");
    } finally {
      failing.mockRestore();
    }
  });
  test("a device proves its signing key over exactly what Flow ID checks", () => {
    expect(
      new TextDecoder().decode(
        deviceAuthorizeMessage({
          kind: "device",
          boxPublicKey: "box",
          signPublicKey: "sign",
          commitment: "commitment",
        }),
      ),
    ).toBe(
      '["flow-note/v3/device-authorize","device","box","sign","commitment"]',
    );
  });
});
