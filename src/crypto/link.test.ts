import { describe, expect, spyOn, test } from "bun:test";
import sodium from "libsodium-wrappers-sumo";
import { commitmentToAnySecret } from "../../tests/commitment-to-any-secret.ts";
import { createSeedRecipient } from "./access-v3.ts";
import {
  codeSymbols,
  createLinkSecret,
  deviceAuthorizeMessage,
  formatPairingCode,
  isLinkSecret,
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

async function pairingDigest(keys: {
  boxPublicKey: string;
  signPublicKey?: string;
}) {
  const bytes = (value: string) =>
    sodium.from_base64(value, sodium.base64_variants.URLSAFE_NO_PADDING);
  return new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      new Uint8Array([
        ...new TextEncoder().encode("flow-note/v3/pairing"),
        ...bytes(keys.boxPublicKey),
        ...bytes(keys.signPublicKey ?? ""),
      ]),
    ),
  );
}

describe("pairing code", () => {
  test("is eight symbols fixed by both keys", async () => {
    const device = await createSeedRecipient(seed, "device");
    const other = await createSeedRecipient(
      new Uint8Array(32).fill(4),
      "device",
    );
    const code = await pairingCode(
      device.boxPublicKey,
      device.signPublicKey ?? "",
    );
    expect(code).toMatch(/^[0-9A-HJKMNP-TV-Z]{8}$/);
    expect(
      await pairingCode(device.boxPublicKey, device.signPublicKey ?? ""),
    ).toBe(code);
    expect(
      await pairingCode(other.boxPublicKey, device.signPublicKey ?? ""),
    ).not.toBe(code);
    expect(
      await pairingCode(device.boxPublicKey, other.signPublicKey ?? ""),
    ).not.toBe(code);
    expect(formatPairingCode(code)).toBe(
      `${code.slice(0, 4)} ${code.slice(4)}`,
    );
    expect(typedPairingCode(` ${formatPairingCode(code).toLowerCase()}-`)).toBe(
      code,
    );
  });
  test("is the digest's first five bytes when they aren't shaped like a user code", async () => {
    const device = await createSeedRecipient(seed, "device");
    const first = codeSymbols((await pairingDigest(device)).subarray(0, 5));
    expect(isLinkSecret(first)).toBe(true);
    expect(
      await pairingCode(device.boxPublicKey, device.signPublicKey ?? ""),
    ).toBe(first);
  });
  test("skips a window shaped like a user code to the next one, as for the first such seed", async () => {
    const device = await createSeedRecipient(
      new Uint8Array(32).fill(25),
      "device",
    );
    expect([device.boxPublicKey, device.signPublicKey]).toEqual([
      "d6GM0qbVrRX4SEUgdHQM_5bdcfQV0oWWMjYurueIYH8",
      "P25BHet8AnZ4SkPrK52XCdM8Vz3BTrhWV4gxa53o1QA",
    ]);
    const digest = await pairingDigest(device);
    expect(codeSymbols(digest.subarray(0, 5))).toBe("KSPFPSJX");
    expect(isLinkSecret("KSPFPSJX")).toBe(false);
    expect(codeSymbols(digest.subarray(5, 10))).toBe("69BTKR98");
    expect(
      await pairingCode(device.boxPublicKey, device.signPublicKey ?? ""),
    ).toBe("69BTKR98");
  });
  test("hashes the digest again when all six windows are shaped like user codes", async () => {
    const device = await createSeedRecipient(seed, "device");
    const userCodeDigest = new Uint8Array(32);
    for (let offset = 0; offset < 30; offset += 5)
      userCodeDigest.set([0x5b, 0x1a, 0xf8, 0x46, 0x53], offset);
    const real = crypto.subtle.digest.bind(crypto.subtle);
    const again = new Uint8Array(await real("SHA-256", userCodeDigest));
    const expected = [0, 5, 10, 15, 20, 25]
      .map((offset) => codeSymbols(again.subarray(offset, offset + 5)))
      .find(isLinkSecret);
    expect(expected).toBe("S59EPF6V");
    let calls = 0;
    const digest = spyOn(crypto.subtle, "digest").mockImplementation(
      (algorithm, data) => {
        calls++;
        return calls === 1
          ? Promise.resolve(userCodeDigest.slice().buffer)
          : real(algorithm, data);
      },
    );
    try {
      expect(
        await pairingCode(device.boxPublicKey, device.signPublicKey ?? ""),
      ).toBe(expected ?? "");
      expect(calls).toBe(2);
    } finally {
      digest.mockRestore();
    }
  });
  test("is never shaped like a user code, whatever the keys", async () => {
    const encode = (bytes: Uint8Array) =>
      sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING);
    let skipped = 0;
    for (let draw = 0; draw < 3000; draw++) {
      const keys = {
        boxPublicKey: encode(crypto.getRandomValues(new Uint8Array(32))),
        signPublicKey: encode(crypto.getRandomValues(new Uint8Array(32))),
      };
      const code = await pairingCode(keys.boxPublicKey, keys.signPublicKey);
      expect(isLinkSecret(code)).toBe(true);
      if (code !== codeSymbols((await pairingDigest(keys)).subarray(0, 5)))
        skipped++;
    }
    expect(skipped).toBeGreaterThan(0);
  });
  test("shows as two groups of four, apart by a space", () => {
    expect(formatPairingCode("7K3M9QXZ")).toBe("7K3M 9QXZ");
  });
  test("reads what was typed: case, O, I, L, spaces and hyphens", () => {
    for (const typed of [
      "7K3M9QXZ",
      "7k3m9qxz",
      "7K3M 9QXZ",
      " 7k3m-9qxz ",
      "7-K-3-M-9-Q-X-Z",
    ])
      expect(typedPairingCode(typed)).toBe("7K3M9QXZ");
    expect(typedPairingCode("oO0 iI1 lL")).toBe("00011111");
    expect(typedPairingCode("ABCD.EFGH")).toBe("ABCDEFGH");
    expect(typedPairingCode("7K3M9QXU")).toBe("7K3M9QXU");
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
    const context = { secret: "7K3M9QXZ", did, recipient };
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
        { ...context, secret: "7K3M9QXY" },
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
  test("refuses anything but eight canonical symbols outside a user code's shape, twelve digits included", async () => {
    const recipient = await createSeedRecipient(seed, "device");
    for (const secret of [
      "123456789012",
      "7K3M9QX",
      "7K3M9QXZA",
      "7k3m9qxz",
      "7K3M 9QXZ",
      "BCDF-GHJK",
      "7K3M9QXU",
      "7K3M9QXL",
      "7K3M9QXO",
      "7K3M9QXI",
      "BCDFGHJK",
      "BCD1MNPQ",
      "",
    ])
      await expect(
        sealLinkHandoff({ secret, did, recipient }, checkpoint),
      ).rejects.toThrow("Invalid link secret");
    const handoff = await sealLinkHandoff(
      { secret: "7K3M9QXZ", did, recipient },
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
  test("is eight symbols, never a user code's shape, fresh each time", () => {
    const secrets = Array.from({ length: 200 }, createLinkSecret);
    for (const secret of secrets) {
      expect(secret).toMatch(/^[0-9A-HJKMNP-TV-Z]{8}$/);
      expect(isLinkSecret(secret)).toBe(true);
    }
    expect(new Set(secrets).size).toBe(200);
  });
  test("draws again while a draw reads as a Flow ID user code", () => {
    const draws = [
      [0x5b, 0x1a, 0xf8, 0x46, 0x53],
      [0xa5, 0xbf, 0xda, 0x71, 0x74],
      [0x3c, 0xc7, 0x44, 0xdf, 0xbf],
    ];
    let calls = 0;
    const random = spyOn(crypto, "getRandomValues").mockImplementation(
      <T extends ArrayBufferView | null>(array: T) => {
        expect(array?.byteLength).toBe(5);
        if (array instanceof Uint8Array) array.set(draws[calls] ?? []);
        calls++;
        return array;
      },
    );
    try {
      expect(draws.map((draw) => codeSymbols(Uint8Array.from(draw)))).toEqual([
        "BCDFGHJK",
        "MPZXMWBM",
        "7K3M9QXZ",
      ]);
      expect(createLinkSecret()).toBe("7K3M9QXZ");
      expect(calls).toBe(3);
    } finally {
      random.mockRestore();
    }
  });
  test("is five random bytes, one symbol per five bits", () => {
    const random = spyOn(crypto, "getRandomValues").mockImplementation(
      <T extends ArrayBufferView | null>(array: T) => {
        expect(array?.byteLength).toBe(5);
        if (array instanceof Uint8Array)
          array.set([0x00, 0x44, 0x32, 0x14, 0xc7]);
        return array;
      },
    );
    try {
      expect(createLinkSecret()).toBe("01234567");
    } finally {
      random.mockRestore();
    }
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
    const commitment = await linkCommitment("7K3M9QXZ", request);
    expect(commitment).toMatch(/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/);
    expect(await matchesLinkCommitment("7K3M9QXZ", request, commitment)).toBe(
      true,
    );
    // Each attempt draws its own nonce, so the same secret and keys never commit the same way twice.
    expect(await linkCommitment("7K3M9QXZ", request)).not.toBe(commitment);
    for (const [secret, changed] of [
      ["7K3M9QXY", request],
      ["7K3M9QXZ", { ...request, kind: "agent" }],
      ["7K3M9QXZ", { ...request, label: "Your MacBook" }],
      ["7K3M9QXZ", { ...request, boxPublicKey: other.boxPublicKey }],
      ["7K3M9QXZ", { ...request, signPublicKey: other.signPublicKey ?? "" }],
      ["BCDFGHJK", request],
    ] as const)
      expect(await matchesLinkCommitment(secret, changed, commitment)).toBe(
        false,
      );
    for (const malformed of ["", "%%%", commitment.slice(0, 40)])
      expect(await matchesLinkCommitment("7K3M9QXZ", request, malformed)).toBe(
        false,
      );
    await expect(linkCommitment("123456789012", request)).rejects.toThrow(
      "Invalid link secret",
    );
    const bytes = sodium.from_base64(
      commitment,
      sodium.base64_variants.URLSAFE_NO_PADDING,
    );
    const nonce = bytes.slice(0, 16);
    expect(await linkCommitment("7K3M9QXZ", request, nonce)).toBe(commitment);
    expect(await commitmentToAnySecret("7K3M9QXZ", request, nonce)).toBe(
      commitment,
    );
  });
  test("checking a commitment throws, rather than reading as a mismatch, when Argon2id can't run", async () => {
    const device = await createSeedRecipient(seed, "device");
    const request = {
      kind: "device",
      label: "Laptop",
      boxPublicKey: device.boxPublicKey,
      signPublicKey: device.signPublicKey ?? "",
    };
    const commitment = await linkCommitment("7K3M9QXZ", request);
    const failing = spyOn(sodium, "crypto_pwhash").mockImplementation(() => {
      throw new Error("Cannot enlarge memory");
    });
    try {
      await expect(
        matchesLinkCommitment("7K3M9QXZ", request, commitment),
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

describe("code symbols", () => {
  const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  const bytesOf = (value: bigint) =>
    Uint8Array.from({ length: 5 }, (_, byte) =>
      Number((value >> BigInt(32 - 8 * byte)) & 0xffn),
    );
  test("map every five-bit value, in every position, to its Crockford symbol", () => {
    expect(alphabet).toHaveLength(32);
    expect(alphabet).not.toMatch(/[ILOU]/);
    for (let value = 0; value < 32; value++)
      for (let position = 0; position < 8; position++)
        expect(
          codeSymbols(bytesOf(BigInt(value) << BigInt(35 - 5 * position))),
        ).toBe(
          `${"0".repeat(position)}${alphabet[value]}${"0".repeat(7 - position)}`,
        );
    expect(codeSymbols(Uint8Array.of(0x00, 0x44, 0x35, 0x2f, 0xdf))).toBe(
      "0123ABYZ",
    );
    expect(codeSymbols(Uint8Array.of(0xde, 0xad, 0xbe, 0xef, 0x42))).toBe(
      "VTPVXVT2",
    );
    expect(codeSymbols(new Uint8Array(5).fill(0xff))).toBe("ZZZZZZZZ");
  });
  test("split the 40 bits evenly: each bit lands in exactly one symbol, five per symbol", () => {
    const bitsPerSymbol = new Array(8).fill(0);
    for (let bit = 0; bit < 40; bit++) {
      const code = codeSymbols(bytesOf(1n << BigInt(bit)));
      const changed = [...code].flatMap((symbol, position) =>
        symbol === "0" ? [] : [position],
      );
      expect(changed).toHaveLength(1);
      bitsPerSymbol[changed[0] ?? 0]++;
    }
    expect(bitsPerSymbol).toEqual(new Array(8).fill(5));
  });
  test("take exactly five bytes", () => {
    for (const length of [0, 4, 6, 32])
      expect(() => codeSymbols(new Uint8Array(length))).toThrow(
        "A code takes exactly five bytes",
      );
  });
});

describe("a Flow ID user code is never a link secret", () => {
  test("whichever way it is typed, it fails every gate", async () => {
    const recipient = await createSeedRecipient(seed, "device");
    const request = {
      kind: "device",
      label: "Laptop",
      boxPublicKey: recipient.boxPublicKey,
      signPublicKey: recipient.signPublicKey ?? "",
    };
    const honest = await linkCommitment("7K3M9QXZ", request);
    const handoff = await sealLinkHandoff(
      { secret: "7K3M9QXZ", did, recipient },
      checkpoint,
    );
    for (const userCode of [
      "MPZX-MWBM",
      "MPZXMWBM",
      "mpzx-mwbm",
      "BCDL-MNPQ",
      "bcdlmnpq",
      "BCDL MNPQ",
      "LLLL-LLLL",
      "ZZZZ-ZZZZ",
    ]) {
      expect(normalizeUserCode(userCode)).not.toBeNull();
      const typed = typedPairingCode(userCode);
      expect(typed).toHaveLength(8);
      for (const secret of [typed, userCode]) {
        expect(isLinkSecret(secret)).toBe(false);
        await expect(linkCommitment(secret, request)).rejects.toThrow(
          "Invalid link secret",
        );
        expect(await matchesLinkCommitment(secret, request, honest)).toBe(
          false,
        );
        await expect(
          sealLinkHandoff({ secret, did, recipient }, checkpoint),
        ).rejects.toThrow("Invalid link secret");
        await expect(
          verifyLinkHandoff(
            handoff,
            seed,
            { secret, did, recipient },
            checkpoint,
          ),
        ).rejects.toThrow("Invalid link secret");
      }
    }
  });
  test("not even against a commitment Flow ID made to it, with or without an L", async () => {
    const recipient = await createSeedRecipient(seed, "device");
    const request = {
      kind: "device",
      label: "Laptop",
      boxPublicKey: recipient.boxPublicKey,
      signPublicKey: recipient.signPublicKey ?? "",
    };
    for (const userCode of ["MPZX-MWBM", "BCDL-MNPQ"]) {
      const typed = typedPairingCode(userCode);
      const forged = await commitmentToAnySecret(typed, request);
      expect(await matchesLinkCommitment(typed, request, forged)).toBe(false);
    }
  });
  test("every user-code letter, in every position, types into the refused shape", () => {
    for (const letter of "BCDFGHJKLMNPQRSTVWXZ")
      for (let position = 0; position < 8; position++) {
        const userCode = `${"MPZXMWBM".slice(0, position)}${letter}${"MPZXMWBM".slice(position + 1)}`;
        expect(normalizeUserCode(userCode)).toBe(userCode);
        expect(isLinkSecret(typedPairingCode(userCode))).toBe(false);
      }
  });
  test("one symbol outside the user-code letters makes a code a secret again", () => {
    for (const code of ["7K3M9QXZ", "BCDFGHJ0", "1111111A", "AAAAAAAA"])
      expect(isLinkSecret(code)).toBe(true);
    for (const code of [
      "7K3M9QXU",
      "7k3m9qxz",
      "7K3M 9QXZ",
      "11111111",
      "BCDFGHJK",
      "123456789012",
    ])
      expect(isLinkSecret(code)).toBe(false);
  });
});
