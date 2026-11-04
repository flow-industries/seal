import { describe, expect, test } from "bun:test";
import {
  type CryptoContext,
  createRecoveryFile,
  createVaultKey,
  decrypt,
  encrypt,
  recoverVaultKey,
} from "./index.ts";

const context: CryptoContext = {
  did: "did:plc:user",
  vault: "vault-id",
  item: "note-id",
  revision: "revision-id",
  epoch: 1,
  assets: ["asset-a", "asset-b"],
};
const source = new TextEncoder().encode(
  "---\ntitle: exact\n---\n<Component />\r\n",
);
describe("authenticated vault encryption", () => {
  test("preserves source bytes and randomizes ciphertext", async () => {
    const key = await createVaultKey();
    const first = await encrypt(source, key, context);
    const second = await encrypt(source, key, context);
    expect(first.nonce).not.toBe(second.nonce);
    expect(await decrypt(first, key, context)).toEqual(source);
  });
  test("rejects wrong key, tampering and all context substitutions", async () => {
    const key = await createVaultKey();
    const envelope = await encrypt(source, key, context);
    await expect(
      decrypt(envelope, await createVaultKey(), context),
    ).rejects.toThrow();
    await expect(
      decrypt(
        {
          ...envelope,
          ciphertext: `${envelope.ciphertext[0] === "A" ? "B" : "A"}${envelope.ciphertext.slice(1)}`,
        },
        key,
        context,
      ),
    ).rejects.toThrow();
    for (const substituted of [
      { ...context, did: "did:plc:other" },
      { ...context, vault: "other" },
      { ...context, item: "other" },
      { ...context, revision: "other" },
      { ...context, epoch: 2 },
      { ...context, assets: [...context.assets].reverse() },
    ]) {
      await expect(decrypt(envelope, key, substituted)).rejects.toThrow();
    }
  });
  test("rejects unsupported formats and malformed authenticated context", async () => {
    const key = await createVaultKey();
    const envelope = await encrypt(source, key, context);
    await expect(
      decrypt(
        JSON.parse(JSON.stringify({ ...envelope, version: 2 })),
        key,
        context,
      ),
    ).rejects.toThrow();
    await expect(
      decrypt({ ...envelope, nonce: "AA" }, key, context),
    ).rejects.toThrow();
    await expect(
      encrypt(source, key, { ...context, epoch: -1 }),
    ).rejects.toThrow();
    await expect(
      encrypt(source, key, { ...context, assets: ["a", "a"] }),
    ).rejects.toThrow();
    const recovery = await createRecoveryFile(key, context);
    await expect(
      recoverVaultKey(
        { ...recovery, wrapped: { ...recovery.wrapped, salt: "AA" } },
        context,
      ),
    ).rejects.toThrow();
  });

  test("recovery is self contained, wrapped and independent from PRF", async () => {
    const key = await createVaultKey();
    const recovery = await createRecoveryFile(key, context);
    const serialized = JSON.parse(JSON.stringify(recovery));
    expect(await recoverVaultKey(serialized, context)).toEqual(key);
    expect(recovery.bearer).not.toBe(Buffer.from(key).toString("base64url"));
    await expect(
      recoverVaultKey(serialized, { ...context, vault: "other" }),
    ).rejects.toThrow();
    await expect(
      recoverVaultKey(
        {
          ...serialized,
          bearer: Buffer.from(await createVaultKey()).toString("base64url"),
        },
        context,
      ),
    ).rejects.toThrow();
  });
});

test("active envelope primitives bind chunk position and complete count", async () => {
  const key = await createVaultKey();
  const chunkContext = { ...context, chunkIndex: 1, chunkCount: 2 };
  const encrypted = await encrypt(source, key, chunkContext);
  expect(await decrypt(encrypted, key, chunkContext)).toEqual(source);
  await expect(
    decrypt(encrypted, key, { ...chunkContext, chunkIndex: 0 }),
  ).rejects.toThrow();
  await expect(
    decrypt(encrypted, key, { ...chunkContext, chunkCount: 3 }),
  ).rejects.toThrow();
  key.fill(0);
});
