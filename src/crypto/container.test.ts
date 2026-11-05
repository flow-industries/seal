import { describe, expect, spyOn, test } from "bun:test";
import sodium from "libsodium-wrappers-sumo";
import {
  baseChunkCount,
  CHUNK_BYTES,
  CHUNK_PLAINTEXT_BYTES,
  containerBlobCount,
  containerChunkCount,
  decryptContainerChunks,
  decryptContainerJournal,
  decryptContainerRoot,
  encryptContainer,
  encryptContainerBase,
  encryptContainerJournal,
  JOURNAL_PLAINTEXT_BYTES,
  MAX_BASE_BYTES,
  MAX_CHUNKS,
  MAX_CONTAINER_BYTES,
  ROOT_BYTES,
} from "./container.ts";

const key = new Uint8Array(32).fill(7);
const context = { did: "did:plc:test", vault: "vault-test", epoch: 3 };
const bytes = (value: string) => new TextEncoder().encode(value);
const unbase64 = (value: string) =>
  sodium.from_base64(value, sodium.base64_variants.URLSAFE_NO_PADDING);

describe("v2 padded container", () => {
  test("empty, single-note and 100-note snapshots have identical public lengths", async () => {
    const snapshots = [
      new Uint8Array(),
      bytes(JSON.stringify([{ body: "one" }])),
      bytes(
        JSON.stringify(
          Array.from({ length: 100 }, (_, id) => ({
            id,
            body: "note with an attachment",
            asset: "AAECAw",
          })),
        ),
      ),
    ];
    for (const input of snapshots) {
      const result = await encryptContainer(key, context, input, {
        recipients: [],
        accessCommitment: "test",
      });
      expect(result.chunks).toHaveLength(1);
      expect(result.chunks[0].length).toBe(CHUNK_BYTES);
      expect(
        unbase64(result.root.nonce).length +
          unbase64(result.root.ciphertext).length,
      ).toBe(ROOT_BYTES);
      const manifest = await decryptContainerRoot(key, context, result.root);
      expect(manifest.metadata).toEqual({
        recipients: [],
        accessCommitment: "test",
      });
      expect(
        await decryptContainerChunks(key, context, manifest, result.chunks),
      ).toEqual(input);
    }
  });
  test("bucket boundaries and maximum are exact", () => {
    expect(containerChunkCount(0)).toBe(1);
    expect(containerChunkCount(CHUNK_PLAINTEXT_BYTES)).toBe(1);
    expect(containerChunkCount(CHUNK_PLAINTEXT_BYTES + 1)).toBe(2);
    expect(containerChunkCount(2 * CHUNK_PLAINTEXT_BYTES + 1)).toBe(4);
    expect(containerChunkCount(MAX_CONTAINER_BYTES)).toBe(MAX_CHUNKS);
    for (const length of [-1, 0.5, NaN, Infinity, MAX_CONTAINER_BYTES + 1])
      expect(() => containerChunkCount(length)).toThrow();
  });
  test("all chunks including padding change for every publication", async () => {
    const input = new Uint8Array(2 * CHUNK_PLAINTEXT_BYTES + 1).fill(5);
    const first = await encryptContainer(key, context, input);
    const second = await encryptContainer(key, context, input);
    expect(first.chunks).toHaveLength(4);
    expect(
      new Set([...first.manifest.chunkHashes, ...second.manifest.chunkHashes])
        .size,
    ).toBe(8);
    expect(first.root).not.toEqual(second.root);
    expect(
      await decryptContainerChunks(key, context, first.manifest, first.chunks),
    ).toEqual(input);
  });
  test("rejects reordered, dropped, duplicate, corrupted and cross-generation chunks", async () => {
    const input = new Uint8Array(CHUNK_PLAINTEXT_BYTES + 1);
    const first = await encryptContainer(key, context, input);
    const second = await encryptContainer(key, context, input);
    const corrupted = first.chunks[0].slice();
    corrupted[100] ^= 1;
    for (const chunks of [
      [first.chunks[1], first.chunks[0]],
      [first.chunks[0]],
      [first.chunks[0], first.chunks[0]],
      [corrupted, first.chunks[1]],
      [second.chunks[0], first.chunks[1]],
      [first.chunks[0].slice(1), first.chunks[1]],
    ]) {
      await expect(
        decryptContainerChunks(key, context, first.manifest, chunks),
      ).rejects.toThrow();
    }
    await expect(
      decryptContainerChunks(
        key,
        context,
        { ...first.manifest, generation: second.manifest.generation },
        first.chunks,
      ),
    ).rejects.toThrow();
    await expect(
      decryptContainerChunks(
        key,
        context,
        { ...first.manifest, vault: "other" },
        first.chunks,
      ),
    ).rejects.toThrow();
    await expect(
      decryptContainerChunks(
        key,
        context,
        { ...first.manifest, epoch: 4 },
        first.chunks,
      ),
    ).rejects.toThrow();
    await expect(
      decryptContainerChunks(
        key,
        { did: "did:plc:other" },
        first.manifest,
        first.chunks,
      ),
    ).rejects.toThrow();
  });
  test("rejects truncated, extended, corrupted roots, wrong keys and DID substitution", async () => {
    const { root } = await encryptContainer(key, context, bytes("private"));
    for (const ciphertext of [
      root.ciphertext.slice(1),
      `${root.ciphertext}A`,
      `${root.ciphertext[0] === "A" ? "B" : "A"}${root.ciphertext.slice(1)}`,
    ]) {
      await expect(
        decryptContainerRoot(key, context, { ...root, ciphertext }),
      ).rejects.toThrow();
    }
    await expect(
      decryptContainerRoot(new Uint8Array(32), context, root),
    ).rejects.toThrow();
    await expect(
      decryptContainerRoot(key, { did: "did:plc:other" }, root),
    ).rejects.toThrow();
    await expect(
      decryptContainerRoot(
        key,
        context,
        Object.assign({}, root, { debug: "leak" }),
      ),
    ).rejects.toThrow();
  });
});

describe("journaled container", () => {
  const metadata = { recipients: [], accessCommitment: "test" };
  const journal = (value: string, entries = 1, compactAt = 1024) => ({
    plaintext: bytes(value),
    entries,
    compactAt,
  });
  test("base chunk counts stay one short of a power of two", () => {
    expect(baseChunkCount(0)).toBe(0);
    expect(baseChunkCount(1)).toBe(1);
    expect(baseChunkCount(CHUNK_PLAINTEXT_BYTES)).toBe(1);
    expect(baseChunkCount(CHUNK_PLAINTEXT_BYTES + 1)).toBe(3);
    expect(baseChunkCount(3 * CHUNK_PLAINTEXT_BYTES)).toBe(3);
    expect(baseChunkCount(3 * CHUNK_PLAINTEXT_BYTES + 1)).toBe(7);
    expect(baseChunkCount(MAX_BASE_BYTES)).toBe(MAX_CHUNKS - 1);
    for (const length of [-1, 0.5, NaN, Infinity, MAX_BASE_BYTES + 1])
      expect(() => baseChunkCount(length)).toThrow();
  });
  test("a multi-chunk base and its journal round trip under one root", async () => {
    const input = new Uint8Array(CHUNK_PLAINTEXT_BYTES + 1).fill(4);
    const { base, chunks } = await encryptContainerBase(key, context, input);
    expect(chunks).toHaveLength(3);
    expect(chunks.every((chunk) => chunk.length === CHUNK_BYTES)).toBe(true);
    const sealed = await encryptContainerJournal(
      key,
      context,
      base,
      journal("journal payload", 2),
      metadata,
    );
    expect(sealed.chunk.length).toBe(CHUNK_BYTES);
    const manifest = await decryptContainerRoot(key, context, sealed.root);
    expect(manifest).toEqual(sealed.manifest);
    expect(manifest).toMatchObject({
      version: 3,
      ...base,
      journal: { entries: 2, compactAt: 1024 },
      metadata,
    });
    expect(containerBlobCount(manifest)).toBe(4);
    expect(
      await decryptContainerChunks(key, context, manifest, chunks),
    ).toEqual(input);
    expect(
      await decryptContainerJournal(key, context, manifest, sealed.chunk),
    ).toEqual(bytes("journal payload"));
  });
  test("an empty base leaves the journal as the only chunk", async () => {
    const { base, chunks } = await encryptContainerBase(
      key,
      context,
      new Uint8Array(),
    );
    expect(base).toMatchObject({ byteLength: 0, chunkCount: 0 });
    expect(chunks).toEqual([]);
    const sealed = await encryptContainerJournal(
      key,
      context,
      base,
      journal("everything"),
      metadata,
    );
    const manifest = await decryptContainerRoot(key, context, sealed.root);
    expect(containerBlobCount(manifest)).toBe(1);
    expect(await decryptContainerChunks(key, context, manifest, [])).toEqual(
      new Uint8Array(),
    );
    expect(
      await decryptContainerJournal(key, context, manifest, sealed.chunk),
    ).toEqual(bytes("everything"));
  });
  test("a journal fills its chunk exactly and no further", async () => {
    const { base } = await encryptContainerBase(key, context, bytes("base"));
    const full = new Uint8Array(JOURNAL_PLAINTEXT_BYTES).fill(9);
    const sealed = await encryptContainerJournal(
      key,
      context,
      base,
      { plaintext: full, entries: 1, compactAt: 0 },
      metadata,
    );
    expect(
      await decryptContainerJournal(
        key,
        context,
        await decryptContainerRoot(key, context, sealed.root),
        sealed.chunk,
      ),
    ).toEqual(full);
    await expect(
      encryptContainerJournal(
        key,
        context,
        base,
        {
          plaintext: new Uint8Array(JOURNAL_PLAINTEXT_BYTES + 1),
          entries: 1,
          compactAt: 0,
        },
        metadata,
      ),
    ).rejects.toThrow("Container journal exceeds limit");
  });
  test("a journal is bound to its base and pinned by the root", async () => {
    const first = await encryptContainerBase(key, context, bytes("first"));
    const second = await encryptContainerBase(key, context, bytes("second"));
    const sealed = await encryptContainerJournal(
      key,
      context,
      first.base,
      journal("first journal"),
      metadata,
    );
    const later = await encryptContainerJournal(
      key,
      context,
      first.base,
      journal("later journal"),
      metadata,
    );
    const corrupted = sealed.chunk.slice();
    corrupted[200] ^= 1;
    const otherBase = {
      ...sealed.manifest,
      ...second.base,
      journal: sealed.manifest.journal,
    };
    for (const [manifest, chunk, did] of [
      [otherBase, sealed.chunk, context.did],
      [later.manifest, sealed.chunk, context.did],
      [sealed.manifest, corrupted, context.did],
      [sealed.manifest, first.chunks[0], context.did],
      [sealed.manifest, sealed.chunk.slice(1), context.did],
      [{ ...sealed.manifest, epoch: 4 }, sealed.chunk, context.did],
      [{ ...sealed.manifest, vault: "other" }, sealed.chunk, context.did],
      [sealed.manifest, sealed.chunk, "did:plc:other"],
    ] as const)
      await expect(
        decryptContainerJournal(key, { did }, manifest, chunk),
      ).rejects.toThrow();
    await expect(
      decryptContainerJournal(
        new Uint8Array(32),
        context,
        sealed.manifest,
        sealed.chunk,
      ),
    ).rejects.toThrow();
    const v2 = await encryptContainer(key, context, bytes("v2"));
    await expect(
      decryptContainerJournal(key, context, v2.manifest, v2.chunks[0]),
    ).rejects.toThrow("Invalid container journal");
  });
  test("journaled manifests reject inconsistent shapes", async () => {
    const { base, chunks } = await encryptContainerBase(
      key,
      context,
      bytes("base"),
    );
    const { manifest } = await encryptContainerJournal(
      key,
      context,
      base,
      journal("journal"),
      metadata,
    );
    for (const invalid of [
      { ...manifest, chunkCount: 2 },
      { ...manifest, byteLength: CHUNK_PLAINTEXT_BYTES + 1 },
      { ...manifest, chunkHashes: [] },
      {
        ...manifest,
        journal: { ...manifest.journal, hash: manifest.chunkHashes[0] },
      },
      {
        ...manifest,
        journal: {
          ...manifest.journal,
          compactAt: JOURNAL_PLAINTEXT_BYTES + 1,
        },
      },
      { ...manifest, journal: { ...manifest.journal, extra: true } },
      { ...manifest, version: 2 },
    ])
      await expect(
        decryptContainerChunks(
          key,
          context,
          // SAFETY: each value is deliberately malformed; decryptContainerChunks re-parses its untrusted manifest before use.
          invalid as typeof manifest,
          chunks,
        ),
      ).rejects.toThrow();
  });
});

test("v2 deterministic wire golden vector", async () => {
  await sodium.ready;
  let counter = 0;
  const randomness = spyOn(crypto, "getRandomValues").mockImplementation(
    <T extends ArrayBufferView>(array: T): T => {
      const bytes = new Uint8Array(
        array.buffer,
        array.byteOffset,
        array.byteLength,
      );
      for (let index = 0; index < bytes.length; index++)
        bytes[index] = counter++ % 251;
      return array;
    },
  );
  try {
    const snapshot = await encryptContainer(
      key,
      context,
      bytes("golden container"),
      { recipients: [], accessCommitment: "test" },
    );
    const digest = async (value: Uint8Array) =>
      Buffer.from(
        await crypto.subtle.digest("SHA-256", new Uint8Array(value)),
      ).toString("hex");
    expect(await digest(bytes(JSON.stringify(snapshot.root)))).toBe(
      "e541ca079542f72796c863e8376ab41e5cd89e2a4df39f1f852cd7007827a961",
    );
    expect(await digest(snapshot.chunks[0])).toBe(
      "38223768938e04e0860f872cab3136605c7d433daf5b3297f69d35441a5153c8",
    );
    expect(
      await decryptContainerChunks(
        key,
        context,
        await decryptContainerRoot(key, context, snapshot.root),
        snapshot.chunks,
      ),
    ).toEqual(bytes("golden container"));
  } finally {
    randomness.mockRestore();
  }
});

test("maximum-capacity vault round trips through the 512 MiB bucket", async () => {
  const plaintext = new Uint8Array(MAX_CONTAINER_BYTES);
  for (let index = 0; index < MAX_CHUNKS; index++)
    plaintext[index * CHUNK_PLAINTEXT_BYTES] = index;
  plaintext[plaintext.length - 1] = 255;
  const snapshot = await encryptContainer(key, context, plaintext);
  expect(snapshot.chunks).toHaveLength(MAX_CHUNKS);
  expect(snapshot.chunks.every((chunk) => chunk.length === CHUNK_BYTES)).toBe(
    true,
  );
  const decoded = await decryptContainerChunks(
    key,
    context,
    await decryptContainerRoot(key, context, snapshot.root),
    snapshot.chunks,
  );
  expect(decoded.length).toBe(MAX_CONTAINER_BYTES);
  expect(
    Buffer.compare(Buffer.from(decoded.buffer), Buffer.from(plaintext.buffer)),
  ).toBe(0);
  plaintext.fill(0);
  decoded.fill(0);
}, 60_000);

test("authenticated roots still reject invalid internal length prefixes", async () => {
  const { root } = await encryptContainer(key, context, bytes("bounded"));
  const material = await crypto.subtle.importKey("raw", key, "HKDF", false, [
    "deriveKey",
  ]);
  const rootKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(32),
      info: bytes(JSON.stringify(["flow-note/v2", "root-key", context.did])),
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  const parameters = {
    name: "AES-GCM",
    iv: new Uint8Array(unbase64(root.nonce)),
    additionalData: bytes(
      JSON.stringify(["flow-note/v2", "root", context.did]),
    ),
    tagLength: 128,
  };
  const plaintext = new Uint8Array(
    await crypto.subtle.decrypt(
      parameters,
      rootKey,
      new Uint8Array(unbase64(root.ciphertext)),
    ),
  );
  try {
    for (const length of [0, 1, ROOT_BYTES, 0xffffffff]) {
      new DataView(plaintext.buffer).setUint32(0, length, false);
      const ciphertext = sodium.to_base64(
        new Uint8Array(
          await crypto.subtle.encrypt(parameters, rootKey, plaintext),
        ),
        sodium.base64_variants.URLSAFE_NO_PADDING,
      );
      await expect(
        decryptContainerRoot(key, context, { ...root, ciphertext }),
      ).rejects.toThrow("Invalid root payload length");
    }
  } finally {
    plaintext.fill(0);
  }
});
