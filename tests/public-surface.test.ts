// biome-ignore-all lint/plugin: Adversarial public-surface qualification must inspect arbitrary encodings and deliberately mutate invalid fixtures.
import { describe, expect, test } from "bun:test";
import {
  createAccessHeader,
  createAccessRecipient,
} from "../src/crypto/access-v2.ts";
import { CHUNK_BYTES, encryptContainer } from "../src/crypto/container.ts";
import {
  assertFreshPublication,
  assertJournalPublication,
  assertQualifiedSnapshot,
  assertSameBucketSurface,
  inspectVaultRecord,
  type PublicSnapshot,
} from "./public-surface-model.ts";

const did = "did:plc:publicsurfacequalification";
const key = crypto.getRandomValues(new Uint8Array(32));
async function fixture(
  noteCount: number,
  passkeys: number,
): Promise<PublicSnapshot> {
  const recipients = await Promise.all(
    Array.from({ length: passkeys }, (_, index) =>
      createAccessRecipient(
        crypto.getRandomValues(new Uint8Array(32)),
        `credential-${index}`,
        did,
      ),
    ),
  );
  const header = await createAccessHeader(
    key,
    recipients.map((recipient) => recipient.publicKey),
    did,
  );
  const bytes = new TextEncoder().encode(
    JSON.stringify(
      Array.from({ length: noteCount }, (_, index) => ({
        path: `private-folder-${index}/private-note.md`,
        source: `# Private note ${index}`,
        attachments: index ? ["private-image.png"] : [],
      })),
    ),
  );
  const sealed = await encryptContainer(
    key,
    { did, vault: "qualification", epoch: 1 },
    bytes,
  );
  const cids = await Promise.all(
    sealed.chunks.map(
      async (chunk) =>
        `b${Buffer.from(await crypto.subtle.digest("SHA-256", new Uint8Array(chunk))).toString("hex")}`,
    ),
  );
  return {
    record: {
      $type: "industries.flow.note.vault",
      version: 2,
      ...header,
      root: sealed.root,
      blobs: cids.map((cid) => ({
        $type: "blob",
        ref: { $link: cid },
        mimeType: "application/octet-stream",
        size: CHUNK_BYTES,
      })),
    },
    listedBlobCids: cids,
    listedBlobSizes: cids.map(() => CHUNK_BYTES),
    reachableBlobSizes: cids.map(() => CHUNK_BYTES),
    noteCollections: ["industries.flow.note.vault"],
    noteRecordUris: [`at://${did}/industries.flow.note.vault/vault`],
    car: { roots: 1, blocks: [] },
  };
}

describe("v2 public observation regression checks", () => {
  test("one and 100 notes with one and three credentials share the same public shape", async () => {
    const a = await fixture(1, 1);
    const b = await fixture(100, 3);
    assertSameBucketSurface(a, b);
    assertFreshPublication(a.record, b.record);
  });
  test("rejects extra fields, extra records, v1 collections, off-size blobs and duplicate chunks", async () => {
    const original = await fixture(1, 1);
    const mutations: ((snapshot: PublicSnapshot) => void)[] = [
      (s) => {
        (s.record as Record<string, unknown>).noteCount = 1;
      },
      (s) => {
        s.noteRecordUris.push(`at://${did}/industries.flow.note.vault/debug`);
      },
      (s) => {
        s.noteCollections.push("game.flow.note.item");
      },
      (s) => {
        s.reachableBlobSizes[0] = CHUNK_BYTES - 1;
      },
      (s) => {
        s.listedBlobSizes[0] = CHUNK_BYTES - 1;
      },
      (s) => {
        const r = s.record as { blobs: unknown[] };
        r.blobs.push(r.blobs[0]);
      },
      (s) => {
        const r = s.record as { access: unknown[] };
        r.access.pop();
      },
    ];
    for (const mutate of mutations) {
      const snapshot = structuredClone(original);
      mutate(snapshot);
      expect(() => assertQualifiedSnapshot(snapshot)).toThrow();
    }
  });
  test("rejects slot and chunk reuse even when sizes match", async () => {
    const before = await fixture(1, 1);
    const after = await fixture(1, 1);
    const reused = structuredClone(after.record) as { access: unknown[] };
    reused.access[0] = (before.record as { access: unknown[] }).access[0];
    expect(() => assertFreshPublication(before.record, reused)).toThrow();
    expect(() =>
      assertFreshPublication(before.record, before.record),
    ).toThrow();
    const wrongBucket = structuredClone(after.record) as { blobs: unknown[] };
    wrongBucket.blobs = [
      ...wrongBucket.blobs,
      ...wrongBucket.blobs,
      ...wrongBucket.blobs,
    ];
    expect(() => inspectVaultRecord(wrongBucket)).toThrow();
  });
  test("a journal publication changes only the last blob and the root", async () => {
    const base = await fixture(1, 1);
    const record = base.record as {
      blobs: { ref: { $link: string } }[];
      root: { nonce: string };
    };
    const journaled = structuredClone(record);
    const chunks = [
      ...record.blobs,
      ...record.blobs.map((blob, index) => ({
        ...blob,
        ref: { $link: `b${"a".repeat(63)}${index}` },
      })),
    ];
    record.blobs = chunks;
    journaled.blobs = [
      ...chunks.slice(0, -1),
      { ...chunks[1], ref: { $link: `b${"c".repeat(64)}` } },
    ];
    journaled.root = { ...record.root, nonce: "Z".repeat(16) };
    assertJournalPublication(record, journaled);
    expect(() => assertJournalPublication(record, record)).toThrow();
    const rewritten = structuredClone(journaled);
    rewritten.blobs[0] = { ...chunks[1], ref: { $link: `b${"d".repeat(64)}` } };
    expect(() => assertJournalPublication(record, rewritten)).toThrow();
  });
});
