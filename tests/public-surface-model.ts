// biome-ignore-all lint/plugin: Adversarial public-surface qualification must inspect arbitrary encodings and deliberately mutate invalid fixtures.
import { strict as assert } from "node:assert";
import { CarReader } from "@ipld/car";
import { decode } from "@ipld/dag-cbor";
import {
  CHUNK_BYTES,
  MAX_CHUNKS,
  ROOT_BYTES,
} from "../src/crypto/container.ts";

const COLLECTION = "industries.flow.note.vault";
const object = (value: unknown): Record<string, unknown> => {
  assert(value !== null && typeof value === "object" && !Array.isArray(value));
  return value as Record<string, unknown>;
};
const keys = (value: unknown, expected: string[]) =>
  assert.deepEqual(Object.keys(object(value)).sort(), expected.sort());
const base64 = (value: unknown, bytes: number) => {
  assert.equal(typeof value, "string");
  const encoded = value as string;
  assert.match(encoded, /^[A-Za-z0-9_-]+$/u);
  assert.equal(Buffer.from(encoded, "base64url").byteLength, bytes);
  assert.equal(
    Buffer.from(encoded, "base64url").toString("base64url"),
    encoded,
  );
};

export function inspectVaultRecord(value: unknown) {
  const record = object(value);
  keys(record, ["$type", "version", "accessSalt", "access", "root", "blobs"]);
  assert.equal(record.$type, COLLECTION);
  assert.equal(record.version, 2);
  base64(record.accessSalt, 32);
  assert(Array.isArray(record.access));
  assert.equal(record.access.length, 16);
  for (const slot of record.access) {
    keys(slot, ["keyId", "wrapped"]);
    base64(slot.keyId, 32);
    base64(slot.wrapped, 112);
  }
  const root = object(record.root);
  keys(root, ["version", "nonce", "ciphertext"]);
  assert.equal(root.version, 2);
  base64(root.nonce, 12);
  base64(root.ciphertext, ROOT_BYTES - 12);
  assert(Array.isArray(record.blobs));
  const count = record.blobs.length;
  assert(count >= 1 && count <= MAX_CHUNKS && (count & (count - 1)) === 0);
  const cids = record.blobs.map((blob: unknown) => {
    const ref = object(blob);
    keys(ref, ["$type", "ref", "mimeType", "size"]);
    assert.equal(ref.$type, "blob");
    assert.equal(ref.mimeType, "application/octet-stream");
    assert.equal(ref.size, CHUNK_BYTES);
    keys(ref.ref, ["$link"]);
    const cid = object(ref.ref).$link;
    assert.equal(typeof cid, "string");
    return cid as string;
  });
  assert.equal(
    new Set(cids).size,
    count,
    "Duplicate chunks reveal occupied capacity",
  );
  return { record, cids, bucket: count };
}

export function publicFingerprint(value: unknown): unknown {
  if (value instanceof Uint8Array) return { bytes: value.byteLength };
  if (typeof value === "string") return { utf8: Buffer.byteLength(value) };
  if (Array.isArray(value)) return value.map(publicFingerprint);
  if (value !== null && typeof value === "object") {
    const record = object(value);
    if (record.asCID === value) return { cid: true };
    return Object.fromEntries(
      Object.keys(record)
        .sort()
        .map((key) => [key, publicFingerprint(record[key])]),
    );
  }
  return value;
}

export async function carFingerprint(bytes: Uint8Array) {
  const car = await CarReader.fromBytes(bytes);
  const blocks: string[] = [];
  for await (const block of car.blocks()) {
    blocks.push(JSON.stringify(publicFingerprint(decode(block.bytes))));
  }
  return { roots: (await car.getRoots()).length, blocks: blocks.sort() };
}

export interface PublicSnapshot {
  record: unknown;
  listedBlobCids: string[];
  listedBlobSizes: number[];
  reachableBlobSizes: number[];
  noteCollections: string[];
  noteRecordUris: string[];
  car: Awaited<ReturnType<typeof carFingerprint>>;
}

export function assertQualifiedSnapshot(snapshot: PublicSnapshot) {
  const inspected = inspectVaultRecord(snapshot.record);
  assert.deepEqual(snapshot.noteCollections, [COLLECTION]);
  assert.equal(snapshot.noteRecordUris.length, 1);
  assert(snapshot.noteRecordUris[0]?.endsWith(`/${COLLECTION}/vault`));
  assert.deepEqual(
    snapshot.reachableBlobSizes,
    inspected.cids.map(() => CHUNK_BYTES),
  );
  assert.deepEqual(
    snapshot.listedBlobSizes,
    snapshot.listedBlobCids.map(() => CHUNK_BYTES),
  );
  for (const cid of inspected.cids)
    assert(snapshot.listedBlobCids.includes(cid));
  return inspected;
}

export function assertSameBucketSurface(a: PublicSnapshot, b: PublicSnapshot) {
  assertQualifiedSnapshot(a);
  assertQualifiedSnapshot(b);
  assert.deepEqual(publicFingerprint(a.record), publicFingerprint(b.record));
  assert.deepEqual(a.reachableBlobSizes, b.reachableBlobSizes);
  assert.deepEqual(a.car, b.car);
}

/** A content-only write: fresh chunks and root over byte-identical access slots. */
export function assertContentPublication(before: unknown, after: unknown) {
  const a = inspectVaultRecord(before);
  const b = inspectVaultRecord(after);
  for (const cid of b.cids)
    assert(!a.cids.includes(cid), "Publication reused a chunk CID");
  assert.equal(a.record.accessSalt, b.record.accessSalt);
  assert.deepEqual(a.record.access, b.record.access);
  assert.notDeepEqual(a.record.root, b.record.root);
}

/** A journal write replaces only the last blob, which is how a public reader tells it from a compaction. */
export function assertJournalPublication(before: unknown, after: unknown) {
  const a = inspectVaultRecord(before);
  const b = inspectVaultRecord(after);
  assert.deepEqual(b.cids.slice(0, -1), a.cids.slice(0, -1));
  assert.notEqual(b.cids.at(-1), a.cids.at(-1));
  assert.equal(a.record.accessSalt, b.record.accessSalt);
  assert.deepEqual(a.record.access, b.record.access);
  assert.notDeepEqual(a.record.root, b.record.root);
}

export function assertFreshPublication(before: unknown, after: unknown) {
  const a = inspectVaultRecord(before);
  const b = inspectVaultRecord(after);
  for (const cid of b.cids)
    assert(!a.cids.includes(cid), "Publication reused a chunk CID");
  assert.notEqual(a.record.accessSalt, b.record.accessSalt);
  const oldSlots = a.record.access as { keyId: string; wrapped: string }[];
  for (const slot of b.record.access as { keyId: string; wrapped: string }[]) {
    assert(
      !oldSlots.some(
        (old) => old.keyId === slot.keyId || old.wrapped === slot.wrapped,
      ),
    );
  }
  assert.notDeepEqual(a.record.root, b.record.root);
}

export async function readPublicSurface(
  pds: string,
  did: string,
): Promise<PublicSnapshot> {
  const rpc = async (name: string, parameters: Record<string, string>) => {
    const url = new URL(`/xrpc/${name}`, pds);
    url.search = new URLSearchParams(parameters).toString();
    const response = await fetch(url, { credentials: "omit" });
    assert.equal(response.status, 200, `${name} public read failed`);
    return response;
  };
  const description = await (
    await rpc("com.atproto.repo.describeRepo", { repo: did })
  ).json();
  const noteCollections: string[] = description.collections.filter(
    (c: string) =>
      c.startsWith("game.flow.note.") || c.startsWith("industries.flow.note."),
  );
  noteCollections.sort();
  const noteRecordUris: string[] = [];
  for (const collection of noteCollections) {
    let cursor: string | undefined;
    do {
      const page = await (
        await rpc("com.atproto.repo.listRecords", {
          repo: did,
          collection,
          limit: "100",
          ...(cursor ? { cursor } : {}),
        })
      ).json();
      noteRecordUris.push(...page.records.map((r: { uri: string }) => r.uri));
      cursor = page.cursor;
    } while (cursor);
  }
  const result = await (
    await rpc("com.atproto.repo.getRecord", {
      repo: did,
      collection: COLLECTION,
      rkey: "vault",
    })
  ).json();
  const { cids } = inspectVaultRecord(result.value);
  const listedBlobCids: string[] = [];
  let cursor: string | undefined;
  do {
    const page = await (
      await rpc("com.atproto.sync.listBlobs", {
        did,
        limit: "100",
        ...(cursor ? { cursor } : {}),
      })
    ).json();
    listedBlobCids.push(...page.cids);
    cursor = page.cursor;
  } while (cursor);
  const listedBlobSizes = await Promise.all(
    listedBlobCids.map(
      async (cid) =>
        (
          await (
            await rpc("com.atproto.sync.getBlob", { did, cid })
          ).arrayBuffer()
        ).byteLength,
    ),
  );
  const reachableBlobSizes = cids.map((cid) => {
    const index = listedBlobCids.indexOf(cid);
    assert(index >= 0, "Reachable blob is absent from public inventory");
    return listedBlobSizes[index];
  });
  const latest = await (
    await rpc("com.atproto.sync.getLatestCommit", { did })
  ).json();
  assert.equal(typeof latest.cid, "string");
  assert.equal(typeof latest.rev, "string");
  const car = await carFingerprint(
    new Uint8Array(
      await (await rpc("com.atproto.sync.getRepo", { did })).arrayBuffer(),
    ),
  );
  return {
    record: result.value,
    listedBlobCids,
    listedBlobSizes,
    reachableBlobSizes,
    noteCollections,
    noteRecordUris,
    car,
  };
}

interface CommitObservation {
  time: string;
  rev: string;
  operations: { action: string; path: string }[];
  blobs: number;
}

export async function observePublicCommits(pds: string, did: string) {
  const url = new URL("/xrpc/com.atproto.sync.subscribeRepos", pds);
  url.protocol = "ws:";
  const socket = new WebSocket(url);
  socket.binaryType = "arraybuffer";
  const commits: CommitObservation[] = [];
  const failures: Error[] = [];
  socket.addEventListener("message", (event) => {
    try {
      assert(event.data instanceof ArrayBuffer);
      const frame = new Uint8Array(event.data);
      let header: Record<string, unknown> | undefined;
      let boundary = 0;
      for (let end = 1; end <= Math.min(frame.length, 128); end++) {
        try {
          header = object(decode(frame.subarray(0, end)));
          boundary = end;
          break;
        } catch {
          /* DAG-CBOR rejects incomplete and trailing bytes. */
        }
      }
      assert(header, "Malformed firehose frame header");
      assert.equal(header.op, 1, "PDS returned a firehose error frame");
      if (header.t !== "#commit") return;
      const body = object(decode(frame.subarray(boundary)));
      if (body.repo !== did) return;
      assert.equal(body.tooBig, false, "Firehose omitted commit operations");
      assert(Array.isArray(body.ops));
      assert(Array.isArray(body.blobs));
      assert.equal(typeof body.time, "string");
      assert.equal(typeof body.rev, "string");
      const operations = body.ops.map((value: unknown) => {
        const op = object(value);
        assert.equal(typeof op.action, "string");
        assert.equal(typeof op.path, "string");
        return { action: op.action as string, path: op.path as string };
      });
      commits.push({
        time: body.time as string,
        rev: body.rev as string,
        operations,
        blobs: body.blobs.length,
      });
    } catch (error) {
      failures.push(error instanceof Error ? error : new Error(String(error)));
    }
  });
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      socket.close();
      reject(new Error("Public firehose connection timed out"));
    }, 5000);
    socket.addEventListener(
      "open",
      () => {
        clearTimeout(timer);
        resolve();
      },
      { once: true },
    );
    socket.addEventListener(
      "error",
      () => {
        clearTimeout(timer);
        reject(new Error("Public firehose unavailable"));
      },
      { once: true },
    );
  });
  return {
    commits,
    async finish(expected: number) {
      const deadline = Date.now() + 5000;
      while (
        commits.length < expected &&
        failures.length === 0 &&
        Date.now() < deadline
      )
        await new Promise((resolve) => setTimeout(resolve, 25));
      socket.close();
      assert.deepEqual(failures, []);
      assert.equal(commits.length, expected);
      for (const commit of commits) {
        assert.equal(commit.operations.length, 1);
        assert.equal(commit.operations[0]?.path, `${COLLECTION}/vault`);
      }
      return commits;
    },
    close: () => socket.close(),
  };
}
