import { afterEach, expect, spyOn, test } from "bun:test";
import Dexie from "dexie";
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import sodium from "libsodium-wrappers-sumo";
import { z } from "zod";
import { localRuntime } from "../src/app/local-runtime.ts";
import {
  type Checkpoint,
  type SeedUnlockPort,
  unlockVaultWithSeed,
} from "../src/app/unlock.ts";
import {
  deriveSeed,
  unwrapAccessKey,
  v2PrfInput,
} from "../src/crypto/access-v2.ts";
import {
  acceptAccess,
  accessMetadataSchema,
  createSeedRecipient,
  openSealedToSeed,
  openWithSeed,
  passkeyAdmin,
  passkeyBinding,
  pinnedAccessSchema,
  recipientsOf,
  seedSigningKey,
  UNTRUSTED_ACCESS,
  vaultRecipientSchema,
} from "../src/crypto/access-v3.ts";
import { entrySigner } from "../src/crypto/authorship.ts";
import {
  encryptContainerBase,
  encryptContainerJournal,
} from "../src/crypto/container.ts";
import {
  deviceAuthorizeMessage,
  linkCommitment,
  matchesLinkCommitment,
  pairingCode,
  sealLinkHandoff,
  typedPairingCode,
} from "../src/crypto/link.ts";
import { passkeyRequestChallenge } from "../src/crypto/passkey-proof.ts";
import { handedCheckpoint } from "../src/device/client.ts";
import {
  decodeSnapshot,
  encodeJournal,
  encodeSnapshot,
  snapshotRemote,
} from "../src/sync/vault-snapshot.ts";
import {
  readVerifiedVaultRoot,
  vaultRecordSchema,
} from "../src/sync/vault-transport.ts";
import { createSession } from "../src/vault/session.ts";
import { revisionDigest } from "../src/vault/storage.ts";
import golden from "./fixtures/note-v3-vault.json" with { type: "json" };

// Written by NOTE's own code before this package existed (`note-v3-vault.json`):
// a passkey admin's vault with a device linked through the browser, and notes
// the admin, the device and nobody signed. Production vaults look like this,
// so every check here reads it exactly as it was written.
//
// Every `flow-note/…` domain string in `src/` is frozen, and this file alone
// fails when any one of the 25 changes:
// - crypto/index: `v1`;
// - crypto/container: `v2`, twice;
// - crypto/access-v2: `v2/prf`, `v2/access-recipient`, `v2/access-header`,
//   `v${version}/access-wrap`;
// - crypto/access-v3: `v3/seed-recipient`, `v3/admin-sign`, `v3/upgrade`,
//   `v2/access-recipient`, `v3/${purpose}`, `v3/access-salt`, `v3/access`,
//   `v3/admin`, `v3/recipient`, `v3/statement`;
// - crypto/authorship: `v3/entry`;
// - crypto/link: `v3/pairing`, `v3/link-commitment`, `v3/device-authorize`,
//   `v3/link`, twice, and `v3/link-secret-key`;
// - crypto/passkey-proof: `v3/passkey-request`.
Dexie.dependencies.IDBKeyRange = IDBKeyRange;
afterEach(() => {
  Dexie.dependencies.indexedDB = new IDBFactory();
});

const decode = (value: string) =>
  sodium.from_base64(value, sodium.base64_variants.URLSAFE_NO_PADDING);
const { did, vault, epoch, credentialId, secret } = golden;
const record = vaultRecordSchema.parse(golden.record.value);
const header = { accessSalt: record.accessSalt, access: record.access };
const checkpoint = z
  .object({
    vault: z.string(),
    epoch: z.number(),
    pinned: pinnedAccessSchema,
    trust: z.enum(["handed", "tofu"]),
    runners: z.array(
      z.object({ recipientId: z.string(), signPublicKey: z.string() }),
    ),
  })
  .parse(golden.checkpoint);
const recipients = {
  admin: vaultRecipientSchema.parse(golden.recipients.admin),
  device: vaultRecipientSchema.parse(golden.recipients.device),
};
const decoded = decodeSnapshot(
  new TextEncoder().encode(
    JSON.stringify({
      version: 2,
      entries: golden.entries.map(({ entry }) => entry),
    }),
  ),
);
const entries = golden.entries.map(({ writer, digest }, index) => {
  const entry = decoded[index];
  if (!entry) throw new Error("Missing entry");
  return { writer, digest, entry };
});
const material = async () => {
  await sodium.ready;
  return {
    key: decode(golden.key),
    prf: decode(golden.prf),
    seed: decode(golden.seed),
  };
};

test("the device's seed and the admin passkey's PRF both open the vault NOTE wrote", async () => {
  const { key, prf, seed } = await material();
  expect((await openWithSeed(header, seed, did)).key).toEqual(key);
  expect((await unwrapAccessKey(header, prf, credentialId, did)).key).toEqual(
    key,
  );
  const { manifest, metadata } = await readVerifiedVaultRoot(key, did, record);
  expect(manifest).toMatchObject({ vault, epoch });
  await acceptAccess(metadata, { did, vault, epoch }, checkpoint.pinned);
});

/** The link tag as NOTE keyed it, kept apart from `src/` so a changed domain string there fails here. */
async function linkTagAsNoteKeyed(code: string, recipientId: string) {
  const derivationSalt = new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(
        JSON.stringify(["flow-note/v3/link", did, recipientId]),
      ),
    ),
  );
  const key = await deriveSeed(
    new TextEncoder().encode(code),
    derivationSalt,
    "flow-note/v3/link-secret-key",
  );
  return sodium.crypto_auth_hmacsha256(
    new TextEncoder().encode(
      JSON.stringify([
        "flow-note/v3/link",
        did,
        recipientId,
        checkpoint.vault,
        checkpoint.epoch,
        checkpoint.pinned.statement,
        checkpoint.trust,
      ]),
    ),
    key,
  );
}

test("the handoff NOTE sealed to the device is keyed as seal keys one, and seed unlock accepts the header", async () => {
  const { key, seed } = await material();
  const own = await createSeedRecipient(seed, "device");
  const { metadata } = await readVerifiedVaultRoot(key, did, record);
  if (!("version" in metadata) || !metadata.link)
    throw new Error("NOTE's vault carries no handoff");
  expect(await openSealedToSeed(decode(metadata.link.sealed), seed)).toEqual(
    await linkTagAsNoteKeyed(secret, own.id),
  );
  // NOTE sealed this handoff under a twelve-digit code; codes are eight symbols now, and nothing reads the old form.
  await expect(
    handedCheckpoint({ header: record }, seed, did, secret),
  ).rejects.toThrow("Invalid link secret");
  const code = typedPairingCode(golden.pairing);
  const handoff = await sealLinkHandoff(
    { secret: code, did, recipient: own },
    checkpoint,
  );
  expect(await openSealedToSeed(decode(handoff.sealed), seed)).toEqual(
    await linkTagAsNoteKeyed(code, own.id),
  );
  let saved: Checkpoint | null = null;
  const port: SeedUnlockPort = {
    current: () => ({
      userId: "owner",
      did,
      recipientId: own.id,
      sessionVersion: 0,
    }),
    checkpoint: async () => checkpoint,
    saveCheckpoint: async (value) => {
      saved = value;
    },
    resolve: async () => ({ did, active: true, authorized: true }),
    readHeader: async () => ({ header: record, cid: golden.record.cid }),
    runners: checkpoint.runners,
    runtime: (session) => localRuntime(session),
  };
  const { runtime } = await unlockVaultWithSeed(port, seed);
  try {
    expect(await runtime.read()).toEqual({ notes: [], folders: [] });
    expect(saved).toMatchObject({ vault, epoch, trust: "handed" });
  } finally {
    runtime.lock();
  }
});

test("keys, recipient ids, the pairing code and the device's link messages derive as NOTE derived them", async () => {
  const { prf, seed } = await material();
  expect((await passkeyAdmin(prf, credentialId, did)).recipient).toEqual(
    recipients.admin,
  );
  const device = await createSeedRecipient(seed, "device", "Laptop");
  expect(device).toEqual(recipients.device);
  const { boxPublicKey, signPublicKey = "" } = device;
  expect(await pairingCode(boxPublicKey, signPublicKey)).toBe(
    golden.pairingCode,
  );
  expect(
    sodium.to_hex(
      deviceAuthorizeMessage({
        kind: "device",
        boxPublicKey,
        signPublicKey,
        commitment: "commitment",
      }),
    ),
  ).toBe(golden.deviceAuthorize);
  expect(
    await linkCommitment(
      typedPairingCode(golden.pairing),
      golden.committed,
      new Uint8Array(16).fill(3),
    ),
  ).toBe(golden.commitment);
  expect(
    await matchesLinkCommitment(
      typedPairingCode(golden.pairing),
      golden.committed,
      golden.commitment,
    ),
  ).toBe(true);
});

test("NOTE's entries keep their digests and signers, and run on the linked device as NOTE decided", async () => {
  const { key, seed } = await material();
  const { metadata } = await readVerifiedVaultRoot(key, did, record);
  const listed = recipientsOf(metadata);
  const signers = new Map<string, string | null>([
    ["admin", recipients.admin.id],
    ["device", recipients.device.id],
    ["nobody", null],
  ]);
  for (const { writer, digest, entry } of entries) {
    expect(signers.has(writer)).toBe(true);
    expect(await revisionDigest(entry)).toBe(digest);
    expect((await entrySigner(entry, { did, vault }, listed))?.id ?? null).toBe(
      signers.get(writer) ?? null,
    );
  }
  const signingKey = await seedSigningKey(seed);
  const session = createSession({
    owner: did,
    vault,
    key,
    epoch,
    authorship: {
      signer: {
        recipientId: recipients.device.id,
        signPublicKey: recipients.device.signPublicKey ?? "",
        privateKey: signingKey,
      },
      access: metadata,
      runners: checkpoint.runners,
    },
  });
  try {
    for (const { entry } of entries) {
      const { remote, blobs } = snapshotRemote(entry);
      await session.applyRemote(remote, blobs);
    }
    const { notes } = await session.readView();
    expect(
      notes
        .map(({ path, source, origin }) => ({
          path,
          source,
          runs: origin?.runs,
        }))
        .sort((a, b) => a.path.localeCompare(b.path)),
    ).toEqual([
      {
        path: "Admin.mdx",
        source: "export const answer = 42\n\n# Admin {answer}\n",
        runs: true,
      },
      {
        path: "Device.md",
        source: "# Device\n\nTyped on the linked device.\n",
        runs: undefined,
      },
      {
        path: "Shared.md",
        source: "Written on the passkey, [[Device]].\n",
        runs: undefined,
      },
      { path: "Unsigned.mdx", source: "# Nobody signed this\n", runs: false },
    ]);
  } finally {
    session.lock();
    signingKey.fill(0);
    await session.database.delete();
  }
});

test("a journal over NOTE's entries seals to the same bytes NOTE's code sealed", async () => {
  const { key } = await material();
  const { metadata } = await readVerifiedVaultRoot(key, did, record);
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
  const sha = async (bytes: Uint8Array) =>
    sodium.to_hex(
      new Uint8Array(
        await crypto.subtle.digest("SHA-256", new Uint8Array(bytes)),
      ),
    );
  try {
    const context = { did, vault, epoch: 1 };
    const { base, chunks } = await encryptContainerBase(
      key,
      context,
      encodeSnapshot(entries.slice(0, 2).map(({ entry }) => entry)),
    );
    const sealed = await encryptContainerJournal(
      key,
      context,
      base,
      {
        plaintext: encodeJournal({
          entries: entries.slice(2).map(({ entry }) => entry),
          removed: ["gone"],
        }),
        entries: 2,
        compactAt: 1024,
      },
      metadata,
    );
    expect({
      root: await sha(new TextEncoder().encode(JSON.stringify(sealed.root))),
      base: await Promise.all(chunks.map(sha)),
      chunk: await sha(sealed.chunk),
    }).toEqual(golden.journal);
  } finally {
    randomness.mockRestore();
  }
});

test("the PRF input, a legacy passkey's upgrade and a passkey request derive as NOTE derived them", async () => {
  const { prf } = await material();
  expect(await v2PrfInput()).toEqual(decode(golden.prfInput));

  const context = { did, vault, epoch };
  const admin = await passkeyAdmin(prf, credentialId, did);
  const { upgrade } = golden;
  expect(
    await passkeyBinding(prf, credentialId, context, admin.recipient),
  ).toEqual(upgrade.binding);
  const signed = accessMetadataSchema.parse(upgrade.metadata);
  expect(await acceptAccess(signed, context, null)).toEqual(
    pinnedAccessSchema.parse(upgrade.pinned),
  );
  const unbound = { ...signed.statement, binding: undefined };
  await expect(
    acceptAccess({ ...signed, statement: unbound }, context, null),
  ).rejects.toThrow(UNTRUSTED_ACCESS);

  const { request, challenge } = golden.passkeyRequest;
  expect(request).toMatchObject({
    did,
    boxPublicKey: admin.recipient.boxPublicKey,
    signPublicKey: admin.recipient.signPublicKey,
  });
  expect(await passkeyRequestChallenge(request)).toEqual(decode(challenge));
});
