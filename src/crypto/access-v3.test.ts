import { expect, test } from "bun:test";
import { createHash } from "node:crypto";
import sodium from "libsodium-wrappers-sumo";
import {
  accessHeaderCommitment,
  createAccessHeader,
  createAccessRecipient,
  deriveSeed,
  passkeySeed,
} from "./access-v2.ts";
import {
  type AccessContext,
  type AccessMetadata,
  type AccessSigner,
  acceptAccess,
  accessSaltFor,
  createAccess,
  createSeedRecipient,
  openWithSeed,
  passkeyAdmin,
  passkeyBinding,
  pinnedRecipients,
  recipientsOf,
  type StatementKind,
  type VaultRecipient,
} from "./access-v3.ts";

const did = "did:plc:signedaccess";
const vault = "0b6e4e2a-5f0e-4c7e-9d1a-3c2b1a0f9e8d";
const context: AccessContext = { did, vault, epoch: 1 };
const key = new Uint8Array(32).fill(11);
const encode = (bytes: Uint8Array) =>
  sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING);
const decode = (value: string) =>
  sodium.from_base64(value, sodium.base64_variants.URLSAFE_NO_PADDING);
const admin = (fill: number, credential: string) =>
  passkeyAdmin(new Uint8Array(32).fill(fill), credential, did);
const sha256 = (...parts: (string | Uint8Array)[]) => {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return new Uint8Array(hash.digest());
};
const tuples = (recipients: readonly VaultRecipient[]) =>
  [...recipients]
    .sort((a, b) => (a.id < b.id ? -1 : 1))
    .map((recipient) => [
      recipient.id,
      recipient.kind,
      recipient.role,
      recipient.boxPublicKey,
      recipient.signPublicKey ?? null,
      recipient.label ?? null,
    ]);
interface Forged {
  kind: StatementKind;
  sequence: number;
  recipients: VaultRecipient[];
  signer: string;
  privateKey: Uint8Array;
}
/** Builds a statement exactly as the ticket specifies, independently of createAccess and its checks. */
async function forge(statement: Forged, at = context) {
  await sodium.ready;
  const nonce = sodium.randombytes_buf(32);
  const salt = sha256(
    "flow-note/v3/access-salt",
    nonce,
    JSON.stringify([
      statement.kind,
      at.did,
      at.vault,
      at.epoch,
      statement.signer,
      statement.sequence,
      tuples(statement.recipients),
      null,
      null,
    ]),
  );
  const header = await createAccessHeader(
    key,
    statement.recipients.map((recipient) => recipient.boxPublicKey),
    at.did,
    salt,
  );
  const accessCommitment = await accessHeaderCommitment(header);
  const message = JSON.stringify([
    "flow-note/v3/access",
    statement.kind,
    at.did,
    at.vault,
    at.epoch,
    statement.signer,
    statement.sequence,
    accessCommitment,
    tuples(statement.recipients),
  ]);
  const metadata: AccessMetadata = {
    version: 3,
    epoch: at.epoch,
    recipients: statement.recipients,
    accessCommitment,
    statement: {
      kind: statement.kind,
      signer: statement.signer,
      sequence: statement.sequence,
      nonce: encode(nonce),
      signature: encode(
        sodium.crypto_sign_detached(
          new TextEncoder().encode(message),
          statement.privateKey,
        ),
      ),
    },
  };
  return { header, metadata, message };
}
async function seedSigner(
  seed: Uint8Array,
  kind: "recovery" | "device" | "agent",
): Promise<AccessSigner> {
  await sodium.ready;
  const derived = await deriveSeed(
    seed,
    new Uint8Array(32),
    "flow-note/v3/sign",
  );
  return {
    recipient: await createSeedRecipient(seed, kind),
    privateKey: sodium.crypto_sign_seed_keypair(derived).privateKey,
  };
}
const access = (
  signer: AccessSigner,
  recipients: VaultRecipient[],
  kind: StatementKind = "create",
  sequence = 1,
  at = context,
) => createAccess(key, at, { kind, sequence, recipients, signer });

test("a passkey signs the canonical statement, and the header salt commits to it", async () => {
  const owner = await admin(7, "owner");
  const created = await access(owner, [owner.recipient]);
  const { metadata } = created;
  expect(metadata.statement).toMatchObject({
    kind: "create",
    signer: owner.recipient.id,
    sequence: 1,
  });
  expect(metadata.accessCommitment).toBe(
    await accessHeaderCommitment(created.header),
  );
  expect(created.header.accessSalt).toBe(
    encode(
      sha256(
        "flow-note/v3/access-salt",
        decode(metadata.statement.nonce),
        JSON.stringify([
          "create",
          did,
          vault,
          1,
          owner.recipient.id,
          1,
          tuples(metadata.recipients),
          null,
          null,
        ]),
      ),
    ),
  );
  expect(await accessSaltFor(metadata, context)).toBe(
    created.header.accessSalt,
  );
  expect(
    sodium.crypto_sign_verify_detached(
      decode(metadata.statement.signature),
      new TextEncoder().encode(
        JSON.stringify([
          "flow-note/v3/access",
          "create",
          did,
          vault,
          1,
          owner.recipient.id,
          1,
          metadata.accessCommitment,
          tuples(metadata.recipients),
        ]),
      ),
      decode(owner.recipient.signPublicKey ?? ""),
    ),
  ).toBe(true);
  const pinned = await acceptAccess(metadata, context, null);
  expect(pinned).toMatchObject({ sequence: 1 });
  expect(pinned.admins).toHaveLength(1);
  expect(pinned.recipients).toHaveLength(1);
  expect(JSON.stringify(pinned)).not.toContain(owner.recipient.id);
  expect(await acceptAccess(metadata, context, pinned)).toBe(pinned);
  for (const tampered of [
    { ...metadata, epoch: 2 },
    { ...metadata, recipients: [{ ...owner.recipient, label: "Renamed" }] },
    {
      ...metadata,
      statement: {
        ...metadata.statement,
        signature: `${metadata.statement.signature[0] === "A" ? "B" : "A"}${metadata.statement.signature.slice(1)}`,
      },
    },
  ])
    await expect(acceptAccess(tampered, context, null)).rejects.toThrow(
      "not signed by a trusted key",
    );
  for (const other of [
    { ...context, did: "did:plc:other" },
    { ...context, vault: crypto.randomUUID() },
  ])
    await expect(acceptAccess(metadata, other, null)).rejects.toThrow(
      "not signed by a trusted key",
    );
  expect(
    await accessSaltFor(
      { ...metadata, recipients: [{ ...owner.recipient, label: "Renamed" }] },
      context,
    ),
  ).not.toBe(created.header.accessSalt);
});

test("passkey keys come from the PRF and keep the v2 recipient identity", async () => {
  const prf = new Uint8Array(32).fill(7);
  const owner = await passkeyAdmin(prf, "owner", did);
  const legacy = await createAccessRecipient(prf, "owner", did);
  expect(owner.recipient).toMatchObject({
    id: legacy.credentialHash,
    kind: "passkey",
    role: "admin",
    boxPublicKey: legacy.publicKey,
  });
  expect(owner.privateKey).toHaveLength(64);
  expect((await passkeyAdmin(prf, "owner", did)).recipient).toEqual(
    owner.recipient,
  );
  expect((await admin(8, "owner")).recipient.signPublicKey).not.toBe(
    owner.recipient.signPublicKey,
  );
  expect(
    (await passkeyAdmin(prf, "owner", "did:plc:other")).recipient.signPublicKey,
  ).not.toBe(owner.recipient.signPublicKey);
});

test("a pinned device accepts only a later change signed by a pinned admin", async () => {
  const owner = await admin(7, "owner");
  const second = await admin(8, "second");
  const device = await seedSigner(new Uint8Array(32).fill(3), "device");
  const intruder = await seedSigner(new Uint8Array(32).fill(4), "recovery");
  const first = await access(owner, [owner.recipient]);
  const pinned = await acceptAccess(first.metadata, context, null);
  const enrolled = await access(
    owner,
    [owner.recipient, device.recipient],
    "change",
    2,
  );
  const next = await acceptAccess(enrolled.metadata, context, pinned);
  expect(next).toMatchObject({ sequence: 2, admins: pinned.admins });
  const dropped = await access(owner, [owner.recipient], "change", 3);
  const latest = await acceptAccess(dropped.metadata, context, next);
  const rejected: [string, AccessMetadata, typeof pinned][] = [
    [
      "migrate",
      (await access(owner, [owner.recipient, device.recipient], "migrate", 2))
        .metadata,
      pinned,
    ],
    [
      "recover",
      (await access(owner, [owner.recipient], "recover", 2)).metadata,
      pinned,
    ],
    [
      "unpinned admin",
      (await access(second, [owner.recipient, second.recipient], "change", 2))
        .metadata,
      pinned,
    ],
    [
      "self-signed intruder",
      (
        await access(
          intruder,
          [owner.recipient, intruder.recipient],
          "change",
          2,
        )
      ).metadata,
      pinned,
    ],
    [
      "writer",
      (
        await forge({
          kind: "change",
          sequence: 2,
          recipients: [owner.recipient, device.recipient],
          signer: device.recipient.id,
          privateKey: device.privateKey,
        })
      ).metadata,
      pinned,
    ],
    ["replayed older change", enrolled.metadata, latest],
    [
      "same sequence",
      (await access(owner, [owner.recipient, device.recipient], "change", 3))
        .metadata,
      latest,
    ],
  ];
  for (const [name, metadata, pin] of rejected)
    await expect(acceptAccess(metadata, context, pin), name).rejects.toThrow(
      "not signed by a trusted key",
    );
  const promoted = (
    await forge({
      kind: "change",
      sequence: 2,
      recipients: [
        owner.recipient,
        { ...device.recipient, kind: "recovery", role: "admin" },
      ],
      signer: device.recipient.id,
      privateKey: device.privateKey,
    })
  ).metadata;
  expect(await acceptAccess(promoted, context, null)).not.toBeNull();
  await expect(acceptAccess(promoted, context, pinned)).rejects.toThrow(
    "not signed by a trusted key",
  );
});

test("unsigned v2 roots, re-keys and late creates need a statement the device can trust", async () => {
  const owner = await admin(7, "owner");
  const legacy = await createAccessRecipient(
    new Uint8Array(32).fill(7),
    "owner",
    did,
  );
  const header = await createAccessHeader(key, [legacy.publicKey], did);
  const unsigned = {
    recipients: [legacy],
    accessCommitment: await accessHeaderCommitment(header),
  };
  expect(await acceptAccess(unsigned, context, null)).toBeNull();
  expect(recipientsOf(unsigned)).toEqual([
    {
      id: legacy.credentialHash,
      kind: "passkey",
      role: "admin",
      boxPublicKey: legacy.publicKey,
    },
  ]);
  const pinned = await acceptAccess(
    (await access(owner, [owner.recipient])).metadata,
    context,
    null,
  );
  await expect(acceptAccess(unsigned, context, pinned)).rejects.toThrow(
    "not signed by a trusted key",
  );
  await expect(
    acceptAccess(unsigned, context, null, { rekeyed: true }),
  ).rejects.toThrow("not signed by a trusted key");
  const rekeyed = { ...context, epoch: 2 };
  for (const kind of ["create", "migrate", "recover"] as const)
    await expect(
      acceptAccess(
        (await access(owner, [owner.recipient], kind, 2, rekeyed)).metadata,
        rekeyed,
        pinned,
        { rekeyed: true },
      ),
    ).rejects.toThrow("not signed by a trusted key");
  await expect(
    acceptAccess(
      (await access(owner, [owner.recipient], "create", 1, rekeyed)).metadata,
      rekeyed,
      null,
    ),
  ).rejects.toThrow("not signed by a trusted key");
  const change = await access(owner, [owner.recipient], "change", 2, rekeyed);
  expect(
    await acceptAccess(change.metadata, rekeyed, pinned, { rekeyed: true }),
  ).toMatchObject({ sequence: 2, admins: pinned.admins });
  await expect(
    acceptAccess(change.metadata, rekeyed, null, { rekeyed: true }),
  ).rejects.toThrow("not signed by a trusted key");
  await expect(
    acceptAccess(change.metadata, rekeyed, null, {
      rekeyed: true,
      unlocker: (await admin(8, "second")).recipient,
    }),
  ).rejects.toThrow("not signed by a trusted key");
  expect(
    await acceptAccess(change.metadata, rekeyed, null, {
      rekeyed: true,
      unlocker: owner.recipient,
    }),
  ).not.toBeNull();
});

test("seed recipient ids are domain separated exactly as Flow ID derives them", async () => {
  const owner = await admin(7, "owner");
  const seed = new Uint8Array(32).fill(3);
  const device = await createSeedRecipient(seed, "device", "Work laptop");
  expect(device.id).toBe("5jQw5sLtIUOBPmf4gk1l94u5Cry9AEsc3m7sQBcimEk");
  expect(device.id).toBe(
    createHash("sha256")
      .update("flow-note/v3/seed-recipient", "utf8")
      .update(Buffer.from(device.signPublicKey ?? "", "base64url"))
      .digest("base64url"),
  );
  const agent = await createSeedRecipient(new Uint8Array(32).fill(5), "agent");
  const recovery = await createSeedRecipient(
    new Uint8Array(32).fill(6),
    "recovery",
  );
  expect(device).toMatchObject({
    kind: "device",
    role: "writer",
    label: "Work laptop",
  });
  expect(agent).toMatchObject({ kind: "agent", role: "agent" });
  expect(recovery).toMatchObject({ kind: "recovery", role: "admin" });
  expect(await createSeedRecipient(seed, "device", "Work laptop")).toEqual(
    device,
  );
  await expect(
    createSeedRecipient(seed, "device", "x".repeat(65)),
  ).rejects.toThrow();
  await expect(
    createSeedRecipient(new Uint8Array(31), "device"),
  ).rejects.toThrow("Invalid recipient seed");
  const enrolled = await access(
    owner,
    [owner.recipient, device, agent],
    "change",
    2,
  );
  expect(await openWithSeed(enrolled.header, seed, did)).toEqual({
    key,
    version: 3,
  });
  await expect(
    openWithSeed(enrolled.header, new Uint8Array(32).fill(9), did),
  ).rejects.toThrow("cannot unlock");
  await expect(
    openWithSeed(enrolled.header, seed, "did:plc:other"),
  ).rejects.toThrow();
  await expect(access(owner, [device])).rejects.toThrow(
    "Access signer must remain an admin",
  );
  const undomained = encode(sha256(decode(device.signPublicKey ?? "")));
  await expect(
    acceptAccess(
      (
        await forge({
          kind: "change",
          sequence: 2,
          recipients: [owner.recipient, { ...device, id: undomained }],
          signer: owner.recipient.id,
          privateKey: owner.privateKey,
        })
      ).metadata,
      context,
      null,
    ),
  ).rejects.toThrow("not signed by a trusted key");
});

test("a legacy passkey upgrades itself only with proof it holds its box key", async () => {
  const prf = new Uint8Array(32).fill(8);
  const owner = await admin(7, "owner");
  const second = await passkeyAdmin(prf, "second", did);
  const legacy: VaultRecipient = {
    id: second.recipient.id,
    kind: "passkey",
    role: "admin",
    boxPublicKey: second.recipient.boxPublicKey,
  };
  const migrated = await access(owner, [owner.recipient, legacy], "migrate");
  const pinned = await acceptAccess(migrated.metadata, context, null);
  expect(pinned.admins).toHaveLength(1);
  const upgradeOf = async (
    binding: Awaited<ReturnType<typeof passkeyBinding>>,
  ) =>
    createAccess(key, context, {
      kind: "upgrade",
      sequence: 2,
      recipients: [owner.recipient, second.recipient],
      signer: second,
      binding,
    });
  const proven = await upgradeOf(
    await passkeyBinding(prf, "second", context, second.recipient),
  );
  const upgraded = await acceptAccess(proven.metadata, context, pinned);
  expect(upgraded.admins).toHaveLength(2);
  expect(
    await accessSaltFor(
      {
        ...proven.metadata,
        statement: { ...proven.metadata.statement, binding: undefined },
      },
      context,
    ),
  ).not.toBe(proven.header.accessSalt);
  const impostor = await admin(9, "impostor");
  const claimed = {
    ...legacy,
    signPublicKey: impostor.recipient.signPublicKey,
  };
  const forgeries = [
    await upgradeOf(
      await passkeyBinding(prf, "other", context, second.recipient),
    ),
    await createAccess(key, context, {
      kind: "upgrade",
      sequence: 2,
      recipients: [owner.recipient, claimed],
      signer: { recipient: claimed, privateKey: impostor.privateKey },
      binding: await passkeyBinding(
        new Uint8Array(32).fill(9),
        "impostor",
        context,
        claimed,
      ),
    }),
    await createAccess(key, context, {
      kind: "upgrade",
      sequence: 2,
      recipients: [
        owner.recipient,
        second.recipient,
        (await admin(10, "extra")).recipient,
      ],
      signer: second,
      binding: await passkeyBinding(prf, "second", context, second.recipient),
    }),
  ];
  for (const forged of forgeries)
    await expect(
      acceptAccess(forged.metadata, context, pinned),
    ).rejects.toThrow("not signed by a trusted key");
  const seed = await passkeySeed(
    prf,
    "second",
    did,
    "flow-note/v2/access-recipient",
  );
  expect(
    sodium.memcmp(
      sodium.crypto_sign_ed25519_pk_to_curve25519(
        sodium.crypto_sign_seed_keypair(seed).publicKey,
      ),
      decode(second.recipient.boxPublicKey),
    ),
  ).toBe(true);
});

test("recovery keeps only the recipients a pin already trusted", async () => {
  const owner = await admin(7, "owner");
  const device = await createSeedRecipient(
    new Uint8Array(32).fill(3),
    "device",
  );
  const intruder = await seedSigner(new Uint8Array(32).fill(4), "recovery");
  const trusted = await access(owner, [owner.recipient, device], "change", 2);
  const pinned = await acceptAccess(trusted.metadata, context, null);
  const planted = await access(
    intruder,
    [owner.recipient, device, intruder.recipient],
    "change",
    3,
  );
  expect(
    (await pinnedRecipients(planted.metadata, pinned)).map((r) => r.id).sort(),
  ).toEqual([owner.recipient.id, device.id].sort());
});

test("every access change re-randomizes every slot", async () => {
  const owner = await admin(7, "owner");
  const device = await createSeedRecipient(
    new Uint8Array(32).fill(3),
    "device",
  );
  const before = await access(owner, [owner.recipient]);
  const after = await access(owner, [owner.recipient, device], "change", 2);
  expect(after.header.accessSalt).not.toBe(before.header.accessSalt);
  for (const slot of after.header.access)
    expect(
      before.header.access.some(
        (old) => old.keyId === slot.keyId || old.wrapped === slot.wrapped,
      ),
    ).toBe(false);
  expect(after.header.access).toHaveLength(16);
});
