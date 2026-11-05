import { expect, test } from "bun:test";
import {
  createSeedRecipient,
  passkeyAdmin,
  seedSigningKey,
  type VaultRecipient,
} from "./access-v3.ts";
import {
  type EntrySigner,
  entrySigner,
  revisionOrigin,
  type SignedRevision,
  signEntry,
} from "./authorship.ts";

const did = "did:plc:authorship";
const vault = "3f0c8a52-71d4-4f8e-9b8e-2a7c4d1e6f90";
const context = { did, vault };
const entry: SignedRevision = {
  id: "note-1",
  revision: "rev-1",
  envelope: { version: 1, nonce: "bm9uY2U", ciphertext: "Y2lwaGVydGV4dA" },
  chunkHashes: ["a".repeat(64)],
};
async function passkey(fill: number) {
  const admin = await passkeyAdmin(
    new Uint8Array(32).fill(fill),
    `credential-${fill}`,
    did,
  );
  const signer: EntrySigner = {
    recipientId: admin.recipient.id,
    signPublicKey: admin.recipient.signPublicKey ?? "",
    privateKey: admin.privateKey,
  };
  return { recipient: admin.recipient, signer };
}
async function seeded(
  fill: number,
  kind: "device" | "agent" | "recovery",
  label?: string,
) {
  const seed = new Uint8Array(32).fill(fill);
  const recipient = await createSeedRecipient(seed, kind, label);
  const signer: EntrySigner = {
    recipientId: recipient.id,
    signPublicKey: recipient.signPublicKey ?? "",
    privateKey: await seedSigningKey(seed),
  };
  return { recipient, signer };
}
async function signed(signer: EntrySigner, value = entry) {
  return { ...value, author: await signEntry(value, context, signer) };
}

test("only an admin's valid signature lets a revision run by itself", async () => {
  const admin = await passkey(1);
  const recovery = await seeded(2, "recovery");
  const device = await seeded(3, "device", "Laptop");
  const agent = await seeded(4, "agent", "Claude");
  const recipients = [
    admin.recipient,
    recovery.recipient,
    device.recipient,
    agent.recipient,
  ];
  expect(
    await revisionOrigin(
      await signed(admin.signer),
      context,
      recipients,
      "every-admin",
    ),
  ).toEqual({ runs: true, author: "Signed by a passkey" });
  expect(
    await revisionOrigin(
      await signed(recovery.signer),
      context,
      recipients,
      "every-admin",
    ),
  ).toEqual({ runs: true, author: "Signed by the recovery file" });
  expect(
    await revisionOrigin(
      await signed(device.signer),
      context,
      recipients,
      "every-admin",
    ),
  ).toEqual({ runs: false, author: "Signed by device “Laptop”" });
  expect(
    await revisionOrigin(
      await signed(agent.signer),
      context,
      recipients,
      "every-admin",
    ),
  ).toEqual({ runs: false, author: "Signed by agent “Claude”" });
  expect(
    await revisionOrigin(entry, context, recipients, "every-admin"),
  ).toEqual({
    runs: false,
    author: "Not signed",
  });
});

test("runners narrow which admins run, and a held admin's kind and label go unnamed", async () => {
  const admin = await passkey(1);
  const recovery = await seeded(2, "recovery", "Recovery file");
  const recipients = [admin.recipient, recovery.recipient];
  const runners = [admin.signer];
  expect(
    await revisionOrigin(
      await signed(admin.signer),
      context,
      recipients,
      runners,
    ),
  ).toEqual({ runs: true, author: "Signed by a passkey" });
  expect(
    await revisionOrigin(
      await signed(recovery.signer),
      context,
      recipients,
      runners,
    ),
  ).toEqual({
    runs: false,
    author: "Signed by another admin key",
    reason:
      "Signed by another admin key listed for this notepad, which this browser can’t confirm",
  });
  expect(
    (
      await revisionOrigin(await signed(admin.signer), context, recipients, [
        { ...admin.signer, signPublicKey: recovery.signer.signPublicKey },
      ])
    ).runs,
  ).toBe(false);
  expect(
    (await revisionOrigin(await signed(admin.signer), context, recipients, []))
      .runs,
  ).toBe(false);
});

test("an unsigned vault keeps today's rule: every revision runs and none is labelled", async () => {
  const agent = await seeded(4, "agent");
  expect(await revisionOrigin(entry, context, null, "every-admin")).toEqual({
    runs: true,
  });
  expect(
    await revisionOrigin(
      await signed(agent.signer),
      context,
      null,
      "every-admin",
    ),
  ).toEqual({ runs: true });
});

test("a signature binds the account, vault, item, revision and exact ciphertext", async () => {
  const admin = await passkey(1);
  const recipients = [admin.recipient];
  const original = await signed(admin.signer);
  expect(await entrySigner(original, context, recipients)).toEqual(
    admin.recipient,
  );
  const tampered: SignedRevision[] = [
    { ...original, id: "note-2" },
    { ...original, revision: "rev-2" },
    {
      ...original,
      envelope: { ...original.envelope, ciphertext: "b3RoZXI" },
    },
    { ...original, envelope: { ...original.envelope, nonce: "b3RoZXI" } },
    { ...original, chunkHashes: ["b".repeat(64)] },
    { ...original, chunkHashes: [] },
  ];
  for (const forged of tampered)
    expect(await entrySigner(forged, context, recipients)).toBeNull();
  for (const other of [
    { did: "did:plc:other", vault },
    { did, vault: "another-vault" },
  ])
    expect(await entrySigner(original, other, recipients)).toBeNull();
});

test("a forged, misattributed or removed signer never runs", async () => {
  const admin = await passkey(1);
  const agent = await seeded(4, "agent", "Claude");
  const recipients: VaultRecipient[] = [admin.recipient, agent.recipient];
  const byAgent = await signed(agent.signer);
  const claimsAdmin = {
    ...byAgent,
    author: {
      recipientId: admin.recipient.id,
      signature: byAgent.author.signature,
    },
  };
  expect(
    await revisionOrigin(claimsAdmin, context, recipients, "every-admin"),
  ).toEqual({
    runs: false,
    author: "Signature not recognized",
  });
  const garbage = {
    ...entry,
    author: { recipientId: admin.recipient.id, signature: "A".repeat(86) },
  };
  expect(
    (await revisionOrigin(garbage, context, recipients, "every-admin")).runs,
  ).toBe(false);
  const byAdmin = await signed(admin.signer);
  expect(
    (await revisionOrigin(byAdmin, context, recipients, "every-admin")).runs,
  ).toBe(true);
  expect(
    await revisionOrigin(byAdmin, context, [agent.recipient], "every-admin"),
  ).toEqual({
    runs: false,
    author: "Signature not recognized",
  });
  const rekeyed = await passkey(9);
  expect(
    (
      await revisionOrigin(
        byAdmin,
        context,
        [{ ...admin.recipient, signPublicKey: rekeyed.signer.signPublicKey }],
        "every-admin",
      )
    ).runs,
  ).toBe(false);
});

test("the verified recipient list, not the signature, decides the role", async () => {
  const device = await seeded(3, "device");
  const asAdmin: VaultRecipient = {
    ...device.recipient,
    kind: "recovery",
    role: "admin",
  };
  const byDevice = await signed(device.signer);
  expect(
    (await revisionOrigin(byDevice, context, [asAdmin], "every-admin")).runs,
  ).toBe(true);
  expect(
    (await revisionOrigin(byDevice, context, [device.recipient], "every-admin"))
      .runs,
  ).toBe(false);
});
