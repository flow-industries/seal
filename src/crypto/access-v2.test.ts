import { expect, test } from "bun:test";
import sodium from "libsodium-wrappers-sumo";
import {
  ACCESS_SLOTS,
  accessHeaderCommitment,
  accessHeaderSchema,
  createAccessHeader,
  createAccessRecipient,
  unwrapAccessKey,
  v2PrfInput,
} from "./access-v2.ts";

const did = "did:plc:owner";
const prf = new Uint8Array(32).fill(7);
const key = new Uint8Array(32).fill(11);

test("one and five recipients have the same public shape and every publication rerandomizes every slot", async () => {
  const recipients = await Promise.all(
    Array.from({ length: 5 }, (_, index) =>
      createAccessRecipient(
        new Uint8Array(32).fill(index + 1),
        `credential-${index}`,
        did,
      ),
    ),
  );
  const publicKeys = recipients.map((recipient) => recipient.publicKey);
  const one = await createAccessHeader(key, publicKeys.slice(0, 1), did);
  const five = await createAccessHeader(key, publicKeys, did);
  const next = await createAccessHeader(key, publicKeys, did);
  expect(JSON.stringify(one).length).toBe(JSON.stringify(five).length);
  expect(accessHeaderSchema.parse(five).access).toHaveLength(16);
  expect(next.accessSalt).not.toBe(five.accessSalt);
  for (const slot of next.access) {
    expect(
      five.access.some(
        (old) => old.keyId === slot.keyId || old.wrapped === slot.wrapped,
      ),
    ).toBe(false);
    const sealed = sodium.from_base64(
      slot.wrapped,
      sodium.base64_variants.URLSAFE_NO_PADDING,
    );
    expect(sealed).toHaveLength(112);
    expect(sealed[31] & 128).toBe(0);
  }
  for (let index = 0; index < recipients.length; index++)
    expect(
      (
        await unwrapAccessKey(
          five,
          new Uint8Array(32).fill(index + 1),
          `credential-${index}`,
          did,
        )
      ).key,
    ).toEqual(key);
});

test("PRF, credential, DID, salt and slot context each gate access", async () => {
  const recipient = await createAccessRecipient(prf, "credential", did);
  const header = await createAccessHeader(key, [recipient.publicKey], did);
  expect(await unwrapAccessKey(header, prf, "credential", did)).toEqual({
    key,
    version: 2,
  });
  await expect(
    unwrapAccessKey(header, new Uint8Array(31), "credential", did),
  ).rejects.toThrow();
  await expect(
    unwrapAccessKey(header, new Uint8Array(32), "credential", did),
  ).rejects.toThrow();
  await expect(unwrapAccessKey(header, prf, "other", did)).rejects.toThrow();
  await expect(
    unwrapAccessKey(header, prf, "credential", "did:plc:other"),
  ).rejects.toThrow();
  const other = await createAccessHeader(key, [recipient.publicKey], did);
  await expect(
    unwrapAccessKey(
      { ...header, accessSalt: other.accessSalt },
      prf,
      "credential",
      did,
    ),
  ).rejects.toThrow();
  await expect(
    unwrapAccessKey(
      {
        ...header,
        access: header.access.map((slot, index) => ({
          ...slot,
          keyId: other.access[index].keyId,
        })),
      },
      prf,
      "credential",
      did,
    ),
  ).rejects.toThrow();
  expect(await v2PrfInput()).toHaveLength(32);
  expect(await v2PrfInput()).toEqual(await v2PrfInput());
});

test("removed recipient and its old decrypted registry cannot unwrap a rotated key", async () => {
  const retained = await createAccessRecipient(prf, "retained", did);
  const revokedPrf = new Uint8Array(32).fill(8);
  const revoked = await createAccessRecipient(revokedPrf, "revoked", did);
  const before = await createAccessHeader(
    key,
    [retained.publicKey, revoked.publicKey],
    did,
  );
  expect(
    (await unwrapAccessKey(before, revokedPrf, "revoked", did)).key,
  ).toEqual(key);
  const rotated = new Uint8Array(32).fill(19);
  const after = await createAccessHeader(rotated, [retained.publicKey], did);
  expect((await unwrapAccessKey(after, prf, "retained", did)).key).toEqual(
    rotated,
  );
  await expect(
    unwrapAccessKey(after, revokedPrf, "revoked", did),
  ).rejects.toThrow();
  expect(Object.keys(retained).sort()).toEqual(["credentialHash", "publicKey"]);
});

test("root commitment covers all slots including dummies and their ordering; schema refuses malformed slots", async () => {
  const recipient = await createAccessRecipient(prf, "credential", did);
  const header = await createAccessHeader(key, [recipient.publicKey], did);
  const commitment = await accessHeaderCommitment(header);
  expect(
    await accessHeaderCommitment({
      ...header,
      access: [...header.access].reverse(),
    }),
  ).not.toBe(commitment);
  expect(
    accessHeaderSchema.safeParse({ ...header, access: header.access.slice(1) })
      .success,
  ).toBe(false);
  expect(accessHeaderSchema.safeParse({ ...header, epoch: 1 }).success).toBe(
    false,
  );
  expect(
    accessHeaderSchema.safeParse({
      ...header,
      access: [...header.access, header.access[0]],
    }).success,
  ).toBe(false);
  expect(
    accessHeaderSchema.safeParse({
      ...header,
      access: header.access.map(() => header.access[0]),
    }).success,
  ).toBe(false);
  await expect(
    createAccessHeader(key, [recipient.publicKey, recipient.publicKey], did),
  ).rejects.toThrow();
});

test("headers are written with 16 slots and read with 16 or 32", async () => {
  const recipient = await createAccessRecipient(prf, "credential", did);
  const other = await createAccessRecipient(prf, "other", did);
  const first = await createAccessHeader(key, [recipient.publicKey], did);
  const second = await createAccessHeader(key, [other.publicKey], did);
  expect(first.access).toHaveLength(ACCESS_SLOTS);
  const wide = {
    accessSalt: first.accessSalt,
    access: [...first.access, ...second.access],
  };
  expect(accessHeaderSchema.parse(wide).access).toHaveLength(32);
  expect((await unwrapAccessKey(wide, prf, "credential", did)).key).toEqual(
    key,
  );
  expect(await accessHeaderCommitment(wide)).not.toBe(
    await accessHeaderCommitment(first),
  );
  for (const length of [15, 17, 31])
    expect(
      accessHeaderSchema.safeParse({
        ...wide,
        access: wide.access.slice(0, length),
      }).success,
    ).toBe(false);
});

test("a signed header seals v3 slots under the salt it is given", async () => {
  const recipient = await createAccessRecipient(prf, "credential", did);
  const salt = new Uint8Array(32).fill(5);
  const signed = await createAccessHeader(
    key,
    [recipient.publicKey],
    did,
    salt,
  );
  expect(signed.accessSalt).toBe(
    sodium.to_base64(salt, sodium.base64_variants.URLSAFE_NO_PADDING),
  );
  expect(await unwrapAccessKey(signed, prf, "credential", did)).toEqual({
    key,
    version: 3,
  });
});
