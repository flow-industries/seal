import sodium from "libsodium-wrappers-sumo";
import { z } from "zod";
import {
  ACCESS_SLOTS,
  type AccessHeader,
  accessHeaderCommitment,
  accessRecipientSchema,
  createAccessHeader,
  createAccessRecipient,
  deriveSeed,
  encoded32,
  openAccessSlot,
  passkeySeed,
  type SlotVersion,
} from "./access-v2.ts";

const encoder = new TextEncoder();
export const encoded64 = z.string().regex(/^[A-Za-z0-9_-]{85}[AQgw]$/);
/** Only `admin` can sign access changes; `writer` and `agent` are advisory until agent runtimes are restricted. */
const roles = {
  passkey: "admin",
  recovery: "admin",
  device: "writer",
  agent: "agent",
} as const;
export type RecipientKind = keyof typeof roles;
/** A passkey without `signPublicKey` came from a v2 root and cannot sign until it upgrades itself. */
export const vaultRecipientSchema = z
  .object({
    id: encoded32,
    kind: z.enum(["passkey", "recovery", "device", "agent"]),
    role: z.enum(["admin", "writer", "agent"]),
    boxPublicKey: encoded32,
    signPublicKey: encoded32.optional(),
    label: z.string().min(1).max(64).optional(),
  })
  .strict()
  .refine(
    (recipient) =>
      recipient.role === roles[recipient.kind] &&
      (recipient.kind === "passkey" || recipient.signPublicKey !== undefined),
  );
export type VaultRecipient = z.infer<typeof vaultRecipientSchema>;
/** What a holder needs to recognise its own slot in a verified root. */
export type RecipientRef = Pick<VaultRecipient, "id" | "boxPublicKey">;
const distinct = (values: readonly string[]) =>
  new Set(values).size === values.length;
/** Only a `change` by a pinned admin, or a legacy passkey's `upgrade`, may replace a pinned statement. */
export type StatementKind =
  | "create"
  | "migrate"
  | "recover"
  | "change"
  | "upgrade";
const bindingSchema = z
  .object({ publicKey: encoded32, signature: encoded64 })
  .strict();
export type LegacyBinding = z.infer<typeof bindingSchema>;
/**
 * The pin handoff for the device the current statement linked (see
 * `src/crypto/link.ts`). It sits outside the statement and the salt, so a
 * content write may drop or garble it; the device then refuses to link.
 */
export const linkHandoffSchema = z
  .object({
    recipient: encoded32,
    sealed: z.string().regex(/^[A-Za-z0-9_-]{107}$/),
    /** How the approving browser came to trust the pin it hands over; the device inherits it, and the sealed tag binds it. */
    trust: z.enum(["handed", "tofu"]),
  })
  .strict();
export type LinkHandoff = z.infer<typeof linkHandoffSchema>;
export const accessMetadataSchema = z
  .object({
    version: z.literal(3),
    epoch: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    recipients: z.array(vaultRecipientSchema).min(1).max(32),
    accessCommitment: z.string().length(43),
    statement: z
      .object({
        kind: z.enum(["create", "migrate", "recover", "change", "upgrade"]),
        signer: encoded32,
        sequence: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
        nonce: encoded32,
        signature: encoded64,
        binding: bindingSchema.optional(),
      })
      .strict(),
    link: linkHandoffSchema.optional(),
  })
  .strict()
  .refine(
    ({ recipients }) =>
      distinct(recipients.map((recipient) => recipient.id)) &&
      distinct(recipients.map((recipient) => recipient.boxPublicKey)),
  );
const legacyMetadataSchema = z
  .object({
    recipients: z.array(accessRecipientSchema).min(1).max(16),
    accessCommitment: z.string().length(43),
  })
  .strict()
  .refine(
    ({ recipients }) =>
      distinct(recipients.map((recipient) => recipient.credentialHash)) &&
      distinct(recipients.map((recipient) => recipient.publicKey)),
  );
export const rootMetadataSchema = z.union([
  accessMetadataSchema,
  legacyMetadataSchema,
]);
export type AccessMetadata = z.infer<typeof accessMetadataSchema>;
export type RootMetadata = z.infer<typeof rootMetadataSchema>;
/**
 * Digests only, so a device's checkpoint holds no root metadata in the clear:
 * the accepted statement, its sequence, the admins able to sign the next one,
 * and every recipient, so recovery can tell which entries it already trusted.
 */
export const pinnedAccessSchema = z
  .object({
    statement: encoded32,
    sequence: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
    admins: z.array(encoded32).max(32),
    recipients: z.array(encoded32).min(1).max(32),
  })
  .strict();
export type PinnedAccess = z.infer<typeof pinnedAccessSchema>;
/** The slots and the root metadata that describes them; content writes reuse both verbatim. */
export interface VaultAccess {
  header: AccessHeader;
  metadata: RootMetadata;
}
/** An admin able to sign access statements. The caller wipes `privateKey`. */
export interface AccessSigner {
  recipient: VaultRecipient;
  privateKey: Uint8Array;
}
export interface AccessContext {
  did: string;
  vault: string;
  epoch: number;
}

function encode(bytes: Uint8Array): string {
  return sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING);
}
function decode(value: string): Uint8Array {
  return sodium.from_base64(value, sodium.base64_variants.URLSAFE_NO_PADDING);
}
async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  const joined = new Uint8Array(
    parts.reduce((length, part) => length + part.length, 0),
  );
  let offset = 0;
  for (const part of parts) {
    joined.set(part, offset);
    offset += part.length;
  }
  return new Uint8Array(await crypto.subtle.digest("SHA-256", joined));
}
const digest = async (text: string) =>
  encode(await sha256(encoder.encode(text)));

/** Flow ID derives the same id when it registers a device, so the two must agree byte for byte. */
export async function seedRecipientId(signPublicKey: string): Promise<string> {
  return encode(
    await sha256(
      encoder.encode("flow-note/v3/seed-recipient"),
      decode(signPublicKey),
    ),
  );
}

/** v2 roots list bare passkeys; they read as legacy admins that cannot sign. */
export function recipientsOf(metadata: RootMetadata): VaultRecipient[] {
  if ("version" in metadata) return metadata.recipients;
  return metadata.recipients.map((recipient) => ({
    id: recipient.credentialHash,
    kind: "passkey",
    role: "admin",
    boxPublicKey: recipient.publicKey,
  }));
}
export function listsRecipient(
  metadata: RootMetadata,
  own: RecipientRef,
): boolean {
  return recipientsOf(metadata).some(
    (recipient) =>
      recipient.id === own.id && recipient.boxPublicKey === own.boxPublicKey,
  );
}

/** The passkey's admin recipient and signing key from one PRF evaluation; persist neither secret. */
export async function passkeyAdmin(
  prf: Uint8Array,
  credentialId: string,
  did: string,
): Promise<AccessSigner> {
  const box = await createAccessRecipient(prf, credentialId, did);
  const seed = await passkeySeed(
    prf,
    credentialId,
    did,
    "flow-note/v3/admin-sign",
  );
  try {
    const pair = sodium.crypto_sign_seed_keypair(seed);
    return {
      recipient: {
        id: box.credentialHash,
        kind: "passkey",
        role: "admin",
        boxPublicKey: box.publicKey,
        signPublicKey: encode(pair.publicKey),
      },
      privateKey: pair.privateKey,
    };
  } finally {
    sodium.memzero(seed);
  }
}
function bindingMessage(
  context: AccessContext,
  recipient: VaultRecipient,
): Uint8Array {
  return encoder.encode(
    JSON.stringify([
      "flow-note/v3/upgrade",
      context.did,
      context.vault,
      context.epoch,
      recipient.id,
      recipient.signPublicKey ?? null,
    ]),
  );
}

/**
 * Proves a legacy passkey owns the signing key it adds. Ed25519 and X25519
 * keys from one seed share a scalar, so this signs with the scalar behind the
 * passkey's v2 box key, once, over a message no other statement uses.
 */
export async function passkeyBinding(
  prf: Uint8Array,
  credentialId: string,
  context: AccessContext,
  recipient: VaultRecipient,
): Promise<LegacyBinding> {
  const seed = await passkeySeed(
    prf,
    credentialId,
    context.did,
    "flow-note/v2/access-recipient",
  );
  try {
    const pair = sodium.crypto_sign_seed_keypair(seed);
    try {
      return {
        publicKey: encode(pair.publicKey),
        signature: encode(
          sodium.crypto_sign_detached(
            bindingMessage(context, recipient),
            pair.privateKey,
          ),
        ),
      };
    } finally {
      sodium.memzero(pair.privateKey);
    }
  } finally {
    sodium.memzero(seed);
  }
}
function bindsBoxKey(
  recipient: VaultRecipient,
  binding: LegacyBinding | undefined,
  context: AccessContext,
): boolean {
  if (!binding) return false;
  try {
    return (
      sodium.memcmp(
        sodium.crypto_sign_ed25519_pk_to_curve25519(decode(binding.publicKey)),
        decode(recipient.boxPublicKey),
      ) &&
      sodium.crypto_sign_verify_detached(
        decode(binding.signature),
        bindingMessage(context, recipient),
        decode(binding.publicKey),
      )
    );
  } catch {
    return false;
  }
}
async function seedPair(seed: Uint8Array, purpose: "box" | "sign") {
  await sodium.ready;
  if (seed.length !== 32) throw new Error("Invalid recipient seed");
  const derived = await deriveSeed(
    seed,
    new Uint8Array(32),
    `flow-note/v3/${purpose}`,
  );
  try {
    return purpose === "box"
      ? sodium.crypto_box_seed_keypair(derived)
      : sodium.crypto_sign_seed_keypair(derived);
  } finally {
    sodium.memzero(derived);
  }
}

/**
 * The public recipient for a holder's 32-byte seed; the holder keeps custody
 * of the seed. The seed isn't bound to a DID: a device derives its recipient
 * when it asks to be linked, before it knows which account will approve it.
 */
export async function createSeedRecipient(
  seed: Uint8Array,
  kind: Exclude<RecipientKind, "passkey">,
  label?: string,
): Promise<VaultRecipient> {
  const box = await seedPair(seed, "box");
  sodium.memzero(box.privateKey);
  const sign = await seedPair(seed, "sign");
  sodium.memzero(sign.privateKey);
  const signPublicKey = encode(sign.publicKey);
  const recipient: VaultRecipient = {
    id: await seedRecipientId(signPublicKey),
    kind,
    role: roles[kind],
    boxPublicKey: encode(box.publicKey),
    signPublicKey,
  };
  if (label !== undefined) recipient.label = label;
  return vaultRecipientSchema.parse(recipient);
}

/** The seed holder's Ed25519 key for signing the entries it writes; the caller wipes it. */
export async function seedSigningKey(seed: Uint8Array): Promise<Uint8Array> {
  return (await seedPair(seed, "sign")).privateKey;
}
/** A recovery seed's admin recipient and signing key; the caller wipes `privateKey`. */
export async function seedSigner(seed: Uint8Array): Promise<AccessSigner> {
  return {
    recipient: await createSeedRecipient(seed, "recovery"),
    privateKey: await seedSigningKey(seed),
  };
}

/** A recipient for public seed keys someone else reported, with its id derived here rather than trusted. */
export async function seedRecipientFromKeys(
  kind: Exclude<RecipientKind, "passkey">,
  boxPublicKey: string,
  signPublicKey: string,
  label: string,
): Promise<VaultRecipient> {
  return vaultRecipientSchema.parse({
    id: await seedRecipientId(signPublicKey),
    kind,
    role: roles[kind],
    boxPublicKey,
    signPublicKey,
    label,
  });
}

/** Opens a box sealed to the seed's box key; null when it was sealed to another key. */
export async function openSealedToSeed(
  sealed: Uint8Array,
  seed: Uint8Array,
): Promise<Uint8Array | null> {
  const pair = await seedPair(seed, "box");
  try {
    return sodium.crypto_box_seal_open(sealed, pair.publicKey, pair.privateKey);
  } catch {
    return null;
  } finally {
    sodium.memzero(pair.privateKey);
  }
}

/** The returned key must still authenticate the root and its access statement before use. */
export async function openWithSeed(
  header: AccessHeader,
  seed: Uint8Array,
  did: string,
): Promise<{ key: Uint8Array; version: SlotVersion }> {
  const pair = await seedPair(seed, "box");
  try {
    return await openAccessSlot(header, pair, did);
  } finally {
    sodium.memzero(pair.privateKey);
  }
}

function sortById(recipients: readonly VaultRecipient[]): VaultRecipient[] {
  return [...recipients].sort((a, b) =>
    a.id < b.id ? -1 : a.id > b.id ? 1 : 0,
  );
}
function tuples(recipients: readonly VaultRecipient[]) {
  return sortById(recipients).map((recipient) => [
    recipient.id,
    recipient.kind,
    recipient.role,
    recipient.boxPublicKey,
    recipient.signPublicKey ?? null,
    recipient.label ?? null,
  ]);
}
interface StatementFields {
  kind: StatementKind;
  signer: string;
  sequence: number;
  recipients: readonly VaultRecipient[];
  binding?: LegacyBinding;
}
/**
 * The header's salt commits to everything the statement says except its
 * signature, including an upgrade's binding, so the statement cannot change
 * while the slots stay byte-identical, which is all Flow ID lets a device
 * token write.
 *
 * This salt and `statementMessage` (with the `tuples` both encode) are frozen:
 * signed vaults exist. Every reader recomputes them, recovery included, so a
 * changed format would strand them beyond even their recovery file. A new
 * format takes a new prefix (`flow-note/v4/...`), and readers keep accepting
 * this one.
 */
async function signedSalt(
  fields: StatementFields,
  context: AccessContext,
  nonce: Uint8Array,
): Promise<Uint8Array> {
  return sha256(
    encoder.encode("flow-note/v3/access-salt"),
    nonce,
    encoder.encode(
      JSON.stringify([
        fields.kind,
        context.did,
        context.vault,
        context.epoch,
        fields.signer,
        fields.sequence,
        tuples(fields.recipients),
        fields.binding?.publicKey ?? null,
        fields.binding?.signature ?? null,
      ]),
    ),
  );
}
/** The salt a v3 root's statement requires of its header. */
export async function accessSaltFor(
  metadata: AccessMetadata,
  context: AccessContext,
): Promise<string> {
  return encode(
    await signedSalt(
      { ...metadata.statement, recipients: metadata.recipients },
      context,
      decode(metadata.statement.nonce),
    ),
  );
}
/** What an admin signs; frozen with {@link signedSalt}. */
function statementMessage(
  fields: StatementFields,
  context: AccessContext,
  accessCommitment: string,
): Uint8Array {
  return encoder.encode(
    JSON.stringify([
      "flow-note/v3/access",
      fields.kind,
      context.did,
      context.vault,
      context.epoch,
      fields.signer,
      fields.sequence,
      accessCommitment,
      tuples(fields.recipients),
    ]),
  );
}
function adminDigest(recipient: VaultRecipient): Promise<string> {
  return digest(
    JSON.stringify([
      "flow-note/v3/admin",
      recipient.id,
      recipient.signPublicKey,
    ]),
  );
}
function recipientDigest(recipient: VaultRecipient): Promise<string> {
  return digest(
    JSON.stringify(["flow-note/v3/recipient", ...tuples([recipient])]),
  );
}
/** The pinned statement's sequence, or the root's, whichever is later; a new statement must exceed it. */
export function nextSequence(
  metadata: RootMetadata,
  pinned: PinnedAccess | null,
): number {
  return (
    Math.max(
      pinned?.sequence ?? 0,
      "version" in metadata ? metadata.statement.sequence : 0,
    ) + 1
  );
}

/**
 * Seals `key` to fresh slots for every recipient and signs the result. The
 * signer stays listed as an admin, so readers can check it against their pin.
 */
export async function createAccess(
  key: Uint8Array,
  context: AccessContext,
  statement: Omit<StatementFields, "signer"> & {
    signer: AccessSigner;
    binding?: LegacyBinding;
  },
): Promise<VaultAccess & { metadata: AccessMetadata }> {
  await sodium.ready;
  const recipients = sortById(
    z
      .array(vaultRecipientSchema)
      .min(1)
      .max(ACCESS_SLOTS)
      .parse(statement.recipients),
  );
  const signer = statement.signer.recipient;
  if (
    !recipients.some(
      (recipient) =>
        recipient.role === "admin" &&
        recipient.id === signer.id &&
        recipient.signPublicKey === signer.signPublicKey,
    )
  )
    throw new Error("Access signer must remain an admin");
  const fields = { ...statement, signer: signer.id, recipients };
  const nonce = sodium.randombytes_buf(32);
  const header = await createAccessHeader(
    key,
    recipients.map((recipient) => recipient.boxPublicKey),
    context.did,
    await signedSalt(fields, context, nonce),
  );
  const accessCommitment = await accessHeaderCommitment(header);
  const signed: AccessMetadata["statement"] = {
    kind: fields.kind,
    signer: fields.signer,
    sequence: fields.sequence,
    nonce: encode(nonce),
    signature: encode(
      sodium.crypto_sign_detached(
        statementMessage(fields, context, accessCommitment),
        statement.signer.privateKey,
      ),
    ),
  };
  if (statement.binding) signed.binding = statement.binding;
  return {
    header,
    metadata: accessMetadataSchema.parse({
      version: 3,
      epoch: context.epoch,
      recipients,
      accessCommitment,
      statement: signed,
    }),
  };
}

/** The recipients of `metadata` this device trusted when it pinned its last statement. */
export async function pinnedRecipients(
  metadata: RootMetadata,
  pinned: PinnedAccess,
): Promise<VaultRecipient[]> {
  const kept: VaultRecipient[] = [];
  for (const recipient of recipientsOf(metadata))
    if (pinned.recipients.includes(await recipientDigest(recipient)))
      kept.push(recipient);
  return kept;
}
export async function isPinnedAdmin(
  recipient: VaultRecipient,
  pinned: PinnedAccess,
): Promise<boolean> {
  return (
    recipient.role === "admin" &&
    !!recipient.signPublicKey &&
    pinned.admins.includes(await adminDigest(recipient))
  );
}
/** An upgrade changes nothing but the signer's own legacy entry, which gains its signing key. */
async function upgradesPinnedSet(
  metadata: AccessMetadata,
  author: VaultRecipient,
  pinned: PinnedAccess,
): Promise<boolean> {
  if (
    author.kind !== "passkey" ||
    metadata.recipients.length !== pinned.recipients.length
  )
    return false;
  const legacy: VaultRecipient = {
    id: author.id,
    kind: author.kind,
    role: author.role,
    boxPublicKey: author.boxPublicKey,
  };
  if (author.label !== undefined) legacy.label = author.label;
  for (const recipient of metadata.recipients)
    if (
      !pinned.recipients.includes(
        await recipientDigest(recipient === author ? legacy : recipient),
      )
    )
      return false;
  return true;
}

export interface AcceptOptions {
  /** The root's epoch is above the device's checkpoint. */
  rekeyed?: boolean;
  /** The passkey unlocking now: an unpinned device trusts a re-key only from it. */
  unlocker?: VaultRecipient;
}
/** The one error for any access statement this device cannot trust. */
export const UNTRUSTED_ACCESS =
  "Vault access change not signed by a trusted key";

/**
 * Accepts `metadata` (already bound to its header by the root's commitment
 * and salt) and returns the admin set to pin.
 *
 * - With a pin, only the pinned statement, a later `change` signed by a
 *   pinned admin, or a legacy passkey's proven `upgrade` passes.
 * - Without one, the first self-consistent statement is trusted, except that
 *   a re-key must be a `change` signed by the unlocking passkey.
 * - An unsigned v2 root passes only while nothing is pinned and no re-key
 *   happened.
 */
export async function acceptAccess(
  metadata: AccessMetadata,
  context: AccessContext,
  pinned: PinnedAccess | null,
  options?: AcceptOptions,
): Promise<PinnedAccess>;
export async function acceptAccess(
  metadata: RootMetadata,
  context: AccessContext,
  pinned: PinnedAccess | null,
  options?: AcceptOptions,
): Promise<PinnedAccess | null>;
export async function acceptAccess(
  metadata: RootMetadata,
  context: AccessContext,
  pinned: PinnedAccess | null,
  { rekeyed = false, unlocker }: AcceptOptions = {},
): Promise<PinnedAccess | null> {
  await sodium.ready;
  if (!("version" in metadata)) {
    if (pinned || rekeyed) throw new Error(UNTRUSTED_ACCESS);
    return null;
  }
  const { kind, signer, signature, binding } = metadata.statement;
  if (
    metadata.epoch !== context.epoch ||
    (kind === "create" && context.epoch !== 1) ||
    (rekeyed && kind !== "change")
  )
    throw new Error(UNTRUSTED_ACCESS);
  const fields = { ...metadata.statement, recipients: metadata.recipients };
  const message = statementMessage(fields, context, metadata.accessCommitment);
  const statement = await digest(
    JSON.stringify([
      "flow-note/v3/statement",
      encode(message),
      signature,
      binding?.publicKey ?? null,
      binding?.signature ?? null,
    ]),
  );
  if (pinned?.statement === statement) return pinned;
  const author = metadata.recipients.find(
    (recipient) => recipient.id === signer && recipient.role === "admin",
  );
  if (!author?.signPublicKey) throw new Error(UNTRUSTED_ACCESS);
  for (const recipient of metadata.recipients)
    if (
      recipient.kind !== "passkey" &&
      recipient.id !== (await seedRecipientId(recipient.signPublicKey ?? ""))
    )
      throw new Error(UNTRUSTED_ACCESS);
  if (
    !sodium.crypto_sign_verify_detached(
      decode(signature),
      message,
      decode(author.signPublicKey),
    ) ||
    (kind === "upgrade" && !bindsBoxKey(author, binding, context))
  )
    throw new Error(UNTRUSTED_ACCESS);
  if (pinned) {
    const authorized =
      metadata.statement.sequence > pinned.sequence &&
      (kind === "change"
        ? await isPinnedAdmin(author, pinned)
        : kind === "upgrade" &&
          (await upgradesPinnedSet(metadata, author, pinned)));
    if (!authorized) throw new Error(UNTRUSTED_ACCESS);
  } else if (
    rekeyed &&
    (unlocker?.id !== author.id ||
      unlocker.signPublicKey !== author.signPublicKey)
  )
    throw new Error(UNTRUSTED_ACCESS);
  const admins: string[] = [];
  const recipients: string[] = [];
  for (const recipient of metadata.recipients) {
    recipients.push(await recipientDigest(recipient));
    if (recipient.role === "admin" && recipient.signPublicKey)
      admins.push(await adminDigest(recipient));
  }
  return pinnedAccessSchema.parse({
    statement,
    sequence: metadata.statement.sequence,
    admins,
    recipients,
  });
}
