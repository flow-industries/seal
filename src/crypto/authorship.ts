import sodium from "libsodium-wrappers-sumo";
import { z } from "zod";
import { encoded32 } from "./access-v2.ts";
import { encoded64, type RootMetadata, type VaultRecipient } from "./access-v3.ts";
import type { Envelope } from "./index.ts";

const encoder = new TextEncoder();
export const entryAuthorSchema = z
  .object({ recipientId: encoded32, signature: encoded64 })
  .strict();
/** Which recipient signed an entry revision. Absent on revisions nobody vouched for. */
export type EntryAuthor = z.infer<typeof entryAuthorSchema>;
/** The ciphertext-level identity of one entry revision, which its author signs. */
export interface SignedRevision {
  id: string;
  revision: string;
  envelope: Envelope;
  chunkHashes?: readonly string[];
  author?: EntryAuthor;
}
export interface EntryContext {
  did: string;
  vault: string;
}
/** A writer's Ed25519 key, held in memory only; its holder wipes `privateKey`. */
export interface EntrySigner {
  recipientId: string;
  signPublicKey: string;
  privateKey: Uint8Array;
}
/** A signed vault's verified recipients; null for an unsigned (v2) vault, whose recipients can't sign, and for a session that was never told its access. */
export type EntryAuthority = readonly VaultRecipient[] | null;
export const authorityOf = (metadata: RootMetadata): EntryAuthority =>
  "version" in metadata ? metadata.recipients : null;
/** Whether a revision may run, and whom Note details credits with it. */
export interface RevisionOrigin {
  runs: boolean;
  /** Absent in a session with no authority to check it against. */
  author?: string;
  /**
   * Set only when a listed admin this session can't confirm signed it: it
   * shows only its source here, and rewriting it here would drop that signature.
   */
  reason?: string;
}
/** An admin whose signature alone lets a revision run; see `revisionOrigin`. */
export type EntryRunner = Pick<EntrySigner, "recipientId" | "signPublicKey">;
/**
 * Whose admin signatures run by themselves: the listed admins a session can
 * confirm, or every listed admin when the session's pin was handed over
 * rather than trusted on first use.
 */
export type RunPolicy = readonly EntryRunner[] | "every-admin";

const encode = (bytes: Uint8Array) =>
  sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING);
const decode = (value: string) =>
  sodium.from_base64(value, sodium.base64_variants.URLSAFE_NO_PADDING);
/**
 * Binds the revision's ciphertext rather than its plaintext, so a signature
 * can be checked before anything is decrypted. Any key holder can encrypt new
 * content under an existing id and revision, so the content hash is what
 * stops a signature moving to other content.
 */
async function entryMessage(
  entry: SignedRevision,
  context: EntryContext,
): Promise<Uint8Array> {
  const content = new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      encoder.encode(
        JSON.stringify([
          entry.envelope.version,
          entry.envelope.nonce,
          entry.envelope.ciphertext,
          entry.chunkHashes ?? [],
        ]),
      ),
    ),
  );
  return encoder.encode(
    JSON.stringify([
      "flow-note/v3/entry",
      context.did,
      context.vault,
      entry.id,
      entry.revision,
      encode(content),
    ]),
  );
}
export async function signEntry(
  entry: SignedRevision,
  context: EntryContext,
  signer: EntrySigner,
): Promise<EntryAuthor> {
  await sodium.ready;
  return {
    recipientId: signer.recipientId,
    signature: encode(
      sodium.crypto_sign_detached(
        await entryMessage(entry, context),
        signer.privateKey,
      ),
    ),
  };
}
/** The listed recipient whose valid signature `entry` carries; null when unsigned, forged or signed by someone no longer listed. */
export async function entrySigner(
  entry: SignedRevision,
  context: EntryContext,
  recipients: readonly VaultRecipient[],
): Promise<VaultRecipient | null> {
  const author = entry.author;
  const signer = recipients.find(
    (recipient) => recipient.id === author?.recipientId,
  );
  if (!author || !signer?.signPublicKey) return null;
  await sodium.ready;
  try {
    return sodium.crypto_sign_verify_detached(
      decode(author.signature),
      await entryMessage(entry, context),
      decode(signer.signPublicKey),
    )
      ? signer
      : null;
  } catch {
    return null;
  }
}
function writerOf(signer: VaultRecipient): string {
  const label = signer.label ? ` “${signer.label}”` : "";
  switch (signer.kind) {
    case "passkey":
      return "a passkey";
    case "recovery":
      return "the recovery file";
    case "device":
      return label ? `device${label}` : "a linked device";
    case "agent":
      return label ? `agent${label}` : "an agent";
  }
}
/** An admin this session can't confirm, named without the kind or label its access statement chose. */
const HELD_WRITER =
  "another admin key listed for this notepad, which this browser can’t confirm";
const confirmed = (signer: VaultRecipient, runners: RunPolicy) =>
  runners === "every-admin" ||
  runners.some(
    (runner) =>
      runner.recipientId === signer.id &&
      runner.signPublicKey === signer.signPublicKey,
  );
/**
 * Only an admin's signature lets a revision run by itself. Code runs with
 * the whole session, so a writer's or agent's MDX could otherwise raise a
 * passkey prompt that signs an access change and promotes its author.
 * `runners` narrows that further: a device that trusted its access statement
 * on first use can't tell a listed admin from one a key holder planted, so
 * the held signer's kind and label, which that statement chose, go unnamed.
 */
export async function revisionOrigin(
  entry: SignedRevision,
  context: EntryContext,
  authority: EntryAuthority,
  runners: RunPolicy,
): Promise<RevisionOrigin> {
  if (!authority) return { runs: true };
  const signer = await entrySigner(entry, context, authority);
  if (!signer)
    return {
      runs: false,
      author: entry.author ? "Signature not recognized" : "Not signed",
    };
  if (signer.role !== "admin")
    return { runs: false, author: `Signed by ${writerOf(signer)}` };
  if (!confirmed(signer, runners))
    return {
      runs: false,
      author: "Signed by another admin key",
      reason: `Signed by ${HELD_WRITER}`,
    };
  return { runs: true, author: `Signed by ${writerOf(signer)}` };
}
/** Who wrote a revision, phrased to finish "written by …" in a prompt; held admins go unnamed, as in `revisionOrigin`. */
export async function revisionWriter(
  entry: SignedRevision,
  context: EntryContext,
  authority: EntryAuthority,
  runners: RunPolicy,
): Promise<string> {
  const signer = authority && (await entrySigner(entry, context, authority));
  if (!signer)
    return entry.author ? "a signer NOTE can’t verify" : "an unknown writer";
  return signer.role === "admin" && !confirmed(signer, runners)
    ? HELD_WRITER
    : writerOf(signer);
}
