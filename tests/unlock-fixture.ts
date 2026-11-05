import type { PinnedVault, VerifiedVault } from "../src/app/unlock.ts";
import {
  type AccessRecipient,
  accessHeaderCommitment,
  createAccessHeader,
} from "../src/crypto/access-v2.ts";
import {
  type AccessContext,
  type AccessSigner,
  acceptAccess,
  createAccess,
  passkeyAdmin,
  type StatementKind,
  type VaultRecipient,
} from "../src/crypto/access-v3.ts";
import { CHUNK_BYTES, encryptContainer } from "../src/crypto/container.ts";
import type {
  VaultRecordV2,
  VaultTransportRpc,
} from "../src/sync/vault-transport.ts";

/** The record `state` describes, as the transport publishes it, with one placeholder chunk. */
export async function encryptedHeader(
  key: Uint8Array,
  state: Pick<VerifiedVault, "vault" | "epoch" | "access">,
  did: string,
): Promise<VaultRecordV2> {
  const container = await encryptContainer(
    key,
    { did, vault: state.vault, epoch: state.epoch },
    new TextEncoder().encode('{"version":2,"entries":[]}'),
    state.access.metadata,
  );
  return {
    $type: "industries.flow.note.vault",
    version: 2,
    ...state.access.header,
    root: container.root,
    blobs: [
      {
        $type: "blob",
        ref: { $link: "chunk" },
        mimeType: "application/octet-stream",
        size: CHUNK_BYTES,
      },
    ],
  };
}

/** A record as the pre-v3 code wrote it: unsigned v2 metadata over freshly sealed slots. */
export async function legacyHeader(
  key: Uint8Array,
  state: { vault: string; epoch: number; recipients: AccessRecipient[] },
  did: string,
): Promise<VaultRecordV2> {
  const header = await createAccessHeader(
    key,
    state.recipients.map((recipient) => recipient.publicKey),
    did,
  );
  return encryptedHeader(
    key,
    {
      ...state,
      access: {
        header,
        metadata: {
          recipients: state.recipients,
          accessCommitment: await accessHeaderCommitment(header),
        },
      },
    },
    did,
  );
}

/** A verified state whose access `signer` signed, as the browser that signed it holds it; `ownRecipient` is the signer's. */
export async function signedVault(
  key: Uint8Array,
  context: AccessContext,
  recipients: readonly VaultRecipient[],
  signer: AccessSigner,
  kind: StatementKind = "create",
  sequence = 1,
): Promise<PinnedVault> {
  const access = await createAccess(key, context, {
    kind,
    sequence,
    recipients,
    signer,
  });
  return {
    vault: context.vault,
    epoch: context.epoch,
    access,
    pinned: await acceptAccess(access.metadata, context, null),
    ownRecipient: {
      id: signer.recipient.id,
      boxPublicKey: signer.recipient.boxPublicKey,
    },
    trust: "created",
  };
}

/** A new vault created by the passkey with this PRF and credential. */
export async function passkeyVault(
  key: Uint8Array,
  did: string,
  prf: Uint8Array,
  credentialId: string,
  vault: string = crypto.randomUUID(),
) {
  const admin = await passkeyAdmin(prf, credentialId, did);
  const state = await signedVault(
    key,
    { did, vault, epoch: 1 },
    [admin.recipient],
    admin,
  );
  return { admin, state };
}

/** A PDS's one vault record and its blobs, in memory. */
export function memoryPds(owner: string) {
  const uri = `at://${owner}/industries.flow.note.vault/vault`;
  let stored: { cid: string; value: VaultRecordV2 } | null = null;
  let commits = 0;
  const blobs = new Map<string, Uint8Array>();
  const rpc: VaultTransportRpc = {
    async records(operation) {
      if (operation.method === "read") {
        if (!stored) throw { code: "NOTE_NOT_FOUND", status: 404 };
        return structuredClone({ uri, ...stored });
      }
      if ((stored?.cid ?? null) !== operation.swapRecord)
        throw { code: "CONFLICT", status: 409 };
      stored = {
        cid: `cid-${++commits}`,
        value: structuredClone(operation.record),
      };
      return { cid: stored.cid, uri };
    },
    async upload(bytes) {
      const cid = `blob-${blobs.size}`;
      blobs.set(cid, bytes.slice());
      return {
        blob: {
          $type: "blob",
          ref: { $link: cid },
          mimeType: "application/octet-stream",
          size: bytes.length,
        },
      };
    },
    async download(cid) {
      return blobs.get(cid)?.slice();
    },
  };
  return {
    rpc,
    get stored() {
      return stored;
    },
    get commits() {
      return commits;
    },
    get uploads() {
      return blobs.size;
    },
  };
}
