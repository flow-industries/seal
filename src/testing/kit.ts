/**
 * Flow ID, its PDS and an approving passkey browser, all in memory, so a
 * plugin or agent can run a whole device link, then sync against a vault,
 * without a server. Synthetic keys only; nothing here is for production.
 */
import sodium from "libsodium-wrappers-sumo";
import { localRuntime } from "../app/local-runtime.ts";
import type { NoteRuntime } from "../app/runtime.ts";
import { synchronizedRuntime } from "../app/synchronized-runtime.ts";
import {
  addVaultRecipient,
  type CheckpointPolicy,
  savedCheckpoint,
  signedState,
  type UnlockPort,
  unlockVault,
} from "../app/unlock.ts";
import {
  nextSequence,
  passkeyAdmin,
  recipientsOf,
  seedRecipientFromKeys,
  type VaultRecipient,
} from "../crypto/access-v3.ts";
import { CHUNK_BYTES } from "../crypto/container.ts";
import {
  deviceAuthorizeMessage,
  normalizeUserCode,
  typedPairingCode,
} from "../crypto/link.ts";
import type { LinkPrompt } from "../device/client.ts";
import {
  AuthVaultTransport,
  readVerifiedVaultRoot,
  type VaultOperation,
  type VaultRecordV2,
  type VaultTransportRpc,
} from "../sync/vault-transport.ts";

/** The account every fake Flow ID here serves. */
export const TEST_DID = "did:plc:devicee2e";
/** The Flow ID origin to pass as `DeviceOptions.host`. */
export const TEST_HOST = "https://id.example";
/** The vault record's AT URI for `TEST_DID`, as the fake PDS answers it. */
export const TEST_VAULT_URI = `at://${TEST_DID}/industries.flow.note.vault/vault`;
const did = TEST_DID;
const uri = TEST_VAULT_URI;

/**
 * Flow ID's device grant and NOTE transport, and the PDS behind them, in
 * memory. Device-token puts follow Flow ID's rule: compare-and-swap, then
 * `accessSalt` and `access` byte-identical to the record they replace.
 */
export function fakeFlowId() {
  let record: { cid: string; value: VaultRecordV2 } | null = null;
  let commits = 0;
  const blobs = new Map<string, Uint8Array>();
  const requests = new Map<
    string,
    {
      userCode: string;
      body: Record<string, string>;
      deviceId?: string;
      redeemed?: boolean;
    }
  >();
  const tokens = new Map<string, string>();
  const violations: string[] = [];
  const authorized: Record<string, string>[] = [];
  function put(
    operation: Extract<VaultOperation, { method: "put" }>,
    device: boolean,
  ) {
    if (operation.swapRecord !== (record?.cid ?? null))
      return Response.json({ code: "CONFLICT" }, { status: 409 });
    if (
      device &&
      (!record ||
        record.value.accessSalt !== operation.record.accessSalt ||
        JSON.stringify(record.value.access) !==
          JSON.stringify(operation.record.access))
    ) {
      violations.push("device rewrote access");
      return Response.json({ code: "ACCESS_CHANGED" }, { status: 403 });
    }
    record = {
      cid: `cid-${++commits}`,
      value: structuredClone(operation.record),
    };
    return Response.json({ cid: record.cid, uri });
  }
  function read() {
    return record
      ? Response.json({ uri, cid: record.cid, value: record.value })
      : Response.json({ code: "NOTE_NOT_FOUND" }, { status: 404 });
  }
  function upload(bytes: Uint8Array) {
    if (bytes.length !== CHUNK_BYTES)
      return Response.json({ code: "INVALID_BODY" }, { status: 400 });
    const cid = `blob-${blobs.size + 1}`;
    blobs.set(cid, bytes.slice());
    return Response.json({
      blob: {
        $type: "blob",
        ref: { $link: cid },
        mimeType: "application/octet-stream",
        size: CHUNK_BYTES,
      },
    });
  }
  const browserRpc: VaultTransportRpc = {
    records: async (operation) => {
      const response =
        operation.method === "read" ? read() : put(operation, false);
      const body = await response.json();
      if (!response.ok) throw body;
      return body;
    },
    upload: async (bytes) => await upload(bytes).json(),
    download: async (cid) => {
      const bytes = blobs.get(cid);
      if (!bytes) throw { code: "NOT_FOUND" };
      return bytes.slice();
    },
  };
  async function fetch(url: string, init: RequestInit): Promise<Response> {
    const path = new URL(url).pathname;
    if (path === "/api/atproto/note/device/authorize") {
      const body = JSON.parse(String(init.body));
      authorized.push(body);
      await sodium.ready;
      // Flow ID's check (`provesNoteDeviceKey`): the device signed its keys and commitment.
      if (
        !sodium.crypto_sign_verify_detached(
          sodium.from_base64(
            body.proof ?? "",
            sodium.base64_variants.URLSAFE_NO_PADDING,
          ),
          deviceAuthorizeMessage(body),
          sodium.from_base64(
            body.signPublicKey,
            sodium.base64_variants.URLSAFE_NO_PADDING,
          ),
        )
      )
        return Response.json({ code: "PROOF_INVALID" }, { status: 400 });
      const deviceCode = `fndc_${crypto.randomUUID()}`;
      const userCode = "BCDF-GHJK";
      requests.set(deviceCode, { userCode, body });
      return Response.json({
        deviceCode,
        userCode,
        verificationUri: `https://note.example/link?code=${userCode}`,
        interval: 1,
        expiresIn: 600,
      });
    }
    if (path === "/api/atproto/note/device/token") {
      const pending = requests.get(JSON.parse(String(init.body)).deviceCode);
      if (!pending)
        return Response.json({ code: "INVALID_GRANT" }, { status: 400 });
      if (!pending.deviceId)
        return Response.json(
          { code: "AUTHORIZATION_PENDING" },
          { status: 400 },
        );
      if (pending.redeemed)
        return Response.json({ code: "INVALID_GRANT" }, { status: 400 });
      pending.redeemed = true;
      const accessToken = `fnd_${crypto.randomUUID()}`;
      tokens.set(accessToken, pending.deviceId);
      return Response.json({
        accessToken,
        refreshToken: `fndr_${crypto.randomUUID()}`,
        expiresIn: 900,
        deviceId: pending.deviceId,
        userId: "owner",
        did,
      });
    }
    if (path === "/api/atproto/note/device/refresh")
      return Response.json({ code: "INVALID_GRANT" }, { status: 400 });
    const token =
      new Headers(init.headers).get("Authorization")?.slice("Bearer ".length) ??
      "";
    if (!tokens.has(token))
      return Response.json({ code: "SIGN_IN_REQUIRED" }, { status: 401 });
    if (path === "/api/atproto/note/records") {
      // SAFETY: only the SDK's device transport posts here, with an operation it typed as a NoteOperation.
      const operation = JSON.parse(String(init.body)) as VaultOperation;
      return operation.method === "read" ? read() : put(operation, true);
    }
    if (path === "/api/atproto/note/upload")
      // SAFETY: the SDK's device transport posts each chunk as raw bytes.
      return upload(new Uint8Array(init.body as ArrayBuffer));
    if (path === "/api/atproto/note/download") {
      const bytes = blobs.get(JSON.parse(String(init.body)).cid);
      return bytes
        ? new Response(bytes.slice())
        : Response.json({ code: "NOT_FOUND" }, { status: 404 });
    }
    return Response.json({ code: "NOT_FOUND" }, { status: 404 });
  }
  return {
    fetch,
    browserRpc,
    violations,
    /** Everything Flow ID received at `authorize`. */
    authorized,
    record: () => record,
    /** Flow ID revokes every device: their tokens stop and refreshes are refused. */
    revokeAll: () => tokens.clear(),
    lookup(userCode: string) {
      for (const pending of requests.values())
        if (
          normalizeUserCode(pending.userCode) === normalizeUserCode(userCode) &&
          !pending.deviceId
        )
          return pending.body;
      throw new Error("DEVICE_CODE_INVALID");
    },
    approve(userCode: string) {
      for (const pending of requests.values())
        if (
          normalizeUserCode(pending.userCode) === normalizeUserCode(userCode) &&
          !pending.deviceId
        ) {
          pending.deviceId = crypto.randomUUID();
          return pending.deviceId;
        }
      throw new Error("DEVICE_CODE_INVALID");
    },
  };
}

export type FakeFlowId = ReturnType<typeof fakeFlowId>;

/** The approving browser: a passkey port that publishes through the browser session, as a passkey app does. Its new vault also lists `admins`. */
export async function adminBrowser(
  note: FakeFlowId,
  admins: readonly VaultRecipient[] = [],
) {
  const key = new Uint8Array(32).fill(9);
  const prf = new Uint8Array(32).fill(7);
  const admin = await passkeyAdmin(prf, "connected", did);
  const state = await signedState(
    key,
    { did, vault: crypto.randomUUID(), epoch: 1 },
    {
      kind: "create",
      sequence: 1,
      recipients: [admin.recipient, ...admins],
      signer: admin,
    },
    "created",
  );
  const created = new AuthVaultTransport(note.browserRpc, {
    key,
    did,
    ...state,
  });
  await created.writeSnapshot([], null);
  created.stop();
  let checkpoint: CheckpointPolicy | null = savedCheckpoint(state);
  const port: UnlockPort = {
    current: () => ({
      userId: "owner",
      did,
      credentialId: "connected",
      sessionVersion: 1,
    }),
    checkpoint: async () => checkpoint,
    saveCheckpoint: async (value) => {
      checkpoint = value;
    },
    resolve: async () => ({ did, active: true, authorized: true }),
    readHeader: async () => {
      const current = note.record();
      return current ? { header: current.value, cid: current.cid } : null;
    },
    publish: async (publishedKey, published, expectedCid) => {
      const reader = new AuthVaultTransport(note.browserRpc, {
        key: publishedKey,
        did,
        ...published,
        pinned: null,
      });
      const previous = await reader.readSnapshot();
      reader.stop();
      if (previous?.cid !== expectedCid)
        throw new Error("Vault changed during recovery");
      const writer = new AuthVaultTransport(note.browserRpc, {
        key: publishedKey,
        did,
        ...published,
      });
      await writer.writeSnapshot(previous.entries, expectedCid);
      writer.stop();
    },
    evaluatePrf: async () => prf.slice(),
    runtime: (session) => localRuntime(session),
  };
  return { note, key, port, state, admin };
}
export type AdminBrowser = Awaited<ReturnType<typeof adminBrowser>>;

/**
 * Approves the device showing `prompt` from the admin's browser, as the
 * link page does: it looks the request up, types the pairing code, and
 * publishes the change that lists the device with its handoff.
 */
export async function approveLink(admin: AdminBrowser, prompt: LinkPrompt) {
  const pending = admin.note.lookup(prompt.userCode);
  await addVaultRecipient(admin.port, {
    recipient: await seedRecipientFromKeys(
      "device",
      pending.boxPublicKey ?? "",
      pending.signPublicKey ?? "",
      pending.label ?? "",
    ),
    link: {
      secret: typedPairingCode(prompt.pairingCode),
      commitment: pending.commitment ?? "",
      approve: async () => admin.note.approve(prompt.userCode),
      revoke: async () => {},
    },
    confirm: async () => {},
  });
}

/**
 * The admin's own notepad over the same vault, syncing with the fake PDS,
 * so a test can write passkey-signed notes for a device to read, and read
 * back what the device wrote. Call `lock()` when done.
 */
export async function openAdminVault(
  admin: AdminBrowser,
): Promise<NoteRuntime & Required<Pick<NoteRuntime, "sync">>> {
  let runtime: ReturnType<typeof synchronizedRuntime> | undefined;
  await unlockVault({
    ...admin.port,
    runtime(session, key, state) {
      runtime = synchronizedRuntime(
        session,
        async () =>
          new AuthVaultTransport(admin.note.browserRpc, { key, did, ...state }),
      );
      return runtime;
    },
  });
  if (!runtime) throw new Error("Vault locked");
  return runtime;
}

/**
 * The admin re-signs access listing every admin but no device or agent, and
 * republishes the vault's notes under it, so each linked device loses its
 * slot: its next open throws `AccessRemovedError` and a running one locks
 * on its next sync. A real removal also re-keys the vault and revokes the
 * device's tokens; call `flowId.revokeAll()` for the second.
 */
export async function dropDevices(admin: AdminBrowser): Promise<void> {
  const current = admin.note.record();
  if (!current) throw new Error("Missing vault");
  const { manifest, metadata } = await readVerifiedVaultRoot(
    admin.key,
    did,
    current.value,
  );
  const reader = new AuthVaultTransport(admin.note.browserRpc, {
    key: admin.key,
    did,
    ...admin.state,
  });
  const snapshot = await reader.readSnapshot();
  reader.stop();
  if (!snapshot) throw new Error("Missing vault");
  const state = await signedState(
    admin.key,
    { did, vault: manifest.vault, epoch: manifest.epoch },
    {
      kind: "change",
      sequence: nextSequence(metadata, null),
      recipients: recipientsOf(metadata).filter(
        (recipient) => recipient.role === "admin",
      ),
      signer: admin.admin,
    },
    "created",
  );
  const writer = new AuthVaultTransport(admin.note.browserRpc, {
    key: admin.key,
    did,
    ...state,
  });
  await writer.writeSnapshot(snapshot.entries, snapshot.cid);
  writer.stop();
  await admin.port.saveCheckpoint(savedCheckpoint(state));
}

/** A credential or checkpoint store in memory, as a plugin's keychain would hold it. */
export function memoryStore<T>() {
  let value: T | null = null;
  return {
    read: async () => (value === null ? null : structuredClone(value)),
    write: async (next: T) => {
      value = structuredClone(next);
    },
  };
}
