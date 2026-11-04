import Dexie, { type Table } from "dexie";
import { z } from "zod";
import {
  LegacyVaultError,
  UnlockError,
  type VaultAccessView,
  VaultMigrationRequiredError,
} from "../src/app/runtime.ts";
import { synchronizedRuntime } from "../src/app/synchronized-runtime.ts";
import type {
  Checkpoint,
  PinTrust,
  UnlockPort,
  VaultHeader,
  VerifiedVault,
} from "../src/app/unlock.ts";
import type { PinnedAccess, VaultAccess } from "../src/crypto/access-v3.ts";
import { SyncFailure } from "../src/sync/records.ts";
import type { SnapshotEntry } from "../src/sync/vault-snapshot.ts";
import {
  AuthVaultTransport,
  MANAGED_QUOTA_BYTES,
  type VaultTransportRpc,
  type VerifiedBase,
  vaultRecordSchema,
} from "../src/sync/vault-transport.ts";

/**
 * Where a browser keeps its pin, and who earned it, in the IndexedDB that
 * `Dexie.dependencies.indexedDB` names when a port opens: switching that
 * factory switches browsers.
 */
class PinDatabase extends Dexie {
  checkpoints!: Table<Checkpoint & { id: string }, string>;
  provenance!: Table<{ id: string; statement: string; trust: PinTrust }>;
  constructor() {
    super("seal-test-pins");
    this.version(1).stores({ checkpoints: "id", provenance: "id" });
  }
}

const savedHeader = z
  .object({ uri: z.string(), cid: z.string(), value: vaultRecordSchema })
  .strict();
const legacyHeader = z.object({
  value: z.object({ $type: z.literal("game.flow.note.vault") }),
});
const failure = z.object({
  status: z.number().optional(),
  code: z.string().optional(),
});

export interface PasskeyPortOptions {
  userId: string;
  did: string;
  credentialId: string;
  rpc: VaultTransportRpc;
  prf: () => Uint8Array;
  /** Flow ID's resolution of the account; `hosting: "flow"` applies the managed PDS quota. */
  resolved?: { active?: boolean; authorized?: boolean; hosting?: string };
  passkeys?: UnlockPort["passkeys"];
  devices?: {
    list(): Promise<{ id: string; recipientId: string }[]>;
    revoke(id: string): Promise<void>;
  };
  writeJournal?: boolean;
}

/** Who can open a signed vault, for the access list; null while access is unsigned. */
export function accessView(
  access: VaultAccess,
  owner: Omit<VaultAccessView, "recipients">,
): VaultAccessView | null {
  return "version" in access.metadata
    ? { ...owner, recipients: access.metadata.recipients }
    : null;
}

/**
 * A passkey browser's unlock port, as an app builds one over Flow ID: the
 * pin lives in this browser's IndexedDB, a newer statement a sync accepts
 * moves it forward and keeps the trust it earned, and every write goes
 * through `rpc`. It holds no offline cache and no legacy reset.
 */
export function passkeyPort(options: PasskeyPortOptions): UnlockPort & {
  transport(key: Uint8Array, state: VerifiedVault): AuthVaultTransport;
} {
  const { did, userId, rpc } = options;
  const id = `${userId}:${did}`;
  const database = new PinDatabase();
  const onPinned =
    (state: VerifiedVault) =>
    async ({ pinned }: { pinned: PinnedAccess }) => {
      const pins = new PinDatabase();
      try {
        await pins.transaction(
          "rw",
          pins.checkpoints,
          pins.provenance,
          async () => {
            const saved = await pins.checkpoints.get(id);
            // A session opened over an unsigned root keeps what it learns to itself; the next unlock judges the statement.
            if (
              saved?.vault !== state.vault ||
              saved.epoch !== state.epoch ||
              !saved.pinned
            )
              return;
            const earned = await pins.provenance.get(id);
            await pins.checkpoints.put({ ...saved, pinned });
            if (earned?.statement === saved.pinned.statement)
              await pins.provenance.put({
                ...earned,
                statement: pinned.statement,
              });
          },
        );
      } finally {
        pins.close();
      }
    };
  const transport = (
    key: Uint8Array,
    state: VerifiedVault,
    over?: VerifiedBase | null,
  ) =>
    new AuthVaultTransport(rpc, {
      key,
      did,
      ...state,
      over,
      quotaBytes:
        options.resolved?.hosting === "flow" ? MANAGED_QUOTA_BYTES : undefined,
      onPinned: onPinned(state),
      writeJournal: options.writeJournal,
    });
  async function readHeader(): Promise<{
    header: VaultHeader;
    cid: string;
  } | null> {
    let response: unknown;
    try {
      response = await rpc.records({
        method: "read",
        collection: "industries.flow.note.vault",
        rkey: "vault",
      });
    } catch (error) {
      const parsed = failure.safeParse(error);
      if (parsed.success && parsed.data.code === "NOTE_LEGACY_VAULT")
        throw new LegacyVaultError();
      if (parsed.success && parsed.data.code === "NOTE_MIGRATION_REQUIRED")
        throw new VaultMigrationRequiredError();
      if (parsed.success && parsed.data.code === "NOTE_NOT_FOUND") return null;
      throw error;
    }
    if (legacyHeader.safeParse(response).success) throw new LegacyVaultError();
    const parsed = savedHeader.safeParse(response);
    if (!parsed.success) throw new UnlockError("Unreadable vault record");
    if (parsed.data.uri !== `at://${did}/industries.flow.note.vault/vault`)
      throw new Error("Vault identity mismatch");
    return { header: parsed.data.value, cid: parsed.data.cid };
  }
  return {
    dispose: () => database.close(),
    current: () => ({
      userId,
      did,
      credentialId: options.credentialId,
      sessionVersion: 0,
    }),
    async checkpoint() {
      const value = await database.checkpoints.get(id);
      if (!value) return null;
      const { id: _, ...checkpoint } = value;
      if (!checkpoint.pinned) return checkpoint;
      const earned = await database.provenance.get(id);
      return {
        ...checkpoint,
        trust:
          earned?.statement === checkpoint.pinned.statement
            ? earned.trust
            : "tofu",
      };
    },
    async saveCheckpoint({ trust, ...checkpoint }) {
      await database.transaction(
        "rw",
        database.checkpoints,
        database.provenance,
        async () => {
          await database.checkpoints.put({ id, ...checkpoint });
          if (checkpoint.pinned && trust && trust !== "tofu")
            await database.provenance.put({
              id,
              statement: checkpoint.pinned.statement,
              trust,
            });
        },
      );
    },
    resolve: async () => ({
      did,
      active: options.resolved?.active ?? true,
      authorized: options.resolved?.authorized ?? true,
    }),
    readHeader,
    async publish(key, state, expectedCid, scope) {
      if (scope === "root" && expectedCid) {
        const writer = transport(key, state);
        try {
          await writer.resealRoot(expectedCid);
        } finally {
          writer.stop();
        }
        return;
      }
      let entries: SnapshotEntry[] = [];
      let over: VerifiedBase | null = null;
      if (expectedCid) {
        // unlockVault verified the record at expectedCid; the reader only fetches its entries for the new access.
        const reader = new AuthVaultTransport(rpc, {
          key,
          did,
          vault: state.vault,
          epoch: state.epoch,
          access: state.access,
          pinned: null,
        });
        try {
          const previous = await reader.readSnapshot();
          if (!previous || previous.cid !== expectedCid)
            throw new Error("Vault changed during recovery");
          entries = previous.entries;
          over = reader.verifiedBase();
        } finally {
          reader.stop();
        }
      }
      const writer = transport(key, state, over);
      try {
        await writer.writeSnapshot(entries, expectedCid);
      } finally {
        writer.stop();
      }
    },
    async rekey(from, to, expectedCid, reencrypt) {
      // A recovery re-keys a root this passkey may not be listed in, so the reader checks only the pin it was given.
      const reader = new AuthVaultTransport(rpc, {
        key: from.key,
        did,
        vault: from.state.vault,
        epoch: from.state.epoch,
        access: from.state.access,
        pinned: from.state.pinned,
      });
      let entries: SnapshotEntry[];
      try {
        const previous = await reader.readSnapshot();
        if (previous?.cid !== expectedCid)
          throw new SyncFailure("conflict", "Vault changed during re-key");
        entries = previous.entries;
      } finally {
        reader.stop();
      }
      const rekeyed = await reencrypt(entries);
      const writer = transport(to.key, to.state);
      try {
        await writer.writeSnapshot(rekeyed, expectedCid);
      } finally {
        writer.stop();
      }
      return rekeyed;
    },
    ...(options.passkeys && { passkeys: options.passkeys }),
    async revokeDevices(recipientIds) {
      const devices = options.devices ?? {
        list: async () => [],
        revoke: async () => {},
      };
      for (const device of await devices.list())
        if (
          "except" in recipientIds
            ? !recipientIds.except.includes(device.recipientId)
            : recipientIds.includes(device.recipientId)
        )
          await devices.revoke(device.id);
    },
    evaluatePrf: async () => options.prf(),
    transport,
    runtime: (session, key, state) => {
      const adapter = transport(key, state);
      const runtime = synchronizedRuntime(session, async () => adapter);
      return {
        ...runtime,
        access: () =>
          accessView(adapter.currentAccess(), {
            did,
            vault: state.vault,
            self: state.ownRecipient.id,
            canChange: state.trust !== "tofu",
          }),
        lock() {
          adapter.stop();
          runtime.lock();
        },
      };
    },
  };
}
