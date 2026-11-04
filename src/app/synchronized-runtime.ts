import { type SyncResult, VaultSyncEngine } from "../sync/vault-engine.ts";
import {
  VaultAccessError,
  type VaultSnapshotTransport,
} from "../sync/vault-snapshot.ts";
import type { VaultSession } from "../vault/session.ts";
import { localRuntime } from "./local-runtime.ts";
import {
  LOCK_FLUSH_TIMEOUT_MS,
  type NoteRuntime,
  SYNC_AUTHORIZATION_REQUIRED,
  SYNC_BLOCKED,
  SYNC_LOCKED,
  SYNC_PENDING,
  SYNC_QUOTA_REACHED,
  SYNC_RATE_LIMITED,
  SYNC_TOO_LARGE,
  SYNCED,
  type SyncBackoffStatus,
  type SyncListener,
  type SyncRefusal,
  type SyncStatus,
  syncBackoffStatus,
  waitAtMost,
} from "./runtime.ts";

export const SYNC_INTERVAL_MS = 30_000;
/** The wait after each consecutive refusal; the last one repeats. */
export const SYNC_BACKOFF_MS = [60_000, 120_000, 300_000, 900_000, 1_800_000];

const refusals = new Map<SyncResult["blocked"], SyncRefusal>([
  ["quota", SYNC_QUOTA_REACHED],
  ["rate-limited", SYNC_RATE_LIMITED],
  ["too-large", SYNC_TOO_LARGE],
]);

function syncStatus(blocked: SyncResult["blocked"], pending: number) {
  if (blocked === "consent") return SYNC_AUTHORIZATION_REQUIRED;
  if (blocked) return SYNC_BLOCKED;
  return pending ? SYNC_PENDING : SYNCED;
}

/**
 * Nothing is flushed or ingested until `connect` hands over a transport; a
 * rejected `connect` leaves sync pending and is asked again on the next sync.
 * After access loss the key is wiped within `flushLimit` ms, saved or not.
 * A quota, rate-limit or size refusal stops automatic syncs, and so every upload,
 * for `SYNC_BACKOFF_MS`; `sync()` and a local edit after the wait end it early,
 * and a delete ends a size refusal's wait at once.
 */
export function synchronizedRuntime(
  session: VaultSession,
  connect: () => Promise<VaultSnapshotTransport>,
  flushLimit = LOCK_FLUSH_TIMEOUT_MS,
): NoteRuntime &
  Required<Pick<NoteRuntime, "subscribe" | "subscribeTrustLoss" | "sync">> {
  const local = localRuntime(session);
  let engine: VaultSyncEngine | null = null;
  const listeners = new Set<SyncListener>();
  let stopped = false;
  let running: Promise<void> | null = null;
  let lastStatus: SyncStatus | undefined;
  let backoff: {
    step: number;
    until: number;
    refusal: SyncRefusal;
    status: SyncBackoffStatus;
  } | null = null;
  const publish = (status: SyncStatus) => {
    if (stopped) return;
    lastStatus = status;
    for (const listener of listeners) listener(status);
  };
  async function coordinate() {
    if (!engine) {
      const transport = await connect();
      if (stopped) {
        transport.stop?.();
        return;
      }
      engine = new VaultSyncEngine(session, transport);
    }
    const result = await engine.sync();
    if (stopped) return;
    const refusal = refusals.get(result.blocked);
    if (refusal) {
      const step = backoff
        ? Math.min(backoff.step + 1, SYNC_BACKOFF_MS.length - 1)
        : 0;
      const until = Date.now() + SYNC_BACKOFF_MS[step];
      backoff = {
        step,
        until,
        refusal,
        status: syncBackoffStatus(refusal, until),
      };
      publish(backoff.status);
      return;
    }
    if (!result.blocked) backoff = null;
    const pending = await session.database.outbox.count();
    publish(syncStatus(result.blocked, pending));
  }
  function synchronize(): Promise<void> {
    if (stopped) return Promise.resolve();
    if (running) return running;
    running = coordinate()
      .catch(async (error) => {
        if (error instanceof VaultAccessError) await lockOut();
        else publish(SYNC_PENDING);
      })
      .finally(() => {
        running = null;
      });
    return running;
  }
  function synchronizeWhenDue() {
    if (backoff && Date.now() < backoff.until) publish(backoff.status);
    else void synchronize();
  }
  const unsubscribe = session.database.subscribe("outbox", () => {
    void (running ?? Promise.resolve())
      .then(async () => {
        if (stopped) return;
        if (backoff && Date.now() >= backoff.until) backoff = null;
        const pending = await session.database.outbox.count();
        if (
          !stopped &&
          !running &&
          pending &&
          (!lastStatus || lastStatus === SYNCED)
        )
          publish(SYNC_PENDING);
      })
      .catch(() => {});
  });
  const interval = setInterval(synchronizeWhenDue, SYNC_INTERVAL_MS);
  void synchronize();
  const flushOnHide = () => {
    if (document.visibilityState === "hidden") synchronizeWhenDue();
  };
  // biome-ignore lint/plugin: Browser lifecycle capability is absent during unit tests.
  if (typeof document !== "undefined")
    document.addEventListener("visibilitychange", flushOnHide);
  function halt() {
    stopped = true;
    unsubscribe();
    clearInterval(interval);
    // biome-ignore lint/plugin: Browser lifecycle capability is absent during unit tests.
    if (typeof document !== "undefined")
      document.removeEventListener("visibilitychange", flushOnHide);
    listeners.clear();
    engine?.stop();
  }
  function stop() {
    halt();
    local.lock();
  }
  /** Sync stops before anyone hears of the loss; the key outlives it only until each listener's local saves settle, or `flushLimit`. */
  async function lockOut() {
    const notified = [...listeners];
    lastStatus = SYNC_LOCKED;
    halt();
    await waitAtMost(
      Promise.allSettled(
        notified.map(async (listener) => listener(SYNC_LOCKED)),
      ),
      flushLimit,
    );
    local.lock();
  }
  return {
    ...local,
    async permanentRemove(id) {
      await local.permanentRemove(id);
      // A delete is what a size refusal asks for, so it needn't wait. Typing does, because each attempt reads the whole vault.
      void (running ?? Promise.resolve()).then(() => {
        if (backoff?.refusal !== SYNC_TOO_LARGE) return;
        backoff = null;
        void synchronize();
      });
    },
    subscribe(listener) {
      if (lastStatus) listener(lastStatus);
      if (stopped) return () => {};
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    sync() {
      backoff = null;
      return synchronize();
    },
    unreadable: () => engine?.unreadable() ?? 0,
    lock: stop,
  };
}
