import type { VaultSession } from "../vault/session.ts";
import { SyncFailure } from "./records.ts";
import {
  captureSnapshot,
  type SnapshotEntry,
  snapshotRemote,
  type VaultSnapshotTransport,
} from "./vault-snapshot.ts";

export interface SyncResult {
  synced: number;
  blocked?: SyncFailure["reason"];
  /** This sync read the vault from the PDS and applied it, so the session now reflects it. */
  read: boolean;
}
export class VaultSyncEngine {
  private stopped = false;
  private running: Promise<SyncResult> | null = null;
  private session: VaultSession;
  private transport: VaultSnapshotTransport;
  /**
   * Entries the last sync couldn't validate. They are never applied, and every
   * write carries them through untouched in place of this device's copy, so
   * one invalid entry can't lock every reader out of the notepad and the
   * Access flow, and a revision from a newer client is never replaced by an
   * older one. A re-key names them (`RekeyBlockedError`) and lets an admin
   * drop them.
   */
  private quarantine: SnapshotEntry[] = [];
  constructor(session: VaultSession, transport: VaultSnapshotTransport) {
    this.session = session;
    this.transport = transport;
  }
  /** How many entries the last sync couldn't read. */
  unreadable(): number {
    return this.quarantine.length;
  }
  stop(): void {
    this.stopped = true;
    this.transport.stop?.();
  }
  sync(): Promise<SyncResult> {
    if (this.running) return this.running;
    this.running = this.run().finally(() => {
      this.running = null;
    });
    return this.running;
  }
  private async run(): Promise<SyncResult> {
    let read = false;
    for (let attempt = 0; attempt < 4 && !this.stopped; attempt++) {
      try {
        const snapshot = await this.transport.readSnapshot();
        if (this.stopped) return { synced: 0, read };
        if (snapshot?.access) this.session.authorize(snapshot.access);
        const incoming: (ReturnType<typeof snapshotRemote> & {
          entry: SnapshotEntry;
        })[] = [];
        const quarantined: SnapshotEntry[] = [];
        for (const entry of snapshot?.entries ?? []) {
          try {
            const parsed = snapshotRemote(entry);
            await this.session.validateRemote(parsed.remote, parsed.blobs);
            incoming.push({ ...parsed, entry });
          } catch {
            quarantined.push(entry);
          }
          if (this.stopped) return { synced: 0, read };
        }
        this.quarantine = quarantined;
        for (const { remote, blobs, entry } of incoming) {
          if (this.stopped) return { synced: 0, read };
          const local = await this.session.database.items.get(remote.record.id);
          // Kept as it is remotely, never applied: other content under a revision id this device already holds.
          if (await this.session.reusesRevision(remote.record, local)) {
            quarantined.push(entry);
            continue;
          }
          if (local?.revision === remote.record.revision) {
            if (!local.author && remote.record.author)
              await this.session.adoptAuthor(remote.record);
            continue;
          }
          await this.session.applyRemote(remote, blobs);
        }
        if (this.stopped) return { synced: 0, read };
        await this.session.repairGraph();
        const unreadable = new Set(quarantined.map((entry) => entry.id));
        for (const id of unreadable) {
          await this.session.keepEditBeside(id);
          if (this.stopped) return { synced: 0, read };
        }
        read = true;
        const captured = await captureSnapshot(this.session.database);
        // An edit that lands on an unreadable item after it was set aside waits for the next sync to set it aside too.
        const pending = captured.pending.filter(
          ({ id }) => !unreadable.has(id),
        );
        if (!pending.length || this.stopped) return { synced: 0, read };
        const entries = captured.entries.filter(
          (entry) => !unreadable.has(entry.id),
        );
        await this.transport.writeSnapshot(
          [...entries, ...quarantined],
          snapshot?.cid ?? null,
        );
        if (this.stopped) return { synced: 0, read };
        await this.session.database.transaction(
          "rw",
          this.session.database.items,
          this.session.database.outbox,
          async () => {
            const published = new Map(
              entries.map((entry) => [entry.id, entry]),
            );
            for (const { id, revision } of pending)
              await this.session.database.acknowledge(
                id,
                revision,
                revision,
                published.get(id),
              );
          },
        );
        return { synced: pending.length, read };
      } catch (error) {
        if (this.stopped) return { synced: 0, read };
        if (!(error instanceof SyncFailure)) throw error;
        if (error.reason !== "conflict" || attempt === 3)
          return { synced: 0, read, blocked: error.reason };
        await new Promise((resolve) => setTimeout(resolve, 25 * 2 ** attempt));
      }
    }
    return { synced: 0, read };
  }
}
