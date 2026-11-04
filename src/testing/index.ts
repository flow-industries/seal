/**
 * Flow ID, its PDS and an approving passkey browser, all in memory, so a
 * plugin or agent can run a whole device link, then sync against a vault,
 * without a server. Synthetic keys only; nothing here is for production.
 * The types below are the kit's whole supported surface.
 */
import type { LinkPrompt } from "../device/client.ts";
import * as kit from "./kit.ts";

export { TEST_DID, TEST_HOST, TEST_VAULT_URI } from "./kit.ts";

/**
 * Flow ID's device grant and NOTE transport, and the PDS behind them.
 * Device-token puts follow Flow ID's rule: compare-and-swap, with access
 * byte-identical to the record they replace.
 */
export interface FakeFlowId {
  /** Answers as Flow ID does: pass it as `DeviceOptions.fetch`, with `TEST_HOST` as the host. */
  fetch(url: string, init: RequestInit): Promise<Response>;
  /** Every rule a device broke, such as rewriting access; empty while each one behaves. */
  readonly violations: readonly string[];
  /** Flow ID revokes every device: their tokens stop and refreshes are refused. */
  revokeAll(): void;
}
/** A passkey's browser, which created a vault on `flowId` and approves devices for it. */
export interface AdminBrowser {
  readonly flowId: FakeFlowId;
}
/** A note in the admin's notepad. */
export interface AdminNote {
  id: string;
  path: string;
  source: string;
  kind: "md" | "mdx";
  revision?: string;
  digest?: string;
}
/** The admin's own notepad over the vault, syncing with the fake PDS. */
export interface AdminNotepad {
  read(): Promise<{ notes: AdminNote[]; folders: string[] }>;
  /** Saves as the passkey typed it: the admin signs it, so its MDX runs on the devices that passkey linked. */
  save(note: AdminNote): Promise<void>;
  sync(): Promise<void>;
  lock(): void;
}
/** A credential or checkpoint store in memory, as a plugin's keychain would hold it. */
export interface MemoryStore<T> {
  read(): Promise<T | null>;
  write(value: T): Promise<void>;
}

const flowIds = new WeakMap<FakeFlowId, kit.FakeFlowId>();
const browsers = new WeakMap<AdminBrowser, kit.AdminBrowser>();
function browserOf(admin: AdminBrowser): kit.AdminBrowser {
  const browser = browsers.get(admin);
  if (!browser) throw new Error("Not an admin browser from adminBrowser()");
  return browser;
}

/** A fresh Flow ID and PDS, holding no vault until `adminBrowser` creates one. */
export function fakeFlowId(): FakeFlowId {
  const flowId = kit.fakeFlowId();
  const handle: FakeFlowId = {
    fetch: flowId.fetch,
    violations: flowId.violations,
    revokeAll: flowId.revokeAll,
  };
  flowIds.set(handle, flowId);
  return handle;
}

/** A passkey's browser that creates a new vault on `flowId`. */
export async function adminBrowser(flowId: FakeFlowId): Promise<AdminBrowser> {
  const note = flowIds.get(flowId);
  if (!note) throw new Error("Not a fake Flow ID from fakeFlowId()");
  const handle: AdminBrowser = { flowId };
  browsers.set(handle, await kit.adminBrowser(note));
  return handle;
}

/**
 * Approves the device showing `prompt`, as the link page does: it looks the
 * request up, types the pairing code, and publishes the change that lists
 * the device with its handoff.
 */
export function approveLink(
  admin: AdminBrowser,
  prompt: LinkPrompt,
): Promise<void> {
  return kit.approveLink(browserOf(admin), prompt);
}

/** Opens the admin's notepad, to write notes for a device to read and read back what it wrote. Call `lock()` when done. */
export async function openAdminVault(
  admin: AdminBrowser,
): Promise<AdminNotepad> {
  const runtime = await kit.openAdminVault(browserOf(admin));
  return {
    read: () => runtime.read(),
    save: (note) => runtime.save(note),
    sync: () => runtime.sync(),
    lock: () => runtime.lock(),
  };
}

/**
 * Re-signs access with the admins alone, keeping the notes, so every linked
 * device loses its slot: its next open throws `AccessRemovedError` and a
 * running one locks on its next sync. Call `flowId.revokeAll()` as well to
 * revoke the devices' tokens, as a real removal does.
 */
export function dropDevices(admin: AdminBrowser): Promise<void> {
  return kit.dropDevices(browserOf(admin));
}

export function memoryStore<T>(): MemoryStore<T> {
  return kit.memoryStore<T>();
}
