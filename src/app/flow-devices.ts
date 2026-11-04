import type { Flow } from "@flow-industries/id";
import { z } from "zod";
import { encoded32 } from "../crypto/access-v2.ts";

/**
 * Devices can be linked; agents can't be yet. Flow ID has the matching
 * switch, and takes the device's commitment and key proof and binds approval
 * to the looked-up recipient.
 *
 * A linking change writes an optional `link` into the access metadata, which
 * every client older than its reader rejects. Never roll a client back past
 * that reader while this is on.
 */
export const LINK_DEVICES = true;
const kind = z.enum(["device", "agent"]);
const instant = z.iso.datetime({ offset: true });
const deviceSchema = z.object({
  id: z.string().min(1).max(64),
  kind,
  label: z.string().max(64),
  recipientId: z.string().min(1).max(64),
  createdAt: instant.optional(),
});
export type FlowDevice = z.infer<typeof deviceSchema>;
/** A pending request as `/link` shows it before the user approves. */
export const pendingDeviceSchema = z.object({
  kind,
  label: z.string().min(1).max(64),
  recipientId: encoded32,
  boxPublicKey: encoded32,
  signPublicKey: encoded32,
  /** The device's commitment to its secret, kind, label and keys (`linkCommitment`); Flow ID only relays it. */
  commitment: encoded32,
  requestedAt: instant,
  requestedFrom: z.object({
    country: z.string().max(16).nullable(),
    network: z.string().max(64).nullable(),
  }),
  reportedUserAgent: z.string().max(1024).nullable(),
  expiresAt: instant,
});
export type PendingDevice = z.infer<typeof pendingDeviceSchema>;
const refusalSchema = z.object({ code: z.string().max(64) });
/** How long a device list may take before Flow ID counts as unreachable, so Access never shows a stale list as current. */
export const LIST_TIMEOUT_MS = 10_000;

/**
 * Flow ID's NOTE device routes, which take the browser session (the SDK only
 * wraps the device side). Failures throw `{ code, status }` like the SDK.
 * `approve` needs the resolved `identity`, and must only ever run inside
 * `addVaultRecipient`, after a fresh passkey unlock in the same tab.
 */
export function flowDeviceApi(
  flow: { user: { id: string } | null; getToken: Flow["getToken"] },
  host: string,
  identity?: { did: string; identityVersion: string },
) {
  async function call(
    action: "list" | "revoke" | "lookup" | "approve",
    body: { deviceId?: string; userCode?: string; recipientId?: string },
    signal?: AbortSignal,
  ) {
    const userId = flow.user?.id;
    const token = await flow.getToken();
    if (!userId || !token) throw { code: "SIGN_IN_REQUIRED", status: 401 };
    let response: Response;
    try {
      response = await fetch(`${host}/api/atproto/note/device/${action}`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "X-Flow-User-Id": userId,
          "Content-Type": "application/json",
          ...(identity && {
            "X-Flow-At-Did": identity.did,
            "X-Flow-Identity-Version": identity.identityVersion,
          }),
        },
        body: JSON.stringify(body),
        credentials: "omit",
        referrerPolicy: "no-referrer",
        signal,
      });
    } catch {
      throw { code: "PDS_UNAVAILABLE", status: 503 };
    }
    const data: unknown = await response.json().catch(() => null);
    if (!response.ok)
      throw {
        code: refusalSchema.safeParse(data).data?.code ?? "PDS_UNAVAILABLE",
        status: response.status,
      };
    return data;
  }
  /** An older Flow ID answers DEVICE_LINKING_DISABLED while its device switch is off; a current one lists devices either way. */
  async function list(): Promise<FlowDevice[]> {
    let devices: unknown;
    try {
      devices = await call("list", {}, AbortSignal.timeout(LIST_TIMEOUT_MS));
    } catch (error) {
      if (
        refusalSchema.safeParse(error).data?.code === "DEVICE_LINKING_DISABLED"
      )
        return [];
      throw error;
    }
    return z.object({ devices: z.array(deviceSchema).max(256) }).parse(devices)
      .devices;
  }
  /** Already revoked (or reaped) counts as revoked. */
  async function revoke(deviceId: string): Promise<void> {
    try {
      await call("revoke", { deviceId });
    } catch (error) {
      if (refusalSchema.safeParse(error).data?.code !== "DEVICE_NOT_FOUND")
        throw error;
    }
  }
  return {
    async lookup(userCode: string): Promise<PendingDevice> {
      return pendingDeviceSchema.parse(await call("lookup", { userCode }));
    },
    /** Approves only the recipient `lookup` showed; Flow ID refuses a code that now names another. */
    async approve(userCode: string, recipientId: string): Promise<string> {
      return z
        .object({ id: z.uuid() })
        .parse(await call("approve", { userCode, recipientId })).id;
    },
    /** Revokes every live device Flow ID lists for this recipient. */
    async revokeRecipient(recipientId: string): Promise<void> {
      for (const device of await list())
        if (device.recipientId === recipientId) await revoke(device.id);
    },
    list,
    revoke,
  };
}
/** What re-keying needs from Flow ID: the devices to revoke before the vault drops them. */
export type FlowDeviceApi = Pick<
  ReturnType<typeof flowDeviceApi>,
  "list" | "revoke"
>;
