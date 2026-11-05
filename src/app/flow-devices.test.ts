import { afterEach, expect, spyOn, test } from "bun:test";
import { z } from "zod";
import { flowDeviceApi, LIST_TIMEOUT_MS } from "./flow-devices.ts";

const servers: ReturnType<typeof Bun.serve>[] = [];
afterEach(() => {
  for (const server of servers.splice(0)) server.stop(true);
});
function flowId(revoke: (deviceId: string) => Response) {
  const requests: { path: string; headers: Headers; body: unknown }[] = [];
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      const path = new URL(request.url).pathname;
      const body = await request.json();
      requests.push({ path, headers: request.headers, body });
      if (path === "/api/atproto/note/device/list")
        return Response.json({
          devices: [
            {
              id: "0e6c2f3a-58a4-4ad1-bb0d-8b3e8c1bd0a1",
              kind: "agent",
              label: "Build agent",
              recipientId: "A".repeat(43),
              did: "did:plc:devices",
              lastUsedAt: null,
            },
          ],
        });
      return revoke(z.object({ deviceId: z.string() }).parse(body).deviceId);
    },
  });
  servers.push(server);
  return { host: `http://127.0.0.1:${server.port}`, requests };
}
const flow = { user: { id: "device-owner" }, getToken: async () => "session" };

test("lists and revokes devices with the browser session, and an already revoked device counts as revoked", async () => {
  let gone = false;
  const { host, requests } = flowId((deviceId) => {
    if (gone)
      return Response.json({ code: "DEVICE_NOT_FOUND" }, { status: 404 });
    gone = true;
    return Response.json({ ok: deviceId.length > 0 });
  });
  const api = flowDeviceApi(flow, host);
  const [device] = await api.list();
  expect(device).toEqual({
    id: "0e6c2f3a-58a4-4ad1-bb0d-8b3e8c1bd0a1",
    kind: "agent",
    label: "Build agent",
    recipientId: "A".repeat(43),
  });
  await api.revoke(device?.id ?? "");
  await api.revoke(device?.id ?? "");
  expect(requests.map((request) => request.path)).toEqual([
    "/api/atproto/note/device/list",
    "/api/atproto/note/device/revoke",
    "/api/atproto/note/device/revoke",
  ]);
  expect(requests[1]?.body).toEqual({ deviceId: device?.id });
  expect(requests[1]?.headers.get("authorization")).toBe("Bearer session");
  expect(requests[1]?.headers.get("x-flow-user-id")).toBe("device-owner");
});

test("a device list Flow ID holds open is cut off, so Access says it couldn't refresh rather than show the last list as current", async () => {
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch: () => new Promise<Response>(() => {}),
  });
  servers.push(server);
  const timeout = AbortSignal.timeout.bind(AbortSignal);
  const timer = spyOn(AbortSignal, "timeout").mockImplementation(() =>
    timeout(50),
  );
  try {
    await expect(
      flowDeviceApi(flow, `http://127.0.0.1:${server.port}`).list(),
    ).rejects.toEqual({ code: "PDS_UNAVAILABLE", status: 503 });
    expect(timer).toHaveBeenCalledWith(LIST_TIMEOUT_MS);
  } finally {
    timer.mockRestore();
  }
});

test("any other refusal stops the change", async () => {
  const { host } = flowId(() =>
    Response.json({ code: "ACCOUNT_CHANGED" }, { status: 409 }),
  );
  await expect(flowDeviceApi(flow, host).revoke("id")).rejects.toEqual({
    code: "ACCOUNT_CHANGED",
    status: 409,
  });
  await expect(
    flowDeviceApi({ user: null, getToken: async () => null }, host).list(),
  ).rejects.toEqual({ code: "SIGN_IN_REQUIRED", status: 401 });
});

test("lookup and approve send the resolved identity and the looked-up recipient, and refuse a request Flow ID never shapes", async () => {
  const requests: { path: string; headers: Headers; body: unknown }[] = [];
  let genuine = true;
  const pending = {
    kind: "device",
    label: "Laptop",
    recipientId: "A".repeat(43),
    boxPublicKey: "A".repeat(43),
    signPublicKey: "A".repeat(43),
    commitment: `${"C".repeat(42)}A`,
    requestedAt: "2026-10-27T10:00:00.000Z",
    requestedFrom: { country: "DE", network: "198.51.100.0/24" },
    reportedUserAgent: "Obsidian/1.7",
    expiresAt: "2026-10-27T10:10:00.000Z",
  };
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      const path = new URL(request.url).pathname;
      requests.push({
        path,
        headers: request.headers,
        body: await request.json(),
      });
      if (path.endsWith("/lookup"))
        return Response.json(genuine ? pending : withoutCommitment);
      return Response.json({
        id: "0e6c2f3a-58a4-4ad1-bb0d-8b3e8c1bd0a1",
        kind: "device",
        label: "Laptop",
      });
    },
  });
  const { commitment: _, ...withoutCommitment } = pending;
  servers.push(server);
  const api = flowDeviceApi(flow, `http://127.0.0.1:${server.port}`, {
    did: "did:plc:devices",
    identityVersion: "7",
  });
  const looked = await api.lookup("BCDFGHJK");
  expect(looked).toMatchObject({
    label: "Laptop",
    commitment: `${"C".repeat(42)}A`,
  });
  expect(await api.approve("BCDFGHJK", looked.recipientId)).toBe(
    "0e6c2f3a-58a4-4ad1-bb0d-8b3e8c1bd0a1",
  );
  expect(requests.map(({ path, body }) => [path, body])).toEqual([
    ["/api/atproto/note/device/lookup", { userCode: "BCDFGHJK" }],
    [
      "/api/atproto/note/device/approve",
      { userCode: "BCDFGHJK", recipientId: "A".repeat(43) },
    ],
  ]);
  expect(requests[1]?.headers.get("x-flow-at-did")).toBe("did:plc:devices");
  expect(requests[1]?.headers.get("x-flow-identity-version")).toBe("7");
  genuine = false;
  await expect(api.lookup("BCDFGHJK")).rejects.toThrow();
});

test("revoking by recipient revokes every device Flow ID lists for it, and only those", async () => {
  const { host, requests } = flowId(() => Response.json({ ok: true }));
  await flowDeviceApi(flow, host).revokeRecipient("A".repeat(43));
  await flowDeviceApi(flow, host).revokeRecipient("B".repeat(43));
  expect(requests.map((request) => [request.path, request.body])).toEqual([
    ["/api/atproto/note/device/list", {}],
    [
      "/api/atproto/note/device/revoke",
      { deviceId: "0e6c2f3a-58a4-4ad1-bb0d-8b3e8c1bd0a1" },
    ],
    ["/api/atproto/note/device/list", {}],
  ]);
});
