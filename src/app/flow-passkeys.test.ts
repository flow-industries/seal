import { afterEach, expect, test } from "bun:test";
import { flowIdAnswered, flowPasskeys } from "./flow-passkeys.ts";

const servers: ReturnType<typeof Bun.serve>[] = [];
afterEach(() => {
  for (const server of servers.splice(0)) server.stop(true);
});
const listed = {
  credentialId: "own-passkey",
  publicKey: `0x${"a".repeat(128)}`,
  createdAt: "2026-10-01T00:00:00.000Z",
};
function flowId(answer: () => Response) {
  const requests: { path: string; headers: Headers }[] = [];
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      requests.push({
        path: new URL(request.url).pathname,
        headers: request.headers,
      });
      return answer();
    },
  });
  servers.push(server);
  return { host: `http://127.0.0.1:${server.port}`, requests };
}
function owner() {
  const user: { id: string } | null = { id: "owner" };
  return { user, getToken: async () => "jwt" };
}

test("reads the signed-in account's passkeys with its token and no account header", async () => {
  const { host, requests } = flowId(() =>
    Response.json({ userId: "owner", passkeys: [listed] }),
  );
  expect(await flowPasskeys(owner(), host)).toEqual([listed]);
  expect(requests.map((request) => request.path)).toEqual([
    "/api/account/passkeys",
  ]);
  expect(requests[0]?.headers.get("authorization")).toBe("Bearer jwt");
  expect(requests[0]?.headers.has("x-flow-user-id")).toBe(false);
});

test("drops a list for another account, or for an account that changed while it was asked", async () => {
  const other = flowId(() =>
    Response.json({ userId: "someone-else", passkeys: [listed] }),
  );
  await expect(flowPasskeys(owner(), other.host)).rejects.toMatchObject({
    code: "ACCOUNT_CHANGED",
  });
  const flow = owner();
  const switched = flowId(() => {
    flow.user = { id: "someone-else" };
    return Response.json({ userId: "owner", passkeys: [listed] });
  });
  await expect(flowPasskeys(flow, switched.host)).rejects.toMatchObject({
    code: "ACCOUNT_CHANGED",
  });
});

test("refuses keys in any encoding but FlowCredential's, and passes Flow ID's refusals on", async () => {
  const prefixed = flowId(() =>
    Response.json({
      userId: "owner",
      passkeys: [{ ...listed, publicKey: `04${"a".repeat(128)}` }],
    }),
  );
  await expect(flowPasskeys(owner(), prefixed.host)).rejects.toEqual({
    code: "INVALID_RESPONSE",
    status: 200,
  });
  const refused = flowId(() =>
    Response.json({ code: "UNAUTHORIZED" }, { status: 401 }),
  );
  await expect(flowPasskeys(owner(), refused.host)).rejects.toEqual({
    code: "UNAUTHORIZED",
    status: 401,
  });
  await expect(
    flowPasskeys({ user: null, getToken: async () => "jwt" }, refused.host),
  ).rejects.toEqual({ code: "SIGN_IN_REQUIRED", status: 401 });
  expect(refused.requests).toHaveLength(1);
});

/** What `flowPasskeys` threw for this answer, or its failure to get one. */
async function failureOf(answer: () => Response) {
  const { host } = flowId(answer);
  return flowPasskeys(owner(), host).then(
    () => {
      throw new Error("Expected a failure");
    },
    (error) => error,
  );
}

test("a list NOTE can't read, a refusal or another account's list is Flow ID's answer, and retrying won't change it", async () => {
  const unusable: [string, () => Response][] = [
    [
      "a credential id outside base64url",
      () =>
        Response.json({
          userId: "owner",
          passkeys: [{ ...listed, credentialId: "not base64url" }],
        }),
    ],
    [
      "more than 100 rows",
      () =>
        Response.json({
          userId: "owner",
          passkeys: Array.from({ length: 101 }, () => listed),
        }),
    ],
    ["a body that isn't JSON", () => new Response("<html>")],
    ["no body", () => new Response(null, { status: 204 })],
    [
      "a refusal",
      () => Response.json({ code: "UNAUTHORIZED" }, { status: 401 }),
    ],
    ["a missing route", () => new Response("gone", { status: 404 })],
    [
      "another account's list",
      () => Response.json({ userId: "someone-else", passkeys: [listed] }),
    ],
  ];
  for (const [name, answer] of unusable)
    expect([name, flowIdAnswered(await failureOf(answer))]).toEqual([
      name,
      true,
    ]);
});

test("a server error, a rate limit, a failed request or a request that never left is no answer", async () => {
  const noAnswer: [string, () => Response][] = [
    ["a 500", () => Response.json({ code: "INTERNAL" }, { status: 500 })],
    ["a proxy's 502", () => new Response("<html>", { status: 502 })],
    ["a 503", () => new Response(null, { status: 503 })],
    [
      "a rate limit",
      () => Response.json({ code: "RATE_LIMITED" }, { status: 429 }),
    ],
  ];
  for (const [name, answer] of noAnswer)
    expect([name, flowIdAnswered(await failureOf(answer))]).toEqual([
      name,
      false,
    ]);
  const closed = flowId(() => Response.json({}));
  servers.pop()?.stop(true);
  expect(
    flowIdAnswered(
      await flowPasskeys(owner(), closed.host).catch((error) => error),
    ),
  ).toBe(false);
  expect(
    flowIdAnswered(
      await flowPasskeys(
        { user: { id: "owner" }, getToken: async () => null },
        closed.host,
      ).catch((error) => error),
    ),
  ).toBe(false);
  expect(flowIdAnswered(new Error("Account changed"))).toBe(false);
});
