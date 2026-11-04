import type { Flow } from "@flow-industries/id";
import { z } from "zod";
import type { RegisteredPasskey } from "../crypto/passkey-proof.ts";

const listSchema = z.object({
  userId: z.string().min(1),
  passkeys: z
    .array(
      z.object({
        credentialId: z
          .string()
          .min(1)
          .max(2048)
          .regex(/^[A-Za-z0-9_-]+$/),
        publicKey: z.string().regex(/^0x[0-9a-f]{128}$/),
        createdAt: z.iso.datetime({ offset: true }),
      }),
    )
    .max(100),
});
const refusalSchema = z.object({ code: z.string().max(64) });
const failureSchema = z.object({ code: z.string(), status: z.number() });

/**
 * The passkeys Flow ID has registered to the signed-in account, from
 * `GET /api/account/passkeys` (SDK `listAccountPasskeys` from 0.35.0). It
 * sends no `X-Flow-User-Id`, which that route's guard refuses without a
 * cookie, and drops a list for any account but the one signed in when it
 * asked. Failures throw `{ code, status }` like `flowDeviceApi`.
 */
export async function flowPasskeys(
  flow: { user: { id: string } | null; getToken: Flow["getToken"] },
  host: string,
): Promise<RegisteredPasskey[]> {
  const userId = flow.user?.id;
  const token = await flow.getToken();
  if (!userId || !token) throw { code: "SIGN_IN_REQUIRED", status: 401 };
  let response: Response;
  try {
    response = await fetch(`${host}/api/account/passkeys`, {
      headers: { Authorization: `Bearer ${token}` },
      credentials: "omit",
      referrerPolicy: "no-referrer",
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
  const listed = listSchema.safeParse(data);
  if (!listed.success)
    throw { code: "INVALID_RESPONSE", status: response.status };
  if (listed.data.userId !== userId || flow.user?.id !== userId)
    throw { code: "ACCOUNT_CHANGED", status: 409 };
  return listed.data.passkeys;
}

/**
 * Whether a failed `flowPasskeys` is Flow ID's own answer: a refusal, or a list
 * NOTE can't read or that names another account. One of those may never change,
 * so it asks rather than refuses, even if it's only a deploy passing through. A
 * request that never left or failed on the way, a server error and a rate limit
 * are no answer at all.
 */
export function flowIdAnswered(
  // biome-ignore lint/plugin: Whatever the port threw is sorted here.
  error: unknown,
): boolean {
  const failure = failureSchema.safeParse(error);
  return (
    failure.success &&
    failure.data.code !== "SIGN_IN_REQUIRED" &&
    failure.data.status < 500 &&
    failure.data.status !== 429
  );
}
