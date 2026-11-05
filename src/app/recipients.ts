import type { VaultRecipient } from "../crypto/access-v3.ts";

const kindNames = {
  passkey: "Passkey",
  recovery: "Recovery file",
  device: "Device",
  agent: "Agent",
} as const;
/** A passkey carried over from before signed access; a re-key drops it unless it first unlocks on a browser that can change access. */
export const unconfirmed = (recipient: VaultRecipient) =>
  recipient.kind === "passkey" && !recipient.signPublicKey;
/** Why a browser whose pin was trusted on first use can't change access, and what it can do instead. */
export const UNTRUSTED_BROWSER =
  "This browser trusted your notepad the first time it opened it, so it can’t change who has access. It can still read, write and download a recovery file. Recovering with a recovery file here lets it change access, but removes every other passkey and device.";
export function recipientName(recipient: VaultRecipient, self?: string) {
  if (recipient.id === self) return "This passkey";
  const name = recipient.label ?? kindNames[recipient.kind];
  if (unconfirmed(recipient)) return `${name} (not yet confirmed)`;
  return recipient.kind === "agent" && recipient.label
    ? `${name} (agent)`
    : name;
}
/** The day and the first characters of the recipient id, so a lost file's entry can be told from the others. */
const stamp = (recipientId: string, day: Date) =>
  [day.toISOString().slice(0, 10), recipientId.slice(0, 4)] as const;
export function recoveryLabel(recipientId: string, day = new Date()) {
  const [date, short] = stamp(recipientId, day);
  return `Recovery file ${date} · ${short}`;
}
export function recoveryFileName(recipientId: string, day = new Date()) {
  const [date, short] = stamp(recipientId, day);
  return `NOTE-recovery-${date}-${short}.json`;
}
