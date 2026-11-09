# @flow-industries/seal

The end-to-end encrypted vault core behind [NOTE](https://note.flow.talk): the encrypted container and journal format, access slots and signed access statements, pins and their provenance, the vault session and its carry rules, the sync transport, and the device client that links a plugin or an agent to a vault.

Notes, paths and attachments are encrypted on the device. The vault lives as encrypted records and blobs on the account's PDS, reached through [Flow ID](https://id.flow.industries). This package holds no UI, editor or renderer: an app supplies those.

## Link a device

```sh
bun add @flow-industries/seal
```

A device links once through a browser, where the person approves it with a passkey that already opens the vault. After that it opens the vault with its own seed and syncs over Flow ID's device token, without a passkey.

```ts
import {
  createDeviceSeed,
  linkDevice,
  openDeviceVault,
} from "@flow-industries/seal";

const seed = createDeviceSeed(); // keep it in the OS keychain, never in the vault folder
const options = {
  host: "https://id.flow.industries",
  credentials, // a NoteDeviceCredentialStore: Flow ID's device tokens, kept like the seed
  checkpoints, // where the device keeps the pin it accepted
};

await linkDevice(seed, {
  ...options,
  label: "Laptop",
  onPrompt({ verificationUri, userCode, pairingCode }) {
    // Show the link and the pairing code. The person types the code in the approving browser.
  },
});

const vault = await openDeviceVault(seed, options);
if (!(await vault.sync()).read) throw new Error("Couldn't reach the vault"); // don't plan against a local copy alone
const [note] = (await vault.read()).notes;
if (note) {
  const saved = await vault.saveNote({ ...note, source: `${note.source}\nmore` });
  await vault.saveNote({ ...note, ...saved, source: `${note.source}\nmore, again` });
}
await vault.stop();
```

`sync()` resolves once every save that resolved before the call is on the PDS: when a sync is already running, it waits for one more run after it. If anything stays queued, for example because the PDS refused the run (offline, quota, rate limit), the status listener hears something other than `SYNCED`. It resolves with `{ read }`, which says whether that sync read the vault from the PDS and applied it. Until one has, `read()` shows only what this device holds locally, which a fresh or offline device may not have filled yet, so don't plan moves or deletions against it.

`saveNote` resolves with the revision the saved content now has; pass it to the next save as `revision` and `digest`. A save on a revision the device can't place throws `NoteChangedError`: read the note again and reapply the edit. Moving an older view the person didn't edit only renames the note and keeps the newer text.

By default, a base the device can still place on an older revision counts as an edit of that revision. So an edited save made on a view that is no longer current replaces whatever landed since, including another device's edit that a sync brought in after you read; the newer text survives only in local history. To push changes planned from an earlier read, use compare-and-swap. Pass `{ current: true }` to `saveNote` or `saveAttachment`, or pass the base as the last argument of `rename(id, path, base)` or `remove(id, base)`. Each then throws `NoteChangedError` unless the base names the stored revision itself. It also throws when a sync lands while the write is committing, even one that brought in an unrelated note, so the expected handling is the same either way: read again and retry.

Attachments follow the same rules. `listAttachments()` lists them without their bytes (`id`, `path`, `mime`, `size`, `revision`, `digest`), `readAttachment(id)` returns one's bytes, and `saveAttachment({ id, path, bytes, revision, digest })` resolves with the new revision. `rename` and `remove` take a note or an attachment. Moving a note rewrites the links to it; moving an attachment leaves them as written, so save the notes that link to it. If your editor already rewrote links for the new names, push the rewritten notes as they are and tell the move which notes to leave alone: `repairLinks` in the options of `rename(id, path, base, options)` or `saveNote(note, options)` takes `true` (the default, repair every linking note), `false` (repair none), or a function that receives each linking note's path and returns whether to repair it. Repairing a note the editor already fixed would re-target its links wherever names swap or chain. Obsidian, with "Automatically update internal links" on, rewrites only the `.md` notes it indexes, so for a move it made pass `(path) => !path.endsWith(".md")`, and NOTE still repairs `.mdx` notes; for a move it didn't see, keep the default. A `rename` to the path the item already has writes nothing and resolves with its current revision, so it is safe to call as an idempotent "be here" step.

The device client hands out only the session's own operations: read, save, rename, trash, merge or extract, and sync. It never exposes raw entries, keys or a signer. It signs only what the device itself wrote: moving, trashing or merging another admin's code writes it unsigned and reports a `TrustLoss`.

Each seed keeps its own local database, named after its recipient id, so two linked devices on one origin, such as two vaults in one desktop app, never share an outbox. Passkey and recovery sessions keep their `flow-note:<did>:<vault>` names. When a device is unlinked, `await vault.stop()` and then `deleteDeviceStorage(seed)`: `stop()` resolves only once no write is in flight and sync has stopped, so nothing races the deletion; edits not yet synced go with it, and no other seed's or passkey's database is touched. To keep the databases in an IndexedDB of your own, pass `indexedDB: { factory, keyRange }` in the device options and to `deleteDeviceStorage`.

### Test without a server

`@flow-industries/seal/testing` runs a whole link in memory: `fakeFlowId()` is Flow ID and the PDS, `adminBrowser(flowId)` is a passkey's browser with a new vault, `approveLink(admin, prompt)` approves a device as the link page does, `openAdminVault(admin)` opens the passkey's own notepad to write and read notes, `dropDevices(admin)` re-signs access without any device, and `memoryStore()` stands in for the keychain. Pass `TEST_HOST` as the host and `flowId.fetch` as `fetch`; `flowId.violations` lists any rule a device broke, and `flowId.revokeAll()` revokes every device's tokens. The kit's own types (`FakeFlowId`, `AdminBrowser`, `AdminNotepad`, `AdminNote`, `MemoryStore`) are its whole surface and follow semver. It uses synthetic keys and is never part of the device entry.

### Runtime requirements

- **IndexedDB.** The local database is IndexedDB through Dexie, which reads the global `indexedDB` once, when it is imported. Under Node, load `fake-indexeddb/auto` before this package: make it the first import of the entry you bundle. Or hand the device an IndexedDB of its own with `indexedDB: { factory, keyRange }` in its options.
- **`fake-indexeddb` is memory only.** Edits not yet synced die with the process. Before exiting, `await vault.sync()` after your last save, check that the last status you heard is `SYNCED`, then `await vault.stop()`. `stop()` never uploads by itself, since it is also how an unlinked device shuts down and must work offline. Electron and browsers keep a real IndexedDB on disk.
- **A bundler for the device entry.** Flow ID's SDK publishes ESM that plain Node can't load, so bundle the device client with Bun or esbuild. With esbuild, mark `mppx` and `mppx/*` external: the SDK's `viem` peer imports it dynamically, and none of it reaches the bundle. Every other module loads under plain Node.
- **Bundle size.** The device entry bundles to about 1.6 MB for Node, with no editor, renderer or UI code (`bun run size`).

## Modules

Only two entry points are supported, and only they follow semver: the root, `@flow-industries/seal`, which is the device client, and `@flow-industries/seal/testing`. Everything under `@flow-industries/seal/internal/*` is there for NOTE alone. It mirrors the source tree and may change in any release, a patch included, so don't build on it:

| Subpath | Holds |
| --- | --- |
| `crypto/index`, `crypto/container` | item envelopes, recovery files, the padded container and its journal |
| `crypto/access-v2`, `crypto/access-v3` | access slots, recipients, signed access statements and pins |
| `crypto/authorship`, `crypto/link`, `crypto/passkey-proof` | entry signatures and run policy, device linking, passkey enrollment proofs |
| `sync/*` | snapshots and journals, the PDS transport, the sync engine, re-keying |
| `vault/*` | the local database, the vault session and its carry rules, links and paths |
| `app/*` | unlock (passkey, recovery and seed), runtimes, Flow ID device and passkey lists |
| `links/*`, `writing/*`, `markdown/*` | link rewriting on rename, metadata and tags, merge and extract, the note dialect |

For example, `import { createSession } from "@flow-industries/seal/internal/vault/session"`. A session's host lends it a preview planner and a search index through `SessionServices`; without them `assetsForNote` and `search` refuse.

## Security model

- **Encryption.** Each item is sealed under the vault key with XChaCha20-Poly1305, bound to its account, vault, epoch, id and revision. The container encrypts each publication with AES-256-GCM in whole 4 MiB chunks, so a PDS reader sees when the vault changed and its size class, not its contents.
- **Access.** The vault key sits in fixed access slots sealed to each recipient: a passkey (through its PRF), a linked device or agent seed, or a recovery file. Only an admin, a passkey or the recovery file, can sign a statement that changes who has access.
- **Pins.** Every client pins the admin set it last accepted and refuses any statement that set didn't sign. A linked device never trusts on first use: it starts from the pin its approving admin sealed to it, under a key derived from the pairing code.
- **Linking.** The device sends Flow ID only its public keys, an Argon2id commitment to a fresh pairing code of eight Crockford base32 characters (shown as `XXXX XXXX`, and never one a Flow ID user code types as, since Flow ID issues those), and a signature proving it holds its key. Flow ID never sees the code. The device refuses a link that takes longer than ten minutes on its own clock.
- **Authorship.** Every revision is signed by whoever wrote it. Code in a note runs only when an admin the session trusts signed its exact revision. A write never signs code it didn't type: moving, trashing or merging another admin's code writes it unsigned and reports a `TrustLoss`.
- **Custody.** A device seed and its Flow ID tokens are bearer secrets. Keep them outside the vault folder, in the OS keychain or Electron `safeStorage`.
- **Limit.** Authenticated encryption proves integrity, not freshness. A fresh device can't tell a replay of an older authenticated state within the same epoch.

## Frozen formats

Production vaults depend on these bytes, so they never change in place:

- the vault record (`industries.flow.note.vault`) and item records;
- the container and journal framing and their chunk size;
- every `flow-note/…` domain-separation string, salt derivation and signing message;
- recipient-id derivation and the number of access slots.

A new format gets a new version, and its reader ships before any writer. `tests/note-written-vault.test.ts` opens a vault written by NOTE's own code before this package existed, and the container and unlock tests carry further golden vectors. A change that breaks any of them is a format change, never a test to update.

The link code (the device secret and the passkey pairing code, with their goldens in the same files) is not a vault format: no vault stores it, and a handoff sealed under it is read only within its link's ten-minute window. Its format may change only in a new minor version that says so, as 0.2.0 did when it went from twelve digits to eight symbols. Outside such a version, a broken link-code golden means the change is wrong, like any other.

## Development

Use Bun 1.4.2 and `bun x bun@1.4.2 install --frozen-lockfile`.

```sh
bun run lint        # Biome, extending @flow-industries/lint
bun run typecheck
bun test            # the unit and golden tests
bun run test:node   # a device links, saves, syncs and reads back under Node
bun run test:package  # builds dist and loads every module through the package exports
bun run size        # bundles the device entry and checks what it reaches
```

## Releasing

Change `version` in `package.json` and merge it. The push to `main` runs `.github/workflows/publish.yml`, which publishes that exact version through npm trusted publishing. There is no npm token. Never publish by hand.

The one exception is 0.1.0. It was published once by hand, to create the package on npm, because npm attaches a trusted publisher only to a package that already exists. Every later version publishes from `publish.yml`.
