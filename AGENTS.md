# AGENTS.md

This file provides guidance to agents working with code in this repository.

`@flow-industries/seal` is the end-to-end encrypted vault core behind NOTE (note.flow.talk): the container and journal format, access slots and signed access statements, pins, the vault session and its carry rules, the sync transport, and the device client. It has no DOM, editor, renderer or UI. Read `README.md` for the security model.

## Layout

`src/index.ts` is the device client's entry and `src/testing/` the in-memory Flow ID kit: these two are the only supported API, held by semver. Every module is also reachable as `@flow-industries/seal/internal/<path>` for NOTE alone, with no semver promise; `src/` mirrors the tree NOTE consumes. A session's preview planner and search index are injected (`SessionServices`), never imported: nothing under `src/` may reach Babel, MDX, CodeMirror, React or a worker. `bun run size` fails if the device bundle does.

Imports are relative with a `.ts` extension; `tsc` rewrites them to `.js` in `dist/`.

## Frozen formats

Every byte a vault stores is frozen: the record and item schemas, container and journal framing, every `flow-note/…` domain-separation string, salt derivation, signing message, recipient-id derivation and the slot count. Production vaults depend on them. Never edit one in place; a new format gets a new version, and its reader ships before any writer. `tests/note-written-vault.test.ts` and its fixture hold a vault NOTE's own code wrote, and the container and unlock tests carry further golden vectors. If a change breaks one of them, the change is wrong, not the test.

## Security rules

- Never serialize keys, seeds, PRF output, recovery material or plaintext into logs, errors, URLs or telemetry.
- A write never signs code it didn't type, and the device client never exposes raw entries, keys or a signer.
- A device never trusts on first use: it starts from the pin its approving admin handed it.
- Only a passkey or recovery admin signs a change to who has access.

## Code style

No comments that say what code does. Doc comments for public APIs and sparse comments explaining why are fine. No emoji in logs.

## Before a PR

Use Bun 1.4.2 (`bun x bun@1.4.2 install --frozen-lockfile`). Run `bun run lint`, `bun run typecheck`, `bun test`, `bun run test:node`, `bun run test:package` and `bun run size`. All of them run in CI.

## Publishing

The package publishes to npm automatically when `version` in `package.json` changes on `main`: `.github/workflows/publish.yml` publishes that exact version through npm trusted publishing (GitHub OIDC, no token). Never run `npm publish` by hand, and never rename `publish.yml`, which the trusted publisher on npmjs.com names. A merge without a version change publishes nothing. The one exception was 0.1.0, published once by hand to create the package, because npm attaches a trusted publisher only to a package that already exists; don't take it as precedent.
