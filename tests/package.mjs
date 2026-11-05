// Loads the built package the way Node resolves it for a consumer: through
// its own `exports`, from `dist`, with no bundler. Run by `bun run test:package`.
import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const dist = new URL("../dist/", import.meta.url).pathname;
function* modules(dir) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) yield* modules(path);
    else if (name.endsWith(".js")) yield relative(dist, path).slice(0, -3);
  }
}
const subpaths = [...modules(dist)].filter((path) => path !== "index");
assert.ok(subpaths.length > 30, `only ${subpaths.length} modules built`);
assert.ok(!subpaths.some((path) => path.endsWith(".test")), "tests shipped");

// Flow ID's SDK publishes extensionless ESM imports, which Node can't load
// unbundled, so the device entry is only checked bundled (`test:node`).
const needsBundler = new Set(["device/client"]);
for (const path of subpaths)
  if (!needsBundler.has(path))
    await import(`@flow-industries/seal/internal/${path}`);
const { memoryStore } = await import("@flow-industries/seal/testing");
const store = memoryStore();
await store.write({ kept: true });
assert.deepEqual(await store.read(), { kept: true });

const { createVaultKey, decrypt, encrypt } = await import(
  "@flow-industries/seal/internal/crypto/index"
);
const key = await createVaultKey();
const context = {
  did: "did:plc:package",
  vault: "vault",
  epoch: 1,
  item: "item",
  revision: "revision",
  assets: [],
};
const envelope = await encrypt(
  new TextEncoder().encode("sealed"),
  key,
  context,
);
assert.equal(
  new TextDecoder().decode(await decrypt(envelope, key, context)),
  "sealed",
);
console.log(`loaded ${subpaths.length - needsBundler.size} modules from dist`);

const [packed] = JSON.parse(
  execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
    encoding: "utf8",
  }),
);
const shipped = packed.files.map((file) => file.path);
for (const required of ["LICENSE", "README.md", "package.json"])
  assert.ok(shipped.includes(required), `${required} not in the tarball`);
assert.ok(
  shipped.every(
    (path) =>
      path === "LICENSE" ||
      path === "README.md" ||
      path === "package.json" ||
      path.startsWith("dist/"),
  ),
  "the tarball ships more than dist, the licence and the readme",
);
console.log(
  `the tarball ships ${shipped.length} files, the licence among them`,
);
