import { expect, test } from "bun:test";
import {
  createPathLookup,
  decodeLinkPath,
  encodeLinkPath,
  normalizeLinkPath,
  type PathEntry,
  resolvePath,
} from "./links.ts";
import { canonicalLinkKey } from "./model.ts";

test("link keys preserve ASCII punctuation, Unicode normalization and contextual casing", () => {
  expect(canonicalLinkKey("Projects/Q4 Review.MDX")).toBe(
    "projects/q4 review.mdx",
  );
  expect(canonicalLinkKey("[]_!@#$%^&*()+-={}\\|:;\"'<>,.?/~`")).toBe(
    "[]_!@#$%^&*()+-={}\\|:;\"'<>,.?/~`",
  );
  expect(canonicalLinkKey("Cafe\u0301.md")).toBe("café.md");
  expect(canonicalLinkKey("İstanbul.md")).toBe("i\u0307stanbul.md");
  expect(canonicalLinkKey("ΟΔΟΣ")).toBe("οδος");
  expect(canonicalLinkKey("ΟΔΟΣ.md")).toBe("οδοσ.md");
  expect(canonicalLinkKey("Kelvin.md")).toBe("kelvin.md");
});

/** `resolvePath` as it was before the lookup: a linear scan per call, kept as the oracle. */
function scanResolvePath(
  target: string,
  fromPath: string,
  entries: readonly { id: string; path: string }[],
  syntax: "wiki" | "markdown" = "wiki",
): string | null {
  const decoded = decodeLinkPath(target.split("#")[0] ?? "");
  if (decoded === null || /^[A-Za-z][A-Za-z0-9+.-]*:|^\/\//u.test(decoded))
    return null;
  const equal = (a: string, b: string) =>
    a.normalize("NFC").toLocaleLowerCase("en-US") ===
    b.normalize("NFC").toLocaleLowerCase("en-US");
  const matchPath = (path: string | null) =>
    path === null
      ? []
      : entries.filter(
          (entry) =>
            equal(entry.path, path) ||
            equal(entry.path, `${path}.md`) ||
            equal(entry.path, `${path}.mdx`),
        );
  if (syntax === "wiki" && decoded.includes("/") && !decoded.startsWith(".")) {
    const root = matchPath(normalizeLinkPath(decoded));
    if (root.length) return root.length === 1 ? (root[0]?.id ?? null) : null;
  }
  const relative = matchPath(normalizeLinkPath(decoded, fromPath));
  if (relative.length)
    return relative.length === 1 ? (relative[0]?.id ?? null) : null;
  if (syntax === "wiki" && !decoded.includes("/")) {
    const names = entries.filter((entry) => {
      const name = entry.path.split("/").at(-1) ?? "";
      return (
        equal(name, decoded) ||
        equal(name, `${decoded}.md`) ||
        equal(name, `${decoded}.mdx`)
      );
    });
    if (names.length === 1) return names[0]?.id ?? null;
  }
  return null;
}

const aliasKey = (alias: string) =>
  alias.trim().normalize("NFC").toLocaleLowerCase("en-US");
const entries: PathEntry[] = [
  { id: "root-plan", path: "Plan.md", aliases: ["Roadmap", "The Plan"] },
  { id: "project-plan", path: "Projects/Plan.md", aliases: ["roadmap"] },
  { id: "project-notes", path: "Projects/Notes.mdx" },
  { id: "deep", path: "Projects/2026/Q4 review.md", aliases: [" Review "] },
  { id: "cafe-nfc", path: "Journal/Café.md" },
  { id: "upper", path: "Journal/README.MD" },
  { id: "dotted", path: "Journal/v1.2 notes.md" },
  { id: "sigma", path: "Greek/ΟΔΟΣ.md", aliases: ["Δρόμος"] },
  { id: "image", path: "Projects/diagram.png" },
  { id: "md-and-mdx-a", path: "Twins/Twin.md" },
  { id: "md-and-mdx-b", path: "Twins/Twin.mdx" },
  { id: "folder-note", path: "Projects" },
];
const fromPaths = [
  ...entries.map((entry) => entry.path),
  "Elsewhere.md",
  "/Elsewhere.md",
  "Deep/er/x.md",
  "Deep/er/y.md",
  "Deep//er/x.md",
];
function targetsFor(path: string): string[] {
  const bare = path.replace(/\.mdx?$/iu, "");
  const name = path.split("/").at(-1) ?? path;
  return [
    path,
    bare,
    name,
    name.replace(/\.mdx?$/iu, ""),
    `/${path}`,
    `/${bare}`,
    `./${name}`,
    `../${path}`,
    `../../${bare}`,
    path.toUpperCase(),
    bare.normalize("NFD"),
    encodeLinkPath(bare),
    `${bare}#Heading`,
    `${name}#^block`,
  ];
}
const targets = [
  ...new Set([
    ...entries.flatMap((entry) => targetsFor(entry.path)),
    ...entries.flatMap((entry) => entry.aliases ?? []),
    "",
    "#Heading",
    "Missing",
    "Projects/Missing",
    "plan",
    "PLAN.MD",
    "Café",
    "οδος",
    "ΟΔΟΣ",
    "https://example.com/Plan.md",
    "//host/Plan.md",
    "mailto:Plan",
    "%E0%A4%A",
    "a/../../Plan",
    "Projects/../Plan",
    "Projects/./Plan",
    "Twins/Twin",
    "Twin",
  ]),
];

test("the path lookup resolves every target exactly as the linear scan did", () => {
  const lookup = createPathLookup(entries, { aliasKey });
  let compared = 0;
  for (const syntax of ["wiki", "markdown"] as const)
    for (const fromPath of fromPaths)
      for (const target of targets) {
        const expected = scanResolvePath(target, fromPath, entries, syntax);
        expect({
          target,
          fromPath,
          syntax,
          id: lookup.resolve(target, fromPath, syntax),
        }).toEqual({ target, fromPath, syntax, id: expected });
        expect(resolvePath(target, fromPath, entries, syntax)).toBe(expected);
        compared++;
      }
  expect(compared).toBeGreaterThan(4000);
});

test("matches unions every rule on its own and aliased keys aliases like the per-note scan", () => {
  const lookup = createPathLookup(entries, { aliasKey });
  for (const syntax of ["wiki", "markdown"] as const)
    for (const fromPath of fromPaths)
      for (const target of targets)
        expect({
          target,
          fromPath,
          syntax,
          ids: lookup.matches(target, fromPath, syntax),
        }).toEqual({
          target,
          fromPath,
          syntax,
          ids: entries
            .filter(
              (entry) =>
                scanResolvePath(target, fromPath, [entry], syntax) === entry.id,
            )
            .map((entry) => entry.id),
        });
  for (const name of [...targets, "ROADMAP", "the plan", "review", "δρόμος"])
    expect({ name, ids: lookup.aliased(name) }).toEqual({
      name,
      ids: entries
        .filter((entry) =>
          (entry.aliases ?? []).some(
            (alias) => aliasKey(alias) === aliasKey(name),
          ),
        )
        .map((entry) => entry.id),
    });
  expect(createPathLookup(entries).aliased("Roadmap")).toEqual([]);
});

test("the ambiguous, final-sigma and twin cases the comparison relies on are present", () => {
  const lookup = createPathLookup(entries, { aliasKey });
  expect(lookup.resolve("Plan", "Elsewhere.md")).toBe("root-plan");
  expect(lookup.resolve("Plan", "Deep/er/x.md")).toBeNull();
  expect(lookup.matches("Plan", "Deep/er/x.md")).toEqual([
    "root-plan",
    "project-plan",
  ]);
  expect(lookup.resolve("ΟΔΟΣ", "Elsewhere.md")).toBe("sigma");
  expect(lookup.resolve("Café".normalize("NFD"), "Journal/README.MD")).toBe(
    "cafe-nfc",
  );
  expect(lookup.resolve("Twins/Twin", "Elsewhere.md")).toBeNull();
  expect(lookup.matches("Twins/Twin", "Elsewhere.md")).toEqual([
    "md-and-mdx-a",
    "md-and-mdx-b",
  ]);
});

test("a lookup is reused only while ids, paths, aliases and the alias key are unchanged", () => {
  const lookup = createPathLookup(entries, { aliasKey });
  const copies = entries.map((entry) => ({
    ...entry,
    aliases: entry.aliases && [...entry.aliases],
  }));
  expect(createPathLookup(copies, { aliasKey, previous: lookup })).toBe(lookup);
  const renamed = copies.map((entry) =>
    entry.id === "deep"
      ? { ...entry, path: "Projects/2026/Q1 review.md" }
      : entry,
  );
  const next = createPathLookup(renamed, { aliasKey, previous: lookup });
  expect(next).not.toBe(lookup);
  expect(next.resolve("Q1 review", "Elsewhere.md")).toBe("deep");
  const realiased = copies.map((entry) =>
    entry.id === "upper" ? { ...entry, aliases: ["Read me"] } : entry,
  );
  expect(
    createPathLookup(realiased, { aliasKey, previous: lookup }).aliased(
      "read me",
    ),
  ).toEqual(["upper"]);
  expect(createPathLookup(copies, { previous: lookup })).not.toBe(lookup);
  expect(
    createPathLookup(copies.slice(1), { aliasKey, previous: lookup }),
  ).not.toBe(lookup);
});

test("path snapshots retain identity only across alias-only changes", () => {
  const entries = [
    { id: "first", path: "First.md", aliases: ["One"] },
    { id: "second", path: "Second.md", aliases: ["Two"] },
  ];
  const first = createPathLookup(entries, { aliasKey });
  const aliases = createPathLookup(
    entries.map((entry) => ({ ...entry, aliases: ["Changed"] })),
    { aliasKey, previous: first },
  );
  expect(aliases.samePaths(first)).toBe(true);
  expect(first.samePaths(aliases)).toBe(true);
  for (const changed of [
    [...entries].reverse(),
    entries.slice(1),
    entries.map((entry) => ({ ...entry, path: `Moved/${entry.path}` })),
  ])
    expect(
      createPathLookup(changed, { aliasKey, previous: first }).samePaths(first),
    ).toBe(false);
});

test("conditional link decoding preserves escaped punctuation, Unicode and malformed-percent behavior", () => {
  const original = (target: string) => {
    try {
      return decodeURIComponent(
        target.replace(/\\([!"#$%&'()*+,\-./:;<=>?@[\]\\^_`{|}~])/gu, "$1"),
      ).normalize("NFC");
    } catch {
      return null;
    }
  };
  for (const target of [
    "",
    "folder/Plain name.md",
    "Cafe\u0301",
    "İ/ΟΔΟΣ",
    "😀",
    "\uD800",
    "\\[escaped\\]",
    "two\\\\slashes",
    "unchanged\\q",
    "\\%41",
    "%41",
    "%25",
    "Cafe%CC%81",
    "%E2%82%AC",
    "%",
    "%GG",
    "%E2%82",
    "%C0%AF",
    "https%3A%2F%2Fexample.com",
    "#Heading",
    "a%23b",
    "a%2Fb",
  ])
    expect({ target, decoded: decodeLinkPath(target) }).toEqual({
      target,
      decoded: original(target),
    });
});

test("cached path decisions preserve precedence, ordered unions and mutable matches snapshots", () => {
  const entries = [
    { id: "root", path: "Name.md", aliases: [] },
    { id: "near", path: "dir/Name.md", aliases: [] },
    { id: "alias", path: "Other.md", aliases: ["Name"] },
  ];
  const first = createPathLookup(entries, { aliasKey });
  const decision = first.pathResolution("Name", "dir/From.md");
  expect(decision).toEqual({
    decoded: "Name",
    id: "near",
    matches: ["root", "near"],
  });
  const matches = first.matches("Name", "dir/From.md");
  matches.reverse();
  matches.push("caller mutation");
  expect(first.matches("Name", "dir/From.md")).toEqual(["root", "near"]);
  expect(first.resolve("Name", "dir/From.md")).toBe("near");
  const aliases = createPathLookup(
    entries.map((entry) => ({ ...entry, aliases: ["Changed"] })),
    { aliasKey, previous: first },
  );
  expect(aliases.pathResolution("Name", "dir/From.md")).toBe(decision);
  const renamed = createPathLookup(
    entries.map((entry) =>
      entry.id === "near" ? { ...entry, path: "dir/Moved.md" } : entry,
    ),
    { aliasKey, previous: aliases },
  );
  expect(renamed.resolve("Name", "dir/From.md")).toBe("root");
  expect(first.pathResolution("Name", "dir/From.md")).toBe(decision);
  for (const target of ["%GG", "https%3A%2F%2Fexample.com", "//external"])
    expect(first.pathResolution(target, "dir/From.md")).toEqual({
      decoded: null,
      id: null,
      matches: [],
    });
});

test("extension candidates retain each distinct entry once in entry order", () => {
  const lookup = createPathLookup([
    { id: "mdx", path: "Name.mdx" },
    { id: "bare", path: "Name" },
    { id: "md", path: "Name.md" },
    { id: "nested", path: "Name.md.md" },
  ]);
  expect(lookup.resolve("Name", "From.md")).toBeNull();
  expect(lookup.matches("Name", "From.md")).toEqual(["mdx", "bare", "md"]);
  expect(lookup.matches("Name.md", "From.md")).toEqual(["md", "nested"]);
});

test("ASCII candidate unions retain normalized names, suffix collisions and relative precedence", () => {
  const entries = [
    { id: "unicode", path: "Kelvin.MDX" },
    { id: "bare", path: "Kelvin" },
    { id: "md", path: "KELVIN.md" },
    { id: "nested", path: "Kelvin.md.MDX" },
    { id: "near", path: "folder/kelvin.md" },
    { id: "empty", path: ".md" },
    { id: "trailing-line", path: "Kelvin.md\n" },
  ];
  const lookup = createPathLookup(entries);
  for (const target of [
    "kelvin",
    "Kelvin",
    "Kelvin.md",
    "",
    "folder/kelvin",
    "Kelvin.md\n",
  ])
    for (const from of ["From.md", "folder/From.md"])
      for (const syntax of ["wiki", "markdown"] as const) {
        expect(lookup.resolve(target, from, syntax)).toBe(
          scanResolvePath(target, from, entries, syntax),
        );
        expect(lookup.matches(target, from, syntax)).toEqual(
          entries
            .filter(
              (entry) =>
                scanResolvePath(target, from, [entry], syntax) === entry.id,
            )
            .map((entry) => entry.id),
        );
      }
  expect(lookup.matches("kelvin", "From.md")).toEqual([
    "unicode",
    "bare",
    "md",
    "near",
  ]);
  expect(lookup.resolve("kelvin", "folder/From.md")).toBe("near");
});

test("unique and missing bare wiki decisions retain casing and fresh matches across folders", () => {
  const entries = [{ id: "unique", path: "remote/Unique.md" }];
  const lookup = createPathLookup(entries);
  for (const target of ["Unique", "UNIQUE", "unique.md", "Missing"]) {
    const decision = lookup.pathResolution(target, "From.md");
    expect(decision.decoded).toBe(target);
    for (const from of ["remote/From.md", "other/From.md", "deep/er/From.md"]) {
      expect(lookup.pathResolution(`${target}#Heading`, from)).toBe(decision);
      expect(lookup.resolve(target, from)).toBe(
        scanResolvePath(target, from, entries),
      );
      const matches = lookup.matches(target, from);
      expect(matches).toEqual([...decision.matches]);
      matches.push("caller mutation");
      expect(lookup.matches(target, "another/From.md")).toEqual([
        ...decision.matches,
      ]);
      expect(decision.matches).not.toContain("caller mutation");
    }
  }
});

test("shared bare wiki decisions preserve scan results at eligibility boundaries", () => {
  const entries = [
    { id: "near", path: "near/Name.mdx" },
    { id: "unique", path: "remote/Unique.md" },
    { id: "unicode", path: "Symbols/Kelvin.MDX" },
    { id: "root", path: "Name.md" },
    { id: "far", path: "remote/Name.md" },
    { id: "suffix", path: "Name.md.md" },
    { id: "folder", path: "near" },
    { id: "escaped", path: "near/[Bracket].md" },
    { id: "percent", path: "remote/100%.md" },
    { id: "sigma", path: "Greek/ΟΔΟΣ.md" },
    { id: "scheme", path: "mailto:Unique.md" },
  ];
  const lookup = createPathLookup(entries);
  for (const target of [
    "Unique",
    "UNIQUE",
    "Unique.md",
    "Missing",
    "Name",
    "NAME.md",
    "kelvin",
    "Kelvin",
    "ΟΔΟΣ",
    "%55nique",
    "%4eame",
    "./Unique",
    "../Unique",
    "near/Name",
    "/Name",
    "[Bracket]",
    "\\[Bracket\\]",
    "100%",
    "100%25",
    ".",
    "..",
    "",
    "#Heading",
    "mailto:Unique",
    "mailto%3AUnique",
    "//host/Unique",
  ])
    for (const from of [
      "From.md",
      "near/From.md",
      "remote/From.md",
      "near/deep/From.md",
    ])
      for (const syntax of ["wiki", "markdown"] as const) {
        expect({
          target,
          from,
          syntax,
          id: lookup.resolve(target, from, syntax),
        }).toEqual({
          target,
          from,
          syntax,
          id: scanResolvePath(target, from, entries, syntax),
        });
        expect(lookup.matches(target, from, syntax)).toEqual(
          entries
            .filter(
              (entry) =>
                scanResolvePath(target, from, [entry], syntax) === entry.id,
            )
            .map((entry) => entry.id),
        );
      }
  expect(lookup.resolve("Name", "near/From.md")).toBe("near");
  expect(lookup.resolve("Name", "elsewhere/From.md")).toBeNull();
  expect(lookup.matches("Name", "near/From.md")).toEqual([
    "near",
    "root",
    "far",
  ]);
});
