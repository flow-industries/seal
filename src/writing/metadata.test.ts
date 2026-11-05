import { expect, spyOn, test } from "bun:test";
import * as yaml from "yaml";
import { gfmParser } from "../vault/table-syntax.ts";
import { maskMarkdownComments } from "./comments.ts";
import {
  noteCssClasses,
  readNoteFrontmatter,
  readNoteMetadata,
  removeNoteProperty,
  updateNoteProperty,
} from "./metadata.ts";

test("metadata handles YAML types and tags without treating code and links as tags", () => {
  const source =
    '---\naliases: ["A, B", Café]\ntags: [work, "#project/one"]\nfinished: false\ncount: 3\ndate: 2026-10-15\nnested:\n  keep: yes\n---\n# Heading\n#inline #日本語 #123\n`#code`\n```md\n#fenced\n```\n[link](https://example.com/#anchor)\n<!-- #comment -->\n\\#escaped';
  const result = readNoteMetadata(source);
  expect(result.error).toBeNull();
  expect(result.aliases).toEqual(["A, B", "Café"]);
  expect(result.tags).toEqual(["work", "project/one", "inline", "日本語"]);
  expect(result.properties.map((property) => property.type)).toEqual([
    "list",
    "tags",
    "checkbox",
    "number",
    "date",
    "unknown",
  ]);
});

test("editing one YAML value preserves comments, nested unknown properties, quote styles and CRLF body bytes", () => {
  const source =
    '---\r\n# context\r\ntitle: "Old" # retain\r\nnested:\r\n  x: [one, two] # custom\r\ntags:\r\n  - one\r\n  - two\r\n---\r\n# Body\r\nuntouched  \r\n';
  const edited = updateNoteProperty(source, "title", "New");
  expect(edited).toBe(source.replace('"Old"', '"New"'));
  const tags = updateNoteProperty(edited, "tags", ["three", "four"]);
  expect(readNoteMetadata(tags).tags).toEqual(["three", "four"]);
  expect(tags).toContain("nested:\r\n  x: [one, two] # custom\r\n");
  expect(tags.endsWith("---\r\n# Body\r\nuntouched  \r\n")).toBe(true);
  expect(removeNoteProperty(edited, "title")).toBe(
    source.replace('title: "Old" # retain\r\n', ""),
  );
});

test("empty, absent, malformed, duplicate and flow-style YAML fail safely or preserve source", () => {
  expect(
    readNoteMetadata(updateNoteProperty("body", "tags", ["work"])).tags,
  ).toEqual(["work"]);
  expect(
    readNoteMetadata(updateNoteProperty("---\nx:\ny: 2\n---\nbody", "x", "yes"))
      .properties[0]?.value,
  ).toBe("yes");
  for (const source of [
    "---\nunclosed",
    "---\nx: [broken\n---\nbody",
    "---\nx: 1\nx: 2\n---",
    "---\n- array\n---",
  ]) {
    expect(readNoteMetadata(source).error).not.toBeNull();
    expect(() => updateNoteProperty(source, "x", 3)).toThrow();
  }
  expect(() => updateNoteProperty("---\n{x: 1}\n---\n", "x", 2)).toThrow();
  expect(removeNoteProperty("body", "absent")).toBe("body");
});

test("inline comments and HTML attributes cannot introduce tags", () => {
  expect(
    readNoteMetadata(
      'Hello <!-- #hidden --> <span title="#attribute">word</span> #visible',
    ).tags,
  ).toEqual(["visible"]);
});

test("multiline properties stay valid YAML and removing referenced anchors fails without returning corrupt source", () => {
  const source = "---\ndescription: old # retained\nother: true\n---\nBody";
  const updated = updateNoteProperty(source, "description", "First\nSecond");
  expect(readNoteMetadata(updated).properties[0]?.value).toBe("First\nSecond");
  expect(updated).toContain("# retained\nother: true\n---\nBody");
  expect(() =>
    removeNoteProperty("---\na: &x hello\nb: *x\n---\nBody", "a"),
  ).toThrow();
  expect(
    readNoteMetadata("---\ndate: 2026-99-99\n---\n").properties[0]?.type,
  ).toBe("text");
});

test("frontmatter-only reads preserve properties and YAML tags without parsing the Markdown body", () => {
  const source =
    '---\naliases: [Alias]\ntags: [work, work, "#project/one"]\ncssclasses: [wide, readable]\nfinished: true\n---\n#body #日本語 `#code`\n%% #hidden %%\n[link](target#anchor)';
  const parse = spyOn(gfmParser, "parse");
  try {
    const frontmatter = readNoteFrontmatter(source);
    expect(noteCssClasses(source)).toEqual(["wide", "readable"]);
    expect(parse).not.toHaveBeenCalled();
    expect(frontmatter.aliases).toEqual(["Alias"]);
    expect(frontmatter.tags).toEqual(["work", "project/one"]);
    const full = readNoteMetadata(source);
    expect(full.properties).toEqual(frontmatter.properties);
    expect(full.frontmatter).toEqual(frontmatter.frontmatter);
    expect(full.aliases).toEqual(frontmatter.aliases);
    expect(full.error).toBe(frontmatter.error);
    expect(full.tags).toEqual(["work", "project/one", "body", "日本語"]);
  } finally {
    parse.mockRestore();
  }
});

test("frontmatter failures still allow full metadata reads to scan body tags", () => {
  const source = "---\naliases: [unfinished\n---\n#visible";
  const frontmatter = readNoteFrontmatter(source);
  const full = readNoteMetadata(source);
  expect(frontmatter.error).not.toBeNull();
  expect(full.error).toBe(frontmatter.error);
  expect(frontmatter.tags).toEqual([]);
  expect(full.tags).toEqual(["visible"]);
});

test("comment-free sources retain exact bytes without a Markdown parse", () => {
  const sources = [
    "",
    "\uFEFF---\r\ntitle: '100% ready'\r\n---\r\n# 日本語 😀\r\n",
    "`single %` and \\% escapes\n```md\n% literal\n```\n",
    "<!-- HTML --> #visible\n    # code\n",
  ];
  const parse = spyOn(gfmParser, "parse");
  try {
    for (const source of sources)
      expect(maskMarkdownComments(source)).toBe(source);
    expect(parse).not.toHaveBeenCalled();
    const source = "`%%code%%` \\%%escaped\n%%hidden%% #visible";
    const masked = maskMarkdownComments(source);
    expect(parse).toHaveBeenCalledTimes(1);
    expect(masked).toBe("`%%code%%` \\%%escaped\n           #visible");
    expect(masked.length).toBe(source.length);
  } finally {
    parse.mockRestore();
  }
});

test("repeated temporal property reads preserve calendar, local and offset validation", () => {
  const cases = [
    ["2024-02-29", "date"],
    ["2026-02-29", "text"],
    ["2026-13-01", "text"],
    ["2026-10-24T09:07", "datetime"],
    ["2026-10-24T09:07:30Z", "datetime"],
    ["2026-10-24T09:07:30+05:30", "datetime"],
    ["2026-10-24T09:07:30-03:00", "datetime"],
    ["2026-10-24T25:07", "text"],
    ["2026-02-29T09:07:30Z", "text"],
    ["ordinary text", "text"],
  ] as const;
  for (let pass = 0; pass < 3; pass++) {
    for (const [value, type] of cases) {
      const result = readNoteFrontmatter(`---\nwhen: "${value}"\n---\n`);
      expect(result.error).toBeNull();
      expect(result.properties).toEqual([{ key: "when", value, type }]);
    }
  }
});

test("metadata without hashtag candidates skips the exclusion tree while actual tags keep their exclusions", () => {
  const parse = spyOn(gfmParser, "parse");
  try {
    expect(
      readNoteMetadata("---\ntags: [front]\n---\n# Heading\nplain text").tags,
    ).toEqual(["front"]);
    expect(readNoteMetadata("\uFEFF# Heading\r\n100% ready\r\n").tags).toEqual(
      [],
    );
    expect(parse).not.toHaveBeenCalled();
    expect(
      readNoteMetadata(
        '#visible #visible #日本語 #parent/child `#code` [label](note#fragment) <!-- #hidden --> <span title="#attribute">text</span> \\#escaped #123',
      ).tags,
    ).toEqual(["visible", "日本語", "parent/child"]);
    expect(parse).toHaveBeenCalledTimes(1);
  } finally {
    parse.mockRestore();
  }
});

test("read-only frontmatter omits CST retention while editing preserves source layout", () => {
  const source =
    '---\r\n# retained\r\nlabel: &label "One" # inline\r\ncopy: *label\r\nfolded: >-\r\n  first\r\n  second\r\n---\r\nBody  \r\n';
  const parse = spyOn(yaml, "parseDocument");
  try {
    const metadata = readNoteFrontmatter(source);
    expect(metadata.error).toBeNull();
    expect(metadata.frontmatter).toEqual({
      start: 0,
      contentStart: source.indexOf("# retained"),
      contentEnd: source.lastIndexOf("---"),
      end: source.indexOf("Body"),
    });
    expect(metadata.properties).toEqual([
      { key: "label", value: "One", type: "text" },
      { key: "copy", value: "One", type: "text" },
      { key: "folded", value: "first second", type: "text" },
    ]);
    expect(parse.mock.calls[0]?.[1]).toEqual({ keepSourceTokens: false });
    const edited = updateNoteProperty(source, "folded", "replacement");
    expect(edited).toContain(
      '# retained\r\nlabel: &label "One" # inline\r\ncopy: *label\r\n',
    );
    expect(edited.endsWith("---\r\nBody  \r\n")).toBe(true);
    expect(
      parse.mock.calls
        .slice(1)
        .every((call) => call[1]?.keepSourceTokens === true),
    ).toBe(true);
    expect(
      readNoteFrontmatter(edited).properties.find(
        (property) => property.key === "folded",
      )?.value,
    ).toBe("replacement");
  } finally {
    parse.mockRestore();
  }
});

test("read-only frontmatter retains malformed YAML and alias expansion limits", () => {
  const expansion =
    "---\na: &a [one, two]\nb: &b [*a, *a]\nc: &c [*b, *b]\nd: &d [*c, *c]\ne: &e [*d, *d]\nf: &f [*e, *e]\ng: [*f, *f]\n---\n#visible";
  const document = yaml.parseDocument(
    expansion.slice(4, expansion.lastIndexOf("---")),
    { keepSourceTokens: true },
  );
  expect(() => document.toJS({ maxAliasCount: 50 })).toThrow();
  const limited = readNoteFrontmatter(expansion);
  expect(limited.error).not.toBeNull();
  expect(limited.properties).toEqual([]);
  expect(readNoteMetadata(expansion).tags).toEqual(["visible"]);
  for (const source of [
    "---\nkey: [broken\n---\nbody",
    "---\nkey: one\nkey: two\n---\nbody",
  ]) {
    expect(readNoteFrontmatter(source).error).not.toBeNull();
    expect(() => updateNoteProperty(source, "key", "fixed")).toThrow();
  }
});

test("inline tags start only after a character that can't continue a word or a path", () => {
  const tagsOf = (body: string) => readNoteMetadata(body).tags;
  expect(tagsOf("#start and #end")).toEqual(["start", "end"]);
  expect(tagsOf("word#no 1#no _#no /#no \\#no")).toEqual([]);
  expect(tagsOf("é#no 中#no 𝐀#no 𝟙#no")).toEqual([]);
  expect(tagsOf("-#dash (#paren) .#dot 😀#emoji\t#tab")).toEqual([
    "dash",
    "paren",
    "dot",
    "emoji",
    "tab",
  ]);
  expect(tagsOf("#a-#b #c/d#e #f/g/h #1 #2x")).toEqual([
    "a-",
    "b",
    "c/d",
    "f/g/h",
    "2x",
  ]);
  expect(tagsOf("line\n#next\r\n#crlf")).toEqual(["next", "crlf"]);
});

test("no source module uses a regex lookbehind, which older WebKit can't parse", async () => {
  const glob = new Bun.Glob("**/*.ts");
  const root = new URL("..", import.meta.url).pathname;
  const found: string[] = [];
  for await (const path of glob.scan(root))
    if (
      !path.endsWith(".test.ts") &&
      /\(\?<[=!]/u.test(await Bun.file(root + path).text())
    )
      found.push(path);
  expect(found).toEqual([]);
});
