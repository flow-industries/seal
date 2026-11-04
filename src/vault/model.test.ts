import { describe, expect, test } from "bun:test";
import { linkRanges, rewriteLinkRanges } from "./links.ts";
import { exportFiles, importFiles, paths } from "./model.ts";

describe("portable vault", () => {
  test("preserves exact source bytes, unknown syntax, assets and empty folders", () => {
    const source = new TextEncoder().encode(
      "\ufeff---\r\nunknown: [one,two]\r\n---\r\n<Component weird={1}/>\r\n",
    );
    const input = [
      { path: "folder/a.mdx", bytes: source },
      { path: "empty", bytes: new Uint8Array(), directory: true },
      { path: "folder/image.bin", bytes: new Uint8Array([0, 255, 1]) },
    ];
    const output = exportFiles(importFiles(input));
    for (const file of input)
      expect(output.find((item) => item.path === file.path)?.bytes).toEqual(
        file.bytes,
      );
  });
  test("rejects traversal, drive paths and normalization collisions", () => {
    for (const path of ["../x.md", "/x.md", "C:/x.md", "x\\a.md", "x/../a.md"])
      expect(() => importFiles([{ path, bytes: new Uint8Array() }])).toThrow();
    expect(() =>
      importFiles([
        { path: "A.md", bytes: new Uint8Array() },
        { path: "a.md", bytes: new Uint8Array() },
      ]),
    ).toThrow("collision");
  });
  test("rejects cycles and missing parents", () => {
    const [item] = importFiles([
      { path: "folder", directory: true, bytes: new Uint8Array() },
    ]);
    expect(() => paths([{ ...item!, parent: item!.id }])).toThrow("cycle");
  });
  test("range edits preserve unrelated source", () => {
    const source =
      '---\r\nodd: thing\r\n---\r\n[[old|display]] + [x](old.md "title")';
    expect(
      rewriteLinkRanges(
        source,
        linkRanges(source).map((range) => ({ ...range, replacement: "new" })),
      ),
    ).toBe('---\r\nodd: thing\r\n---\r\n[[new|display]] + [x](new "title")');
  });
});
test("code examples comments and escaped links are not rename candidates", () => {
  const source =
    "`[[old]]`\n```md\n[[old]]\n```\n<!-- [[old]] -->\n\\[[old]]\n[[real]]";
  expect(linkRanges(source).map((range) => range.target)).toEqual(["real"]);
});
test("single deeply nested import cannot bypass item and path bounds", () => {
  expect(() =>
    importFiles([{ path: `${"x/".repeat(65)}a.md`, bytes: new Uint8Array() }]),
  ).toThrow("depth");
  expect(() =>
    importFiles([{ path: `${"x".repeat(256)}.md`, bytes: new Uint8Array() }]),
  ).toThrow();
});
test("portable paths reject NTFS ADS and Windows invalid characters", () => {
  for (const path of [
    "safe.txt:payload",
    "what?.md",
    "star*.md",
    "bad|name.md",
    'quote".md',
    `del${String.fromCharCode(127)}.md`,
  ])
    expect(() => importFiles([{ path, bytes: new Uint8Array() }])).toThrow();
});
