import { expect, spyOn, test } from "bun:test";
import { parser as commonmark } from "@lezer/markdown";
import { noteParser } from "../links/mentions.ts";
import { noteMarkdown } from "../markdown/syntax.ts";
import { linkRanges } from "./links.ts";
import { gfmParser, markdownParser, noteGfm } from "./table-syntax.ts";

const table = "| A | B |\n| --- | --- |\n| one | two |\n";
const crlf = (source: string) => source.replaceAll("\n", "\r\n");
/** An editor's configuration: CommonMark with `noteGfm` and the note dialect added in one step. */
const editorParser = commonmark.configure([noteGfm, noteMarkdown]);
function rows(
  source: string,
  parser: Pick<typeof markdownParser, "parse"> = markdownParser,
) {
  const found: { name: string; cells: number }[] = [];
  parser.parse(source).iterate({
    enter(node) {
      if (["Table", "TableHeader", "TableRow"].includes(node.name))
        found.push({
          name: node.name,
          cells: node.node.getChildren("TableCell").length,
        });
    },
  });
  return found;
}
const parsed = [
  { name: "Table", cells: 0 },
  { name: "TableHeader", cells: 2 },
  { name: "TableRow", cells: 2 },
];

test("CRLF rows, whitespace after the closing pipe and a leading BOM still make a table, with no cell for the CR or BOM", () => {
  for (const source of [
    crlf(table),
    `﻿# Title\r\n\r\n${crlf(table)}`,
    table.replaceAll("|\n", "|  \n"),
    crlf(table.replaceAll("|\n", "| \t\n")),
    crlf(`Intro line\n${table}`),
    `﻿${table}`,
    `﻿${crlf(table)}`,
    table.replace("| --- | --- |", "| --- | --- |   "),
  ]) {
    expect({ source, rows: rows(source) }).toEqual({ source, rows: parsed });
    expect({ source, rows: rows(source, noteParser) }).toEqual({
      source,
      rows: parsed,
    });
  }
});

test("LF tables and non-tables parse exactly as Lezer's own GFM parser reads them", () => {
  for (const source of [
    table,
    `Intro line\n${table}`,
    "|a|b|\n|-|-|\n|1|2|",
    "a | b\n--- | ---\nc | d",
    "| A | B |\n| :-- | --: |\n| 1 \\| 2 | `x|y` |",
    "> | quoted | table |\n> | --- | --- |\n> | 1 | 2 |",
    "| A | B |\n| --- |\n| 1 | 2 |",
    "| not | a table |\nplain text",
    "- | in a list |\n  | --- |",
    "| a | b |\n| --- | --- |\n| 1 | 2 |\n| --- | --- |\n| 3 | 4 |",
    "| a | b |\n| --- | --- |\n| 1 | 2 |\n\n| c | d |\n| - | - |",
  ])
    expect({ source, tree: markdownParser.parse(source).toString() }).toEqual({
      source,
      tree: gfmParser.parse(source).toString(),
    });
});

test("an editor's configuration reads a CRLF table under a paragraph line and a BOM-first table as tables", () => {
  for (const source of [crlf(`# Title\n\nIntro line\n${table}`), `﻿${table}`]) {
    expect({ source, rows: rows(source, editorParser) }).toEqual({
      source,
      rows: parsed,
    });
    expect({ source, tree: editorParser.parse(source).toString() }).toEqual({
      source,
      tree: noteParser.parse(source).toString(),
    });
  }
});

test("a CRLF or BOM block the lenient parser rejects stays prose, as Reading shows it", () => {
  for (const source of [
    "| Item | Link |\r\n| --- | --- | ---\r\n| one | [[Plan\\|plan]] |\r\n",
    "﻿| Item | Link |\n| --- | --- | --- |\n| one | [[Plan\\|plan]] |\n",
  ]) {
    expect({ source, rows: rows(source) }).toEqual({ source, rows: [] });
    expect(linkRanges(source).map((link) => link.target)).toEqual([
      "Plan\\|plan",
    ]);
  }
});

test("a backslash at a CRLF row's end escapes nothing, so the CR never joins the cell", () => {
  const source = "| A | B\\\r\n| --- | --- |\r\n| 1 | 2 |\r\n";
  const cells: string[] = [];
  markdownParser.parse(source).iterate({
    enter(node) {
      if (node.name === "TableCell")
        cells.push(source.slice(node.from, node.to));
    },
  });
  expect(cells).toEqual(["A", "B\\", "1", "2"]);
});

test("each table cell is parsed once, and the index parser runs no HTML parser", () => {
  const tables = Array.from(
    { length: 50 },
    (_, index) =>
      `| a | b | c |\n| --- | --- | --- |\n| x | **y** | ${index} |\n`,
  ).join("\n");
  const parseInline = spyOn(markdownParser, "parseInline");
  try {
    let cells = 0;
    markdownParser.parse(tables).iterate({
      enter(node) {
        if (node.name === "TableCell") cells++;
      },
    });
    expect(cells).toBe(300);
    expect(parseInline).toHaveBeenCalledTimes(cells);
  } finally {
    parseInline.mockRestore();
  }
  const html = "<div>\n<span>text</span>\n</div>\n";
  // `resolveInner` enters mounted trees, where an HTML sub-parse would put its tags.
  const innermost = (parser: Pick<typeof markdownParser, "parse">) =>
    parser.parse(html).resolveInner(html.indexOf("span"), 1).name;
  expect(innermost(markdownParser)).toBe("HTMLBlock");
  expect(innermost(noteParser)).toBe("HTMLBlock");
});
