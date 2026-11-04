import { expect, test } from "bun:test";
import { noteParser } from "../links/mentions.ts";
import { noteMarkdown } from "../markdown/syntax.ts";
import { gfmParser, markdownParser } from "./table-syntax.ts";

interface Span {
  name: string;
  from: number;
  to: number;
}
type Parser = Pick<typeof markdownParser, "parse">;

const BOM = "\uFEFF";
/** Lezer's own GFM tables under the note dialect: what `noteParser` must equal on LF input. */
const lezerNote = gfmParser.configure(noteMarkdown);
const pairs: [string, Parser, Parser][] = [
  ["gfm", markdownParser, gfmParser],
  ["note", noteParser, lezerNote],
];

/** Mulberry32: deterministic, so a failure names a reproducible seed. */
function random(seed: number) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let mixed = Math.imul(state ^ (state >>> 15), state | 1);
    mixed ^= mixed + Math.imul(mixed ^ (mixed >>> 7), mixed | 61);
    return ((mixed ^ (mixed >>> 14)) >>> 0) / 4_294_967_296;
  };
}

/**
 * An LF note of tables and everything that meets them: rows with or without
 * outer pipes on each side, delimiter-shaped and pipe-less body rows, invalid
 * delimiter cells, escapes, code spans and links holding pipes, indentation and
 * tabs, setext underlines, HTML blocks, fences, indented code, link references,
 * math blocks, quotes and lists with lazy lines. `crlfSafe` leaves out what
 * Lezer itself reads differently once lines end in `\r`.
 */
function generatedNote(seed: number, crlfSafe = false): string {
  const next = random(seed);
  const count = (limit: number) => Math.floor(next() * limit);
  const chance = (odds: number) => next() < odds;
  const choose = <T>(items: readonly [T, ...T[]]): T =>
    items[count(items.length)] ?? items[0];
  const words: [string, ...string[]] = [
    "alpha",
    "x",
    "Plan",
    "a|b",
    "\\|",
    "`code`",
    "`a|b`",
    "``x|`y``",
    "**bold**",
    "[[Plan|plan]]",
    "[[Plan\\|plan]]",
    "$x|y$",
    "[l](u)",
    "\\",
    "\\\\",
    "~~s~~",
    "-",
    ":",
    "---",
    "&amp;",
  ];
  if (!crlfSafe) words.push("#", ">", "1.", "\t", "<span>", "<b>|</b>");
  const word = () => choose(words);
  const space = () => choose(["", "", " ", " ", "  ", "\t"]);
  const cell = () => Array.from({ length: count(4) }, word).join(" ");
  const pipes = (cells: string[]) =>
    `${chance(0.75) ? "|" : ""}${cells.join("|")}${chance(0.75) ? "|" : ""}`;
  const row = (cells: number) =>
    pipes(Array.from({ length: cells }, () => space() + cell() + space()));
  const delimiter = (cells: number) =>
    pipes(
      Array.from({ length: cells }, () =>
        chance(0.05)
          ? choose(["--x", "", "=", " - - "])
          : `${space()}${chance(0.3) ? ":" : ""}${"-".repeat(1 + count(4))}${chance(0.3) ? ":" : ""}${space()}`,
      ),
    );
  const indent = () => choose(["", "", "", " ", "  ", "   ", "    ", "\t"]);
  const table = (): string[] => {
    const columns = 1 + count(4);
    const lines = [
      indent() + row(columns),
      indent() +
        delimiter(
          chance(0.85) ? columns : Math.max(1, columns + choose([-1, 1, 2])),
        ),
    ];
    for (let body = count(5); body > 0; body--) {
      const kind = choose([
        "row",
        "row",
        "row",
        "delimiter",
        "plain",
        "bare",
        "short",
      ]);
      if (kind === "row")
        lines.push(
          indent() + row(Math.max(1, columns + choose([0, 0, 0, -1, 1]))),
        );
      else if (kind === "delimiter")
        lines.push(
          indent() + delimiter(choose([columns, columns, columns + 1, 1])),
        );
      else if (kind === "plain") lines.push(indent() + cell());
      else if (kind === "bare") lines.push(choose(["|", "||", "| |"]));
      else lines.push(row(1));
    }
    return lines;
  };
  const paragraph = () =>
    Array.from(
      { length: 1 + count(3) },
      () => indent() + (chance(0.3) ? row(1 + count(3)) : cell() || "text"),
    );
  const leaf = (depth: number): string[] => {
    switch (count(16)) {
      case 0:
      case 1:
      case 2:
        return table();
      case 3:
        return [...paragraph(), ...table()];
      case 4:
        return paragraph();
      case 5:
        return [
          choose(["Title | x", "a | b", "| a | b |", "Title", "x|y|z"]),
          choose(["---", "===", "- - -", "|---|", "--- | ---", "---|---"]),
        ];
      case 6:
        return [
          choose(
            crlfSafe
              ? ["# h | x", "## | a | b |"]
              : ["# h | x", "## | a | b |", "#"],
          ),
          ...(chance(0.5) ? table() : []),
        ];
      case 7:
        if (crlfSafe) return table();
        return [
          choose(["<div>", "<table>", "<!--", "<script>", "<custom-x>"]),
          ...table(),
          choose(["</div>", "-->", "</script>", "", "</table>"]),
        ];
      case 8: {
        const fence = choose(["```", "~~~", "````", "```md"]);
        const body = table();
        return chance(0.8)
          ? [fence, ...body, fence.replace(/[a-z]+$/u, "")]
          : [fence, ...body];
      }
      case 9:
        return table().map((line) => `    ${line}`);
      case 10:
        return [choose(["---", "***", "- - -", "___"])];
      case 11:
        return [
          choose(["[a]: /url | x", "[a|b]: /u", "[x]: <y> 'z|w'"]),
          ...(chance(0.5) ? table() : []),
        ];
      case 12:
        return ["$$", ...table(), ...(chance(0.8) ? ["$$"] : [])];
      case 13:
        return depth > 2 ? table() : quote(depth + 1);
      case 14:
        return depth > 2 ? paragraph() : list(depth + 1);
      default:
        return [...table(), ...paragraph()];
    }
  };
  const quote = (depth: number) => {
    const prefix = choose(["> ", ">", "> ", " > "]);
    return blocks(depth, 1 + count(3)).map((line, index) =>
      index > 0 && chance(0.1) ? line : `${prefix}${line}`,
    );
  };
  const list = (depth: number) => {
    const marker = choose(["- ", "* ", "1. ", "2) ", "-\t"]);
    const pad = " ".repeat(marker.replace("\t", "    ").length);
    return blocks(depth, 1 + count(3)).map((line, index) =>
      index === 0 ? `${marker}${line}` : chance(0.1) ? line : `${pad}${line}`,
    );
  };
  const blocks = (depth: number, total: number): string[] => {
    const lines: string[] = [];
    for (let index = 0; index < total; index++) {
      if (index > 0)
        for (let gap = choose([0, 1, 1, 1, 2]); gap > 0; gap--)
          lines.push(chance(0.1) ? " " : "");
      lines.push(...leaf(depth));
    }
    return lines;
  };
  const lines = blocks(0, 1 + count(7)).map((line) =>
    line.replace(/\|[ \t]+$/u, "|"),
  );
  return lines.join("\n") + (chance(0.5) ? "\n" : "");
}

function spans(parser: Parser, source: string): Span[] {
  const found: Span[] = [];
  parser.parse(source).iterate({
    enter(node) {
      found.push({ name: node.name, from: node.from, to: node.to });
    },
  });
  return found;
}
/** Tables and every node inside them. */
function tableSpans(all: Span[]): Span[] {
  let end = -1;
  return all.filter((span) => {
    if (span.name === "Table") end = span.to;
    return span.name === "Table" || span.from < end;
  });
}
function cellsHolding(all: Span[], source: string, character: string) {
  return all.filter(
    (span) =>
      span.name === "TableCell" &&
      source.slice(span.from, span.to).includes(character),
  );
}

test("on 3,000 generated LF notes both lenient parsers build exactly Lezer's trees", () => {
  let tables = 0;
  for (let seed = 1; seed <= 3000; seed++) {
    const source = generatedNote(seed);
    for (const [name, lenient, lezer] of pairs) {
      const actual = spans(lenient, source);
      expect({ seed, name, source, actual }).toEqual({
        seed,
        name,
        source,
        actual: spans(lezer, source),
      });
      if (name === "gfm" && actual.some((span) => span.name === "Table"))
        tables++;
    }
  }
  expect(tables).toBeGreaterThan(900);
});

test("on 2,000 generated notes in CRLF, tables match Lezer's LF tables and no cell holds a CR", () => {
  let tables = 0;
  for (let seed = 1; seed <= 2000; seed++) {
    const lf = generatedNote(seed, true);
    const source = lf.replaceAll("\n", "\r\n");
    const breaksBefore: number[] = [];
    for (let index = 0, breaks = 0; index <= lf.length; index++) {
      breaksBefore.push(breaks);
      if (lf[index] === "\n") breaks++;
    }
    const mapped = (offset: number) => offset + (breaksBefore[offset] ?? 0);
    for (const [name, lenient, lezer] of pairs) {
      const actual = spans(lenient, source);
      expect({ seed, name, cells: cellsHolding(actual, source, "\r") }).toEqual(
        { seed, name, cells: [] },
      );
      const expected = tableSpans(spans(lezer, lf));
      // A row or table ends at its line's CR, as Lezer's CRLF paragraphs do.
      const found = tableSpans(actual).map((span) => ({
        ...span,
        to: source[span.to - 1] === "\r" ? span.to - 1 : span.to,
      }));
      expect({ seed, name, source, found }).toEqual({
        seed,
        name,
        source,
        found: expected.map((span) => ({
          name: span.name,
          from: mapped(span.from),
          to: mapped(span.to),
        })),
      });
      if (name === "gfm")
        tables += expected.filter((span) => span.name === "Table").length;
    }
  }
  expect(tables).toBeGreaterThan(1000);
});

test("on 1,000 generated notes behind a BOM, no cell holds the BOM and a first table stays a table", () => {
  for (let seed = 1; seed <= 1000; seed++) {
    const lf = generatedNote(seed);
    const source = BOM + lf;
    for (const [name, lenient, lezer] of pairs) {
      const actual = spans(lenient, source);
      expect({ seed, name, cells: cellsHolding(actual, source, BOM) }).toEqual({
        seed,
        name,
        cells: [],
      });
      const expected = spans(lezer, lf);
      const first = (all: Span[]) =>
        all.find((span) => span.name !== "Document");
      const expectedFirst = first(expected);
      if (expectedFirst?.name !== "Table" || expectedFirst.from !== 0) continue;
      // The BOM opens the note's first block, so that block and its header start at 0.
      const found = tableSpans(actual)
        .filter((span) => span.to <= expectedFirst.to + 1)
        .map((span) => ({
          ...span,
          from: span.from === 0 ? 1 : span.from,
        }));
      expect({ seed, name, source, found }).toEqual({
        seed,
        name,
        source,
        found: tableSpans(expected)
          .filter((span) => span.to <= expectedFirst.to)
          .map((span) => ({
            name: span.name,
            from: span.from + 1,
            to: span.to + 1,
          })),
      });
    }
  }
});
