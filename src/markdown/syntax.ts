import type { MarkdownConfig, MarkdownExtension } from "@lezer/markdown";
import { noteGfm } from "../vault/table-syntax.ts";

const DOLLAR = 36;
const BANG = 33;
const BRACKET = 91;
const CLOSE_BRACKET = 93;
const BACKSLASH = 92;
const NEWLINE = 10;

const highlightDelimiter = { resolve: "Highlight", mark: "HighlightMark" };

/**
 * Note syntax beyond CommonMark and GFM, parsed the way the reading view
 * (remark with math) reads it, so live preview and reading never disagree:
 * `==highlight==`, `[[wiki links]]`, `![[embeds]]`, `$inline$` and `$$` math
 * blocks.
 */
export const noteMarkdown: MarkdownConfig = {
  defineNodes: [
    "Highlight",
    "HighlightMark",
    "WikiLink",
    "WikiMark",
    "Embed",
    "EmbedMark",
    "InlineMath",
    "InlineMathMark",
    { name: "BlockMath", block: true },
    "BlockMathMark",
  ],
  parseBlock: [
    {
      name: "BlockMath",
      before: "FencedCode",
      // Like a code fence, `$$` ends a paragraph above it, the way remark-math reads it.
      endLeaf: (cx, line) =>
        cx.parentType().name === "Document" && mathFence(line),
      parse(cx, line) {
        if (cx.parentType().name !== "Document" || !mathFence(line))
          return false;
        const from = cx.lineStart + line.pos;
        const marks = [cx.elt("BlockMathMark", from, from + 2)];
        while (cx.nextLine())
          if (/^ {0,3}\$\$\s*$/u.test(line.text)) {
            const at = cx.lineStart + line.pos;
            marks.push(cx.elt("BlockMathMark", at, at + 2));
            cx.nextLine();
            break;
          }
        cx.addElement(cx.elt("BlockMath", from, cx.prevLineEnd(), marks));
        return true;
      },
    },
  ],
  parseInline: [
    {
      name: "Highlight",
      parse(cx, next, pos) {
        if (next !== 61 || cx.char(pos + 1) !== 61) return -1;
        return cx.addDelimiter(
          highlightDelimiter,
          pos,
          pos + 2,
          cx.char(pos + 2) !== 32,
          cx.char(pos - 1) !== 32,
        );
      },
    },
    {
      name: "Embed",
      before: "Image",
      parse(cx, next, pos) {
        if (
          next !== BANG ||
          cx.char(pos + 1) !== BRACKET ||
          cx.char(pos + 2) !== BRACKET
        )
          return -1;
        const end = wikiEnd(cx, pos + 1);
        if (end < 0) return -1;
        return cx.addElement(
          cx.elt("Embed", pos, end, [
            cx.elt("EmbedMark", pos, pos + 1),
            cx.elt("WikiLink", pos + 1, end, [
              cx.elt("WikiMark", pos + 1, pos + 3),
              cx.elt("WikiMark", end - 2, end),
            ]),
          ]),
        );
      },
    },
    {
      name: "WikiLink",
      before: "Link",
      parse(cx, next, pos) {
        if (next !== BRACKET || cx.char(pos + 1) !== BRACKET) return -1;
        const end = wikiEnd(cx, pos);
        if (end < 0) return -1;
        return cx.addElement(
          cx.elt("WikiLink", pos, end, [
            cx.elt("WikiMark", pos, pos + 2),
            cx.elt("WikiMark", end - 2, end),
          ]),
        );
      },
    },
    {
      name: "InlineMath",
      before: "Escape",
      parse(cx, next, pos) {
        if (next !== DOLLAR || cx.char(pos - 1) === DOLLAR) return -1;
        let run = 1;
        while (cx.char(pos + run) === DOLLAR) run++;
        if (run > 2) return -1;
        for (let end = pos + run; end < cx.end; end++) {
          const char = cx.char(end);
          if (char === NEWLINE) return -1;
          if (char === BACKSLASH) {
            end++;
            continue;
          }
          if (char !== DOLLAR) continue;
          let close = 0;
          while (cx.char(end + close) === DOLLAR) close++;
          if (close !== run) {
            end += close - 1;
            continue;
          }
          if (end === pos + run) return -1;
          return cx.addElement(
            cx.elt("InlineMath", pos, end + run, [
              cx.elt("InlineMathMark", pos, pos + run),
              cx.elt("InlineMathMark", end, end + run),
            ]),
          );
        }
        return -1;
      },
    },
  ],
};

/** Whether the line opens a `$$` math block: `$$` with nothing but an optional label after it. */
function mathFence(line: { next: number; pos: number; text: string }) {
  return (
    line.next === DOLLAR &&
    line.text.charCodeAt(line.pos + 1) === DOLLAR &&
    !line.text.slice(line.pos + 2).includes("$")
  );
}

/** The end of the `[[…]]` that opens at `pos`, or -1. */
function wikiEnd(cx: { char(pos: number): number; end: number }, pos: number) {
  for (let end = pos + 2; end < cx.end - 1; end++) {
    if (cx.char(end) === NEWLINE) return -1;
    if (cx.char(end) === BACKSLASH) {
      end++;
      continue;
    }
    if (cx.char(end) === CLOSE_BRACKET && cx.char(end + 1) === CLOSE_BRACKET)
      return end + 2;
  }
  return -1;
}

/** NOTE's Markdown on top of lang-markdown's CommonMark language: `noteGfm`, then `noteMarkdown`. */
export const noteExtensions: MarkdownExtension = [noteGfm, noteMarkdown];

const MEDIA = /!\[\[[^\]\n]+\]\]|!\[[^\]\n]*\]\([^)\n]*\)/gu;

/** Whether the text holds embeds or images and nothing else but whitespace. */
export function mediaOnly(text: string) {
  const rest = text.replace(MEDIA, "");
  return rest !== text && !rest.trim();
}

/** Lines `from..to` (1-based, inclusive) of a frontmatter block at the top of the note, or null. */
export function frontmatterLines(doc: {
  lines: number;
  line(number: number): { text: string };
}): { first: number; last: number } | null {
  if (!/^﻿?---\r?$/u.test(doc.line(1).text)) return null;
  for (let number = 2; number <= Math.min(doc.lines, 500); number++)
    if (/^(?:---|\.\.\.)\r?$/u.test(doc.line(number).text))
      return { first: 1, last: number };
  return null;
}
