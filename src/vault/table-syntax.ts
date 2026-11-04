import {
  Autolink,
  type BlockContext,
  type BlockParser,
  parser as commonmark,
  type Element,
  Emoji,
  GFM,
  type LeafBlock,
  type LeafBlockParser,
  type Line,
  type MarkdownExtension,
  Strikethrough,
  Subscript,
  Superscript,
  Table,
  TaskList,
} from "@lezer/markdown";

const TAB = 9;
const CR = 13;
const BOM = 0xfeff;
const SPACE = 32;
const DASH = 45;
const COLON = 58;
const BACKSLASH = 92;
const PIPE = 124;

const delimiterLine =
  /^[>\s]*\|?(?:\s*:?-+:?\s*\|)+(?:\s*:?-+:?\s*)?[ \t\r]*$/u;

function parseRow(
  cx: BlockContext,
  line: string,
  startI = 0,
  elements?: Element[],
  offset = 0,
): number {
  let count = 0;
  let first = true;
  let cellStart = -1;
  let cellEnd = -1;
  let escaped = false;
  const parseCell = () =>
    elements?.push(
      cx.elt(
        "TableCell",
        offset + cellStart,
        offset + cellEnd,
        cx.parser.parseInline(
          line.slice(cellStart, cellEnd),
          offset + cellStart,
        ),
      ),
    );
  for (let i = startI; i < line.length; i++) {
    const next = line.charCodeAt(i);
    if (next === PIPE && !escaped) {
      if (!first || cellStart > -1) count++;
      first = false;
      if (cellStart > -1) parseCell();
      elements?.push(cx.elt("TableDelimiter", i + offset, i + offset + 1));
      cellStart = cellEnd = -1;
    } else if (
      (escaped && next !== CR) ||
      (next !== SPACE && next !== TAB && next !== CR && next !== BOM)
    ) {
      if (cellStart < 0) cellStart = i;
      cellEnd = i + 1;
    }
    escaped = !escaped && next === BACKSLASH;
  }
  if (cellStart > -1) {
    count++;
    parseCell();
  }
  return count;
}

function hasPipe(text: string, start: number): boolean {
  for (let i = start; i < text.length; i++) {
    const next = text.charCodeAt(i);
    if (next === PIPE) return true;
    if (next === BACKSLASH) i++;
  }
  return false;
}

class TableParser implements LeafBlockParser {
  /** Null before the second line, false when it isn't a table, else the rows so far. */
  private rows: Element[] | false | null = null;
  nextLine(cx: BlockContext, line: Line, leaf: LeafBlock) {
    if (this.rows === null) {
      this.rows = false;
      const text = line.text.slice(line.pos);
      if (
        (line.next === DASH || line.next === COLON || line.next === PIPE) &&
        delimiterLine.test(text)
      ) {
        const header: Element[] = [];
        if (
          parseRow(cx, leaf.content, 0, header, leaf.start) ===
          parseRow(cx, text, 0)
        )
          this.rows = [
            cx.elt(
              "TableHeader",
              leaf.start,
              leaf.start + leaf.content.length,
              header,
            ),
            cx.elt(
              "TableDelimiter",
              cx.lineStart + line.pos,
              cx.lineStart + line.text.length,
            ),
          ];
      }
    } else if (this.rows) {
      const cells: Element[] = [];
      parseRow(cx, line.text, line.pos, cells, cx.lineStart);
      this.rows.push(
        cx.elt(
          "TableRow",
          cx.lineStart + line.pos,
          cx.lineStart + line.text.length,
          cells,
        ),
      );
    }
    return false;
  }
  finish(cx: BlockContext, leaf: LeafBlock) {
    if (!this.rows) return false;
    cx.addLeafElement(
      leaf,
      cx.elt("Table", leaf.start, leaf.start + leaf.content.length, this.rows),
    );
    return true;
  }
}

/**
 * Lezer's GFM table block parser, also accepting what GitHub and the reading
 * view accept: rows ending in `\r` (CRLF notes), spaces or tabs after the
 * closing pipe and a byte order mark before the first row.
 */
export const tableBlock: BlockParser = {
  name: "Table",
  leaf: (_, leaf) => (hasPipe(leaf.content, 0) ? new TableParser() : null),
  endLeaf(cx, line, leaf) {
    if (
      leaf.parsers.some((parser) => parser instanceof TableParser) ||
      !hasPipe(line.text, line.basePos)
    )
      return false;
    const next = cx.peekLine();
    return (
      delimiterLine.test(next) &&
      parseRow(cx, line.text, line.basePos) === parseRow(cx, next, line.basePos)
    );
  },
  before: "SetextHeading",
};

/**
 * GFM, Subscript, Superscript and Emoji, as CodeMirror's `markdownLanguage`
 * bundles them, with `tableBlock` as the table parser. It extends CommonMark
 * so Lezer's own table parser is never registered: once configured, its
 * `endLeaf` stays even when the parser is replaced, and it would split this
 * parser's tables and miscount CRLF rows. An editor adds its own node props,
 * such as folding, as a further extension; props never change a parse.
 */
export const noteGfm: MarkdownExtension = [
  {
    defineNodes: Table.defineNodes,
    parseBlock: [tableBlock],
  },
  TaskList,
  Strikethrough,
  Autolink,
  Subscript,
  Superscript,
  Emoji,
];

/** `noteGfm` for code that reads notes' structure without NOTE's own syntax. */
export const markdownParser = commonmark.configure(noteGfm);

/**
 * Lezer's own GFM with Subscript, Superscript and Emoji: exactly the parser
 * CodeMirror's `markdownLanguage` wraps, without the editor's node props.
 * Tags and comments are found with it, and its tables read CRLF rows
 * differently from `noteGfm`, so swapping it would change which tags a note has.
 */
export const gfmParser = commonmark.configure([
  GFM,
  Subscript,
  Superscript,
  Emoji,
]);
