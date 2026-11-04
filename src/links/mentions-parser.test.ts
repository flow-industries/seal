import { expect, test } from "bun:test";
import { parser as commonmark } from "@lezer/markdown";
import { noteMarkdown } from "../markdown/syntax.ts";
import { noteGfm } from "../vault/table-syntax.ts";
import { mentionPlaces, noteParser } from "./mentions.ts";

/** An editor's configuration: CommonMark with `noteGfm` and the note dialect added in one step. */
const editorParser = commonmark.configure([noteGfm, noteMarkdown]);

function spans(parser: Pick<typeof noteParser, "parse">, source: string) {
  const result: { name: string; from: number; to: number }[] = [];
  parser.parse(source).iterate({
    enter(node) {
      result.push({ name: node.name, from: node.from, to: node.to });
    },
  });
  return result;
}

test("mention parsing keeps the editor's outer structure without mounting HTML languages", () => {
  const lf = [
    "# Heading",
    "",
    "Plain mention, [[Plan]], ![[Picture.png]], ==highlight== and $x$.",
    "",
    "| Name | Link |",
    "| --- | --- |",
    "| Cell mention | [[Plan\\|label]] |",
    "",
    "> Quoted mention",
    "",
    "- List mention",
    "",
    "$$",
    "math mention",
    "$$",
    "",
    "<div>",
    "<span>Hidden mention</span>",
    "</div>",
    "",
    "<script>",
    "const broken = (",
    "</script>",
    "",
    "```html",
    "<span>Code mention</span>",
    "```",
  ].join("\n");

  for (const source of [lf, lf.replaceAll("\n", "\r\n"), `﻿${lf}`]) {
    expect(spans(noteParser, source)).toEqual(spans(editorParser, source));
    const htmlAt = source.indexOf("span");
    expect(noteParser.parse(source).resolveInner(htmlAt, 1).name).toBe(
      "HTMLBlock",
    );

    const place = mentionPlaces(source);
    for (const text of ["Plain mention", "Quoted mention", "List mention"]) {
      const at = source.indexOf(text);
      expect(place(at, at + text.length)).toBe("prose");
    }
    const cellAt = source.indexOf("Cell mention");
    expect(place(cellAt, cellAt + "Cell mention".length)).toBe("cell");
    for (const text of ["Hidden mention", "Code mention", "math mention"]) {
      const at = source.indexOf(text);
      expect(place(at, at + text.length)).toBeNull();
    }
  }
});
