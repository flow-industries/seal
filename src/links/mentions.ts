import { noteMarkdown } from "../markdown/syntax.ts";
import {
  excludedRanges,
  type SourceRange,
  tableRanges,
} from "../vault/links.ts";
import { markdownParser } from "../vault/table-syntax.ts";
import type { IndexedNote } from "./index.ts";

/** NOTE's own dialect (wiki links, embeds, math), so mentions follow what the reading view renders. */
export const noteParser = markdownParser.configure(noteMarkdown);

/** Where a mention sits: only `prose` and `cell` mentions can be rewritten into a link. */
export type MentionPlace = "prose" | "cell" | "heading";

const NOT_PROSE = new Set([
  "URL",
  "Autolink",
  "Image",
  "LinkReference",
  "WikiLink",
  "Embed",
  "InlineMath",
  "BlockMath",
]);

interface ProseMap {
  excluded: SourceRange[];
  /** Links, URLs and math; a match touching one is part of it, so these count inclusively. */
  syntax: SourceRange[];
  headings: SourceRange[];
  tables: SourceRange[];
}

function proseMap(source: string): ProseMap {
  const tree = noteParser.parse(source);
  const map: ProseMap = {
    excluded: excludedRanges(source, tree),
    syntax: [],
    headings: [],
    tables: tableRanges(source, tree),
  };
  tree.iterate({
    enter(node) {
      const range = { start: node.from, end: node.to };
      if (
        NOT_PROSE.has(node.name) ||
        (node.name === "Link" &&
          (node.node.getChild("URL") || node.node.getChild("LinkLabel")))
      ) {
        map.syntax.push(range);
        return false;
      }
      if (/^(?:ATX|Setext)Heading\d$/u.test(node.name))
        map.headings.push(range);
    },
  });
  return map;
}

/** Keyed by the link index's own note objects, so an unchanged note is parsed once, not per keystroke. */
const proseMaps = new WeakMap<IndexedNote, ProseMap>();

/**
 * Classifies text matches in one note, parsing it only once something matched (and once per
 * edit of an indexed note). Code, links, URLs, emails, math, tags, `^id`s, paths, file names
 * and link or footnote definitions are not mentions.
 */
export function mentionPlaces(
  source: string,
  cacheKey?: IndexedNote,
): (start: number, end: number) => MentionPlace | null {
  let map = cacheKey ? proseMaps.get(cacheKey) : undefined;
  return (start, end) => {
    let run = start;
    while (run > 0 && /[\p{L}\p{N}_/-]/u.test(source[run - 1] ?? "")) run--;
    // The match may end a longer token: `#launch-plan`, `^launch-plan`, `docs/launch-plan`.
    const lead = source[run - 1] ?? "";
    if (
      /[#^/@\\]/u.test(source[start - 1] ?? "") ||
      lead === "^" ||
      lead === "@" ||
      source.slice(run, start).includes("/") ||
      (lead === "#" && /^\s?$/u.test(source[run - 2] ?? "")) ||
      source[end] === "@" ||
      /^\.[\p{L}\p{N}]/u.test(source.slice(end, end + 2)) ||
      (source[end] === "/" && /\w/u.test(source[end + 1] ?? ""))
    )
      return null;
    if (!map) {
      map = proseMap(source);
      if (cacheKey) proseMaps.set(cacheKey, map);
    }
    const overlaps = (range: SourceRange) =>
      start < range.end && end > range.start;
    if (
      map.excluded.some(overlaps) ||
      map.syntax.some((range) => start <= range.end && end >= range.start)
    )
      return null;
    if (map.headings.some(overlaps)) return "heading";
    return map.tables.some(overlaps) ? "cell" : "prose";
  };
}
