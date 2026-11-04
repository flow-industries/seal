import { markdownLanguage } from "@codemirror/lang-markdown";

/** Replaces Obsidian comments with spaces while retaining UTF-16 offsets and line breaks. */
export function maskMarkdownComments(source: string): string {
  if (!source.includes("%%")) return source;
  const excluded: { from: number; to: number }[] = [];
  const frontmatter =
    /^(?:\uFEFF)?---[^\S\r\n]*\r?\n[\s\S]*?^(?:---|\.\.\.)[^\S\r\n]*(?:\r?\n|$)/mu.exec(
      source,
    );
  if (frontmatter?.index === 0)
    excluded.push({ from: 0, to: frontmatter[0].length });
  markdownLanguage.parser.parse(source).iterate({
    enter(node) {
      if (["FencedCode", "CodeBlock", "InlineCode"].includes(node.name)) {
        excluded.push({ from: node.from, to: node.to });
        return false;
      }
    },
  });
  const escaped = (at: number) => {
    let count = 0;
    while (at > 0 && source[--at] === "\\") count++;
    return count % 2 === 1;
  };
  const ranges: { from: number; to: number }[] = [];
  for (let index = 0; index < source.length - 1; index++) {
    if (
      source.slice(index, index + 2) !== "%%" ||
      escaped(index) ||
      excluded.some((range) => index >= range.from && index < range.to)
    )
      continue;
    let end = index + 2;
    while (
      end < source.length - 1 &&
      (source.slice(end, end + 2) !== "%%" || escaped(end))
    )
      end++;
    const to = end < source.length - 1 ? end + 2 : source.length;
    ranges.push({ from: index, to });
    index = to - 1;
  }
  let result = source;
  for (const range of ranges.reverse())
    result =
      result.slice(0, range.from) +
      result.slice(range.from, range.to).replace(/[^\r\n]/g, " ") +
      result.slice(range.to);
  return result;
}
