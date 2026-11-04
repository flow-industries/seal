import { canonicalLinkKey, paths, type VaultItem } from "./model.ts";
import { markdownParser } from "./table-syntax.ts";

export interface LinkRange {
  start: number;
  end: number;
  target: string;
  syntax?: "wiki" | "markdown";
  embed?: boolean;
}
export interface SourceRange {
  start: number;
  end: number;
}

/** Source offsets excluded from prose indexing and link edits. */
export function excludedRanges(
  source: string,
  tree = markdownParser.parse(source),
): SourceRange[] {
  const ranges: SourceRange[] = [];
  const frontmatter =
    /^(?:\ufeff)?---\r?\n[\s\S]*?\r?\n(?:---|\.\.\.)[ \t]*(?:\r?\n|$)/u.exec(
      source,
    );
  if (frontmatter) ranges.push({ start: 0, end: frontmatter[0].length });
  tree.iterate({
    enter(node) {
      if (
        [
          "FencedCode",
          "CodeBlock",
          "InlineCode",
          "HTMLBlock",
          "HTMLTag",
          "Comment",
          "CommentBlock",
        ].includes(node.name)
      ) {
        ranges.push({ start: node.from, end: node.to });
        return false;
      }
    },
  });
  for (const match of source.matchAll(
    /<!--[\s\S]*?(?:-->|$)|%%[\s\S]*?(?:%%|$)/gu,
  )) {
    if (
      !ranges.some(
        (range) => match.index >= range.start && match.index < range.end,
      )
    )
      ranges.push({ start: match.index, end: match.index + match[0].length });
  }
  return ranges;
}

function escaped(source: string, offset: number): boolean {
  let slashes = 0;
  while (offset > 0 && source[--offset] === "\\") slashes++;
  return slashes % 2 === 1;
}

/**
 * Length of the target in a wiki link's inner text: up to the first unescaped
 * `|`. A table cell must escape its alias pipe as `\|`, so there an escaped
 * pipe ends the target too, and its backslash belongs to the separator.
 * `inTable` is asked only once an escaped pipe turns up.
 */
export function wikiTargetLength(
  content: string,
  inTable: () => boolean,
): number {
  for (let i = 0; i < content.length; i++) {
    if (content[i] !== "|") continue;
    if (!escaped(content, i)) return i;
    if (inTable()) return i - 1;
  }
  return content.length;
}
const within = (ranges: readonly SourceRange[], offset: number) =>
  ranges.some((range) => offset >= range.start && offset < range.end);

/** GFM tables in `source`, read from `tree` when given. */
export function tableRanges(
  source: string,
  tree = markdownParser.parse(source),
): SourceRange[] {
  const ranges: SourceRange[] = [];
  tree.iterate({
    enter(node) {
      if (node.name !== "Table") return;
      // Like an LF row's `\n`, a CRLF row's `\r` ends the table without belonging to it.
      const end = source[node.to - 1] === "\r" ? node.to - 1 : node.to;
      ranges.push({ start: node.from, end });
      return false;
    },
  });
  return ranges;
}

/** The target of the wiki link `source.slice(from, to)`, read the way `linkRanges` reads it. */
export function wikiLinkTarget(
  source: string,
  from: number,
  to: number,
): string {
  const content = source.slice(from + 2, to - 2);
  return content.slice(
    0,
    wikiTargetLength(content, () => within(tableRanges(source), from)),
  );
}

export function linkRanges(
  source: string,
  tree = markdownParser.parse(source),
  excluded: readonly SourceRange[] = excludedRanges(source, tree),
): LinkRange[] {
  const ranges: LinkRange[] = [];
  let tables: SourceRange[] | undefined;
  const inTable = (offset: number) => {
    tables ??= tableRanges(source, tree);
    return within(tables, offset);
  };
  const available = (start: number, end: number) =>
    !excluded.some((range) => start < range.end && end > range.start);
  tree.iterate({
    enter(node) {
      if (node.name !== "URL" || !available(node.from, node.to)) return;
      const parent = node.node.parent;
      if (
        parent?.name !== "Link" &&
        parent?.name !== "Image" &&
        parent?.name !== "LinkReference"
      )
        return;
      const angled = source[node.from] === "<";
      const start = node.from + Number(angled);
      const end = node.to - Number(angled);
      ranges.push({
        start,
        end,
        target: source.slice(start, end),
        syntax: "markdown",
        embed: parent.name === "Image",
      });
    },
  });
  for (const match of source.matchAll(/!?\[\[((?:\\.|[^\]\\\r\n])+)\]\]/gu)) {
    if (
      escaped(source, match.index) ||
      !available(match.index, match.index + match[0].length)
    )
      continue;
    const content = match[1]!;
    const length = wikiTargetLength(content, () => inTable(match.index));
    const start = match.index + (match[0].startsWith("!") ? 3 : 2);
    ranges.push({
      start,
      end: start + length,
      target: content.slice(0, length),
      syntax: "wiki",
      embed: match[0].startsWith("!"),
    });
  }
  return ranges.sort((a, b) => a.start - b.start);
}

/** Encodes a vault path without changing its slash-separated structure. */
export function encodeLinkPath(path: string): string {
  return path
    .split("/")
    .map((segment) =>
      encodeURIComponent(segment).replace(
        /[!'()*]/gu,
        (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`,
      ),
    )
    .join("/");
}

export function decodeLinkPath(target: string): string | null {
  try {
    const unescaped = target.includes("\\")
      ? target.replace(/\\([!"#$%&'()*+,\-./:;<=>?@[\]\\^_`{|}~])/gu, "$1")
      : target;
    return (
      unescaped.includes("%") ? decodeURIComponent(unescaped) : unescaped
    ).normalize("NFC");
  } catch {
    return null;
  }
}

export function normalizeLinkPath(
  target: string,
  fromPath = "",
): string | null {
  const base = target.startsWith("/") ? [] : fromPath.split("/").slice(0, -1);
  for (const segment of target.split("/")) {
    if (segment === "..") {
      if (!base.length) return null;
      base.pop();
    } else if (segment !== "." && segment) base.push(segment);
  }
  return base.join("/");
}

export interface PathEntry {
  id: string;
  path: string;
  aliases?: readonly string[];
}
type LinkSyntax = "wiki" | "markdown";

const sameStrings = (
  a: readonly string[] = [],
  b: readonly string[] = [],
): boolean =>
  a === b ||
  (a.length === b.length && a.every((value, index) => value === b[index]));

/** Path-only answers for one target; aliases remain a separate lookup. */
export interface PathResolution {
  readonly decoded: string | null;
  readonly id: string | null;
  readonly matches: readonly string[];
}

/** Link resolution over a fixed set of entries, indexed once so each lookup costs the same at any vault size. */
export interface PathLookup {
  /** Whether both snapshots contain the same ids, paths and entry order, independent of aliases. */
  samePaths(previous: PathLookup): boolean;
  /** Reuses the decoded target, decisive match and all path candidates together. */
  pathResolution(
    target: string,
    fromPath: string,
    syntax?: LinkSyntax,
  ): PathResolution;
  /** The entry `target` resolves to from `fromPath`: the first rule with any match decides, and more than one match is ambiguous. */
  resolve(target: string, fromPath: string, syntax?: LinkSyntax): string | null;
  /** Every entry that some resolution rule matches on its own, in entry order. */
  matches(target: string, fromPath: string, syntax?: LinkSyntax): string[];
  /** Entries with an alias whose key equals the key of `name`, in entry order. */
  aliased(name: string): readonly string[];
}

/** Remembers answers up to `cap` per generation and keeps the previous generation, so a working set near the cap degrades gradually instead of being dropped at once. */
class Memo<V> {
  private recent = new Map<string, V>();
  private older = new Map<string, V>();
  private readonly cap: number;
  constructor(cap: number) {
    this.cap = cap;
  }
  get(key: string, compute: () => V): V {
    const known = this.recent.get(key);
    if (known !== undefined) return known;
    const value = this.older.get(key) ?? compute();
    if (this.recent.size >= this.cap) {
      this.older = this.recent;
      this.recent = new Map();
    }
    this.recent.set(key, value);
    return value;
  }
}
const memoCap = (entries: number) => Math.max(50_000, entries * 16);

class PathNames {
  private readonly exact = new Map<string, number[]>();
  private readonly ascii = new Map<string, number[]>();

  add(name: string, position: number) {
    const key = canonicalLinkKey(name);
    addPosition(this.exact, key, position);
    if (!/^\p{ASCII}*$/u.test(key)) return;
    addPosition(this.ascii, key, position);
    if (key.endsWith(".md"))
      addPosition(this.ascii, key.slice(0, -3), position);
    else if (key.endsWith(".mdx"))
      addPosition(this.ascii, key.slice(0, -4), position);
  }

  matches(name: string): readonly number[] {
    if (/^\p{ASCII}*$/u.test(name))
      return this.ascii.get(name.toLowerCase()) ?? [];
    const found: number[] = [];
    // A suffix can change Unicode casing, so non-ASCII names need each complete candidate.
    for (const candidate of [name, `${name}.md`, `${name}.mdx`])
      for (const position of this.exact.get(canonicalLinkKey(candidate)) ?? [])
        found.push(position);
    return found.length > 1 ? found.sort((a, b) => a - b) : found;
  }
}

/** The path half of a lookup. It does not depend on aliases, so an alias edit keeps it and its memo. */
class PathCore {
  readonly ids: string[];
  private readonly paths: string[];
  private readonly byPath = new PathNames();
  private readonly byName = new PathNames();
  /** Canonicalizing is slow in browsers and every render resolves the same links again. */
  private readonly resolved: Memo<PathResolution>;

  constructor(entries: readonly PathEntry[]) {
    this.ids = entries.map((entry) => entry.id);
    this.paths = entries.map((entry) => entry.path);
    this.resolved = new Memo(memoCap(entries.length));
    entries.forEach((entry, position) => {
      this.byPath.add(entry.path, position);
      const name = entry.path.slice(entry.path.lastIndexOf("/") + 1);
      this.byName.add(name, position);
    });
  }

  holds(entries: readonly PathEntry[]) {
    return (
      entries.length === this.ids.length &&
      entries.every(
        (entry, position) =>
          entry.id === this.ids[position] &&
          entry.path === this.paths[position],
      )
    );
  }

  // The first nonempty rule decides; matches also retains the union of every rule in entry order.
  resolve(
    target: string,
    fromPath: string,
    syntax: LinkSyntax,
  ): PathResolution {
    const path = target.split("#")[0] ?? "";
    if (
      syntax === "wiki" &&
      path !== "." &&
      path !== ".." &&
      /^\p{ASCII}+$/u.test(path) &&
      !/[/\\%]|^[A-Za-z][A-Za-z0-9+.-]*:/u.test(path)
    ) {
      const positions = this.byName.matches(path);
      // Relative matches are a subset of bare-name matches, so an unambiguous answer is folder-independent.
      if (positions.length <= 1)
        return this.resolved.get(`wiki\0\0${path}`, () => {
          const only = positions[0];
          return {
            decoded: path,
            id: only === undefined ? null : (this.ids[only] ?? null),
            matches: this.idsAt(positions),
          };
        });
    }
    const folder = fromPath.slice(0, fromPath.lastIndexOf("/") + 1);
    return this.resolved.get(`${syntax}\0${folder}\0${path}`, () => {
      const decoded = decodeLinkPath(path);
      if (decoded === null || /^[A-Za-z][A-Za-z0-9+.-]*:|^\/\//u.test(decoded))
        return { decoded: null, id: null, matches: [] };
      const rules: (readonly number[])[] = [];
      const addRule = (names: PathNames, name: string | null) => {
        if (name === null) return;
        const positions = names.matches(name);
        if (positions.length) rules.push(positions);
      };
      if (
        syntax === "wiki" &&
        decoded.includes("/") &&
        !decoded.startsWith(".")
      )
        addRule(this.byPath, normalizeLinkPath(decoded));
      addRule(this.byPath, normalizeLinkPath(decoded, fromPath));
      if (syntax === "wiki" && !decoded.includes("/"))
        addRule(this.byName, decoded);
      const decisive = rules[0];
      const only = decisive?.length === 1 ? decisive[0] : undefined;
      const positions =
        rules.length > 1
          ? [...new Set(rules.flat())].sort((a, b) => a - b)
          : (decisive ?? []);
      return {
        decoded,
        id: only === undefined ? null : (this.ids[only] ?? null),
        matches: this.idsAt(positions),
      };
    });
  }

  idsAt(positions: readonly number[]): string[] {
    return positions.flatMap((position) => this.ids[position] ?? []);
  }
}
function addPosition(
  map: Map<string, number[]>,
  key: string,
  position: number,
) {
  const positions = map.get(key);
  if (!positions) map.set(key, [position]);
  else if (positions.at(-1) !== position) positions.push(position);
}

class PathIndex implements PathLookup {
  readonly core: PathCore;
  private readonly aliases: (readonly string[] | undefined)[];
  private readonly aliasKey?: (alias: string) => string;
  private readonly byAlias = new Map<string, number[]>();
  private readonly aliasedNames: Memo<readonly string[]>;

  constructor(
    core: PathCore,
    entries: readonly PathEntry[],
    aliasKey?: (alias: string) => string,
  ) {
    this.core = core;
    this.aliasKey = aliasKey;
    this.aliases = entries.map((entry) => entry.aliases);
    this.aliasedNames = new Memo(memoCap(entries.length));
    if (aliasKey)
      entries.forEach((entry, position) => {
        for (const alias of entry.aliases ?? [])
          addPosition(this.byAlias, aliasKey(alias), position);
      });
  }

  samePaths(previous: PathLookup): boolean {
    return previous instanceof PathIndex && previous.core === this.core;
  }

  holdsAliases(
    entries: readonly PathEntry[],
    aliasKey?: (alias: string) => string,
  ) {
    return (
      aliasKey === this.aliasKey &&
      entries.every((entry, position) =>
        sameStrings(entry.aliases, this.aliases[position]),
      )
    );
  }

  pathResolution(
    target: string,
    fromPath: string,
    syntax: LinkSyntax = "wiki",
  ) {
    return this.core.resolve(target, fromPath, syntax);
  }

  resolve(target: string, fromPath: string, syntax: LinkSyntax = "wiki") {
    return this.pathResolution(target, fromPath, syntax).id;
  }

  matches(target: string, fromPath: string, syntax: LinkSyntax = "wiki") {
    return [...this.pathResolution(target, fromPath, syntax).matches];
  }

  aliased(name: string) {
    const { aliasKey } = this;
    if (!aliasKey) return [];
    return this.aliasedNames.get(name, () =>
      this.core.idsAt(this.byAlias.get(aliasKey(name)) ?? []),
    );
  }
}

/**
 * Builds a lookup, reusing `previous` when its ids, paths and aliases still
 * match. When only aliases changed, the path maps and their memo carry over.
 */
export function createPathLookup(
  entries: readonly PathEntry[],
  options: {
    aliasKey?: (alias: string) => string;
    previous?: PathLookup;
  } = {},
): PathLookup {
  const { aliasKey, previous } = options;
  if (previous instanceof PathIndex && previous.core.holds(entries))
    return previous.holdsAliases(entries, aliasKey)
      ? previous
      : new PathIndex(previous.core, entries, aliasKey);
  return new PathIndex(new PathCore(entries), entries, aliasKey);
}

export function resolvePath(
  target: string,
  fromPath: string,
  entries: readonly { id: string; path: string }[],
  syntax: LinkSyntax = "wiki",
): string | null {
  return new PathIndex(new PathCore(entries), entries).resolve(
    target,
    fromPath,
    syntax,
  );
}

/** Resolves links between vault items, deriving their paths and lookup once, on first use, for every link that follows. */
export function linkResolver(items: readonly VaultItem[]) {
  let index: Map<string, string> | undefined;
  let lookup: PathLookup | undefined;
  return (
    target: string,
    from: string,
    syntax: LinkSyntax = "wiki",
  ): string | null => {
    if (!index || !lookup) {
      index = paths(items);
      lookup = createPathLookup([...index].map(([id, path]) => ({ id, path })));
    }
    if (target.startsWith("#")) return from;
    return lookup.resolve(target, index.get(from) ?? "", syntax);
  };
}

export function rewriteLinkRanges(
  source: string,
  replacements: readonly (LinkRange & { replacement: string })[],
): string {
  let result = source;
  let last = source.length;
  for (const range of [...replacements].sort((a, b) => b.start - a.start)) {
    if (
      range.start < 0 ||
      range.end < range.start ||
      range.end > last ||
      source.slice(range.start, range.end) !== range.target
    )
      throw new Error("Invalid source range");
    result =
      result.slice(0, range.start) +
      range.replacement +
      result.slice(range.end);
    last = range.start;
  }
  return result;
}
