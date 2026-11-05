import { createHeadingIdAllocator } from "../markdown/heading-ids.ts";
import {
  createPathLookup,
  decodeLinkPath,
  encodeLinkPath,
  excludedRanges,
  type LinkRange,
  linkRanges,
  normalizeLinkPath,
  type PathLookup,
} from "../vault/links.ts";
import { canonicalLinkKey, safeSegment } from "../vault/model.ts";
import { markdownParser } from "../vault/table-syntax.ts";
import { readNoteFrontmatter } from "../writing/metadata.ts";
import { mentionLinkText, wikiLinkPath } from "./edits.ts";
import { mentionPlaces } from "./mentions.ts";

export interface LinkNote {
  id: string;
  path: string;
  source: string;
  kind: "md" | "mdx";
}
export interface NoteAnchor {
  id: string;
  text: string;
  line: number;
  start: number;
  end: number;
  level?: number;
}
export interface IndexedNote extends LinkNote {
  aliases: string[];
  headings: NoteAnchor[];
  blocks: NoteAnchor[];
  links: LinkRange[];
}
export interface LinkIndex {
  notes: readonly IndexedNote[];
  byId: ReadonlyMap<string, IndexedNote>;
}
export interface NoteTarget {
  id: string;
  path: string;
  line?: number;
  fragment?: string;
}
export interface NoteReference {
  noteId: string;
  path: string;
  line: number;
  text: string;
  target?: string;
  resolvedId?: string;
  syntax?: "wiki" | "markdown";
  /** Source offsets of an unlinked mention's matched text, present only where a link can replace it. */
  start?: number;
  end?: number;
}
export interface NoteReferences {
  outgoing: NoteReference[];
  backlinks: NoteReference[];
  unlinked: NoteReference[];
}
export interface LinkCompletion {
  label: string;
  target: string;
  detail: string;
  kind: "note" | "heading" | "block";
}

function lineAt(source: string, offset: number): number {
  return source.slice(0, offset).split("\n").length;
}
function plainHeading(text: string): string {
  return text
    .replace(/!?(?:\[([^\]]+)\]\([^)]*\))/gu, "$1")
    .replace(/[*_`]/gu, "")
    .trim();
}
function headingKey(text: string): string {
  return canonicalLinkKey(plainHeading(text));
}
function slug(text: string): string {
  return headingKey(text)
    .replace(/[^\p{L}\p{N}\s_-]/gu, "")
    .replace(/\s/gu, "-");
}
function noteName(path: string): string {
  return path
    .split("/")
    .at(-1)!
    .replace(/\.mdx?$/iu, "");
}

/** Reuses unchanged snapshots from a caller-owned index; discard it when locking. */
export function createLinkIndex(
  notes: readonly LinkNote[],
  previous?: LinkIndex,
): LinkIndex {
  const indexed = notes.map((note) => {
    const cached = previous?.byId.get(note.id);
    if (
      cached &&
      cached.path === note.path &&
      cached.source === note.source &&
      cached.kind === note.kind
    )
      return cached;
    const tree = markdownParser.parse(note.source);
    const excluded = excludedRanges(note.source, tree);
    const headings: NoteAnchor[] = [];
    const blocks: NoteAnchor[] = [];
    const nextHeadingId = createHeadingIdAllocator();
    tree.iterate({
      enter(node) {
        const match = /^(?:ATX|Setext)Heading([1-6])$/u.exec(node.name);
        if (
          !match ||
          excluded.some(
            (range) => node.from >= range.start && node.from < range.end,
          )
        )
          return;
        const text = plainHeading(
          note.source
            .slice(node.from, node.to)
            .replace(/^ {0,3}#{1,6}\s+/u, "")
            .replace(/\s+#+\s*$/u, "")
            .replace(/\r?\n[=-]+\s*$/u, ""),
        );
        headings.push({
          id: nextHeadingId(slug(text)),
          text,
          line: lineAt(note.source, node.from),
          start: node.from,
          end: note.source.length,
          level: Number(match[1]),
        });
      },
    });
    for (let i = 0; i < headings.length; i++) {
      const heading = headings[i]!;
      heading.end =
        headings.slice(i + 1).find((next) => next.level! <= heading.level!)
          ?.start ?? note.source.length;
    }
    for (const match of note.source.matchAll(
      /(?:^|[ \t])\^([\w-]+)[ \t]*(?=\r?$)/gmu,
    )) {
      if (
        excluded.some(
          (range) => match.index >= range.start && match.index < range.end,
        )
      )
        continue;
      const prefix = note.source.slice(0, match.index);
      const lineStart = prefix.lastIndexOf("\n") + 1;
      const standalone = !prefix.slice(lineStart).trim();
      const end = standalone ? prefix.trimEnd().length : match.index;
      if (!end) continue;
      let block = tree.resolveInner(end, -1);
      while (block.parent && block.parent.name !== "Document") {
        if (!standalone && block.name === "ListItem") break;
        block = block.parent;
      }
      const start = block.from;
      blocks.push({
        id: match[1]!,
        text: note.source.slice(start, end).trim(),
        line: lineAt(note.source, start),
        start,
        end,
      });
    }
    return {
      ...note,
      aliases: readNoteFrontmatter(note.source).aliases,
      headings,
      blocks,
      links: linkRanges(note.source, tree, excluded),
    };
  });
  const index = {
    notes: indexed,
    byId: new Map(indexed.map((note) => [note.id, note])),
  };
  const prior = previous && pathLookups.get(previous);
  if (prior)
    pathLookups.set(
      index,
      createPathLookup(indexed, { aliasKey: headingKey, previous: prior }),
    );
  return index;
}

/** Built on first use and carried to the next index while paths and aliases are unchanged; dies with its index on lock. */
const pathLookups = new WeakMap<LinkIndex, PathLookup>();
function pathLookup(index: LinkIndex): PathLookup {
  let lookup = pathLookups.get(index);
  if (!lookup) {
    lookup = createPathLookup(index.notes, { aliasKey: headingKey });
    pathLookups.set(index, lookup);
  }
  return lookup;
}

export interface ResolvedLink {
  link: LinkRange;
  /** The note the link leads to, ignoring a fragment that no longer resolves. */
  id: string | undefined;
}
/** Kept per indexed note and path snapshot, with every actual alias fallback revalidated. */
const resolvedLinkCache = new WeakMap<
  IndexedNote,
  {
    lookup: PathLookup;
    aliases: ReadonlyMap<string, readonly string[]>;
    links: readonly ResolvedLink[];
  }
>();
/** A note's links to other notes, URLs and other schemes left out. */
export function resolvedLinks(
  index: LinkIndex,
  note: IndexedNote,
): readonly ResolvedLink[] {
  const lookup = pathLookup(index);
  const cached = resolvedLinkCache.get(note);
  if (
    cached &&
    (cached.lookup === lookup ||
      (lookup.samePaths(cached.lookup) &&
        sameAliasResults(lookup, cached.aliases)))
  ) {
    if (cached.lookup !== lookup)
      resolvedLinkCache.set(note, { ...cached, lookup });
    return cached.links;
  }
  const aliases = new Map<string, readonly string[]>();
  const links = note.links.flatMap((link) => {
    if (/^[A-Za-z][A-Za-z0-9+.-]*:|^\/\//u.test(link.target)) return [];
    // Note-level references keep their destination even when a fragment stops resolving.
    const path = link.target.split("#")[0] ?? "";
    const candidates = noteCandidates(
      index,
      path,
      note.id,
      link.syntax ?? "wiki",
      aliases,
    );
    return [
      { link, id: candidates.length === 1 ? candidates[0]?.id : undefined },
    ];
  });
  resolvedLinkCache.set(note, { lookup, aliases, links });
  return links;
}

function sameAliasResults(
  lookup: PathLookup,
  aliases: ReadonlyMap<string, readonly string[]>,
): boolean {
  for (const [name, previous] of aliases) {
    const current = lookup.aliased(name);
    if (
      current.length !== previous.length ||
      current.some((id, index) => id !== previous[index])
    )
      return false;
  }
  return true;
}

export type UnresolvedLink =
  | { kind: "missing-note"; path: string }
  | { kind: "ambiguous"; candidates: { id: string; path: string }[] }
  | { kind: "missing-fragment" }
  | { kind: "invalid" };

function noteCandidates(
  index: LinkIndex,
  path: string,
  fromId: string,
  syntax: "wiki" | "markdown",
  aliases?: Map<string, readonly string[]>,
): readonly IndexedNote[] {
  const from = index.byId.get(fromId);
  if (!from) return [];
  if (!path) return [from];
  const lookup = pathLookup(index);
  const {
    decoded,
    id,
    matches: paths,
  } = lookup.pathResolution(path, from.path, syntax);
  if (decoded === null) return [];
  if (id) {
    const note = index.byId.get(id);
    return note ? [note] : [];
  }
  const notes = (ids: readonly string[]) =>
    ids.flatMap((match) => index.byId.get(match) ?? []);
  const matches = notes(paths);
  if (matches.length || syntax === "markdown") return matches;
  const aliased = lookup.aliased(decoded);
  aliases?.set(decoded, aliased);
  return notes(aliased);
}

/** Classifies an unresolved note target before offering an explicit create action. */
export function describeUnresolvedLink(
  index: LinkIndex,
  target: string,
  fromId: string,
  syntax: "wiki" | "markdown" = "wiki",
): UnresolvedLink {
  const from = index.byId.get(fromId);
  if (!from || !target || resolveNoteLink(index, target, fromId, syntax))
    return { kind: "invalid" };
  const separator = target.indexOf("#");
  const rawPath = separator < 0 ? target : target.slice(0, separator);
  const decoded = decodeLinkPath(rawPath);
  if (
    decoded === null ||
    (separator >= 0 && decodeLinkPath(target.slice(separator + 1)) === null)
  )
    return { kind: "invalid" };
  const candidates = noteCandidates(index, rawPath, fromId, syntax);
  if (candidates.length > 1)
    return {
      kind: "ambiguous",
      candidates: candidates
        .map(({ id, path }) => ({ id, path }))
        .sort(
          (a, b) => a.path.localeCompare(b.path) || a.id.localeCompare(b.id),
        ),
    };
  if (candidates.length === 1 && separator >= 0)
    return { kind: "missing-fragment" };
  if (
    !decoded ||
    /^[A-Za-z][A-Za-z0-9+.-]*:/u.test(decoded) ||
    decoded.includes("//") ||
    decoded.endsWith("/")
  )
    return { kind: "invalid" };
  try {
    for (const segment of decoded.replace(/^\//u, "").split("/")) {
      if (segment !== "." && segment !== "..") safeSegment(segment);
    }
    const base =
      syntax === "wiki" && decoded.includes("/") && !decoded.startsWith(".")
        ? ""
        : from.path;
    const normalized = normalizeLinkPath(decoded, base);
    if (!normalized) return { kind: "invalid" };
    const path = /\.mdx?$/iu.test(normalized) ? normalized : `${normalized}.md`;
    const segments = path.split("/");
    if (path.length > 4096 || segments.length > 64) return { kind: "invalid" };
    segments.forEach(safeSegment);
    const canonical = (value: string) =>
      value.normalize("NFC").toLocaleLowerCase("en-US");
    const proposed = canonical(path);
    if (
      index.notes.some((note) => {
        const existing = canonical(note.path);
        return (
          existing === proposed ||
          existing.startsWith(`${proposed}/`) ||
          proposed.startsWith(`${existing}/`)
        );
      })
    )
      return { kind: "invalid" };
    return { kind: "missing-note", path };
  } catch {
    return { kind: "invalid" };
  }
}

function findHeading(
  note: IndexedNote,
  fragment: string,
): NoteAnchor | undefined {
  const direct =
    note.headings.find((heading) => heading.id === fragment) ??
    note.headings.find(
      (heading) => headingKey(heading.text) === headingKey(fragment),
    );
  if (direct) return direct;
  let parent: NoteAnchor | undefined;
  for (const part of fragment.split("#")) {
    if (!part) return undefined;
    const scope = parent;
    parent = note.headings.find(
      (heading) =>
        (!scope ||
          (heading.start > scope.start && heading.start < scope.end)) &&
        (heading.id === part || headingKey(heading.text) === headingKey(part)),
    );
    if (!parent) return undefined;
  }
  return parent;
}

/** The fragment that resolves to this heading: its text when unique, else its numbered slug. */
export function headingFragment(note: IndexedNote, anchor: NoteAnchor): string {
  return note.headings.filter(
    (heading) => headingKey(heading.text) === headingKey(anchor.text),
  ).length === 1 && findHeading(note, anchor.text) === anchor
    ? anchor.text
    : anchor.id;
}

function completionPath(
  index: LinkIndex,
  note: IndexedNote,
  syntax: "wiki" | "markdown",
): string {
  const full = encodeLinkPath(`/${note.path}`);
  if (syntax === "markdown") return full;
  const short = encodeLinkPath(`/${note.path.replace(/\.mdx?$/iu, "")}`);
  return pathLookup(index).resolve(short, note.path, syntax) === note.id
    ? short
    : full;
}

export function resolveNoteLink(
  index: LinkIndex,
  target: string,
  fromId: string,
  syntax: "wiki" | "markdown" = "wiki",
): NoteTarget | null {
  const separator = target.indexOf("#");
  const path = separator < 0 ? target : target.slice(0, separator);
  const candidates = noteCandidates(index, path, fromId, syntax);
  const note = candidates.length === 1 ? candidates[0] : undefined;
  if (!note) return null;
  const id = note.id;
  if (separator < 0 || separator === target.length - 1)
    return { id, path: note.path };
  const fragment = decodeLinkPath(target.slice(separator + 1));
  if (fragment === null) return null;
  const anchor = fragment.startsWith("^")
    ? note.blocks.find((block) => block.id === fragment.slice(1))
    : findHeading(note, fragment);
  if (!anchor) return null;
  return { id, path: note.path, line: anchor.line, fragment };
}

export function resolveNoteEmbed(
  index: LinkIndex,
  target: string,
  fromId: string,
  syntaxOrOptions:
    | "wiki"
    | "markdown"
    | { ancestors?: readonly string[]; maxDepth?: number } = "wiki",
  options: { ancestors?: readonly string[]; maxDepth?: number } = {},
): { noteId: string; notePath: string; source: string; line: number } | null {
  const syntax = syntaxOrOptions === "markdown" ? "markdown" : "wiki";
  const bounds =
    syntaxOrOptions === "wiki" || syntaxOrOptions === "markdown"
      ? options
      : syntaxOrOptions;
  const resolved = resolveNoteLink(index, target, fromId, syntax);
  const ancestors = bounds.ancestors ?? [fromId];
  if (
    !resolved ||
    ancestors.includes(resolved.id) ||
    ancestors.length >= (bounds.maxDepth ?? 8)
  )
    return null;
  const note = index.byId.get(resolved.id)!;
  const anchor = resolved.fragment?.startsWith("^")
    ? note.blocks.find((block) => block.id === resolved.fragment!.slice(1))
    : note.headings.find((heading) => heading.line === resolved.line);
  return {
    noteId: note.id,
    notePath: note.path,
    source: anchor ? note.source.slice(anchor.start, anchor.end) : note.source,
    line: anchor?.line ?? 1,
  };
}

export function completeNoteLinks(
  index: LinkIndex,
  query: string,
  fromId: string,
  syntax: "wiki" | "markdown" = "wiki",
): LinkCompletion[] {
  const globalHeadings = query.startsWith("##");
  const separator = query.indexOf("#");
  if (separator >= 0) {
    const path = query.slice(0, separator);
    const resolved = globalHeadings
      ? null
      : resolveNoteLink(index, path, fromId, syntax);
    const selected = resolved ? index.byId.get(resolved.id) : undefined;
    const notes = globalHeadings ? index.notes : selected ? [selected] : [];
    const fragment = query.slice(separator + (globalHeadings ? 2 : 1));
    const blocks = fragment.startsWith("^");
    const parentEnd = blocks ? -1 : fragment.lastIndexOf("#");
    const parentPath = parentEnd < 0 ? "" : fragment.slice(0, parentEnd);
    const needle = headingKey(
      blocks ? fragment.slice(1) : fragment.slice(parentEnd + 1),
    );
    return notes
      .flatMap((note) => {
        const parent = parentPath ? findHeading(note, parentPath) : undefined;
        if (parentPath && !parent) return [];
        return (blocks ? note.blocks : note.headings)
          .filter(
            (anchor) =>
              (!parent ||
                (anchor.start > parent.start && anchor.start < parent.end)) &&
              headingKey(blocks ? anchor.id : anchor.text).includes(needle),
          )
          .map((anchor) => {
            const notePath =
              !globalHeadings && !path
                ? ""
                : completionPath(index, note, syntax);
            const heading = headingFragment(note, anchor);
            const targetFragment = blocks
              ? `^${anchor.id}`
              : heading
                  .split("#")
                  .map((part) => encodeURIComponent(part))
                  .join("#");
            return {
              label: blocks ? `^${anchor.id}` : anchor.text,
              target: `${notePath}#${targetFragment}`,
              detail: `${note.path}:${anchor.line}`,
              kind: blocks ? ("block" as const) : ("heading" as const),
            };
          });
      })
      .slice(0, 100);
  }
  const needle = headingKey(query);
  return index.notes
    .flatMap((note) =>
      [noteName(note.path), ...note.aliases]
        .filter(
          (label) =>
            headingKey(label).includes(needle) ||
            headingKey(note.path).includes(needle),
        )
        .map((label) => ({ label, note })),
    )
    .slice(0, 100)
    .map(({ label, note }) => ({
      label,
      target: completionPath(index, note, syntax),
      detail: note.path,
      kind: "note" as const,
    }));
}

function reference(note: IndexedNote, offset: number): NoteReference {
  const start = note.source.lastIndexOf("\n", offset - 1) + 1;
  const end = note.source.indexOf("\n", offset);
  return {
    noteId: note.id,
    path: note.path,
    line: lineAt(note.source, offset),
    text: note.source.slice(start, end < 0 ? note.source.length : end).trim(),
  };
}

export function noteReferences(index: LinkIndex, id: string): NoteReferences {
  const outgoing: NoteReference[] = [];
  const backlinks: NoteReference[] = [];
  const unlinked: NoteReference[] = [];
  const current = index.byId.get(id);
  if (!current) return { outgoing, backlinks, unlinked };
  // Longest first, so "launch plan" wins over the "plan" inside it on the same line.
  const patterns = [...new Set([noteName(current.path), ...current.aliases])]
    .filter(Boolean)
    .sort((a, b) => b.length - a.length)
    .map(
      (name) => new RegExp(name.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "giu"),
    );
  let shortest: string | undefined;
  const shortestPath = () => {
    shortest ??= wikiLinkPath(index, current);
    return shortest;
  };
  for (const note of index.notes) {
    for (const { link, id: resolvedId } of resolvedLinks(index, note)) {
      if (note.id !== id && resolvedId !== id) continue;
      const row = {
        ...reference(note, link.start),
        target: link.target,
        syntax: link.syntax,
        resolvedId,
      };
      if (note.id === id) outgoing.push(row);
      if (resolvedId === id) backlinks.push(row);
    }
    if (note.id === id) continue;
    const placeOf = mentionPlaces(note.source, note);
    const seen = new Set<number>();
    for (const pattern of patterns) {
      for (const match of note.source.matchAll(pattern)) {
        const start = match.index;
        const end = start + match[0].length;
        if (
          /[\p{L}\p{N}_]/u.test(note.source[start - 1] ?? "") ||
          /[\p{L}\p{N}_]/u.test(note.source[end] ?? "")
        )
          continue;
        const place = placeOf(start, end);
        if (!place) continue;
        const row = reference(note, start);
        // A heading can't take a link, and a cell can't take a label holding a pipe or bracket.
        const linkable =
          place === "prose" ||
          (place === "cell" &&
            mentionLinkText(shortestPath(), match[0], true) !== null);
        if (!seen.has(row.line)) {
          unlinked.push(linkable ? { ...row, start, end } : row);
          seen.add(row.line);
        }
      }
    }
  }
  return { outgoing, backlinks, unlinked };
}
