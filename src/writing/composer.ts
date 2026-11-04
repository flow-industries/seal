import {
  createLinkIndex,
  type LinkIndex,
  type LinkNote,
  resolveNoteLink,
} from "../links/index.ts";
import { rebaseOutgoingLinks } from "../links/rename.ts";
import { encodeLinkPath, linkRanges, rewriteLinkRanges } from "../vault/links.ts";
import { safeSegment } from "../vault/model.ts";
import { attachmentMarkdown } from "./attachments.ts";
import { readNoteMetadata } from "./metadata.ts";

export type ComposeRequest =
  | {
      kind: "extract";
      originId: string;
      expectedSource: string;
      from: number;
      to: number;
      path: string;
    }
  | {
      kind: "merge";
      originId: string;
      targetId: string;
      expectedSource: string;
      expectedTargetSource?: string;
    };

function bodyStart(source: string): number {
  const metadata = readNoteMetadata(source);
  if (metadata.error) throw new Error(metadata.error);
  return metadata.frontmatter?.end ?? (source.startsWith("\uFEFF") ? 1 : 0);
}

function splitsSurrogate(source: string, offset: number): boolean {
  return (
    /[\uD800-\uDBFF]/u.test(source.charAt(offset - 1)) &&
    /[\uDC00-\uDFFF]/u.test(source.charAt(offset))
  );
}

function redirectLinks(
  source: string,
  fromId: string,
  originId: string,
  target: LinkNote,
  index: LinkIndex,
  fragments: ReadonlyMap<string, string>,
  onlyMovedAnchors = false,
): string {
  const targetIndex = createLinkIndex([target]);
  return rewriteLinkRanges(
    source,
    linkRanges(source).flatMap((link) => {
      const separator = link.target.indexOf("#");
      const path =
        separator < 0 ? link.target : link.target.slice(0, separator);
      if (resolveNoteLink(index, path, fromId, link.syntax)?.id !== originId)
        return [];
      const resolved = resolveNoteLink(index, link.target, fromId, link.syntax);
      const anchorKind = resolved?.fragment?.startsWith("^") ? "^" : "";
      const mapped = resolved?.line
        ? fragments.get(`${anchorKind}:${resolved.line}`)
        : undefined;
      if (onlyMovedAnchors && !mapped) return [];
      let fragment = separator < 0 ? "" : link.target.slice(separator);
      if (mapped) {
        const preserved = resolveNoteLink(
          targetIndex,
          fragment,
          target.id,
          link.syntax,
        );
        const canonical = resolveNoteLink(
          targetIndex,
          `#${mapped}`,
          target.id,
          link.syntax,
        );
        if (!preserved || preserved.line !== canonical?.line)
          fragment = `#${encodeLinkPath(mapped)}`;
      }
      return [
        { ...link, replacement: encodeLinkPath(`/${target.path}`) + fragment },
      ];
    }),
  );
}

export function extractNote(
  request: Extract<ComposeRequest, { kind: "extract" }>,
  notes: readonly LinkNote[],
  assets: readonly { id: string; path: string }[],
) {
  const origin = notes.find((note) => note.id === request.originId);
  if (!origin) throw new Error("Missing source note");
  if (origin.source !== request.expectedSource)
    throw new Error("Source changed before extraction");
  const { from, to, path } = request;
  if (
    !/\.mdx?$/iu.test(path) ||
    path.length > 4096 ||
    path.split("/").length > 64
  )
    throw new Error("Note path must end in .md or .mdx and fit path bounds");
  path.split("/").forEach(safeSegment);
  if (/[\uD800-\uDFFF]/u.test(path))
    throw new Error("Invalid character in note path");
  if (
    !Number.isInteger(from) ||
    !Number.isInteger(to) ||
    from < bodyStart(origin.source) ||
    to > origin.source.length ||
    from >= to ||
    splitsSurrogate(origin.source, from) ||
    splitsSurrogate(origin.source, to)
  )
    throw new Error(
      "Select body text without splitting frontmatter or a character",
    );
  const selected = origin.source.slice(from, to);
  if (!selected.trim()) throw new Error("Select text to extract");
  let targetId = `extracted:${origin.id}`;
  while (notes.some((note) => note.id === targetId)) targetId += ":";
  const target: LinkNote = {
    id: targetId,
    path,
    source: selected,
    kind: origin.kind,
  };
  const index = createLinkIndex(notes);
  const old = index.byId.get(origin.id)!;
  const extractedIndex = createLinkIndex([target]).byId.get(target.id)!;
  const fragments = new Map<string, string>();
  for (const [anchors, moved, prefix] of [
    [old.headings, extractedIndex.headings, ""],
    [old.blocks, extractedIndex.blocks, "^"],
  ] as const) {
    for (const anchor of anchors) {
      const next = moved.find((value) => value.start === anchor.start - from);
      if (next)
        fragments.set(`${prefix}:${anchor.line}`, `${prefix}${next.id}`);
    }
  }
  const redirected = redirectLinks(
    selected,
    origin.id,
    origin.id,
    target,
    index,
    fragments,
    true,
  );
  const extracted = rebaseOutgoingLinks(
    redirected,
    origin.id,
    path,
    [...notes, target],
    assets,
  );
  const label = path
    .split("/")
    .at(-1)!
    .replace(/\.mdx?$/iu, "");
  const remaining =
    origin.source.slice(0, from) +
    attachmentMarkdown(path, origin.path, label, "text/markdown") +
    origin.source.slice(to);
  return {
    origin: redirectLinks(
      remaining,
      origin.id,
      origin.id,
      target,
      index,
      fragments,
      true,
    ),
    extracted,
  };
}

export function mergeNotes(
  request: Extract<ComposeRequest, { kind: "merge" }>,
  notes: readonly LinkNote[],
  assets: readonly { id: string; path: string }[],
): Map<string, string> {
  const index = createLinkIndex(notes);
  const origin = index.byId.get(request.originId);
  const target = index.byId.get(request.targetId);
  if (!origin || !target || origin.id === target.id)
    throw new Error("Choose another active note to merge into");
  if (
    origin.source !== request.expectedSource ||
    (request.expectedTargetSource !== undefined &&
      target.source !== request.expectedTargetSource)
  )
    throw new Error("Source changed before merge");
  const start = bodyStart(origin.source);
  bodyStart(target.source);
  const body = origin.source.slice(start);
  if (!body.trim()) throw new Error("Source has no body to merge");
  const newline = target.source.includes("\r\n") ? "\r\n" : "\n";
  const separator = target.source.length ? newline.repeat(2) : "";
  const joined: LinkNote = {
    ...target,
    source: target.source + separator + body,
  };
  const joinedIndex = createLinkIndex([joined]).byId.get(target.id)!;
  if (
    origin.blocks.some((block) =>
      target.blocks.some((other) => other.id === block.id),
    )
  )
    throw new Error("Rename duplicate block IDs before merging");
  const fragments = new Map<string, string>();
  for (const [anchors, combined, prefix] of [
    [origin.headings, joinedIndex.headings, ""],
    [origin.blocks, joinedIndex.blocks, "^"],
  ] as const) {
    for (const anchor of anchors) {
      const offset =
        target.source.length + separator.length + anchor.start - start;
      const next = combined.find((value) => value.start === offset);
      if (!next) throw new Error("Close Markdown blocks before merging notes");
      fragments.set(`${prefix}:${anchor.line}`, `${prefix}${next.id}`);
    }
  }
  const changes = new Map<string, string>();
  for (const note of notes) {
    if (note.id === origin.id) continue;
    const repaired = redirectLinks(
      note.source,
      note.id,
      origin.id,
      joined,
      index,
      fragments,
    );
    if (note.id === target.id || repaired !== note.source)
      changes.set(note.id, repaired);
  }
  const redirected = redirectLinks(
    body,
    origin.id,
    origin.id,
    joined,
    index,
    fragments,
  );
  changes.set(
    target.id,
    changes.get(target.id)! +
      separator +
      rebaseOutgoingLinks(redirected, origin.id, target.path, notes, assets),
  );
  return changes;
}
