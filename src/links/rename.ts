import {
  encodeLinkPath,
  linkRanges,
  resolvePath,
  rewriteLinkRanges,
} from "../vault/links.ts";
import { createLinkIndex, type LinkNote, resolveNoteLink } from "./index.ts";

function relativePath(from: string, to: string): string {
  const base = from.split("/").slice(0, -1);
  const destination = to.split("/");
  while (base.length && base[0] === destination[0]) {
    base.shift();
    destination.shift();
  }
  return [...base.map(() => ".."), ...destination].join("/");
}
function destinationPath(
  original: string,
  syntax: "wiki" | "markdown" | undefined,
  fromPath: string,
  destination: { id: string; path: string },
  entries: readonly { id: string; path: string }[],
): string {
  let replacement: string;
  if (syntax === "wiki") {
    const path = /\.mdx?$/iu.test(original)
      ? destination.path
      : destination.path.replace(/\.mdx?$/iu, "");
    replacement = encodeLinkPath(`/${path}`);
    if (resolvePath(replacement, fromPath, entries, syntax) !== destination.id)
      replacement = encodeLinkPath(`/${destination.path}`);
  } else {
    replacement = encodeLinkPath(
      original.startsWith("/")
        ? `/${destination.path}`
        : relativePath(fromPath, destination.path),
    );
    if (original.startsWith("./") && !replacement.startsWith("."))
      replacement = `./${replacement}`;
  }
  if (resolvePath(replacement, fromPath, entries, syntax) !== destination.id)
    throw new Error("Cannot safely repair note link");
  return replacement;
}

/** Preserves resolved destinations when copying source into another note path. */
export function rebaseOutgoingLinks(
  source: string,
  fromId: string,
  toPath: string,
  notes: readonly LinkNote[],
  assets: readonly { id: string; path: string }[] = [],
): string {
  const index = createLinkIndex(notes);
  const from = index.byId.get(fromId);
  if (!from) throw new Error("Missing source note");
  const entries = [...notes, ...assets];
  const existing = notes.find(
    (note) =>
      note.path.normalize("NFC").toLocaleLowerCase("en-US") ===
      toPath.normalize("NFC").toLocaleLowerCase("en-US"),
  );
  let destinationId = existing?.id ?? `rebase:${fromId}`;
  while (!existing && index.byId.has(destinationId)) destinationId += ":";
  const context = existing
    ? index
    : createLinkIndex(
        [...notes, { id: destinationId, path: toPath, source: "", kind: "md" }],
        index,
      );
  const prospectiveEntries = [...context.notes, ...assets];
  const replacements = linkRanges(source).flatMap((link) => {
    const separator = link.target.indexOf("#");
    const path = separator < 0 ? link.target : link.target.slice(0, separator);
    const fragment = separator < 0 ? "" : link.target.slice(separator);
    const id =
      resolveNoteLink(index, path, fromId, link.syntax)?.id ??
      resolvePath(path, from.path, entries, link.syntax);
    if (!id) return [];
    if (!path && toPath === from.path) return [];
    const nextId = path
      ? (resolveNoteLink(context, path, destinationId, link.syntax)?.id ??
        resolvePath(path, toPath, prospectiveEntries, link.syntax))
      : null;
    if (nextId === id) return [];
    const destination = entries.find((entry) => entry.id === id);
    if (!destination) return [];
    return [
      {
        ...link,
        replacement:
          destinationPath(
            path,
            link.syntax,
            toPath,
            destination,
            prospectiveEntries,
          ) + fragment,
      },
    ];
  });
  return rewriteLinkRanges(source, replacements);
}

/** Repairs only references with an unambiguous pre-edit destination. */
export function repairMovedNoteLinks(
  before: readonly LinkNote[],
  after: readonly LinkNote[],
  assets: readonly { id: string; path: string }[] = [],
): Map<string, string> {
  const previous = createLinkIndex(before);
  const next = createLinkIndex(after);
  const oldEntries = [...before, ...assets];
  const newEntries = [...after, ...assets];
  const result = new Map<string, string>();
  for (const note of after) {
    const oldNote = previous.byId.get(note.id);
    if (!oldNote) continue;
    const replacements = linkRanges(note.source).flatMap((link) => {
      const separator = link.target.indexOf("#");
      const path =
        separator < 0 ? link.target : link.target.slice(0, separator);
      const fragment = separator < 0 ? "" : link.target.slice(separator);
      if (!path) return [];
      const oldId =
        resolveNoteLink(previous, path, note.id, link.syntax)?.id ??
        resolvePath(path, oldNote.path, oldEntries, link.syntax);
      if (!oldId) return [];
      const nextId =
        resolveNoteLink(next, path, note.id, link.syntax)?.id ??
        resolvePath(path, note.path, newEntries, link.syntax);
      if (oldId === nextId) return [];
      const destination = newEntries.find((entry) => entry.id === oldId);
      if (!destination) return [];
      const replacement = destinationPath(
        path,
        link.syntax,
        note.path,
        destination,
        newEntries,
      );
      return [{ ...link, replacement: replacement + fragment }];
    });
    if (replacements.length)
      result.set(note.id, rewriteLinkRanges(note.source, replacements));
  }
  return result;
}
