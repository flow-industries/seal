import { resolvePath } from "../vault/links.ts";
import type { LinkIndex, NoteReference } from "./index.ts";
import { mentionPlaces } from "./mentions.ts";

/** A change computed from one version of a note, written only while `guard.text` is still at `guard.from..guard.to`. */
export interface GuardedEdit {
  from: number;
  to: number;
  insert: string;
  guard: { from: number; to: number; text: string };
}

/** Returns null when the note changed under the edit, so stale offsets never write. */
export function applyGuardedEdit(
  source: string,
  edit: GuardedEdit,
): string | null {
  return source.slice(edit.guard.from, edit.guard.to) === edit.guard.text
    ? source.slice(0, edit.from) + edit.insert + source.slice(edit.to)
    : null;
}

/**
 * The new source for a write to a note other than the open one, or why nothing may be written:
 * `blocked` while the vault is locked, a rename or extract/merge runs, or a save is failing.
 */
export function planNoteEdit(
  note: { path: string; source: string },
  edit: GuardedEdit,
  blocked: boolean,
): { source: string } | { error: string } {
  if (blocked)
    return {
      error: `Save your pending edits before changing ${note.path}. Nothing was changed.`,
    };
  const source = applyGuardedEdit(note.source, edit);
  return source === null
    ? {
        error: `${note.path} changed, so nothing was changed there. Try again.`,
      }
    : { source };
}

function wikiEscape(text: string): string {
  return text.replace(
    /[%#|[\]\\]/gu,
    (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

/** The shortest wiki path that resolves to the note from anywhere in the vault: its name, then its folder path. */
export function wikiLinkPath(
  index: LinkIndex,
  note: { id: string; path: string },
): string {
  const stem = note.path.replace(/\.mdx?$/iu, "");
  const name = wikiEscape(stem.split("/").at(-1) ?? stem);
  if (
    index.notes.filter((entry) => resolvePath(name, "", [entry]) === entry.id)
      .length === 1
  )
    return name;
  const rooted = (path: string) =>
    wikiEscape(path.includes("/") ? path : `/${path}`);
  return resolvePath(rooted(stem), "", index.notes) === note.id
    ? rooted(stem)
    : rooted(note.path);
}

/** A `[[path#fragment]]` link whose fragment survives the resolver's decoding. */
export function wikiLink(path: string, fragment?: string): string {
  return `[[${path}${fragment === undefined ? "" : `#${wikiEscape(fragment)}`}]]`;
}

/**
 * Keeps the mention's visible text: an alias or a different case becomes the link label.
 * A table cell escapes the label's pipe as `\|`, because a bare `|` would split the cell.
 */
export function mentionLinkText(
  path: string,
  matched: string,
  cell = false,
): string | null {
  if (matched === path) return `[[${path}]]`;
  if (/[[\]|\r\n]/u.test(matched)) return null;
  return `[[${path}${cell ? "\\|" : "|"}${matched}]]`;
}

/** Turns one unlinked mention of `targetId` into a link, guarded by the text the scan found. */
export function mentionLinkEdit(
  index: LinkIndex,
  targetId: string,
  mention: NoteReference,
): GuardedEdit | null {
  const target = index.byId.get(targetId);
  const source = index.byId.get(mention.noteId)?.source;
  if (
    !target ||
    source === undefined ||
    mention.start === undefined ||
    mention.end === undefined
  )
    return null;
  const place = mentionPlaces(source)(mention.start, mention.end);
  if (place !== "prose" && place !== "cell") return null;
  const guard = {
    from: mention.start,
    to: mention.end,
    text: source.slice(mention.start, mention.end),
  };
  const insert = mentionLinkText(
    wikiLinkPath(index, target),
    guard.text,
    place === "cell",
  );
  return insert ? { from: guard.from, to: guard.to, insert, guard } : null;
}
