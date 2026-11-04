import type { NoteSearchIndex } from "../src/vault/session.ts";

/**
 * A stand-in for an app's full-text index, as a session's tests need one:
 * every query word must appear in a note's path or source, ignoring case.
 */
export function createSearchIndex(): NoteSearchIndex {
  const notes = new Map<string, string>();
  return {
    async update({ upsert, remove }) {
      for (const id of remove) notes.delete(id);
      for (const note of upsert)
        notes.set(note.id, `${note.path}\n${note.source}`.toLowerCase());
    },
    async search(query) {
      const words = query.toLowerCase().split(/\s+/u).filter(Boolean);
      return [...notes]
        .filter(([, text]) => words.every((word) => text.includes(word)))
        .map(([id]) => ({ id }));
    },
    lock: () => notes.clear(),
  };
}
