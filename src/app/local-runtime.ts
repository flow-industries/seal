import { Unzip, UnzipInflate, zipSync } from "fflate";
import { importLimits, type PortableFile } from "../vault/model.ts";
import type {
  ContentSource,
  Provenance,
  VaultSession,
} from "../vault/session.ts";
import { readAttachmentFiles } from "../writing/attachments.ts";
import type { ComposeRequest } from "../writing/composer.ts";
import {
  DEFAULT_WRITING_PREFERENCES,
  isInternalWritingPath,
  parseWritingPreferences,
  serializeWritingPreferences,
  WRITING_PREFERENCES_PATH,
  type WritingPreferences,
} from "../writing/preferences.ts";
import type { Endorse, NoteRuntime, NoteView } from "./runtime.ts";

function zip(files: readonly PortableFile[]): Blob {
  const tree: Record<string, Uint8Array> = Object.create(null);
  for (const file of files)
    tree[file.directory ? `${file.path}/` : file.path] = file.bytes;
  return new Blob([new Uint8Array(zipSync(tree))], {
    type: "application/zip",
  });
}

async function archive(
  file: File,
  remainingBytes: number,
  remainingFiles: number,
): Promise<PortableFile[]> {
  if (file.size > importLimits.bytes) throw new Error("Archive too large");
  const compressed = new Uint8Array(await file.arrayBuffer());
  const view = new DataView(compressed.buffer);
  let directory = -1;
  for (
    let offset = compressed.length - 22;
    offset >= Math.max(0, compressed.length - 65_557);
    offset--
  ) {
    if (
      view.getUint32(offset, true) === 0x06054b50 &&
      offset + 22 + view.getUint16(offset + 20, true) === compressed.length
    ) {
      directory = offset;
      break;
    }
  }
  if (
    directory < 0 ||
    view.getUint16(directory + 4, true) !== 0 ||
    view.getUint16(directory + 6, true) !== 0
  )
    throw new Error("Unsupported or corrupt archive");
  const entries = view.getUint16(directory + 10, true);
  const directorySize = view.getUint32(directory + 12, true);
  const directoryOffset = view.getUint32(directory + 16, true);
  if (
    entries === 65_535 ||
    entries > remainingFiles ||
    view.getUint16(directory + 8, true) !== entries ||
    directoryOffset + directorySize !== directory
  )
    throw new Error("Unsupported or corrupt archive directory");
  const results: PortableFile[] = [];
  let count = 0;
  let total = 0;
  const pending: Promise<void>[] = [];
  const unzip = new Unzip((entry) => {
    if (++count > remainingFiles) throw new Error("Too many archive entries");
    const completion = new Promise<void>((resolve, reject) => {
      const chunks: Uint8Array[] = [];
      let size = 0;
      entry.ondata = (error, chunk, final) => {
        if (error) {
          reject(error);
          return;
        }
        size += chunk.length;
        total += chunk.length;
        if (size > importLimits.fileBytes || total > remainingBytes) {
          entry.terminate();
          reject(new Error("Archive expansion exceeded limits"));
          return;
        }
        chunks.push(chunk);
        if (final) {
          const bytes = new Uint8Array(size);
          let offset = 0;
          for (const part of chunks) {
            bytes.set(part, offset);
            offset += part.length;
          }
          results.push({
            path: entry.name,
            bytes,
            directory: entry.name.endsWith("/"),
          });
          resolve();
        }
      };
      entry.start();
    });
    // Attach a rejection handler before streaming callbacks can throw.
    completion.catch(() => {});
    pending.push(completion);
  });
  unzip.register(UnzipInflate);
  unzip.push(compressed, true);
  await Promise.all(pending);
  if (count !== entries) throw new Error("Archive entry count mismatch");
  return results;
}

export function localRuntime(session: VaultSession) {
  let locked = false;
  const check = () => {
    if (locked) throw new Error("Vault locked");
  };
  const subscriptions = new Set<() => void>();
  let preferenceWrites: Promise<void> = Promise.resolve();
  async function read() {
    check();
    const view = await session.readView();
    check();
    return {
      notes: view.notes
        .filter((note) => !isInternalWritingPath(note.path))
        .map(({ format, ...note }) => ({ ...note, kind: format })),
      folders: view.folders.filter((path) => !isInternalWritingPath(path)),
    };
  }
  async function list(): Promise<NoteView[]> {
    return (await read()).notes;
  }
  return {
    read,
    list,
    subscribeChanges(listener) {
      check();
      const changed = () => {
        if (!locked) listener();
      };
      const unsubscribe = session.database.subscribe("items", changed);
      const unsubscribeAuthority = session.subscribeAuthority(changed);
      const remove = () => {
        unsubscribe();
        unsubscribeAuthority();
        subscriptions.delete(remove);
      };
      subscriptions.add(remove);
      return remove;
    },
    subscribeTrustLoss(listener) {
      // The shell subscribes after the sync subscription, which may already have locked the runtime.
      if (locked) return () => {};
      const unsubscribe = session.subscribeTrustLoss((loss) => {
        if (!locked) listener(loss);
      });
      const remove = () => {
        unsubscribe();
        subscriptions.delete(remove);
      };
      subscriptions.add(remove);
      return remove;
    },
    async preferences() {
      check();
      const snapshot = await session.readMetadata();
      check();
      const note = snapshot.notes.find(
        (item) => item.path.toLowerCase() === WRITING_PREFERENCES_PATH,
      );
      if (!note) return structuredClone(DEFAULT_WRITING_PREFERENCES);
      const { source } = await snapshot.read(note.id);
      check();
      return parseWritingPreferences(source);
    },
    async savePreferences(value: WritingPreferences) {
      check();
      const source = serializeWritingPreferences(value);
      const write = preferenceWrites.then(async () => {
        check();
        const snapshot = await session.readMetadata();
        check();
        const existing = snapshot.notes.find(
          (item) => item.path.toLowerCase() === WRITING_PREFERENCES_PATH,
        );
        await session.saveNote(
          existing?.id ?? crypto.randomUUID(),
          WRITING_PREFERENCES_PATH,
          source,
        );
        check();
      });
      preferenceWrites = write.catch(() => {});
      return write;
    },
    assets: (note) => session.assetsForNote(note.id, note.source),
    folders: async () => (await read()).folders,
    createFolder: async (path) => {
      check();
      if (isInternalWritingPath(path))
        throw new Error("This folder is reserved for vault preferences.");
      await session.createFolder(path);
      check();
    },
    async trash() {
      check();
      const snapshot = await session.readMetadata();
      check();
      const result = await Promise.all(
        snapshot.trash
          .filter((note) => !isInternalWritingPath(note.path))
          .map(async (note) => ({
            id: note.id,
            path: note.path,
            kind: note.format,
            ...(await snapshot.read(note.id)),
          })),
      );
      check();
      return result;
    },
    restore: (id: string, endorsed?: string) =>
      session.restore(id, endorsed).then(() => {}),
    permanentRemove: (id) => session.permanentRemove(id),
    async save(note: NoteView, provenance?: Provenance) {
      check();
      if (isInternalWritingPath(note.path))
        throw new Error("This path is reserved for vault preferences.");
      await session.saveNote(
        note.id,
        note.path,
        note.source,
        provenance,
        note.revision && note.digest
          ? { revision: note.revision, digest: note.digest }
          : undefined,
      );
      check();
    },
    async writerToEndorse(
      note: Pick<NoteView, "path"> & { id?: string },
      sources?: readonly ContentSource[],
    ) {
      check();
      const writer = await session.writerToEndorse(note, sources);
      check();
      return writer;
    },
    canTrust: () => session.signsAsAdmin(),
    async trust(revisions) {
      check();
      await session.trust(revisions);
      check();
    },
    async compose(request: ComposeRequest, endorsed?: boolean) {
      check();
      const result = await session.compose(request, endorsed);
      check();
      return result;
    },
    async remove(id: string, endorsed?: string) {
      check();
      await session.remove(id, endorsed);
      check();
    },
    async holdsCode(id) {
      check();
      const holds = await session.holdsCode(id);
      check();
      return holds;
    },
    async addAttachments(note, files) {
      const attachments = await readAttachmentFiles(files, check);
      try {
        const inserted = await session.addAttachments(
          note.id,
          note.path,
          attachments,
        );
        check();
        return inserted;
      } finally {
        for (const attachment of attachments) attachment.bytes.fill(0);
      }
    },
    async import(files: File[], endorse?: Endorse) {
      check();
      const portable: PortableFile[] = [];
      let total = 0;
      let expandedBytes = 0;
      if (files.length > importLimits.files) throw new Error("Too many files");
      for (const file of files) {
        total += file.size;
        if (file.size > importLimits.bytes || total > importLimits.bytes)
          throw new Error("Import too large");
        if (file.name.toLowerCase().endsWith(".zip")) {
          const expanded = await archive(
            file,
            importLimits.bytes - expandedBytes,
            importLimits.files - portable.length,
          );
          expandedBytes += expanded.reduce(
            (sum, entry) => sum + entry.bytes.length,
            0,
          );
          portable.push(...expanded);
        } else {
          if (file.size > importLimits.fileBytes)
            throw new Error("File too large");
          expandedBytes += file.size;
          if (
            expandedBytes > importLimits.bytes ||
            portable.length >= importLimits.files
          )
            throw new Error("Import expansion exceeded limits");
          portable.push({
            path: file.webkitRelativePath || file.name,
            mime: file.type,
            bytes: new Uint8Array(await file.arrayBuffer()),
          });
        }
      }
      check();
      await session.import(portable, endorse);
      return list();
    },
    async export(mode = "exact") {
      check();
      const converted =
        mode === "obsidian" ? await session.exportObsidian() : null;
      const files = converted?.files ?? (await session.export());
      check();
      if (converted?.losses.length) {
        const taken = new Set(files.map((file) => file.path));
        let report = "NOTE-export-losses.txt";
        while (taken.has(report)) report = `_${report}`;
        files.push({
          path: report,
          bytes: new TextEncoder().encode(
            "MDX components/events cannot execute in Obsidian. Originals are retained as .mdx; .md fallback keeps source fenced.\n" +
              converted.losses.join("\n"),
          ),
        });
      }
      return zip(files);
    },
    async exportNote(note) {
      check();
      const files = await session.exportNote(note.id, note.source);
      check();
      const [source] = files;
      if (!source) throw new Error("Missing note");
      const name = source.path.split("/").at(-1) ?? source.path;
      if (files.length === 1)
        return new File([new Uint8Array(source.bytes)], name, {
          type: "text/markdown",
        });
      return new File([zip(files)], `${name.replace(/\.mdx?$/iu, "")}.zip`, {
        type: "application/zip",
      });
    },
    async history(id) {
      check();
      const note = (await list()).find((item) => item.id === id);
      if (!note) throw new Error("Missing note");
      const versions = await session.history(id);
      check();
      return versions.map((version) => ({
        ...note,
        source: version.source,
        revision: version.revision,
        historyId: version.historyId,
      }));
    },
    async restoreVersion(id: string, historyId: string, endorsed?: boolean) {
      check();
      await session.restoreVersion(id, historyId, endorsed);
      const restored = (await list()).find((note) => note.id === id);
      if (!restored) throw new Error("Missing note");
      return restored;
    },
    async search(query) {
      check();
      const results = await session.search(query);
      check();
      return results
        .filter((note) => !isInternalWritingPath(note.path))
        .map((note) => ({ id: note.id, line: note.line }));
    },
    async recovery() {
      check();
      const file = await session.createRecoveryFile();
      check();
      return new Blob([JSON.stringify(file)], { type: "application/json" });
    },
    lock() {
      locked = true;
      for (const unsubscribe of subscriptions) unsubscribe();
      preferenceWrites = Promise.resolve();
      session.lock();
    },
  } satisfies NoteRuntime;
}
