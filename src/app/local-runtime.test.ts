import { expect, test } from "bun:test";
import Dexie from "dexie";
import { IDBKeyRange, indexedDB } from "fake-indexeddb";
import { unzipSync, zipSync } from "fflate";
import { createSearchIndex } from "../../tests/search-index.ts";
import { createVaultKey } from "../crypto/index.ts";
import { createSession } from "../vault/session.ts";
import { localRuntime } from "./local-runtime.ts";

Dexie.dependencies.indexedDB = indexedDB;
Dexie.dependencies.IDBKeyRange = IDBKeyRange;

async function fixture() {
  const session = createSession({
    owner: "did:plc:import-regression",
    vault: crypto.randomUUID(),
    key: await createVaultKey(),
  });
  return { session, runtime: localRuntime(session) };
}

test("ZIP import/export preserves BOM mixed newlines and rejects unsafe paths atomically", async () => {
  const { session, runtime } = await fixture();
  try {
    const source = new TextEncoder().encode(
      "\ufeff# Title\r\nunknown:: value\nexport const A = () => <button />\r\n",
    );
    const bytes = zipSync({
      "Folder/exact.mdx": source,
      "Empty/": new Uint8Array(),
    });
    await runtime.import([new File([bytes], "vault.zip")]);
    const exported = unzipSync(
      new Uint8Array(await (await runtime.export()).arrayBuffer()),
    );
    expect(exported["Folder/exact.mdx"]).toEqual(source);
    expect(exported["Empty/"]).toEqual(new Uint8Array());
    const unsafe = zipSync({
      "../escape.md": new TextEncoder().encode("unsafe"),
      "safe.md": source,
    });
    await expect(
      runtime.import([new File([unsafe], "unsafe.zip")]),
    ).rejects.toThrow();
    expect((await runtime.list()).map((note) => note.path)).toEqual([
      "Folder/exact.mdx",
    ]);
    const raw = JSON.stringify(await session.database.items.toArray());
    expect(raw).not.toContain("unknown:: value");
    expect(raw).not.toContain("exact.mdx");
  } finally {
    runtime.lock();
  }
});

test("subscribing to trust loss after the runtime locked is a no-op", async () => {
  const { runtime } = await fixture();
  runtime.lock();
  const unsubscribe = runtime.subscribeTrustLoss?.(() => {});
  expect(unsubscribe).toBeFunction();
  unsubscribe?.();
});

test("corrupt archives leave existing encrypted notes intact", async () => {
  const { runtime } = await fixture();
  try {
    await runtime.import([new File(["retained"], "retained.md")]);
    await expect(
      runtime.import([new File([new Uint8Array([1, 2, 3])], "corrupt.zip")]),
    ).rejects.toThrow();
    expect((await runtime.list())[0]?.source).toBe("retained");
  } finally {
    runtime.lock();
  }
});

test("failed runtime rename and source save leaves folder graph and encrypted state unchanged", async () => {
  const { session, runtime } = await fixture();
  const id = crypto.randomUUID();
  try {
    await runtime.save({
      id,
      path: "original.md",
      source: "retained source",
      kind: "md",
    });
    const snapshot = await Promise.all([
      session.database.items.toArray(),
      session.database.outbox.toArray(),
      session.database.history.toArray(),
    ]);
    const fail = () => {
      throw new Error("Injected local storage failure");
    };
    session.database.outbox.hook("updating", fail);
    await expect(
      runtime.save({
        id,
        path: "New/Nested/renamed.md",
        source: "latest source",
        kind: "md",
      }),
    ).rejects.toThrow("Injected");
    session.database.outbox.hook("updating").unsubscribe(fail);
    expect(
      await Promise.all([
        session.database.items.toArray(),
        session.database.outbox.toArray(),
        session.database.history.toArray(),
      ]),
    ).toEqual(snapshot);
    expect(await session.listFolders()).toEqual([]);
    const [retained] = await runtime.list();
    expect(retained).toEqual({
      id,
      path: "original.md",
      source: "retained source",
      kind: "md",
      revision: expect.any(String),
      digest: expect.any(String),
      created: expect.any(String),
      modified: expect.any(String),
    });
    await runtime.save({
      id,
      path: "New/Nested/renamed.md",
      source: "latest source",
      kind: "md",
    });
    const [renamed] = await runtime.list();
    expect(renamed).toEqual({
      id,
      path: "New/Nested/renamed.md",
      source: "latest source",
      kind: "md",
      revision: expect.any(String),
      digest: expect.any(String),
      created: retained?.created,
      modified: expect.any(String),
    });
    expect(Date.parse(renamed?.modified ?? "")).toBeGreaterThanOrEqual(
      Date.parse(retained?.modified ?? ""),
    );
  } finally {
    runtime.lock();
  }
});

test("preferences persist encrypted with normal outbox and stay out of note surfaces after unlock", async () => {
  const { DEFAULT_WRITING_PREFERENCES, WRITING_PREFERENCES_PATH } =
    await import("../writing/preferences.ts");
  const key = await createVaultKey();
  const options = {
    owner: "did:plc:preferences",
    vault: crypto.randomUUID(),
    key,
    createSearchIndex,
  };
  const session = createSession(options);
  const runtime = localRuntime(session);
  const bookmarkId = "private-bookmarked-note-id";
  const preferences = {
    ...DEFAULT_WRITING_PREFERENCES,
    templatesFolder: "Private Templates",
    bookmarks: [bookmarkId],
    propertyTypes: { "[[original]]": "text" as const },
  };
  try {
    const initial = await runtime.preferences();
    initial.bookmarks.push("caller-mutation");
    expect((await runtime.preferences()).bookmarks).toEqual([]);
    expect(await session.database.items.count()).toBe(0);
    await runtime.savePreferences(preferences);
    const settings = (await session.listNotes()).find(
      (note) => note.path === WRITING_PREFERENCES_PATH,
    );
    if (!settings) throw new Error("Expected settings note");
    expect(await session.database.outbox.get(settings.id)).toBeDefined();
    const raw = JSON.stringify(
      await Promise.all([
        session.database.items.toArray(),
        session.database.outbox.toArray(),
        session.database.history.toArray(),
      ]),
    );
    for (const privateValue of [
      bookmarkId,
      "Private Templates",
      "[[original]]",
      "settings.md",
    ])
      expect(raw).not.toContain(privateValue);
    expect(await runtime.list()).toEqual([]);
    expect(await runtime.folders()).toEqual([]);
    expect(await runtime.search("private")).toEqual([]);
    expect(await session.search("private")).toEqual([]);
    const id = crypto.randomUUID();
    await runtime.save({
      id,
      path: "original.md",
      source: "real note",
      kind: "md",
    });
    await runtime.save({
      id,
      path: "renamed.md",
      source: "real note",
      kind: "md",
    });
    expect(await runtime.preferences()).toEqual(preferences);
    runtime.lock();
    await expect(runtime.preferences()).rejects.toThrow("locked");
    const reopenedSession = createSession(options);
    const reopened = localRuntime(reopenedSession);
    try {
      expect(await reopened.preferences()).toEqual(preferences);
      expect((await reopened.list()).map((note) => note.path)).toEqual([
        "renamed.md",
      ]);
      await reopenedSession.remove(settings.id);
      expect(await reopened.trash()).toEqual([]);
    } finally {
      reopened.lock();
    }
  } finally {
    runtime.lock();
  }
});

test("invalid preferences cannot replace a valid encrypted revision and queued saves keep one settings note", async () => {
  const { DEFAULT_WRITING_PREFERENCES } = await import(
    "../writing/preferences.ts"
  );
  const { session, runtime } = await fixture();
  try {
    await Promise.all([
      runtime.savePreferences({
        ...DEFAULT_WRITING_PREFERENCES,
        bookmarks: ["first"],
      }),
      runtime.savePreferences({
        ...DEFAULT_WRITING_PREFERENCES,
        bookmarks: ["second"],
      }),
    ]);
    expect(await session.listNotes()).toHaveLength(1);
    expect((await runtime.preferences()).bookmarks).toEqual(["second"]);
    const snapshot = await session.database.items.toArray();
    await expect(
      runtime.savePreferences({
        ...DEFAULT_WRITING_PREFERENCES,
        dailyFolder: "../unsafe",
      }),
    ).rejects.toThrow();
    expect(await session.database.items.toArray()).toEqual(snapshot);
    await expect(
      runtime.save({
        id: crypto.randomUUID(),
        path: ".NOTE/settings.md",
        source: "bad",
        kind: "md",
      }),
    ).rejects.toThrow("reserved");
    const [settings] = await session.listNotes();
    if (!settings) throw new Error("Expected settings note");
    await session.saveNote(settings.id, settings.path, '{"version":999}');
    await expect(runtime.preferences()).rejects.toThrow("unsupported version");
  } finally {
    runtime.lock();
  }
});

test("preferences reads and queued writes reject when the vault locks during asynchronous storage", async () => {
  const { DEFAULT_WRITING_PREFERENCES } = await import(
    "../writing/preferences.ts"
  );
  const { session, runtime } = await fixture();
  await runtime.savePreferences(DEFAULT_WRITING_PREFERENCES);
  const originalMetadata = session.readMetadata.bind(session);
  session.readMetadata = async () => {
    const snapshot = await originalMetadata();
    return {
      ...snapshot,
      async read(id) {
        const source = await snapshot.read(id);
        runtime.lock();
        return source;
      },
    };
  };
  await expect(runtime.preferences()).rejects.toThrow("locked");
  const second = await fixture();
  const queued = second.runtime.savePreferences(DEFAULT_WRITING_PREFERENCES);
  second.runtime.lock();
  await expect(queued).rejects.toThrow("locked");
});

test("Obsidian export keeps MDX originals, adds fenced fallbacks and a loss report", async () => {
  const { runtime } = await fixture();
  try {
    const source = new TextEncoder().encode("# Live\n\n<Counter />\n");
    await runtime.import([
      new File([source], "Live.mdx"),
      new File(["taken"], "NOTE-export-losses.txt"),
    ]);
    const exported = unzipSync(
      new Uint8Array(await (await runtime.export("obsidian")).arrayBuffer()),
    );
    expect(Object.keys(exported).sort()).toEqual([
      "Live.md",
      "Live.mdx",
      "NOTE-export-losses.txt",
      "_NOTE-export-losses.txt",
    ]);
    expect(exported["Live.mdx"]).toEqual(source);
    expect(new TextDecoder().decode(exported["Live.md"])).toBe(
      "```mdx\n# Live\n\n<Counter />\n\n```\n",
    );
    expect(
      new TextDecoder().decode(exported["_NOTE-export-losses.txt"]),
    ).toEndWith("\nLive.mdx");
  } finally {
    runtime.lock();
  }
});

test("note download is the exact source alone, or a ZIP with its attachments and directly embedded notes", async () => {
  const { runtime } = await fixture();
  const encoder = new TextEncoder();
  const exact = encoder.encode("\ufeff# Plain\r\n\r\nNo attachments.\r\n");
  const media =
    "# Media\n\n![[pixel.png]]\n\n![Relative](../assets/pixel.png)\n\n[Spec](../assets/spec.pdf)\n\n[[Plain]]\n\n![[Other]]\n";
  const other = encoder.encode(
    "\ufeff# Other\r\n\r\n![[other.png]]\r\n\r\n![[Third]]\r\n",
  );
  const pixel = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10, 1, 2]);
  const pdf = encoder.encode("%PDF-1.7\nbody");
  try {
    const vault = zipSync({
      "Notes/Plain.md": exact,
      "Notes/Media.md": encoder.encode(media),
      "assets/pixel.png": pixel,
      "assets/spec.pdf": pdf,
      "assets/unused.png": pixel,
      "Notes/Other.md": other,
      "assets/other.png": pixel,
      "Notes/Third.md": encoder.encode("# Third\n\n![[third.png]]\n"),
      "assets/third.png": pixel,
    });
    await runtime.import([new File([vault], "vault.zip")]);
    const notes = new Map(
      (await runtime.list()).map((item) => [item.path, item]),
    );
    const note = notes.get("Notes/Media.md");
    const plain = notes.get("Notes/Plain.md");
    if (!note || !plain) throw new Error("Missing fixture notes");
    const download = await runtime.exportNote(plain);
    expect(download.name).toBe("Plain.md");
    expect(new Uint8Array(await download.arrayBuffer())).toEqual(exact);

    const archive = await runtime.exportNote({
      ...note,
      source: `${note.source}Unsaved edit\n`,
    });
    expect(archive.name).toBe("Media.zip");
    const files = unzipSync(new Uint8Array(await archive.arrayBuffer()));
    expect(Object.keys(files).sort()).toEqual([
      "Notes/Media.md",
      "Notes/Other.md",
      "assets/other.png",
      "assets/pixel.png",
      "assets/spec.pdf",
    ]);
    expect(files["Notes/Other.md"]).toEqual(other);
    expect(new TextDecoder().decode(files["Notes/Media.md"])).toBe(
      `${media}Unsaved edit\n`,
    );
    expect(files["assets/pixel.png"]).toEqual(pixel);
    expect(files["assets/spec.pdf"]).toEqual(pdf);
  } finally {
    runtime.lock();
  }
  await expect(
    runtime.exportNote({ id: crypto.randomUUID(), source: "" }),
  ).rejects.toThrow("locked");
});

test("reading notes and preferences skips unselected attachment and trash chunks", async () => {
  const session = createSession({
    owner: "did:plc:read-model",
    vault: crypto.randomUUID(),
    key: await createVaultKey(),
  });
  const runtime = localRuntime(session);
  try {
    await session.import([
      { path: "text.md", bytes: new TextEncoder().encode("body") },
      { path: "unselected.bin", bytes: new Uint8Array(80_000) },
    ]);
    const discarded = await session.create("discarded.md");
    await session.save(discarded, "x".repeat(70_000));
    await session.remove(discarded);
    const rows = await session.database.items.toArray();
    const chunked = rows.filter((row) => row.encryptedBlobs?.length);
    expect(chunked).toHaveLength(2);
    await session.database.items.bulkPut(
      chunked.map((row) => ({ ...row, encryptedBlobs: [] })),
    );
    expect((await session.readMetadata()).trash.map((note) => note.id)).toEqual(
      [discarded],
    );
    expect((await runtime.preferences()).bookmarks).toEqual([]);
    await expect(runtime.trash()).rejects.toThrow("Missing encrypted chunks");
    const first = await runtime.read();
    expect(first.notes.map((note) => note.source)).toEqual(["body"]);
    expect(first.notes[0]?.revision).toBeDefined();
    const id = first.notes[0]!.id;
    await runtime.save({ ...first.notes[0]!, source: "updated" });
    const second = await runtime.read();
    expect(second.notes[0]?.source).toBe("updated");
    expect(second.notes[0]?.revision).not.toBe(first.notes[0]?.revision);
    expect(second.notes[0]?.id).toBe(id);
  } finally {
    runtime.lock();
    await session.database.delete();
  }
});
