import { expect, test } from "bun:test";
import Dexie from "dexie";
import { IDBKeyRange, indexedDB } from "fake-indexeddb";
import { localRuntime } from "../app/local-runtime.ts";
import { createVaultKey } from "../crypto/index.ts";
import { validExecutionInput } from "../render/protocol";
import { mediaMime } from "../vault/model.ts";
import { createSession } from "../vault/session.ts";
import {
  attachmentMarkdown,
  filesFromTransfer,
  planAttachments,
  readAttachmentFiles,
} from "./attachments.ts";

Dexie.dependencies.indexedDB = indexedDB;
Dexie.dependencies.IDBKeyRange = IDBKeyRange;
const png = () => new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]);
const pdf = () =>
  new TextEncoder().encode(
    "%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n",
  );
async function fixture() {
  const session = createSession({
    owner: "did:plc:attachments",
    vault: crypto.randomUUID(),
    key: await createVaultKey(),
  });
  const runtime = localRuntime(session);
  const id = await session.create("Projects/Plan.md");
  const note = { id, path: "Projects/Plan.md" };
  return { session, runtime, note };
}

test("attachment planning handles case/Unicode collisions and encodes Markdown-sensitive paths", () => {
  const files = [
    { name: "Café (one)[2].png", mime: "image/png", bytes: png() },
    { name: "Café (one)[2].png", mime: "image/png", bytes: png() },
  ];
  const result = planAttachments("Notes/Plan.md", files, [
    "Notes/attachments/CAFE\u0301 (ONE)[2].PNG",
  ]);
  expect(result.map((file) => file.name)).toEqual([
    "Café (one)[2] 2.png",
    "Café (one)[2] 3.png",
  ]);
  expect(result[0]?.markdown).toBe(
    "![Café (one)\\[2\\] 2.png](attachments/Caf%C3%A9%20%28one%29%5B2%5D%202.png)",
  );
  expect(
    attachmentMarkdown(
      "Other/a b.txt",
      "Notes/Plan.md",
      "a b.txt",
      "text/plain",
    ),
  ).toBe("[a b.txt](../Other/a%20b.txt)");
  expect(() =>
    planAttachments(
      "Notes/Plan.md",
      [{ name: "../escape.png", mime: "image/png", bytes: png() }],
      [],
    ),
  ).toThrow("Unsafe");
});

test("PDF signature detection is bounded and unsupported/spoofed files stay download links", () => {
  expect(mediaMime(pdf())).toBe("application/pdf");
  expect(mediaMime(new TextEncoder().encode("%PDF-9.8\n"))).toBe(
    "application/octet-stream",
  );
  expect(mediaMime(new TextEncoder().encode("<html>%PDF-1.7"))).toBe(
    "application/octet-stream",
  );
  expect(
    planAttachments(
      "Plan.md",
      [
        {
          name: "fake.png",
          mime: "image/png",
          bytes: new TextEncoder().encode("not an image"),
        },
      ],
      [],
    )[0]?.markdown,
  ).toBe("[fake.png](attachments/fake.png)");
  expect(
    validExecutionInput({
      source: "",
      assets: [
        { id: "pdf", mime: "application/pdf", bytes: pdf(), path: "a.pdf" },
      ],
    }),
  ).toBe(true);
});

test("file-only transfer leaves ordinary text paste alone and file read failures do not mutate inputs", async () => {
  expect(filesFromTransfer(null)).toEqual([]);
  const file = new File([png()], "image.png", { type: "image/png" });
  let checks = 0;
  const prepared = await readAttachmentFiles([file], () => {
    checks++;
  });
  expect(checks).toBeGreaterThan(1);
  expect(prepared[0]?.bytes).toEqual(png());
  prepared[0]?.bytes.fill(0);
  expect(new Uint8Array(await file.arrayBuffer())).toEqual(png());
  await expect(
    readAttachmentFiles(
      [new File([new Uint8Array(8_000_001)], "large.bin")],
      () => {},
    ),
  ).rejects.toThrow("8 MB");
  class FailedFile extends File {
    override async arrayBuffer(): Promise<ArrayBuffer> {
      throw new Error("Read failed");
    }
  }
  await expect(
    readAttachmentFiles([file, new FailedFile([], "failed.txt")], () => {}),
  ).rejects.toThrow("Read failed");
  expect(new Uint8Array(await file.arrayBuffer())).toEqual(png());
});

test("attachment import saves encrypted original MIME/bytes atomically without rewriting note text", async () => {
  const { session, runtime, note } = await fixture();
  try {
    await session.save(note.id, "Retained note text");
    const result = await runtime.addAttachments?.(note, [
      new File([png()], "image.png", { type: "image/png" }),
      new File([pdf()], "plan.pdf", { type: "application/pdf" }),
    ]);
    expect(result?.map((item) => item.path)).toEqual([
      "Projects/attachments/image.png",
      "Projects/attachments/plan.pdf",
    ]);
    expect(await session.open(note.id)).toBe("Retained note text");
    const exported = await session.export();
    expect(
      exported.find((file) => file.path.endsWith("image.png"))?.bytes,
    ).toEqual(png());
    expect(exported.find((file) => file.path.endsWith("plan.pdf"))?.mime).toBe(
      "application/pdf",
    );
    const selected = await session.assetsForNote(
      note.id,
      "![[attachments/plan.pdf#page=2&height=400]]",
    );
    expect(selected[0]?.mime).toBe("application/pdf");
    expect(selected[0]?.paths).toEqual(["attachments/plan.pdf"]);
    expect(selected[0]?.bytes).toEqual(pdf());
    const serialized = JSON.stringify(await session.database.items.toArray());
    expect(serialized).not.toContain("plan.pdf");
    expect(serialized).not.toContain("application/pdf");
    const again = await runtime.addAttachments?.(note, [
      new File([png()], "IMAGE.png", { type: "image/png" }),
    ]);
    expect(again?.[0]?.name).toBe("IMAGE 2.png");
  } finally {
    runtime.lock();
  }
});

test("storage failure and stale note context leave note and attachment graph unchanged", async () => {
  const { session, runtime, note } = await fixture();
  try {
    const baseline = await session.database.items.toArray();
    const fail = () => {
      throw new Error("Storage failed");
    };
    session.database.outbox.hook("creating", fail);
    await expect(
      runtime.addAttachments?.(note, [new File([png()], "image.png")]),
    ).rejects.toThrow("Storage failed");
    session.database.outbox.hook("creating").unsubscribe(fail);
    expect(await session.database.items.toArray()).toEqual(baseline);
    await session.rename(note.id, "Other.md");
    await expect(
      runtime.addAttachments?.(note, [new File([png()], "image.png")]),
    ).rejects.toThrow("note moved");
    expect(
      (await session.export()).some((file) => file.path.endsWith("image.png")),
    ).toBe(false);
  } finally {
    runtime.lock();
  }
});

test("lock during asynchronous file read cancels attachment writes", async () => {
  const { session, runtime, note } = await fixture();
  let finish: ((value: ArrayBuffer) => void) | undefined;
  class DelayedFile extends File {
    override arrayBuffer(): Promise<ArrayBuffer> {
      return new Promise((resolve) => {
        finish = resolve;
      });
    }
  }
  const baseline = await session.database.items.count();
  const pending = runtime.addAttachments?.(note, [
    new DelayedFile([png()], "image.png"),
  ]);
  runtime.lock();
  finish?.(png().buffer);
  await expect(pending).rejects.toThrow("Vault locked");
  await session.database.open();
  expect(await session.database.items.count()).toBe(baseline);
  session.database.close();
});

test("ordinary Markdown never discovers executable modules and generic attachments use inert preview MIME", async () => {
  const { session, runtime, note } = await fixture();
  try {
    const original = new File(
      ["<script>never execute</script>"],
      "snippet.html",
      { type: "text/html" },
    );
    const [file] = (await runtime.addAttachments?.(note, [original])) ?? [];
    if (!file) throw new Error("Missing attachment");
    const selected = await session.assetsForNote(
      note.id,
      `${file.markdown}\nimport Broken from './missing.ts'\n<unfinished`,
    );
    expect(selected).toHaveLength(1);
    expect(selected[0]?.mime).toBe("application/octet-stream");
    expect(
      (await session.export()).find((entry) =>
        entry.path.endsWith("snippet.html"),
      )?.mime,
    ).toBe(original.type);
    expect(mediaMime(new TextEncoder().encode("RIFF1234WAVE"))).toBe(
      "audio/wav",
    );
    expect(mediaMime(new TextEncoder().encode("OggS1234"))).toBe("audio/ogg");
    expect(mediaMime(new TextEncoder().encode("fLaC1234"))).toBe("audio/flac");
  } finally {
    runtime.lock();
  }
});
