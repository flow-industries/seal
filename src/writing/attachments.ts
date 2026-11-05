import { boundedName, mediaMime, safeSegment } from "../vault/model.ts";

export const attachmentLimits = { files: 32, bytes: 8_000_000 } as const;
export interface AttachmentFile {
  name: string;
  mime: string;
  bytes: Uint8Array;
}
export interface AttachmentInsertion {
  id: string;
  path: string;
  name: string;
  mime: string;
  markdown: string;
}
export interface AttachmentPlan extends AttachmentFile {
  path: string;
  markdown: string;
}

export function filesFromTransfer(
  transfer: Pick<DataTransfer, "files"> | null,
): File[] {
  return transfer ? Array.from(transfer.files) : [];
}

/** The encoded Markdown link target of a vault path, relative to the note. */
export function attachmentTarget(path: string, notePath: string): string {
  const from = notePath.split("/").slice(0, -1);
  const to = path.split("/");
  while (from.length && to.length && from[0] === to[0]) {
    from.shift();
    to.shift();
  }
  return [...from.map(() => ".."), ...to]
    .map((segment) =>
      encodeURIComponent(segment).replace(
        /[!'()*]/gu,
        (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`,
      ),
    )
    .join("/");
}

export function attachmentMarkdown(
  path: string,
  notePath: string,
  name: string,
  mime: string,
): string {
  const relative = attachmentTarget(path, notePath);
  const label = name.replace(/[\\[\]]/gu, "\\$&");
  const embed =
    /^(?:image|audio|video)\//u.test(mime) || mime === "application/pdf";
  return `${embed ? "!" : ""}[${label}](${relative})`;
}

export function planAttachments(
  notePath: string,
  files: readonly AttachmentFile[],
  existingPaths: readonly string[],
): AttachmentPlan[] {
  notePath.split("/").forEach(safeSegment);
  if (!files.length || files.length > attachmentLimits.files)
    throw new Error("Choose between 1 and 32 attachments.");
  const size = files.reduce((total, file) => total + file.bytes.byteLength, 0);
  if (size > attachmentLimits.bytes)
    throw new Error("Attachments must total 8 MB or less.");
  const folder = [...notePath.split("/").slice(0, -1), "attachments"].join("/");
  const normalize = (path: string) =>
    path.normalize("NFC").toLocaleLowerCase("en-US");
  const occupied = new Set(existingPaths.map(normalize));
  return files.map((file) => {
    const original = safeSegment(file.name);
    const extension =
      original.lastIndexOf(".") > 0
        ? original.slice(original.lastIndexOf("."))
        : "";
    const base = extension ? original.slice(0, -extension.length) : original;
    let name = original;
    let count = 1;
    while (occupied.has(normalize(`${folder}/${name}`)))
      name = boundedName(base, ` ${++count}${extension}`);
    const path = `${folder}/${name}`;
    occupied.add(normalize(path));
    return {
      ...file,
      name,
      path,
      markdown: attachmentMarkdown(path, notePath, name, mediaMime(file.bytes)),
    };
  });
}

export async function readAttachmentFiles(
  files: readonly File[],
  checkContext: () => void,
): Promise<AttachmentFile[]> {
  checkContext();
  if (!files.length || files.length > attachmentLimits.files)
    throw new Error("Choose between 1 and 32 attachments.");
  if (
    files.reduce((total, file) => total + file.size, 0) > attachmentLimits.bytes
  )
    throw new Error("Attachments must total 8 MB or less.");
  for (const file of files) safeSegment(file.name);
  const result: AttachmentFile[] = [];
  try {
    for (const file of files) {
      checkContext();
      const bytes = new Uint8Array(await file.arrayBuffer());
      result.push({
        name: file.name,
        mime: file.type || mediaMime(bytes),
        bytes,
      });
      checkContext();
      if (bytes.byteLength !== file.size)
        throw new Error(
          "Attachment changed while being read. Select the file again.",
        );
    }
    return result;
  } catch (error) {
    for (const file of result) file.bytes.fill(0);
    throw error;
  }
}
