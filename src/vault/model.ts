export type ItemKind = "note" | "folder" | "asset";
export interface VaultItem {
  id: string;
  kind: ItemKind;
  name: string;
  parent: string | null;
  createdAt: string;
  updatedAt: string;
  format?: "md" | "mdx";
  mime?: string;
  bytes: Uint8Array;
  trashed?: boolean;
  permanent?: boolean;
  revisionCounter?: number;
}
export const newId = () => crypto.randomUUID();
/** Case-insensitive keys for paths, aliases and headings, preserving Unicode casing and normalization. */
export function canonicalLinkKey(text: string): string {
  return /^\p{ASCII}*$/u.test(text)
    ? text.toLowerCase()
    : text.normalize("NFC").toLocaleLowerCase("en-US");
}
export function safeSegment(name: string): string {
  if (
    !name ||
    new TextEncoder().encode(name).length > 255 ||
    name === "." ||
    name === ".." ||
    /[/\\<>:"|?*]/u.test(name) ||
    Array.from(name).some(
      (char) => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127,
    ) ||
    /[. ]$/u.test(name) ||
    /^[A-Za-z]:/u.test(name) ||
    /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/iu.test(name)
  )
    throw new Error("Unsafe path segment");
  return name;
}
export function boundedName(base: string, suffix: string): string {
  const characters = Array.from(base);
  while (
    new TextEncoder().encode(`${characters.join("")}${suffix}`).length > 255
  ) {
    if (!characters.length) throw new Error("Name suffix exceeds bounds");
    characters.pop();
  }
  return `${characters.join("")}${suffix}`;
}
export function paths(items: readonly VaultItem[]): Map<string, string> {
  const byId = new Map(items.map((item) => [item.id, item]));
  if (byId.size !== items.length) throw new Error("Duplicate item identifier");
  const result = new Map<string, string>();
  const visiting = new Set<string>();
  const derive = (item: VaultItem): string => {
    const cached = result.get(item.id);
    if (cached) return cached;
    if (visiting.has(item.id)) throw new Error("Folder cycle");
    if (visiting.size >= 64) throw new Error("Folder path depth exceeded");
    visiting.add(item.id);
    const parent = item.parent === null ? null : byId.get(item.parent);
    if (item.parent !== null && (!parent || parent.kind !== "folder"))
      throw new Error("Missing folder");
    const path = `${parent ? `${derive(parent)}/` : ""}${safeSegment(item.name)}`;
    visiting.delete(item.id);
    result.set(item.id, path);
    return path;
  };
  const collisions = new Set<string>();
  for (const item of items) {
    const path = canonicalLinkKey(derive(item));
    if (collisions.has(path)) throw new Error("Filesystem path collision");
    collisions.add(path);
  }
  return result;
}
export function mediaMime(bytes: Uint8Array): string {
  const prefix = Array.from(bytes.slice(0, 12));
  if (prefix.slice(0, 8).join() === "137,80,78,71,13,10,26,10")
    return "image/png";
  if (prefix[0] === 255 && prefix[1] === 216 && prefix[2] === 255)
    return "image/jpeg";
  const text = new TextDecoder().decode(bytes.slice(0, 12));
  if (/^%PDF-(?:1\.[0-7]|2\.0)(?:[\r\n\t ]|$)/u.test(text))
    return "application/pdf";
  if (text.startsWith("GIF87a") || text.startsWith("GIF89a"))
    return "image/gif";
  if (text.startsWith("RIFF") && text.slice(8) === "WEBP") return "image/webp";
  if (text.startsWith("RIFF") && text.slice(8) === "WAVE") return "audio/wav";
  if (text.startsWith("OggS")) return "audio/ogg";
  if (text.startsWith("fLaC")) return "audio/flac";
  if (
    prefix.slice(0, 4).join() === "26,69,223,163" &&
    new TextDecoder().decode(bytes.slice(0, 4096)).includes("webm")
  )
    return "video/webm";
  if (
    text.startsWith("ID3") ||
    (prefix[0] === 255 && ((prefix[1] ?? 0) & 224) === 224)
  )
    return "audio/mpeg";
  if (text.slice(4, 8) === "ftyp")
    return text.slice(8).startsWith("M4A") ? "audio/mp4" : "video/mp4";
  return "application/octet-stream";
}
export interface PortableFile {
  path: string;
  bytes: Uint8Array;
  directory?: boolean;
  mime?: string;
}
export const importLimits = {
  files: 10_000,
  bytes: 512_000_000,
  fileBytes: 32_000_000,
};
export function importFiles(files: readonly PortableFile[]): VaultItem[] {
  if (files.length > importLimits.files)
    throw new Error("Import file count exceeded");
  let total = 0;
  const prepared = files.map((file) => {
    if (file.path.length > 4096) throw new Error("Import path exceeds bounds");
    if (file.path.startsWith("/") || file.path.includes("\\"))
      throw new Error("Unsafe import path");
    const segments = file.path.replace(/\/$/u, "").split("/").map(safeSegment);
    if (segments.length > 64)
      throw new Error("Import path depth exceeds bounds");
    total += file.bytes.byteLength;
    if (
      file.bytes.byteLength > importLimits.fileBytes ||
      total > importLimits.bytes
    )
      throw new Error("Import byte limit exceeded");
    if (segments.includes(".obsidian")) return null;
    return { file, segments };
  });
  const items: VaultItem[] = [];
  const folders = new Map<string, string>();
  const timestamp = new Date().toISOString();
  for (const entry of prepared) {
    if (!entry) continue;
    let parent: string | null = null;
    const folderCount = entry.file.directory
      ? entry.segments.length
      : entry.segments.length - 1;
    for (let index = 0; index < folderCount; index++) {
      const path = entry.segments.slice(0, index + 1).join("/");
      let id = folders.get(path);
      if (!id) {
        id = newId();
        folders.set(path, id);
        items.push({
          id,
          kind: "folder",
          name: entry.segments[index]!,
          parent,
          createdAt: timestamp,
          updatedAt: timestamp,
          bytes: new Uint8Array(),
        });
      }
      parent = id;
    }
    if (entry.file.directory) continue;
    const name = entry.segments.at(-1)!;
    const format = /\.mdx$/iu.test(name)
      ? "mdx"
      : /\.md$/iu.test(name)
        ? "md"
        : undefined;
    if (format)
      new TextDecoder("utf-8", { fatal: true }).decode(entry.file.bytes);
    items.push({
      id: newId(),
      kind: format ? "note" : "asset",
      name,
      parent,
      createdAt: timestamp,
      updatedAt: timestamp,
      ...(format
        ? { format }
        : { mime: entry.file.mime || mediaMime(entry.file.bytes) }),
      bytes: entry.file.bytes.slice(),
    });
  }
  if (items.length > importLimits.files)
    throw new Error("Imported item count exceeded");
  paths(items);
  return items;
}
export function exportFiles(items: readonly VaultItem[]): PortableFile[] {
  const index = paths(items);
  return items.map((item) => {
    const file: PortableFile = {
      path: index.get(item.id)!,
      bytes: item.bytes.slice(),
    };
    if (item.kind === "folder") file.directory = true;
    if (item.mime) file.mime = item.mime;
    return file;
  });
}
export function obsidianExport(items: readonly VaultItem[]): {
  files: PortableFile[];
  losses: string[];
} {
  const files = exportFiles(items);
  const losses: string[] = [];
  for (const file of [...files]) {
    if (!file.path.endsWith(".mdx")) continue;
    losses.push(file.path);
    const source = new TextDecoder().decode(file.bytes);
    const fence = "`".repeat(
      Math.max(
        3,
        ...Array.from(source.matchAll(/`+/gu), (match) => match[0].length + 1),
      ),
    );
    files.push({
      path: `${file.path.slice(0, -4)}.md`,
      bytes: new TextEncoder().encode(`${fence}mdx\n${source}\n${fence}\n`),
    });
  }
  const names = new Set<string>();
  for (const file of files) {
    const name = file.path.normalize("NFC").toLowerCase();
    if (names.has(name)) throw new Error("Converted export path collision");
    names.add(name);
  }
  // biome-ignore lint/plugin: Return the declared portable export contract.
  return { files, losses };
}
