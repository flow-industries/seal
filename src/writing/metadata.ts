import { isMap, isNode, isScalar, parseDocument, stringify } from "yaml";
import { z } from "zod";
import { gfmParser } from "../vault/table-syntax.ts";
import { maskMarkdownComments } from "./comments.ts";

export interface FrontmatterRange {
  start: number;
  contentStart: number;
  contentEnd: number;
  end: number;
}
export type PropertyType =
  | "text"
  | "number"
  | "checkbox"
  | "date"
  | "datetime"
  | "tags"
  | "list"
  | "unknown";
export interface NoteProperty {
  key: string;
  value: string | number | boolean | string[] | null;
  type: PropertyType;
  expectedType?: EditablePropertyType;
}
export interface NoteMetadata {
  frontmatter: FrontmatterRange | null;
  properties: NoteProperty[];
  aliases: string[];
  tags: string[];
  error: string | null;
}

export function frontmatterRange(source: string): FrontmatterRange | null {
  const opening = /^(?:\uFEFF)?---[ \t]*\r?\n/u.exec(source);
  if (!opening) return null;
  const closing = /^(?:---|\.\.\.)[ \t]*(?:\r?\n|$)/gmu;
  closing.lastIndex = opening[0].length;
  const match = closing.exec(source);
  if (!match)
    return {
      start: 0,
      contentStart: opening[0].length,
      contentEnd: source.length,
      end: source.length,
    };
  return {
    start: 0,
    contentStart: opening[0].length,
    contentEnd: match.index,
    end: match.index + match[0].length,
  };
}

const dateSchema = z.iso.date();
const datetimeSchema = z.iso.datetime({ local: true, offset: true });

const propertySchema = z.union([
  z.boolean().transform((value) => ({ value, type: "checkbox" as const })),
  z
    .number()
    .finite()
    .transform((value) => ({ value, type: "number" as const })),
  z.string().transform((value) => ({
    value,
    type: dateSchema.safeParse(value).success
      ? ("date" as const)
      : datetimeSchema.safeParse(value).success
        ? ("datetime" as const)
        : ("text" as const),
  })),
  z
    .array(
      z
        .string()
        .min(1)
        .regex(/^[^\r\n]*$/u),
    )
    .transform((value) => ({ value, type: "list" as const })),
  z.unknown().transform(() => ({ value: null, type: "unknown" as const })),
]);
const propertiesSchema = z.record(z.string(), propertySchema);
const metadataStrings = z.union([
  z.string().transform((value) => [value]),
  z.array(z.string()),
  z.unknown().transform(() => []),
]);
const editableValue = z.union([
  z.string(),
  z.number().finite(),
  z.boolean(),
  z.array(z.string()),
]);
function parseFrontmatter(
  source: string,
  range = frontmatterRange(source),
  keepSourceTokens = true,
) {
  if (!range) return { range, document: null };
  if (range.contentEnd === source.length)
    throw new Error("Close frontmatter with --- before editing properties.");
  const document = parseDocument(
    source.slice(range.contentStart, range.contentEnd),
    { keepSourceTokens },
  );
  if (
    document.errors.length ||
    (document.contents !== null && !isMap(document.contents))
  )
    throw new Error(
      "Fix the YAML frontmatter in source before editing properties.",
    );
  return { range, document };
}

export function readNoteFrontmatter(
  source: string,
  propertyTypes: PropertyTypes = {},
): NoteMetadata {
  const result: NoteMetadata = {
    frontmatter: frontmatterRange(source),
    properties: [],
    aliases: [],
    tags: [],
    error: null,
  };
  try {
    const { document } = parseFrontmatter(source, result.frontmatter, false);
    const values = document
      ? propertiesSchema.parse(document.toJS({ maxAliasCount: 50 }) ?? {})
      : null;
    if (values) {
      result.properties = Object.entries(values).map(([key, property]) => {
        const preferred =
          propertyTypes[key] ??
          (key === "tags" || key === "tag" ? "tags" : undefined);
        if (!preferred) return { key, ...property };
        try {
          return {
            key,
            value: convertPropertyValue({ key, ...property }, preferred),
            type: preferred,
          };
        } catch {
          return { key, ...property, type: "unknown", expectedType: preferred };
        }
      });
      result.aliases = [
        ...new Set(
          [
            ...metadataStrings.parse(values.aliases?.value),
            ...metadataStrings.parse(values.alias?.value),
          ].filter(Boolean),
        ),
      ];
      result.tags = [
        ...metadataStrings.parse(values.tags?.value),
        ...metadataStrings.parse(values.tag?.value),
      ]
        .flatMap((value) => value.split(/[,\s]+/u))
        .map((value) => value.replace(/^#/u, ""))
        .filter(Boolean);
    }
  } catch (error) {
    result.error =
      error instanceof Error ? error.message : "Unable to read frontmatter.";
  }
  result.tags = [...new Set(result.tags)];
  return result;
}

export function readNoteMetadata(
  source: string,
  propertyTypes: PropertyTypes = {},
): NoteMetadata {
  const result = readNoteFrontmatter(source, propertyTypes);
  const bodyStart = result.frontmatter?.end ?? 0;
  const body = maskMarkdownComments(source.slice(bodyStart));
  const candidates = [
    ...body.matchAll(
      /(?<![\p{L}\p{N}_/\\])#([\p{L}\p{N}_-]+(?:\/[\p{L}\p{N}_-]+)*)/gu,
    ),
  ];
  if (!candidates.length) return result;
  const excluded: { from: number; to: number }[] = [];
  gfmParser.parse(body).iterate({
    enter(node) {
      if (
        [
          "FencedCode",
          "CodeBlock",
          "InlineCode",
          "HTMLBlock",
          "CommentBlock",
          "Comment",
          "HTMLTag",
          "URL",
          "Link",
          "Image",
        ].includes(node.name)
      ) {
        excluded.push({ from: node.from, to: node.to });
        return false;
      }
    },
  });
  for (const match of candidates) {
    if (
      !/[\p{L}_-]/u.test(match[1] ?? "") ||
      excluded.some(
        (range) => match.index >= range.from && match.index < range.to,
      )
    )
      continue;
    result.tags.push(match[1] ?? "");
  }
  result.tags = [...new Set(result.tags)];
  return result;
}

export function updateNoteProperty(
  source: string,
  key: string,
  value: string | number | boolean | string[],
): string {
  if (!key.trim() || key.includes("\n") || key.includes("\r"))
    throw new Error("Enter a property name.");
  if (!editableValue.safeParse(value).success)
    throw new Error("Enter a finite number.");
  const { range, document } = parseFrontmatter(source);
  const newline = source.includes("\r\n") ? "\r\n" : "\n";
  const encoded = stringify(value, {
    collectionStyle: "flow",
    lineWidth: 0,
    defaultStringType: "QUOTE_DOUBLE",
  }).trimEnd();
  if (!range || !document) {
    const bom = source.startsWith("\uFEFF") ? "\uFEFF" : "";
    return `${bom}---${newline}${stringify({ [key]: value }, { collectionStyle: "block", lineWidth: 0 }).replace(/\n/gu, newline)}---${newline}${source.slice(bom.length)}`;
  }
  if (isMap(document.contents) && document.contents.flow)
    throw new Error("Edit flow-style frontmatter in source.");
  const pair = isMap(document.contents)
    ? document.contents.items.find(
        (item) => isScalar(item.key) && item.key.value === key,
      )
    : undefined;
  if (!pair) {
    const entry = `${stringify(key).trimEnd()}: ${encoded}${newline}`;
    return (
      source.slice(0, range.contentEnd) + entry + source.slice(range.contentEnd)
    );
  }
  if (!pair.value || !("range" in pair.value) || !pair.value.range)
    throw new Error("Edit this property in source.");
  const [from, to] = pair.value.range;
  const old = source.slice(range.contentStart + from, range.contentStart + to);
  const suffix = old.match(/\r?\n$/u)?.[0] ?? "";
  const prefix = from === to ? " " : "";
  const updated =
    source.slice(0, range.contentStart + from) +
    prefix +
    encoded +
    suffix +
    source.slice(range.contentStart + to);
  parseFrontmatter(updated).document?.toJS({ maxAliasCount: 50 });
  return updated;
}

export function removeNoteProperty(source: string, key: string): string {
  const { range, document } = parseFrontmatter(source);
  if (!range || !document || !isMap(document.contents)) return source;
  if (document.contents.flow)
    throw new Error("Edit flow-style frontmatter in source.");
  const pair = document.contents.items.find(
    (item) => isScalar(item.key) && item.key.value === key,
  );
  if (!pair || !isScalar(pair.key) || !pair.key.range) return source;
  const valueEnd =
    pair.value && "range" in pair.value ? pair.value.range?.[2] : undefined;
  const from = range.contentStart + pair.key.range[0];
  const end = range.contentStart + (valueEnd ?? pair.key.range[2]);
  const lineStart = source.lastIndexOf("\n", from - 1) + 1;
  const nextLine = source.indexOf("\n", end);
  const to = source[end - 1] === "\n" ? end : nextLine < 0 ? end : nextLine + 1;
  const updated = source.slice(0, lineStart) + source.slice(to);
  parseFrontmatter(updated).document?.toJS({ maxAliasCount: 50 });
  return updated;
}

export const editablePropertyTypeSchema = z.enum([
  "text",
  "number",
  "checkbox",
  "date",
  "datetime",
  "list",
  "tags",
]);
export type EditablePropertyType = z.infer<typeof editablePropertyTypeSchema>;
export const propertyTypesSchema = z.record(
  z.string().min(1).max(256),
  editablePropertyTypeSchema,
);
export type PropertyTypes = z.infer<typeof propertyTypesSchema>;

export function convertPropertyValue(
  property: NoteProperty,
  type: EditablePropertyType,
): string | number | boolean | string[] {
  if (property.type === "unknown")
    throw new Error(
      "Nested or unsupported properties must be edited in source.",
    );
  const value = property.value;
  if (type === "list" || type === "tags") {
    const values = metadataStrings.parse(value);
    if (!values.length && value !== "" && !Array.isArray(value))
      throw new Error("Convert this value to text before making a list.");
    if (type === "list") return values;
    const tags = values
      .flatMap((entry) => entry.split(/[,\s]+/u))
      .map((entry) => entry.replace(/^#/u, ""))
      .filter(Boolean);
    if (
      tags.some(
        (entry) =>
          !/^[\p{L}\p{N}_-]+(?:\/[\p{L}\p{N}_-]+)*$/u.test(entry) ||
          !/[\p{L}_-]/u.test(entry),
      )
    )
      throw new Error(
        "Tags use letters, numbers, underscores, hyphens, and nested paths.",
      );
    return [...new Set(tags)];
  }
  if (Array.isArray(value) && value.length > 1)
    throw new Error(
      "A multi-value list cannot become a single value without losing data.",
    );
  const scalar = Array.isArray(value) ? (value[0] ?? "") : value;
  const text = String(scalar ?? "");
  if (type === "text") return text;
  if (type === "number") {
    if (!text.trim() || !Number.isFinite(Number(text)))
      throw new Error("This value is not a finite number.");
    return Number(text);
  }
  if (type === "checkbox") {
    if (text === "true") return true;
    if (text === "false") return false;
    throw new Error("Checkbox values must be true or false.");
  }
  if (type === "date" && dateSchema.safeParse(text).success) return text;
  if (type === "datetime") {
    if (dateSchema.safeParse(text).success) return `${text}T00:00`;
    if (datetimeSchema.safeParse(text).success) return text;
  }
  throw new Error(
    type === "date"
      ? "Use a date in YYYY-MM-DD format."
      : "Use a date and time in YYYY-MM-DDTHH:mm format.",
  );
}

export function changeNotePropertyType(
  source: string,
  key: string,
  type: EditablePropertyType,
): string {
  const { document } = parseFrontmatter(source);
  const node = document?.get(key, true);
  if (isNode(node) && "tag" in node && node.tag)
    throw new Error(
      "Properties with explicit YAML tags must be changed in source.",
    );
  const metadata = readNoteMetadata(source);
  if (metadata.error) throw new Error(metadata.error);
  const property = metadata.properties.find((entry) => entry.key === key);
  if (!property) throw new Error("Property no longer exists.");
  return updateNoteProperty(source, key, convertPropertyValue(property, type));
}

export function propertyLinks(
  property: NoteProperty,
): { target: string; label: string }[] {
  const values = metadataStrings.parse(property.value);
  const links = values.flatMap((value) =>
    Array.from(
      value.matchAll(/\[\[([^\]|\r\n]+)(?:\|([^\]\r\n]+))?\]\]/gu),
      (match) => ({
        target: match[1] ?? "",
        label: match[2] ?? match[1] ?? "",
      }),
    ),
  );
  return [
    ...new Map(
      links.map((link) => [`${link.target}:${link.label}`, link]),
    ).values(),
  ];
}

export function noteCssClasses(source: string): string[] {
  const property = readNoteFrontmatter(source).properties.find(
    (entry) => entry.key === "cssclasses",
  );
  return [
    ...new Set(
      metadataStrings
        .parse(property?.value)
        .flatMap((value) => value.split(/\s+/u))
        .filter((value) => /^[_a-zA-Z][_a-zA-Z0-9-]{0,63}$/u.test(value)),
    ),
  ].slice(0, 32);
}
