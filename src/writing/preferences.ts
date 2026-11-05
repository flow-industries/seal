import { z } from "zod";
import { safeSegment } from "../vault/model.ts";

export const WRITING_PREFERENCES_PATH = ".note/settings.md";
export const WRITING_PREFERENCES_BYTES = 65_536;

export function isInternalWritingPath(path: string): boolean {
  const normalized = path.normalize("NFC").toLocaleLowerCase("en-US");
  return normalized === ".note" || normalized.startsWith(".note/");
}

const noteId = z.string().regex(/^[A-Za-z0-9_-]{1,128}$/u);
const folder = z
  .string()
  .max(1024)
  .refine((value) => {
    if (!value) return true;
    if (isInternalWritingPath(value)) return false;
    const segments = value.split("/");
    if (segments.length > 32) return false;
    try {
      segments.forEach(safeSegment);
      return true;
    } catch {
      return false;
    }
  }, "Choose a relative folder path without empty or parent segments.");
const hasControlCharacters = (value: string) =>
  Array.from(value).some(
    (character) =>
      character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
  );
const format = z
  .string()
  .min(1)
  .max(128)
  .refine((value) => !hasControlCharacters(value));
export const writingPropertyTypeSchema = z.enum([
  "text",
  "number",
  "checkbox",
  "date",
  "datetime",
  "list",
  "tags",
]);
export type WritingPropertyType = z.infer<typeof writingPropertyTypeSchema>;
const propertyName = z
  .string()
  .min(1)
  .max(128)
  .refine(
    (value) =>
      !hasControlCharacters(value) &&
      !["__proto__", "constructor", "prototype"].includes(value),
  );

export const writingPreferencesSchema = z.strictObject({
  version: z.literal(1),
  templatesFolder: folder,
  dailyFolder: folder,
  dailyDateFormat: format,
  dailyTemplateId: noteId.optional(),
  dateFormat: format,
  timeFormat: format,
  bookmarks: z
    .array(noteId)
    .max(500)
    .refine(
      (value) => new Set(value).size === value.length,
      "A note can only be bookmarked once.",
    ),
  propertyTypes: z
    .unknown()
    .refine((value) => {
      // biome-ignore lint/plugin: Validate raw keys at the JSON boundary before Zod drops __proto__.
      if (!value || typeof value !== "object" || Array.isArray(value))
        return false;
      const keys = Object.keys(value);
      return (
        keys.length <= 200 &&
        keys.every((key) => propertyName.safeParse(key).success)
      );
    }, "Use at most 200 valid property names.")
    .pipe(z.record(propertyName, writingPropertyTypeSchema)),
});
export type WritingPreferences = z.infer<typeof writingPreferencesSchema>;
export const DEFAULT_WRITING_PREFERENCES: WritingPreferences = {
  version: 1,
  templatesFolder: "templates",
  dailyFolder: "",
  dailyDateFormat: "YYYY-MM-DD",
  dateFormat: "YYYY-MM-DD",
  timeFormat: "HH:mm",
  bookmarks: [],
  propertyTypes: {},
};

export function parseWritingPreferences(source: string): WritingPreferences {
  if (new TextEncoder().encode(source).byteLength > WRITING_PREFERENCES_BYTES)
    throw new Error("Writing preferences exceed the size limit.");
  try {
    return writingPreferencesSchema.parse(JSON.parse(source));
  } catch {
    throw new Error(
      "Writing preferences are invalid or use an unsupported version.",
    );
  }
}

export function serializeWritingPreferences(value: WritingPreferences): string {
  const result = writingPreferencesSchema.safeParse(value);
  if (!result.success) throw new Error("Check the writing preference values.");
  const source = JSON.stringify(result.data);
  if (new TextEncoder().encode(source).byteLength > WRITING_PREFERENCES_BYTES)
    throw new Error("Writing preferences exceed the size limit.");
  return source;
}
