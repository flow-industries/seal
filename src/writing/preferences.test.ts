import { expect, test } from "bun:test";
import {
  DEFAULT_WRITING_PREFERENCES,
  isInternalWritingPath,
  parseWritingPreferences,
  serializeWritingPreferences,
  writingPreferencesSchema,
} from "./preferences.ts";

test("writing preferences validate paths, identifiers, versions and bounded typed metadata", () => {
  expect(
    parseWritingPreferences(
      serializeWritingPreferences(DEFAULT_WRITING_PREFERENCES),
    ),
  ).toEqual(DEFAULT_WRITING_PREFERENCES);
  for (const patch of [
    { version: 2 },
    { unexpected: true },
    { dailyFolder: "../outside" },
    { templatesFolder: ".NOTE/templates" },
    { dailyFolder: "a//b" },
    { dailyTemplateId: "<script>" },
    { bookmarks: ["same", "same"] },
    { bookmarks: Array.from({ length: 501 }, (_, index) => `note-${index}`) },
    { propertyTypes: { custom: "unknown" } },
    { propertyTypes: JSON.parse('{"__proto__":"text"}') },
    {
      propertyTypes: Object.fromEntries(
        Array.from({ length: 201 }, (_, index) => [`key-${index}`, "text"]),
      ),
    },
  ])
    expect(
      writingPreferencesSchema.safeParse({
        ...DEFAULT_WRITING_PREFERENCES,
        ...patch,
      }).success,
    ).toBe(false);
  expect(() => parseWritingPreferences("x".repeat(65_537))).toThrow(
    "size limit",
  );
  expect(() => parseWritingPreferences("export default () => null")).toThrow(
    "invalid",
  );
  expect(isInternalWritingPath(".NOTE/settings.mdx")).toBe(true);
  expect(isInternalWritingPath("notes/settings.md")).toBe(false);
});
