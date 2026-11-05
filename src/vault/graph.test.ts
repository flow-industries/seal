import { expect, test } from "bun:test";
import { repairGraph } from "./graph.ts";
import { paths, type VaultItem } from "./model.ts";

const item = (
  id: string,
  name: string,
  parent: string | null,
  kind: VaultItem["kind"] = "folder",
): VaultItem => {
  const value: VaultItem = {
    id,
    name,
    parent,
    kind,
    createdAt: "now",
    updatedAt: "now",
    bytes: new TextEncoder().encode(id),
  };
  if (kind === "note") value.format = "md";
  return value;
};
test("cycles missing/deleted parents and collisions preserve every item and exact source", () => {
  const input = [
    item("a", "a", "b"),
    item("b", "b", "a"),
    item("c", "lost.md", "missing", "note"),
    { ...item("d", "deleted", null), trashed: true },
    item("e", "orphan.md", "d", "note"),
    item("f", "Same.md", null, "note"),
    item("g", "same.md", null, "note"),
  ];
  const result = repairGraph(input);
  expect(result.items).toHaveLength(input.length);
  expect(result.repairs.map((value) => value.reason)).toContain("cycle");
  expect(result.repairs.map((value) => value.reason)).toContain(
    "missing-parent",
  );
  expect(result.repairs.map((value) => value.reason)).toContain("collision");
  for (const original of input)
    expect(
      result.items.find((value) => value.id === original.id)?.bytes,
    ).toEqual(original.bytes);
  expect(() =>
    paths(result.items.filter((value) => !value.trashed)),
  ).not.toThrow();
  expect(repairGraph(result.items).repairs).toHaveLength(0);
  expect(
    repairGraph([...input].reverse()).items.sort((a, b) =>
      a.id.localeCompare(b.id),
    ),
  ).toEqual(result.items.sort((a, b) => a.id.localeCompare(b.id)));
});
