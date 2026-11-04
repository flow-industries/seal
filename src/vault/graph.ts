import { boundedName, paths, safeSegment, type VaultItem } from "./model.ts";
export interface GraphRepair {
  id: string;
  reason: "missing-parent" | "cycle" | "collision" | "unsafe-name" | "depth";
}
export interface GraphRepairResult {
  items: VaultItem[];
  repairs: GraphRepair[];
}
export function repairGraph(items: readonly VaultItem[]): GraphRepairResult {
  if (items.length > 10000) throw new Error("Graph item limit exceeded");
  const copies = items.map((item) => ({ ...item }));
  const byId = new Map(copies.map((item) => [item.id, item]));
  if (byId.size !== copies.length)
    throw new Error("Duplicate graph identifiers");
  const repairs: GraphRepair[] = [];
  const mark = (item: VaultItem, reason: GraphRepair["reason"]) => {
    repairs.push({ id: item.id, reason });
  };
  const live = copies
    .filter((item) => !item.trashed)
    .sort((a, b) => a.id.localeCompare(b.id));
  for (const [index, item] of live.entries()) {
    try {
      safeSegment(item.name);
    } catch {
      item.name = `Recovered ${index + 1}${item.format ? `.${item.format}` : ""}`;
      mark(item, "unsafe-name");
    }
    const parent = item.parent ? byId.get(item.parent) : null;
    if (
      item.parent &&
      (!parent || parent.kind !== "folder" || parent.trashed)
    ) {
      item.parent = null;
      mark(item, "missing-parent");
    }
  }
  for (const start of live) {
    const ancestry: VaultItem[] = [];
    const seen = new Map<string, number>();
    let current: VaultItem | undefined = start;
    while (current) {
      const loop = seen.get(current.id);
      if (loop !== undefined) {
        const cycle = ancestry
          .slice(loop)
          .sort((a, b) => a.id.localeCompare(b.id));
        const root = cycle[0];
        if (!root) throw new Error("Empty graph cycle");
        root.parent = null;
        mark(root, "cycle");
        break;
      }
      if (ancestry.length >= 64) {
        start.parent = null;
        mark(start, "depth");
        break;
      }
      seen.set(current.id, ancestry.length);
      ancestry.push(current);
      current = current.parent ? byId.get(current.parent) : undefined;
    }
  }
  const occupied = new Set<string>();
  for (const item of live) {
    const key = (name: string) =>
      `${item.parent ?? ""}\u0000${name.normalize("NFC").toLocaleLowerCase("en-US")}`;
    if (occupied.has(key(item.name))) {
      const extension = item.format ? `.${item.format}` : "";
      const base =
        extension && item.name.toLowerCase().endsWith(extension)
          ? item.name.slice(0, -extension.length)
          : item.name;
      let ordinal = 2;
      const candidate = (ordinal: number) => {
        const suffix = ` conflict ${ordinal}${extension}`;
        return boundedName(base, suffix);
      };
      let name = candidate(ordinal);
      while (occupied.has(key(name))) {
        name = candidate(++ordinal);
      }
      item.name = name;
      mark(item, "collision");
    }
    occupied.add(key(item.name));
  }
  paths(live);
  return { items: copies, repairs };
}
