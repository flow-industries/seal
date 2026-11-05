import { boundedName, newId, type VaultItem } from "../vault/model.ts";
export function conflictName(item: VaultItem, label = "conflict"): string {
  const extension = item.format ? `.${item.format}` : "";
  const base =
    extension && item.name.toLowerCase().endsWith(extension)
      ? item.name.slice(0, -extension.length)
      : item.name;
  const suffix = ` ${label} ${newId().slice(0, 8)}${extension}`;
  return boundedName(base, suffix);
}
export function draftAfterTombstone(local: VaultItem): VaultItem {
  return {
    ...local,
    id: newId(),
    parent: null,
    name: conflictName(local, "recovered draft"),
    permanent: false,
    trashed: false,
  };
}
