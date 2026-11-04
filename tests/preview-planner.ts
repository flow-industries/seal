import { linkRanges, linkResolver } from "../src/vault/links.ts";
import { mediaMime, paths, type VaultItem } from "../src/vault/model.ts";
import type { PlanPreviewAssets, SelectedAsset } from "../src/vault/session.ts";

const MAX_ASSET_BYTES = 8_000_000;
const MAX_ASSETS = 32;
const RELATIVE_IMPORT =
  /^\s*import\s+(?:[^'"\n]*\s+from\s+)?['"](\.{1,2}\/[^'"\n]+)['"]/gmu;

/**
 * A stand-in for an app's preview planner, as a session's tests need one:
 * linked media within the same bounds, and an `.mdx` note's relative imports
 * one level deep, found by pattern rather than compiled. It never evaluates
 * anything, and what it selects is the session's to check and mark.
 */
export const planPreviewAssets: PlanPreviewAssets = async (
  note,
  source,
  items,
  read,
) => {
  const assets: SelectedAsset[] = [];
  let bytes = 0;
  const select = async (item: VaultItem, alias: string, module?: string) => {
    const known = assets.find((asset) => asset.id === item.id);
    if (known) {
      known.paths = [...new Set([...(known.paths ?? []), alias])];
      return;
    }
    if (assets.length >= MAX_ASSETS)
      throw new Error("Note asset preview exceeds bounds");
    const content = await read(item.id, MAX_ASSET_BYTES - bytes);
    if (!content) throw new Error("Note asset preview exceeds bounds");
    bytes += content.length;
    if (bytes > MAX_ASSET_BYTES) {
      content.fill(0);
      throw new Error("Note asset preview exceeds bounds");
    }
    assets.push({
      id: item.id,
      mime: module ? "text/javascript" : mediaMime(content),
      bytes: content,
      path: alias,
      paths: [alias],
      ...(module && { canonicalPath: module }),
    });
  };
  try {
    const resolve = linkResolver(items);
    for (const link of linkRanges(source)) {
      const target = link.target.split("#")[0] ?? "";
      if (!target || target.length > 1024 || /[?\\:]/u.test(target)) continue;
      const id = resolve(target, note.id, link.syntax);
      const asset = items.find(
        (item) => item.id === id && item.kind === "asset",
      );
      if (asset) await select(asset, target);
    }
    if (note.format !== "mdx") return assets;
    const index = paths(items);
    const folder = (index.get(note.id) ?? "").split("/").slice(0, -1);
    for (const [, specifier = ""] of source.matchAll(RELATIVE_IMPORT)) {
      const path = [...folder];
      for (const segment of specifier.split("/"))
        if (segment === "..") path.pop();
        else if (segment !== ".") path.push(segment);
      const resolved = path.join("/");
      const module = items.find(
        (item) => item.kind === "asset" && index.get(item.id) === resolved,
      );
      if (!module) throw new Error("Referenced note module unavailable");
      await select(module, specifier, resolved);
    }
    return assets;
  } catch (error) {
    for (const asset of assets) asset.bytes.fill(0);
    throw error;
  }
};
