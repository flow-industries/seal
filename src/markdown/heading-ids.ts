/** Allocates document-scoped IDs without colliding with literal heading suffixes. */
export function createHeadingIdAllocator() {
  const used = new Set<string>();
  const nextSuffix = new Map<string, number>();
  return (base: string): string => {
    let suffix = nextSuffix.get(base) ?? 0;
    let id = suffix ? `${base}-${suffix}` : base;
    while (used.has(id)) id = `${base}-${++suffix}`;
    nextSuffix.set(base, suffix + 1);
    used.add(id);
    return id;
  };
}
