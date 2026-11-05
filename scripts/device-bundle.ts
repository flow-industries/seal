/**
 * Bundles the device entry the way a plugin or agent ships it and fails if
 * it reaches an editor, renderer or UI package, or outgrows its budget.
 */
const FORBIDDEN = [
  "@babel/",
  "@codemirror/",
  "@mdx-js/",
  "@orama/",
  "/react/",
  "/react-dom/",
  "@flow-industries/ui/",
];
const BUDGET_BYTES = 2_500_000;

const result = await Bun.build({
  entrypoints: ["src/index.ts"],
  target: "node",
  metafile: true,
});
if (!result.success || !result.metafile) {
  for (const log of result.logs) console.error(log);
  process.exit(1);
}
const inputs = Object.keys(result.metafile.inputs);
const reached = inputs.filter((path) =>
  FORBIDDEN.some((name) => path.includes(name)),
);
const bytes = result.outputs.reduce((sum, output) => sum + output.size, 0);
console.log(
  `device bundle: ${(bytes / 1e6).toFixed(2)} MB from ${inputs.length} inputs`,
);
if (reached.length) {
  console.error(`device bundle reaches ${reached.join(", ")}`);
  process.exit(1);
}
if (bytes > BUDGET_BYTES) {
  console.error(`device bundle exceeds ${BUDGET_BYTES} bytes`);
  process.exit(1);
}
