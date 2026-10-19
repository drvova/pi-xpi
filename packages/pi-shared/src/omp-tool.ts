/**
 * OMP-native tool metadata.
 *
 * XPI's tools are declared against the Pi (`@earendil-works`) `ToolDefinition`,
 * whose prompt surface is `promptSnippet` / `promptGuidelines`. The OMP fork
 * (`@oh-my-pi/pi-coding-agent`) runs those tools through its legacy-pi compat
 * layer, but its *native* `ToolDefinition` has no such fields — it governs a
 * tool with `approval` (an approval tier) and `loadMode` instead. Without those,
 * every XPI tool defaults to `approval: "exec"` on OMP, so even read-only
 * lookups prompt as if they execute code.
 *
 * These fields mirror `@oh-my-pi/pi-coding-agent@18.12.3`'s `ToolDefinition`
 * (`approval` from `@oh-my-pi/pi-agent-core`: defaults to `"exec"` when omitted;
 * `ToolLoadMode = "essential" | "discoverable"`). They are attached without
 * widening the Pi type (`withOmpMetadata`), so the Pi host simply ignores the
 * extra keys while OMP reads them natively. Keep this file in sync if OMP's
 * tool contract changes.
 */

/** OMP approval tier. `read` = read-only, `write` = mutation, `exec` = code execution. */
export type ToolApprovalTier = "read" | "write" | "exec";

/** OMP tool presentation. `essential` stays top-level; `discoverable` is found via tool search. */
export type ToolLoadModeTier = "essential" | "discoverable";

/** Native OMP tool-definition fields the Pi host does not use. */
export interface OmpToolMetadata {
  /** Approval tier OMP gates this tool with (defaults to `"exec"` when omitted). */
  approval?: ToolApprovalTier;
  /** Whether OMP keeps the tool top-level (`essential`) or behind tool search. */
  loadMode?: ToolLoadModeTier;
  /** Whether the tool may read `skill://` instruction content under OMP. */
  readsSkillUris?: boolean;
}

/**
 * Attach OMP-native metadata to a tool definition at runtime without changing
 * its static (Pi) type. OMP reads the extra keys; Pi ignores them. The returned
 * value keeps `def`'s type exactly, so it stays assignable to Pi's `registerTool`.
 */
export function withOmpMetadata<T extends object>(def: T, meta: OmpToolMetadata): T {
  return { ...def, ...meta } as T;
}
