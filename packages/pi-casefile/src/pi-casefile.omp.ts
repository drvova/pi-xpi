/**
 * OMP host entry point for the casefile extension.
 *
 * Mirror of `pi-casefile.ts` (the Pi entry), but supplies the TUI primitives from
 * OMP's own `@oh-my-pi/pi-tui` so the OMP build never resolves the Pi packages.
 * OMP reads this via the `omp.extensions` manifest field.
 *
 * `casefileExtension` types its `pi` parameter against Pi's `ExtensionAPI`; the
 * OMP `ExtensionAPI` is a compatible superset for the subset this extension
 * uses (`registerTool`, `registerCommand`, `on`, `ui`), so the host object is
 * cast once here at the boundary rather than threading two API types through
 * the shared module.
 */

import type { ExtensionAPI as EarendilExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { matchesKey, Text, truncateToWidth } from "@oh-my-pi/pi-tui";
import { type CasefileHost, casefileExtension } from "./extension.ts";

export default function ompCasefileExtension(pi: ExtensionAPI) {
  const host: CasefileHost = {
    Text: Text as unknown as CasefileHost["Text"],
    matchesKey: matchesKey as unknown as CasefileHost["matchesKey"],
    truncateToWidth: truncateToWidth as unknown as CasefileHost["truncateToWidth"],
  };
  return casefileExtension(pi as unknown as EarendilExtensionAPI, host);
}
