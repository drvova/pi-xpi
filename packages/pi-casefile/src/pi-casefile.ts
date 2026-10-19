/**
 * Pi host entry point for the casefile extension.
 *
 * Wires the host-agnostic extension in `extension.ts` with Pi's TUI primitives
 * from `@earendil-works/pi-tui`. The OMP-native entry is `pi-casefile.omp.ts`, which
 * supplies the same primitives from `@oh-my-pi/pi-tui`. Neither build pulls in
 * the other host's packages.
 *
 * All named exports (ledger helpers, XP-mode helpers, `casefileExtension`,
 * `CasefileHost`) are re-exported here so existing importers keep working.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { matchesKey, Text, truncateToWidth } from "@earendil-works/pi-tui";
import { casefileExtension } from "./extension.ts";

export * from "./extension.ts";

export default function piCasefileExtension(pi: ExtensionAPI) {
  return casefileExtension(pi, { Text, matchesKey, truncateToWidth });
}
