/**
 * Pi host entry point for the todo extension.
 *
 * Wires the host-agnostic extension in `extension.ts` with Pi's TUI and
 * component primitives from `@earendil-works/*`. The OMP-native entry is
 * `index.omp.ts`, which supplies the same primitives from `@oh-my-pi/*`.
 * All named exports are re-exported so existing importers keep working.
 */

import { DynamicBorder, type ExtensionAPI, keyText } from "@earendil-works/pi-coding-agent";
import { Container, Text, truncateToWidth } from "@earendil-works/pi-tui";
import { registerTodo } from "./extension.ts";

export * from "./extension.ts";

export default function piRegisterTodo(pi: ExtensionAPI) {
  return registerTodo(pi, { Text, Container, truncateToWidth, DynamicBorder, keyText });
}
