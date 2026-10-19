/**
 * OMP host entry point for the todo extension.
 *
 * Mirror of `pi-xtodo.ts` (the Pi entry), but supplies the primitives from OMP's
 * own `@oh-my-pi/*` packages so the OMP build never resolves the Pi packages.
 * OMP reads this via the `omp.extensions` manifest field. The `pi` object is
 * cast once at this boundary (OMP's `ExtensionAPI` is a compatible superset of
 * the subset the shared module uses).
 */

import type { ExtensionAPI as EarendilExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { Container, Text, truncateToWidth } from "@oh-my-pi/pi-tui";
import { DynamicBorder } from "@oh-my-pi/pi-tui/chrome";
import { registerTodo, type XtodoHost } from "./extension.ts";

// On OMP, DynamicBorder is a pi-tui/chrome component (Pi exposes it from
// pi-coding-agent). keyText has no stable native export on OMP, so it is
// omitted — the widget falls back to a static expand hint.
export default function ompRegisterTodo(pi: ExtensionAPI) {
  const host: XtodoHost = {
    Text: Text as unknown as XtodoHost["Text"],
    Container: Container as unknown as XtodoHost["Container"],
    truncateToWidth: truncateToWidth as unknown as XtodoHost["truncateToWidth"],
    DynamicBorder: DynamicBorder as unknown as XtodoHost["DynamicBorder"],
  };
  return registerTodo(pi as unknown as EarendilExtensionAPI, host);
}
