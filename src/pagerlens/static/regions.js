// A table card that can scroll sideways on a phone is a keyboard-reachable, named region (axe: scrollable-region-focusable).
import { h, scrollRegion } from "/kit/ui.js";

export const flush = (label, ...kids) => scrollRegion(h("div", { class: "card flush" }, ...kids), label);
