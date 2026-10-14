// Minimal, safe Markdown renderer for reports: headings, lists, quotes, rules, bold, inline code. Text nodes only.
import { h } from "/static/ui.js";

function inline(text) {
  const out = [];
  const re = /(\*\*[^*]+\*\*|`[^`]+`|\*[^*]+\*)/g;
  let last = 0, m;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const tok = m[0];
    if (tok.startsWith("**")) out.push(h("strong", {}, tok.slice(2, -2)));
    else if (tok.startsWith("`")) out.push(h("code", {}, tok.slice(1, -1)));
    else out.push(h("em", {}, tok.slice(1, -1)));
    last = m.index + tok.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

export function renderMarkdown(md) {
  const root = h("div", { class: "md" });
  let list = null;
  const closeList = () => { list = null; };
  for (const raw of md.split("\n")) {
    const line = raw.replace(/\s+$/, "");
    if (!line) { closeList(); continue; }
    const head = /^(#{1,3})\s+(.*)$/.exec(line);
    const item = /^(\s*)(?:[-*]|\d+\.)\s+(.*)$/.exec(line);
    if (head) { closeList(); root.append(h("h" + (head[1].length + 1), {}, inline(head[2]))); }
    else if (/^---+$/.test(line)) { closeList(); root.append(h("hr")); }
    else if (line.startsWith("> ")) { closeList(); root.append(h("blockquote", {}, inline(line.slice(2)))); }
    else if (item) {
      const ordered = /^\s*\d+\./.test(line);
      const nested = item[1].length >= 2 && list;
      if (!list) { list = h(ordered ? "ol" : "ul"); root.append(list); }
      const li = h("li", {}, inline(item[2]));
      if (nested && list.lastChild) {
        let sub = list.lastChild.querySelector("ul");
        if (!sub) { sub = h("ul"); list.lastChild.append(sub); }
        sub.append(li);
      } else list.append(li);
    } else { closeList(); root.append(h("p", {}, inline(line))); }
  }
  return root;
}
