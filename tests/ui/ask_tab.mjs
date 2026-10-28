// The Ask tab without a browser: suggested questions, the typing state, verified-source chips, flagged citations, textContent-only
// rendering (an answer full of markup stays text, a hostile link is never made a link), keyboard use, errors with Retry, and a
// conversation and a half-typed question that survive the router re-running the tab. Run: node tests/ui/ask_tab.mjs
import { readFileSync } from "node:fs";
import { fail, find, findAll, findId, installDom } from "./fakedom.mjs";

const posts = [];
let hold = null;                        // when set, the next POST waits for hold.resolve()
let script = [];                        // queued responses for POST /api/ask: {status, body}
let ready = { ready: true, reason: "", suggestions: ["Why is checkout-api failing?", "Have we seen this before?", "What is slow in the database?"] };

const dom = await installDom({ hash: "#ask", routes: async (p) => (p === "/api/ask" ? ready : {}) });
const delegate = globalThis.fetch;
globalThis.fetch = async (p, init = {}) => {
  if (p !== "/api/ask" || (init.method || "GET") !== "POST") return delegate(p, init);
  posts.push(JSON.parse(init.body));
  if (hold) await new Promise((r) => { hold.resolve = r; });
  const next = script.shift() || { status: 200, body: answer("ok") };
  return { ok: next.status < 400, status: next.status, headers: { get: () => "application/json" }, json: async () => next.body };
};

const answer = (text, extra = {}) => ({ conversation_id: "c0ffee0123456789", answer: text, sources: [], unverified: [], warnings: [], steps: [], grounded: true, ...extra });
const text = (el) => (el.data !== undefined ? String(el.data) : "") + (el.textContent || "") + (el.children || []).map(text).join(" ");
const btn = (root, label) => find(root, (e) => e.tag === "button" && text(e).trim() === label);
const click = (el) => el.listeners.click[0]({ preventDefault() {}, stopPropagation() {} });

const { initAsk } = await import("/static/ask.js");
await initAsk();
await dom.settle();
const box = dom.el("view-ask");
const log = () => findId(box, "ask-log");

// 1. what is on the page: a heading, the three suggestions, a labelled input, a live log
if (!text(box).includes("Ask PagerLens")) fail("no heading");
const chips = findAll(box, (e) => e.tag === "button" && e.className === "chip");
if (chips.length !== 3 || text(chips[0]).trim() !== "Why is checkout-api failing?") fail("the three suggested questions are not offered: " + chips.map(text));
const input = findId(box, "ask-input");
if (!input || input.tag !== "textarea") fail("no question box");
const label = find(box, (e) => e.tag === "label" && e.attrs.for === "ask-input");
if (!label || !text(label).includes("Your question")) fail("the question box has no label");
if (log().attrs.role !== "log" || log().attrs["aria-live"] !== "polite" || !log().attrs["aria-label"]) fail("the conversation is not a named live log");
if (!input.attrs["aria-describedby"] || !findId(box, "ask-hint")) fail("the keyboard hint is not tied to the input");
if (!btn(box, "New conversation") || !btn(box, "Ask")) fail("missing buttons");

// 2. a suggestion sends it; while it runs there is a typing state, the button is disabled and a second Enter does not send twice
hold = {};
const first = click(chips[0]);
await dom.settle();
if (posts.length !== 1 || posts[0].messages.at(-1).content !== "Why is checkout-api failing?" || posts[0].messages.at(-1).role !== "user") fail("the suggestion was not sent as a user message: " + JSON.stringify(posts));
if ("conversation_id" in posts[0]) fail("a first question must not carry a conversation id");
const typing = findAll(log(), (e) => e.attrs?.role === "status");
if (typing.length !== 1 || !text(typing[0]).includes("looking things up")) fail("no typing state while waiting");
if (log().attrs["aria-busy"] !== "true") fail("the log is not marked busy");
if (btn(box, "Ask").disabled !== true) fail("Ask must be disabled while a question is running");
input.value = "a second question typed while waiting";
input.listeners.input[0]({ target: input });
input.dispatch("keydown", { key: "Enter", shiftKey: false });
await dom.settle();
if (posts.length !== 1) fail("Enter while a question is running must not send a second one");
if (input.value !== "a second question typed while waiting") fail("the draft was lost while waiting");
hold.resolve();
hold = null;
script = [];
await first;
await dom.settle();

// 3. the first answer arrives (default "ok"); now a rich one with sources, a flagged citation and steps
if (!text(log()).includes("ok") || findAll(log(), (e) => e.attrs?.role === "status").length) fail("the answer did not replace the typing state");
if (document.activeElement !== input) fail("focus should return to the question box after an answer");
script = [{ status: 200, body: answer("It was the release [incident #3]; see [evidence #12] and [incident #99: UNVERIFIED, not found].", {
  sources: [{ type: "incident", id: 3, ref: "incident #3", label: "HighErrorRate (checkout-api, open)", link: "#incidents/3", verified: true },
            { type: "evidence", id: 12, ref: "evidence #12", label: "recent_deploys: 1 deploy", link: "#incidents/3", verified: true },
            { type: "runbook", id: 2, ref: "runbook #2", label: "Bad release (bad_deploy)", link: "#runbooks", verified: true },
            { type: "incident", id: 4, ref: "incident #4", label: "evil", link: "javascript:alert(1)", verified: true }],
  unverified: [{ type: "incident", id: 99, ref: "incident #99", reason: "not_found" }, { type: "runbook", id: 7, ref: "runbook #7", reason: "not_read" }],
  warnings: ["2 citation(s) could not be verified and are marked UNVERIFIED in the answer", "the question hit its time, token or tool limit"],
  steps: [{ tool: "list_incidents" }, { tool: "get_incident" }, { tool: "(refused)", error: true }] }) }];
input.value = "and what happened?";
input.dispatch("keydown", { key: "Enter", shiftKey: false });
await dom.settle();
if (posts.length !== 2 || posts[1].conversation_id !== "c0ffee0123456789") fail("the second question's body: " + JSON.stringify(posts[1]));
await dom.settle();
const all = text(log());
if (!all.includes("[incident #99: UNVERIFIED, not found]")) fail("the flagged citation must stay visible in the answer");
const links = findAll(log(), (e) => e.tag === "a");
if (links.length !== 3 || !links.every((a) => /^#(incidents\/\d+|runbooks)$/.test(a.attrs.href))) fail("source chips: " + JSON.stringify(links.map((a) => a.attrs.href)));
if (!links.some((a) => text(a).includes("incident #3") && text(a).includes("HighErrorRate"))) fail("a chip must show the reference and what it is");
if (all.includes("evil") && links.some((a) => a.attrs.href.startsWith("javascript"))) fail("a hostile link became a link");
const chipLike = findAll(log(), (e) => e.className === "chip" && text(e).includes("incident #4"));
if (chipLike.length !== 1) fail("an unsafe link must still show as plain text, not vanish silently");
if (!all.includes("Could not verify: incident #99 (no such record), runbook #7 (never read in this conversation)")) fail("the unverified note: " + all);
if (!all.includes("time, token or tool limit") || all.includes("could not be verified and are marked")) fail("warnings: the generic unverified one is replaced by the specific note");
if (!all.includes("Looked at: list_incidents, get_incident") || all.includes("(refused)")) fail("what it looked at: " + all);
if (!all.includes("Verified sources")) fail("the chips need their heading");

// 4. a later question carries the conversation id the server returned
script = [{ status: 200, body: answer("third") }];
input.value = "one more";
click(btn(box, "Ask"));
await dom.settle();
if (posts[2].conversation_id !== "c0ffee0123456789") fail("the conversation id was not reused");
if (posts[2].messages.at(-1).content !== "one more") fail("the new question is the last message");

// 5. markup in an answer is text: no element is ever created from it
script = [{ status: 200, body: answer('<img src=x onerror=alert(1)> <script>alert(2)</script> **not bold**') }];
input.value = "xss?";
click(btn(box, "Ask"));
await dom.settle();
if (findAll(box, (e) => ["img", "script", "b", "strong"].includes(e.tag)).length) fail("markup in an answer became an element");
if (!text(log()).includes("<img src=x onerror=alert(1)>")) fail("the markup must be visible as text");
const src = readFileSync(new URL("../../src/pagerlens/static/ask.js", import.meta.url), "utf8");
if (/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function|createContextualFragment/.test(src)) fail("ask.js must only use textContent-style rendering");

// 6. an error shows with Try again (focused), the question is not duplicated, and retry sends the same thing
script = [{ status: 429, body: { detail: "too many questions: at most 10 a minute per user; wait a moment" } }, { status: 200, body: answer("recovered") }];
const turnsBefore = findAll(log(), (e) => e.className === "msg user").length;
input.value = "will this fail?";
input.dispatch("keydown", { key: "Enter", shiftKey: false });
await dom.settle();
const alerts = findAll(log(), (e) => e.attrs?.role === "alert");
if (alerts.length !== 1 || !text(alerts[0]).includes("too many questions")) fail("the error must be shown: " + text(log()).slice(-200));
const retry = findId(log(), "ask-retry");
if (!retry || document.activeElement !== retry) fail("Try again must exist and take the focus");
const sent = posts.length;
await click(retry);
await dom.settle();
if (posts.length !== sent + 1 || JSON.stringify(posts.at(-1).messages) !== JSON.stringify(posts[sent - 1].messages)) fail("retry must send the same messages");
if (findAll(log(), (e) => e.className === "msg user").length !== turnsBefore + 1) fail("retry must not duplicate the question");
if (findAll(log(), (e) => e.attrs?.role === "alert").length || !text(log()).includes("recovered")) fail("the error should clear once it works");

// 7. Shift+Enter is a new line, not a send
const n = posts.length;
input.value = "line one";
const ev = input.dispatch("keydown", { key: "Enter", shiftKey: true });
await dom.settle();
if (posts.length !== n || ev.defaultPrevented) fail("Shift+Enter must not send or be swallowed");
if (find(box, (e) => e.tag === "button" && e.attrs?.type === "submit")) fail("there is no form: nothing may submit the page");

// 8. the router re-running the tab keeps the conversation and the draft (and does not resend anything)
input.value = "half a thought";
input.listeners.input[0]({ target: input });
await initAsk();
await dom.settle();
const again = findId(dom.el("view-ask"), "ask-input");
if (again.value !== "half a thought") fail("a redraw wiped the draft");
if (!text(findId(dom.el("view-ask"), "ask-log")).includes("recovered") || posts.length !== n) fail("the conversation must survive re-entering the tab");

// 9. New conversation clears it, including the id
click(btn(dom.el("view-ask"), "New conversation"));
await dom.settle();
if (text(findId(dom.el("view-ask"), "ask-log")).includes("recovered")) fail("New conversation did not clear the log");
script = [{ status: 200, body: answer("fresh") }];
findId(dom.el("view-ask"), "ask-input").value = "start over";
click(btn(dom.el("view-ask"), "Ask"));
await dom.settle();
if ("conversation_id" in posts.at(-1)) fail("a new conversation must not reuse the old id");

// 10. without a chat account the tab says why, and questions are still allowed (the server answers with the real error)
ready = { ready: false, reason: "no chat account is configured: an administrator adds one under Settings", suggestions: [] };
await initAsk();
await dom.settle();
const notice = text(findId(dom.el("view-ask"), "ask-notice"));
if (!notice.includes("no chat account is configured")) fail("the missing account is not explained: " + notice);
if (findAll(dom.el("view-ask"), (e) => e.tag === "button" && e.className === "chip").length !== 3) fail("fallback suggestions are missing");

console.log("ok: the Ask tab (suggestions, typing state, verified chips, flagged citations, textContent only, keyboard, retry, persistence)");
process.exit(0);
