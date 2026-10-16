// Reach UI. Plain JS, no build step. All text from the API goes through textContent.
const $ = (s) => document.querySelector(s);
const el = (tag, attrs = {}, ...kids) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) k === "class" ? (e.className = v) : e.setAttribute(k, v);
  for (const k of kids) e.append(k instanceof Node ? k : document.createTextNode(String(k)));
  return e;
};
const estate = () => $("#estate").value;
async function api(path, body) {
  const sep = path.includes("?") ? "&" : "?";
  const r = await fetch(`${path}${sep}estate=${estate()}`, body
    ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ...body, estate: estate() }) }
    : {});
  const j = await r.json();
  if (!r.ok) throw new Error(j.error || r.status);
  return j;
}

// ---------------------------------------------------------------- graph
let cy;
const COL = { Source: 0, Agent: 1, Data: 2, Sink: 3 };
const COLX = [0.06, 0.33, 0.58, 0.79]; // fraction of width; every label sits to the right of its node
const COLOR = { Source: "#f0883e", Agent: "#58a6ff", Data: "#d2a8ff", Sink: "#ff7b72" };

function drawEstate(view) {
  const byCol = [[], [], [], []];
  view.nodes.forEach((n) => byCol[COL[n.kind]].push(n));
  const box = $("#cy").getBoundingClientRect();
  const W = Math.max(box.width, 600), H = Math.max(box.height, 400);
  document.querySelectorAll(".cols span").forEach((s, i) => (s.style.left = `${COLX[i] * W - 6}px`));
  const els = [];
  byCol.forEach((col, ci) => {
    col.sort((a, b) => a.id.localeCompare(b.id));
    const step = (H - 110) / Math.max(col.length, 1);
    const stagger = ci === 3 ? step / 2 : 0; // sinks sit between data rows so labels never share a line
    col.forEach((n, i) => els.push({
      data: { id: n.id, label: n.id, kind: n.kind },
      position: { x: W * COLX[ci], y: 50 + step * (i + 0.25) + stagger },
    }));
  });
  view.edges.forEach((e, i) => {
    const [s, t] = e.leg === "INGESTS" ? [e.target, e.agent] : [e.agent, e.target];
    els.push({ data: { id: `e${i}`, source: s, target: t, usable: e.usable, tools: e.tools.join(", ") } });
  });
  view.delegations.forEach((d, i) => els.push({ data: { id: `d${i}`, source: d.src, target: d.dst, deleg: true } }));
  if (cy) cy.destroy();
  cy = cytoscape({
    container: $("#cy"), elements: els, layout: { name: "preset" },
    style: [
      { selector: "node", style: { "background-color": (n) => COLOR[n.data("kind")], label: "data(label)", color: "#e6edf3",
        "font-size": 11, "text-valign": "center", "text-halign": "right", "text-margin-x": 7,
        "text-background-color": "#0d1117", "text-background-opacity": 0.85, "text-background-padding": 2, width: 14, height: 14 } },
      { selector: "edge", style: { width: 1.2, "line-color": "#30363d", "target-arrow-color": "#30363d",
        "target-arrow-shape": "triangle", "arrow-scale": 0.7, "curve-style": "bezier", opacity: 0.8 } },
      { selector: "edge[!usable][!deleg]", style: { "line-style": "dotted", opacity: 0.4 } },
      { selector: "edge[?deleg]", style: { "line-style": "dashed", "line-color": "#58a6ff", "target-arrow-color": "#58a6ff",
        width: 2, "curve-style": "unbundled-bezier", "control-point-distances": 60 } },
      { selector: ".hl", style: { "line-color": "#f85149", "target-arrow-color": "#f85149", width: 3.5, opacity: 1, "z-index": 9 } },
      { selector: "node.hl", style: { "border-width": 3, "border-color": "#f85149", width: 20, height: 20 } },
      { selector: ".dim", style: { opacity: 0.12 } },
    ],
  });
  cy.on("tap", "edge", (ev) => { const t = ev.target.data("tools"); if (t) $("#paths-summary").textContent = `tools on this edge: ${t}`; });
}

function highlight(p) {
  if (!cy) return;
  cy.elements().removeClass("hl").addClass("dim");
  const names = [p.untrusted, ...p.handoff, p.private, p.sink];
  names.forEach((n) => cy.getElementById(n).removeClass("dim").addClass("hl"));
  const link = (a, b) => cy.edges(`[source = "${CSS.escape(a)}"][target = "${CSS.escape(b)}"]`).removeClass("dim").addClass("hl");
  link(p.untrusted, p.entry);
  for (let i = 0; i < p.handoff.length - 1; i++) link(p.handoff[i], p.handoff[i + 1]);
  link(p.reader, p.private);
  link(p.sender, p.sink);
}
function clearHighlight() { cy && cy.elements().removeClass("hl dim"); }

// ---------------------------------------------------------------- panels
const hop = (name, kind) => el("span", { class: `hop k-${kind}` }, name);
const arrow = () => el("span", { class: "arrow" }, "->");
function pathLine(p) {
  const kids = [hop(p.untrusted, "Source")];
  p.handoff.forEach((a) => kids.push(arrow(), hop(a, "Agent")));
  kids.push(arrow(), hop(p.private, "Data"), arrow(), hop(p.sink, "Sink"));
  return el("div", {}, ...kids);
}

async function loadPaths() {
  const r = await api("/api/paths");
  $("#cypher").textContent = r.cypher;
  const box = $("#paths"); box.replaceChildren();
  const paths = r.paths || [];
  const cross = paths.filter((p) => p.handoff.length > 1).length;
  $("#paths-summary").textContent = paths.length
    ? `${paths.length} lethal-trifecta paths, ${cross} of them cross agents. Click one to trace it.`
    : (r.note || "No paths.");
  paths.forEach((p) => {
    const d = el("div", { class: "path", tabindex: "0", role: "button" },
      ...(p.severity ? [el("span", { class: `sev sev-${p.severity}` }, p.severity.replaceAll("-", " ")),
                        el("span", { class: "k-Agent" }, p.entry)] : []),
      pathLine(p),
      el("div", { class: "muted" }, `tools: ${[...new Set([...p.in_tools, ...p.read_tools, ...p.out_tools])].slice(0, 6).join(", ")}`));
    const pick = () => { document.querySelectorAll(".path.sel").forEach((x) => x.classList.remove("sel")); d.classList.add("sel"); highlight(p); };
    d.addEventListener("click", pick); d.addEventListener("keydown", (e) => (e.key === "Enter" || e.key === " ") && pick());
    box.append(d);
  });
}

async function loadFix(mode) {
  const r = await api(`/api/fix?mode=${mode}`);
  const box = $("#fix"); box.replaceChildren();
  box.append(el("p", {}, `${r.actions.length} change(s), cost ${r.cost}. Breaks workflows: ${r.breaks_workflows.length ? r.breaks_workflows.join(", ") : "none"}.`));
  const ul = el("ul"); r.actions.forEach((a) => ul.append(el("li", {}, a))); box.append(ul);
  if (r.residual_paths.length) box.append(el("p", { class: "muted" },
    `${r.residual_paths.length} path(s) cannot be closed without breaking a workflow. The runtime guard (Red team tab) covers them.`));
}

async function runRed(scn) {
  const box = $("#red"); box.replaceChildren(el("p", { class: "muted" }, "Running..."));
  const r = await api("/api/redteam", { scenario: scn, llm: $("#use-llm").checked });
  box.replaceChildren(el("p", { class: "muted" }, `victim: ${r.victim}`));
  r.runs.forEach((run) => {
    box.append(el("h3", {}, `Guard ${run.guard ? "ON" : "OFF"}`));
    run.events.forEach((e) => {
      box.append(el("div", { class: `ev ${e.verdict}` }, `${e.agent.padEnd(16)} ${e.tool.padEnd(20)} ${e.verdict.padEnd(9)} ${e.detail || ""}`));
      if (e.path) {
        const p = e.path;
        box.append(el("div", { class: "ev BLOCKED" }, `path: ${p.untrusted[1]} (${p.untrusted[0]}) -> ${p.private[1]} (${p.private[0]}) -> ${p.sink[1]} (${p.sink[0]})`));
      }
    });
    box.append(el("div", { class: `verdict ${run.exfiltrated ? "leak" : "safe"}` },
      run.exfiltrated ? "Attacker inbox: RECEIVED private data" : "Attacker inbox: empty"));
    const b = run.events.find((e) => e.path);
    if (b) {
      const agents = [...new Set(run.events.filter((e) => e.verdict !== "delegated").map((e) => e.agent))];
      highlight({ untrusted: b.path.untrusted[1], entry: agents[0], handoff: agents, reader: b.agent,
        private: b.path.private[1], sender: b.agent, sink: b.path.sink[1] });
    }
  });
}

const fmt = (ms) => new Date(ms).toLocaleString();
async function loadTimeline() {
  const r = await api("/api/timeline");
  const t = el("table", {}, el("tr", {}, el("th", {}, "when"), el("th", {}, "event"), el("th", {}, "detail")));
  const rows = [...r.scans.map((s) => ({ at: s.at, ev: "scan", d: `${s.open} open paths` })),
    ...r.changes.map((c) => ({ at: c.at, ev: c.kind, d: `${c.agent} -> ${c.target} (by ${c.actor})` }))].sort((a, b) => b.at - a.at);
  rows.forEach((x) => t.append(el("tr", {}, el("td", {}, fmt(x.at)), el("td", {}, x.ev), el("td", {}, x.d))));
  $("#timeline").replaceChildren(t);
}
async function rescan() {
  const r = await api("/api/scan", {});
  const box = $("#scan-out"); box.replaceChildren(el("p", {}, `${r.open} open paths. ${r.opened.length} opened, ${r.closed.length} closed since the last scan.`));
  const why = (cs) => (cs.length ? cs.map((c) => `${c.kind} ${c.agent} -> ${c.target}`).join("; ") : "no recorded change explains it");
  r.opened.forEach((o) => box.append(el("div", { class: "ev BLOCKED" }, `OPENED ${o.key}  <- ${why(o.opened_by)}`)));
  r.closed.forEach((c) => box.append(el("div", { class: "ev", style: "color:var(--ok)" }, `CLOSED ${c.key}  <- ${why(c.closed_by)}`)));
  await Promise.all([loadTimeline(), loadPaths(), loadEstate()]);
}
async function applyChange() {
  const r = await api("/api/change", { kind: $("#ch-kind").value, agent: $("#ch-agent").value.trim(), target: $("#ch-target").value.trim() });
  $("#scan-out").replaceChildren(el("p", {}, r.outcome === "applied" ? `Applied ${r.change}. Rescan to see what it opened or closed.` : `Not applied: ${r.outcome}`));
  loadTimeline();
}

async function ask() {
  const box = $("#answer"); box.replaceChildren(el("p", { class: "muted" }, "Thinking..."));
  try {
    const r = await api("/api/ask", { question: $("#q").value });
    box.replaceChildren(el("p", {}, r.text),
      el("p", { class: "muted" }, `planner: ${r.planner} | name check: ${r.checked} | outcome: ${r.outcome}`),
      el("h3", {}, "Tool trace"));
    r.trace.forEach((s) => box.append(el("div", { class: "ev" }, `${s.tool.padEnd(14)} ${JSON.stringify(s.args)}  ${s.ms} ms  ${s.outcome}`)));
  } catch (e) { box.replaceChildren(el("p", { class: "BLOCKED" }, `Error: ${e.message}`)); }
}

// ---------------------------------------------------------------- chokepoints + reach
let lastView = { nodes: [] };
function hlNames(names) {
  if (!cy) return;
  cy.elements().removeClass("hl").addClass("dim");
  const shown = names.filter((n) => cy.getElementById(n).length);
  shown.forEach((n) => cy.getElementById(n).removeClass("dim").addClass("hl"));
  for (let i = 0; i < shown.length - 1; i++) {
    const a = CSS.escape(shown[i]), b = CSS.escape(shown[i + 1]);
    cy.edges(`[source = "${a}"][target = "${b}"], [source = "${b}"][target = "${a}"]`).removeClass("dim").addClass("hl");
  }
}
async function loadChoke() {
  const box = $("#choke"); box.replaceChildren(el("p", { class: "muted" }, "Running algo.betweenness..."));
  const r = await api("/api/chokepoints?limit=10");
  $("#choke-cypher").textContent = r.cypher || "";
  if (r.outcome !== "answered_with_path" || !r.chokepoints.length) {
    box.replaceChildren(el("p", { class: "muted" }, r.note || "Nothing to rank in this estate.")); return;
  }
  const max = Math.max(...r.chokepoints.map((c) => c.paths_through), 1);
  const t = el("table", {}, el("tr", {}, el("th", {}, "node"), el("th", {}, `paths through (of ${r.paths_total})`), el("th", {}, "betweenness")));
  r.chokepoints.forEach((c) => {
    const tr = el("tr", { tabindex: "0", style: "cursor:pointer" },
      el("td", { class: `k-${c.kind === "Tool" ? "Agent" : c.kind}` }, c.name),
      el("td", {}, el("div", { class: "bar", style: `width:${Math.max(4, 100 * c.paths_through / max)}%` }), String(c.paths_through)),
      el("td", {}, String(c.score)));
    const pick = () => hlNames([c.agent || c.name]);
    tr.addEventListener("click", pick); tr.addEventListener("keydown", (e) => e.key === "Enter" && pick());
    t.append(tr);
  });
  box.replaceChildren(t);
}
function fillReachSelects() {
  const by = (k) => lastView.nodes.filter((n) => n.kind === k).map((n) => n.id).sort();
  const opt = (sel, groups) => {
    const cur = sel.value; sel.replaceChildren();
    groups.forEach(([label, ids]) => { if (!ids.length) return; const g = el("optgroup", { label }); ids.forEach((i) => g.append(el("option", { value: i }, i))); sel.append(g); });
    if ([...sel.options].some((o) => o.value === cur)) sel.value = cur;
  };
  opt($("#r-src"), [["untrusted input", by("Source")], ["private data", by("Data")], ["agents", by("Agent")]]);
  opt($("#r-dst"), [["external sinks", by("Sink")], ["agents", by("Agent")], ["private data", by("Data")]]);
}
async function traceReach() {
  const box = $("#route");
  const r = await api(`/api/reach?src=${encodeURIComponent($("#r-src").value)}&dst=${encodeURIComponent($("#r-dst").value)}&k=3`);
  if (r.cypher) $("#choke-cypher").textContent = r.cypher;
  if (r.outcome !== "answered_with_path") {
    box.replaceChildren(el("p", { class: "muted" }, `${r.outcome.replaceAll("_", " ")}: ${r.note || r.name || ""}`)); clearHighlight(); return;
  }
  box.replaceChildren();
  r.routes.forEach((rt, i) => {
    const kids = [];
    rt.hops.forEach((h, j) => { if (j) kids.push(arrow()); kids.push(hop(h, rt.kinds[j] === "Tool" ? "Agent" : rt.kinds[j])); });
    const d = el("div", { class: "path", tabindex: "0", role: "button" }, el("div", {}, ...kids),
      el("div", { class: "muted" }, `${rt.hops.length - 1} hops, weight ${rt.weight}${rt.via.includes("DELEGATES") ? ", crosses a handoff" : ""}`));
    const pick = () => hlNames(rt.hops.filter((_, j) => rt.kinds[j] !== "Tool"));
    d.addEventListener("click", pick); box.append(d);
    if (i === 0) pick();
  });
}

// ---------------------------------------------------------------- gateway
async function runGateway(scn) {
  const box = $("#gw");
  const llm = $("#gw-llm").checked;
  box.replaceChildren(el("p", { class: "muted" }, llm ? "Running a real model twice through the gateway (rate limits can make this take a minute)..." : "Running..."));
  const r = await api("/api/gateway/run", { scenario: scn, llm });
  box.replaceChildren(el("p", { class: "muted" }, `victim: ${r.victim}`));
  r.runs.forEach((run) => {
    box.append(el("h3", {}, run.mode === "audit" ? "Gateway in audit mode (logs only)" : "Gateway enforcing"),
      el("div", { class: "muted" }, `task ${run.task}`));
    run.events.forEach((e) => {
      if (e.say) { box.append(el("div", { class: "ev muted" }, `model says: ${e.say}`)); return; }
      box.append(el("div", { class: `ev ${e.blocked ? "BLOCKED" : ""}` },
        `${e.agent.padEnd(16)} ${e.tool.padEnd(28)} ${e.blocked ? "BLOCKED" : "ok"}`));
      if (e.path) {
        const p = e.path;
        box.append(el("div", { class: "ev BLOCKED" },
          `why: ${p.untrusted[0]} entered via ${p.untrusted[1]}${p.untrusted[2] ? ` (${p.untrusted[2]})` : ""}, ` +
          `${p.private[0]} read via ${p.private[1]}${p.private[2] ? ` (${p.private[2]})` : ""}, ${p.sink[1]} would send to ${p.sink[0]}`));
      }
    });
    box.append(el("div", { class: `verdict ${run.exfiltrated.length ? "leak" : "safe"}` },
      run.exfiltrated.length ? `Attacker inbox: RECEIVED data (${run.exfiltrated.join(", ")})` : "Attacker inbox: empty"));
  });
  await loadLedger();
  if (estate() === "gateway") await loadAll();
}
async function loadLedger() {
  const r = await api("/api/gateway/ledger");
  if (!r.calls.length) { $("#ledger").replaceChildren("No calls yet."); return; }
  const t = el("table", {}, el("tr", {}, ...["task", "#", "agent", "tool", "verdict"].map((h) => el("th", {}, h))));
  r.calls.slice(0, 60).forEach((c) => t.append(el("tr", {},
    el("td", {}, c.task), el("td", {}, String(c.seq)), el("td", { class: "k-Agent" }, c.agent), el("td", {}, c.tool),
    el("td", { class: ["blocked", "denied"].includes(c.verdict) ? "BLOCKED" : c.verdict === "audit-would-block" ? "k-Source" : "" }, c.verdict))));
  $("#ledger").replaceChildren(t);
}

// ---------------------------------------------------------------- ask a human
// The held call waits in another thread on the server; its Approval node lives in the
// graph, so any process (this UI, `reach.approve`, a second gateway) can decide it.
async function runAsk(scn) {
  const box = $("#ask");
  box.replaceChildren(el("p", { class: "muted" }, "Running with the gateway in ask mode..."));
  const { job, task } = await api("/api/gateway/ask", { scenario: scn });
  for (let i = 0; i < 240; i++) {
    const st = await api(`/api/gateway/ask-status?job=${job}`);
    if (st.status !== "running") { showAskResult(box, st, task); return; }
    const { pending } = await api("/api/approvals");
    const mine = pending.filter((p) => p.task === task);
    if (mine.length && !box.querySelector(`[data-ap="${mine[0].id}"]`)) {
      const p = mine[0];
      const yes = el("button", { class: "primary" }, "Approve this send");
      const no = el("button", {}, "Deny it");
      const card = el("div", { class: "card approval", "data-ap": p.id, role: "alertdialog", "aria-label": "Approval needed" },
        el("strong", {}, `Approval needed: ${p.agent} wants to call ${p.tool}`),
        el("div", { class: "ev BLOCKED" }, `why held: ${p.why}`),
        el("div", { class: "row" }, yes, no));
      const decideIt = async (approve) => { yes.disabled = no.disabled = true; await api("/api/approvals/decide", { id: p.id, approve }); };
      yes.addEventListener("click", () => decideIt(true));
      no.addEventListener("click", () => decideIt(false));
      box.replaceChildren(el("p", { class: "muted" }, `task ${task}: the call is held in the gateway until you decide.`), card);
      yes.focus();
    }
    await new Promise((r) => setTimeout(r, 500));
  }
}
function showAskResult(box, st, task) {
  if (st.status === "error") { box.replaceChildren(el("p", { class: "BLOCKED" }, st.error)); return; }
  box.replaceChildren(el("h3", {}, `Ask mode result (task ${task})`));
  st.events.forEach((e) => box.append(el("div", { class: `ev ${e.blocked ? "BLOCKED" : ""}` },
    `${e.agent.padEnd(16)} ${e.tool.padEnd(28)} ${e.blocked ? "DENIED" : "ok"}`)));
  box.append(el("div", { class: `verdict ${st.exfiltrated.length ? "leak" : "safe"}` },
    st.exfiltrated.length ? `You approved it: attacker inbox RECEIVED data` : "Attacker inbox: empty"));
  loadLedger();
}

// ---------------------------------------------------------------- my setup
async function scanSetup(which) {
  const box = $("#setup"); box.replaceChildren(el("p", { class: "muted" }, "Scanning configs..."));
  const r = await api("/api/setup", { which });
  const sev = r.severity || {};
  box.replaceChildren(
    el("div", { class: `verdict ${r.paths ? "leak" : "safe"}` },
      `${r.paths} lethal-trifecta path(s) across ${r.clients.length} client(s). ` +
      `${sev["all-legs-auto-approved"] || 0} with every step auto-approved, ${sev["partly-auto-approved"] || 0} partly.`));
  const t = el("table", {}, el("tr", {}, el("th", {}, "client"), el("th", {}, "server"), el("th", {}, "tool list from"), el("th", {}, "tools")));
  r.clients.slice(0, 40).forEach((c) => c.servers.forEach((s, i) => t.append(el("tr", {},
    el("td", { class: "k-Agent" }, i ? "" : c.client), el("td", {}, s.name),
    el("td", { class: s.source === "unmodelled" ? "BLOCKED" : "muted" }, s.source), el("td", {}, String(s.tools ?? 0))))));
  box.append(t);
  if (r.unmodelled.length) box.append(el("p", { class: "muted" },
    `Unmodelled, not scanned and NOT safe: ${r.unmodelled.map((u) => (u.clients > 1 ? `${u.server} (x${u.clients})` : u.server)).join(", ")}. ` +
    "Run `reach.setup --live` to ask those servers for their tools."));
  $("#estate").value = which;
  await loadAll();
}
async function loadEstate() { lastView = await api("/api/estate"); drawEstate(lastView); fillReachSelects(); }
async function loadAll() {
  $("#paths-summary").textContent = "Loading...";
  try {
    await loadEstate(); await loadPaths(); await loadTimeline();
    if (!$("#t-choke").hidden) await loadChoke();
    if (!lastView.nodes.length) $("#paths-summary").textContent =
      estate() === "gateway" ? "Empty: run a scenario in the Gateway tab and the gateway registers what it proxies here."
      : estate() === "mine" ? "Empty: use My setup -> Scan this machine." : "Empty estate.";
  } catch (e) { $("#paths-summary").textContent = `Error: ${e.message}`; }
}
document.querySelectorAll("[role=tab]").forEach((b) => b.addEventListener("click", () => {
  document.querySelectorAll("[role=tab]").forEach((x) => x.setAttribute("aria-selected", x === b));
  document.querySelectorAll("[role=tabpanel]").forEach((p) => (p.hidden = p.id !== b.getAttribute("aria-controls")));
  if (b.id !== "b-paths") clearHighlight();
  if (b.id === "b-choke") loadChoke().catch((e) => ($("#choke").textContent = e.message));
  if (b.id === "b-gw") loadLedger().catch(() => {});
}));
document.querySelectorAll("[data-ask]").forEach((b) => b.addEventListener("click", () => runAsk(b.dataset.ask).catch((e) => ($("#ask").textContent = e.message))));
document.querySelectorAll("[data-gw]").forEach((b) => b.addEventListener("click", () => runGateway(b.dataset.gw).catch((e) => ($("#gw").textContent = e.message))));
$("#r-go").addEventListener("click", () => traceReach().catch((e) => ($("#route").textContent = e.message)));
async function proposeHardening() {
  const box = $("#harden-out");
  box.replaceChildren(el("p", { class: "muted" }, "Planning edits for each config..."));
  const r = await api("/api/harden", {});
  box.replaceChildren(el("p", { class: "muted" }, `Dry run: nothing is written. ${r.note}`));
  r.configs.forEach((c) => {
    const card = el("div", { class: "card" }, el("strong", {}, `${c.agent} (${c.file}): ${c.paths} path(s)`));
    if (!c.edits.length) card.append(el("div", { class: "muted" }, "Already guarded: every send needs a human."));
    c.edits.forEach((e) => card.append(el("div", {}, `${e.kind}: ${(e.tools || e.servers).join(", ")}`), el("div", { class: "muted" }, e.why)));
    card.append(el("div", { class: "verdict safe" }, `after: ${c.paths_guarded_after}/${c.paths} guarded; ${c.capabilities_removed} tools removed`));
    if (c.diff) { const d = el("details", {}, el("summary", {}, "diff")); d.append(el("pre", {}, c.diff)); card.append(d); }
    box.append(card);
  });
}
$("#harden").addEventListener("click", () => proposeHardening().catch((e) => ($("#harden-out").textContent = e.message)));
$("#setup-sample").addEventListener("click", () => scanSetup("sample").catch((e) => ($("#setup").textContent = e.message)));
$("#setup-mine").addEventListener("click", () => scanSetup("mine").catch((e) => ($("#setup").textContent = e.message)));
api("/api/config").then((c) => {
  if (c.public) { $("#opt-mine").remove(); $("#setup-mine").remove(); $("#setup-note").remove(); }
  if (!c.llm) $("#gw-llm-wrap").remove();
}).catch(() => {});
document.querySelectorAll("[data-scn]").forEach((b) => b.addEventListener("click", () => runRed(b.dataset.scn).catch((e) => ($("#red").textContent = e.message))));
$("#fix-zero").addEventListener("click", () => loadFix("zero_break"));
$("#fix-all").addEventListener("click", () => loadFix("close_all"));
$("#scan").addEventListener("click", () => rescan().catch((e) => ($("#scan-out").textContent = e.message)));
$("#ch-apply").addEventListener("click", applyChange);
$("#ask").addEventListener("click", ask);
$("#q").addEventListener("keydown", (e) => e.key === "Enter" && ask());
$("#estate").addEventListener("change", loadAll);
loadAll();
