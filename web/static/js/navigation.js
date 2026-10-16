const state = {
  overview: null,
  summaries: [],
  graphIndexById: new Map(),
  graph: null,
  selectedGraphId: null,
  selectedNodeId: null,
  activeFilter: "",
  activeClassFilter: "",
  selectedPath: "all",
  showApproximate: true,
  transform: { x: 0, y: 0, scale: 1 },
  bounds: { width: 1000, height: 600 },
};

const $ = (selector) => document.querySelector(selector);
const svgNS = "http://www.w3.org/2000/svg";

const colors = {
  "Intent Redirection": "var(--red)",
  "Intent Injection": "var(--amber)",
  "Intent Spoofing": "var(--purple)",
};

const classificationLabels = {
  primary_finding: "confirmed",
  confirmed: "confirmed",
  supporting_flow: "non-prooved",
  unresolved_diagnostic: "non-prooved",
  non_prooved: "non-prooved",
  unconfirmed: "unconfirmed",
};

const classificationAliases = {
  confirmed: new Set(["confirmed", "primary_finding"]),
  non_prooved: new Set(["non_prooved", "supporting_flow", "unresolved_diagnostic"]),
};

function classificationLabel(value) {
  return classificationLabels[value] || value?.replaceAll("_", " ") || "unconfirmed";
}

function el(name, attributes = {}) {
  const node = document.createElementNS(svgNS, name);
  Object.entries(attributes).forEach(([key, value]) => node.setAttribute(key, value));
  return node;
}

function escapeHTML(value) {
  return String(value ?? "—")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function shortText(value, length = 25) {
  const text = String(value ?? "—");
  return text.length > length ? `${text.slice(0, length - 1)}…` : text;
}

function formatNumber(value) {
  return new Intl.NumberFormat("ko-KR").format(value ?? 0);
}

async function fetchJSON(url) {
  const target = new URL(url, location.origin);
  const project = new URLSearchParams(location.search).get("project");
  if (project && !target.searchParams.has("project")) target.searchParams.set("project", project);
  const response = await fetch(target);
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json();
}

async function initialize() {
  try {
    const [overview, summaries] = await Promise.all([
      fetchJSON("/api/overview"),
      fetchJSON("/api/graphs"),
    ]);
    state.overview = overview;
    state.summaries = summaries;
    state.graphIndexById = new Map(summaries.map((graph, index) => [graph.graph_id, index + 1]));
    renderOverview();
    renderGraphList();
    if (summaries.length) await selectGraph(summaries[0].graph_id);
  } catch (error) {
    $("#empty-state").innerHTML = `<div class="error-message">데이터를 불러오지 못했습니다.<br>${escapeHTML(error.message)}</div>`;
  }
}

function renderOverview() {
  $("#package-name").textContent = state.overview.package;
}

function filteredSummaries() {
  return state.summaries.filter((graph) => {
    const matchesType = !state.activeFilter || graph.candidate_types.some((item) => item.toLowerCase().includes(state.activeFilter));
    const matchesClass = !state.activeClassFilter
      || classificationAliases[state.activeClassFilter]?.has(graph.classification)
      || graph.classification === state.activeClassFilter;
    const haystack = [
      graph.graph_id,
      graphDisplayLabel(graph.graph_id),
      ...graph.entry_points,
      graph.sink,
      ...graph.candidate_types,
      ...(graph.source_keys || []),
      ...(graph.target_components || []),
    ].join(" ").toLowerCase();
    return matchesType && matchesClass;
  });
}

function graphDisplayLabel(graphId) {
  const index = state.graphIndexById.get(graphId);
  if (!Number.isInteger(index)) return "flow-000";
  return `flow-${String(index).padStart(3, "0")}`;
}

function renderGraphList() {
  const values = filteredSummaries();
  $("#graph-count").textContent = `${values.length} / ${state.summaries.length}`;
  $("#graph-list").innerHTML = values.map((graph) => `
    <button class="graph-item ${graph.graph_id === state.selectedGraphId ? "active" : ""}" data-graph-id="${escapeHTML(graph.graph_id)}">
      <div class="graph-item-top">
        <span class="graph-item-id">${escapeHTML(graphDisplayLabel(graph.graph_id))}</span>
        <span class="graph-item-paths">${graph.effect_path_count} effect · ${graph.branch_candidate_count} branch · ${graph.supporting_control_count} support</span>
      </div>
      <div class="graph-classification ${escapeHTML(graph.classification)}">${escapeHTML(classificationLabel(graph.classification))}</div>
      <div class="graph-item-entry">↳ ${escapeHTML(graph.entry_points.join(", "))}</div>
      <div class="graph-item-sink">◎ ${escapeHTML(graph.sink)}</div>
      <div class="graph-item-evidence">${formatNumber(graph.confirmed_path_count)} confirmed · ${formatNumber(graph.review_path_count)} review</div>
      ${graph.source_keys?.length ? `<div class="graph-item-evidence">keys: ${escapeHTML(graph.source_keys.join(", "))}</div>` : ""}
      <div class="mini-types">
        ${graph.candidate_types.map((item) => `<i class="mini-type" title="${escapeHTML(item)}" style="background:${colors[item] || "var(--blue)"}"></i>`).join("")}
      </div>
    </button>
  `).join("") || `<div class="inspector-empty"><p>조건과 일치하는 graph가 없습니다.</p></div>`;

  document.querySelectorAll(".graph-item").forEach((button) => {
    button.addEventListener("click", () => selectGraph(button.dataset.graphId));
  });
}

async function selectGraph(graphId) {
  state.selectedGraphId = graphId;
  state.selectedNodeId = null;
  state.selectedPath = "all";
  renderGraphList();
  state.graph = await fetchJSON(`/api/graphs/${encodeURIComponent(graphId)}`);
  renderGraphHeader();
  renderPathOptions();
  renderInspector(null);
  renderGraph();
  requestAnimationFrame(fitGraph);
}

function renderGraphHeader() {
  const graph = state.graph;
  const nodeById = new Map(graph.resolved_nodes.map((node) => [node.id, node]));
  const entries = graph.entry_points.map((id) => nodeById.get(id)?.label || id);
  const sink = nodeById.get(graph.sink);
  $("#graph-short-id").textContent = graphDisplayLabel(graph.graph_id);
  $("#graph-title").textContent = `${entries.join(", ")} → ${sink?.label || graph.sink}`;
  $("#type-badges").innerHTML = graph.candidate_types.map((item) => `
    <span class="type-badge" style="color:${colors[item] || "var(--blue)"}">${escapeHTML(item)}</span>
  `).join("") + `<span class="type-badge classification-badge">${escapeHTML(classificationLabel(graph.classification))}</span>`;
  const supportingControls = graph.paths.filter(isSupportingControl).length;
  const branchCandidates = graph.paths.filter(isBranchCandidate).length;
  const standaloneBranchCandidates = graph.paths.filter(isStandaloneBranchCandidate).length;
  $("#graph-metrics").innerHTML = [
    [graph.resolved_nodes.length, "nodes"],
    [graph.resolved_edges.length, "edges"],
    [graph.paths.length - supportingControls - standaloneBranchCandidates, "effects"],
    [branchCandidates, "branch sinks"],
    [supportingControls, "supports"],
  ].map(([value, label]) => `<div class="metric-card"><b>${formatNumber(value)}</b><span>${label}</span></div>`).join("");
}

function isSupportingControl(path) {
  if (Object.hasOwn(path, "supporting")) return path.supporting === true;
  if (path.reporting_role !== undefined && path.reporting_role !== null) {
    return path.reporting_role === "supporting_control";
  }
  return path.source_role === "control" && path.branch_candidate !== true;
}

function isStandaloneBranchCandidate(path) {
  return isBranchCandidate(path) && !isSupportingControl(path);
}

function isBranchCandidate(path) {
  return path.branch_candidate === true;
}

function renderPathOptions() {
  const nodeById = new Map(state.graph.resolved_nodes.map((node) => [node.id, node]));
  $("#path-select").innerHTML = `
    <option value="all">All paths (${state.graph.paths.length})</option>
    ${state.graph.paths.map((path, index) => {
      const source = nodeById.get(path.source_id);
      const branchCandidate = isBranchCandidate(path);
      const supportingControl = isSupportingControl(path);
      const purpose = branchCandidate && supportingControl
        ? "Branch candidate · linked support"
        : branchCandidate
          ? "Branch-controlled sink"
          : supportingControl
            ? "Reachability support"
            : "Effect";
      const sourceName = source?.key || source?.field || source?.label || path.source_role || path.evidence_mode;
      return `<option value="${index}">Path ${String(index + 1).padStart(2, "0")} · ${purpose} · ${escapeHTML(sourceName)} · ${escapeHTML(path.confirmation_status || "unconfirmed")}</option>`;
    }).join("")}
  `;
  $("#path-select").value = "all";
}

function activePaths() {
  if (state.selectedPath === "all") return state.graph.paths;
  const path = state.graph.paths[Number(state.selectedPath)];
  return path ? [path] : state.graph.paths;
}

function graphSelection() {
  const paths = activePaths();
  const nodeIds = new Set();
  const edgeIds = new Set();
  paths.forEach((path) => {
    path.node_ids.forEach((id) => nodeIds.add(id));
    path.edge_ids.forEach((id) => edgeIds.add(id));
  });
  let edges = state.graph.resolved_edges.filter((edge) => edgeIds.has(edge.id));
  if (!state.showApproximate) edges = edges.filter((edge) => edge.direct);
  if (!state.showApproximate) {
    const connected = new Set(state.graph.entry_points);
    state.graph.sources.forEach((id) => connected.add(id));
    connected.add(state.graph.sink);
    edges.forEach((edge) => { connected.add(edge.source); connected.add(edge.target); });
    [...nodeIds].forEach((id) => { if (!connected.has(id)) nodeIds.delete(id); });
  }
  const nodes = state.graph.resolved_nodes.filter((node) => nodeIds.has(node.id));
  return { paths, nodes, edges };
}

function computeLayout(nodes, paths) {
  const ranks = new Map();
  const appearances = new Map();
  paths.forEach((path) => {
    path.node_ids.forEach((id, index) => {
      if (!appearances.has(id)) appearances.set(id, []);
      appearances.get(id).push(index);
    });
  });
  nodes.forEach((node) => {
    const values = appearances.get(node.id) || [0];
    ranks.set(node.id, Math.round(values.reduce((sum, value) => sum + value, 0) / values.length));
  });

  const groups = new Map();
  nodes.forEach((node) => {
    const rank = ranks.get(node.id) || 0;
    if (!groups.has(rank)) groups.set(rank, []);
    groups.get(rank).push(node);
  });

  const positions = new Map();
  const sortedRanks = [...groups.keys()].sort((a, b) => a - b);
  let maxRows = 1;
  sortedRanks.forEach((rank, rankIndex) => {
    const group = groups.get(rank).sort((a, b) => nodeWeight(a) - nodeWeight(b) || a.label.localeCompare(b.label));
    maxRows = Math.max(maxRows, group.length);
    const gap = 128;
    const total = (group.length - 1) * gap;
    group.forEach((node, row) => {
      positions.set(node.id, { x: 105 + rankIndex * 205, y: 100 + row * gap - total / 2 + (maxRows - 1) * gap / 2 });
    });
  });
  return {
    positions,
    width: Math.max(500, sortedRanks.length * 205 + 80),
    height: Math.max(340, maxRows * 128 + 100),
  };
}

function nodeWeight(node) {
  return { entry_point: 0, component: 1, source: 2, guard: 3, method: 4, state: 5, value: 6, sink: 9 }[node.type] ?? 7;
}

function glyph(node) {
  return { entry_point: "E", component: "C", source: "S", sink: "!", method: "M", state: "F", value: "V", dispatch: "D", guard: "G" }[node.type] || "N";
}

function renderGraph() {
  if (!state.graph) return;
  const { paths, nodes, edges } = graphSelection();
  const layout = computeLayout(nodes, paths);
  state.bounds = { width: layout.width, height: layout.height };
  const edgeLayer = $("#edge-layer");
  const nodeLayer = $("#node-layer");
  edgeLayer.replaceChildren();
  nodeLayer.replaceChildren();

  edges.forEach((edge) => {
    const from = layout.positions.get(edge.source);
    const to = layout.positions.get(edge.target);
    if (!from || !to) return;
    const dx = Math.max(42, (to.x - from.x) * 0.48);
    const pathData = `M ${from.x + 32} ${from.y} C ${from.x + dx} ${from.y}, ${to.x - dx} ${to.y}, ${to.x - 32} ${to.y}`;
    const line = el("path", { d: pathData, class: `graph-edge ${edge.direct ? "direct" : "approximate"}` });
    const title = el("title");
    title.textContent = `${edge.type}: ${edge.relation || ""}`;
    line.appendChild(title);
    edgeLayer.appendChild(line);
    const hit = el("path", { d: pathData, class: "edge-hit" });
    hit.addEventListener("click", (event) => { event.stopPropagation(); renderEdgeInspector(edge); });
    edgeLayer.appendChild(hit);
  });

  nodes.forEach((node) => {
    const position = layout.positions.get(node.id);
    const group = el("g", { class: `graph-node ${node.type} ${state.selectedNodeId === node.id ? "selected" : ""}`, transform: `translate(${position.x}, ${position.y})`, tabindex: "0", role: "button", "aria-label": `${node.type} ${node.label}` });
    group.appendChild(el("circle", { class: "node-halo", r: 35 }));
    group.appendChild(el("circle", { class: "node-ring", r: 27, stroke: "currentColor" }));
    const glyphText = el("text", { class: "node-glyph", x: 0, y: 1 });
    glyphText.textContent = glyph(node);
    group.appendChild(glyphText);
    const title = el("text", { class: "node-title", x: 0, y: 48 });
    title.textContent = shortText(node.label, 29);
    group.appendChild(title);
    const subtitle = el("text", { class: "node-subtitle", x: 0, y: 62 });
    subtitle.textContent = node.id;
    group.appendChild(subtitle);
    const activate = (event) => { event.stopPropagation(); state.selectedNodeId = node.id; renderInspector(node); renderGraph(); };
    group.addEventListener("click", activate);
    group.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") activate(event); });
    nodeLayer.appendChild(group);
  });

  $("#empty-state").classList.toggle("hidden", nodes.length > 0);
  applyTransform();
}

function applyTransform() {
  const { x, y, scale } = state.transform;
  $("#viewport-layer").setAttribute("transform", `translate(${x} ${y}) scale(${scale})`);
}

function fitGraph() {
  const stage = $("#graph-stage");
  const width = stage.clientWidth;
  const height = stage.clientHeight;
  const scale = Math.min(1.18, Math.max(0.18, Math.min((width - 70) / state.bounds.width, (height - 60) / state.bounds.height)));
  state.transform = {
    scale,
    x: (width - state.bounds.width * scale) / 2,
    y: (height - state.bounds.height * scale) / 2,
  };
  applyTransform();
}

function zoomBy(factor, center = null) {
  const stage = $("#graph-stage");
  const point = center || { x: stage.clientWidth / 2, y: stage.clientHeight / 2 };
  const oldScale = state.transform.scale;
  const nextScale = Math.min(2.5, Math.max(0.15, oldScale * factor));
  const worldX = (point.x - state.transform.x) / oldScale;
  const worldY = (point.y - state.transform.y) / oldScale;
  state.transform.x = point.x - worldX * nextScale;
  state.transform.y = point.y - worldY * nextScale;
  state.transform.scale = nextScale;
  applyTransform();
}

function renderInspector(node) {
  const inspector = $(".inspector");
  if (!node) {
    $("#inspector-id").textContent = "NO SELECTION";
    $("#inspector-content").innerHTML = `<div class="inspector-empty"><div class="inspect-icon">◎</div><p>노드를 선택하면 메서드, 컴포넌트, key, 근거를 확인할 수 있습니다.</p></div>`;
    inspector.classList.remove("open");
    return;
  }
  inspector.classList.add("open");
  $("#inspector-id").textContent = node.id;
  const details = [
    ["Component", node.component],
    ["Method", node.method],
    ["API", node.api],
    ["Extra key", node.key],
    ["Instruction", node.instruction],
    ["Offset", node.offset === null ? null : `0x${Number(node.offset).toString(16).padStart(4, "0")}`],
    ["Relation", node.metadata?.relation],
    ["Rule", node.metadata?.rule],
    ["Attacker controlled", node.metadata?.attacker_controlled],
  ].filter(([, value]) => value !== null && value !== undefined && value !== "");
  const availableTargets = node.id === state.graph?.sink
    ? state.graph.outgoing_targets || []
    : [];
  $("#inspector-content").innerHTML = `
    <span class="node-type-label" style="color:${nodeColor(node.type)}">${escapeHTML(node.type)}</span>
    <h3 class="inspector-title">${escapeHTML(node.label)}</h3>
    <dl class="detail-list">
      ${details.map(([label, value]) => `<div class="detail-row"><dt>${escapeHTML(label)}</dt><dd>${escapeHTML(value)}</dd></div>`).join("")}
    </dl>
    ${availableTargets.length ? `
      <section class="available-targets">
        <h4>available_target <span>${availableTargets.length}</span></h4>
        <ul>
          ${availableTargets.map((target) => `
            <li>
              <code>${escapeHTML(target.target_component)}</code>
            </li>
          `).join("")}
        </ul>
      </section>
    ` : ""}
  `;
}

function renderEdgeInspector(edge) {
  state.selectedNodeId = null;
  $(".inspector").classList.add("open");
  $("#inspector-id").textContent = edge.id;
  const evidence = edge.evidence || {};
  const details = [
    ["Source", edge.source], ["Target", edge.target], ["Type", edge.type],
    ["Relation", edge.relation], ["Evidence mode", evidence.mode],
    ["Method", evidence.method], ["Instruction", evidence.instruction],
    ["Resolution", evidence.resolution], ["Source site", evidence.source_site],
  ].filter(([, value]) => value !== null && value !== undefined && value !== "");
  $("#inspector-content").innerHTML = `
    <span class="node-type-label" style="color:${edge.direct ? "var(--blue)" : "var(--purple)"}">${edge.direct ? "DIRECT EDGE" : "APPROXIMATE EDGE"}</span>
    <h3 class="inspector-title">${escapeHTML(edge.type)}</h3>
    <dl class="detail-list">${details.map(([label, value]) => `<div class="detail-row"><dt>${escapeHTML(label)}</dt><dd>${escapeHTML(value)}</dd></div>`).join("")}</dl>
  `;
}

function nodeColor(type) {
  return {
    entry_point: "var(--cyan)",
    component: "var(--purple)",
    source: "var(--amber)",
    sink: "var(--red)",
    method: "var(--blue)",
    state: "var(--blue)",
    value: "var(--green)",
  }[type] || "var(--muted)";
}

function bindControls() {
  document.querySelectorAll(".filter-chip").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".filter-chip").forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
      state.activeFilter = button.dataset.filter;
      renderGraphList();
    });
  });
  document.querySelectorAll(".class-filter-chip").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".class-filter-chip").forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
      state.activeClassFilter = button.dataset.classFilter;
      renderGraphList();
    });
  });
  $("#path-select").addEventListener("change", (event) => {
    state.selectedPath = event.target.value;
    renderGraph();
    requestAnimationFrame(fitGraph);
  });
  $("#approx-toggle").addEventListener("change", (event) => {
    state.showApproximate = event.target.checked;
    renderGraph();
    requestAnimationFrame(fitGraph);
  });
  $("#fit-button").addEventListener("click", fitGraph);
  $("#zoom-in").addEventListener("click", () => zoomBy(1.2));
  $("#zoom-out").addEventListener("click", () => zoomBy(0.82));

  const svg = $("#graph-svg");
  svg.addEventListener("wheel", (event) => {
    event.preventDefault();
    const rect = svg.getBoundingClientRect();
    zoomBy(event.deltaY < 0 ? 1.12 : 0.89, { x: event.clientX - rect.left, y: event.clientY - rect.top });
  }, { passive: false });

  let drag = null;
  svg.addEventListener("pointerdown", (event) => {
    if (event.target.closest?.(".graph-node")) return;
    drag = { x: event.clientX, y: event.clientY, originX: state.transform.x, originY: state.transform.y };
    svg.setPointerCapture(event.pointerId);
    svg.classList.add("panning");
  });
  svg.addEventListener("pointermove", (event) => {
    if (!drag) return;
    state.transform.x = drag.originX + event.clientX - drag.x;
    state.transform.y = drag.originY + event.clientY - drag.y;
    applyTransform();
  });
  const finishPan = (event) => {
    if (!drag) return;
    drag = null;
    svg.releasePointerCapture?.(event.pointerId);
    svg.classList.remove("panning");
  };
  svg.addEventListener("pointerup", finishPan);
  svg.addEventListener("pointercancel", finishPan);
  svg.addEventListener("click", (event) => {
    if (event.target === svg) {
      state.selectedNodeId = null;
      renderInspector(null);
      renderGraph();
    }
  });
  window.addEventListener("resize", fitGraph);
}

bindControls();
initialize();
