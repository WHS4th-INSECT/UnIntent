(() => {
  const pageState = {
    page: "overview",
    projects: [],
    projectQuery: "",
    projectPage: 1,
    dynamicOverview: null,
    dynamicFlows: [],
    dynamicFlowFilter: "all",
    dynamicPayloads: [],
    dynamicSelectedFlow: null,
    dynamicSelectedPayload: null,
  };

  const q = (selector) => document.querySelector(selector);
  const qa = (selector) => [...document.querySelectorAll(selector)];

  function esc(value) {
    return String(value ?? "—")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;");
  }

  function num(value) {
    return new Intl.NumberFormat("ko-KR").format(value ?? 0);
  }

  function statusClass(value) {
    return String(value || "not_tested").replaceAll(/[^a-z0-9_]/gi, "_");
  }

  function projectDisplayName(project) {
    return String(project.apk_name || project.id || "Unknown project").replace(/\.apk$/i, "");
  }

  async function getJSON(url) {
    const target = new URL(url, location.origin);
    const project = new URLSearchParams(location.search).get("project");
    if (project && !target.searchParams.has("project")) target.searchParams.set("project", project);
    const response = await fetch(target);
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
    return response.json();
  }

  function switchPage(page) {
    if (!["overview", "projects", "static", "dynamic", "analyze", "reports"].includes(page)) page = "overview";
    pageState.page = page;
    if (location.hash !== `#${page}`) history.replaceState(null, "", `#${page}`);
    qa(".lab-page").forEach((item) => { item.hidden = item.id !== `${page}-page`; });
    q("#app-shell").dataset.activePage = page;
    qa(".page-nav").forEach((item) => item.classList.toggle("active", item.dataset.page === page));
    qa(".static-page-region").forEach((item) => item.classList.toggle("page-hidden", page !== "static"));
    q("#dynamic-page").hidden = page !== "dynamic";
    q("#topbar-page-name").textContent = {
      overview: "Overview", projects: "Projects", analyze: "Analyze", reports: "Reports",
      static: "정적분석 결과",
      dynamic: "동적분석 결과",
    }[page];
    if (page === "static") window.dispatchEvent(new Event("resize"));
    window.dispatchEvent(new CustomEvent("dashboard:pagechange", { detail: { page } }));
  }

  function renderProjects(projects) {
    if (projects) pageState.projects = projects;
    const allProjects = pageState.projects;
    const selectedId = new URLSearchParams(location.search).get("project")
      || allProjects.find((item) => item.selected)?.id;
    const filtered = allProjects.filter((project) => {
      const projectName = projectDisplayName(project);
      return !pageState.projectQuery || projectName.toLowerCase().includes(pageState.projectQuery);
    });
    const pageSize = 15;
    const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
    pageState.projectPage = Math.min(pageState.projectPage, totalPages);
    const start = (pageState.projectPage - 1) * pageSize;
    const visible = filtered.slice(start, start + pageSize);

    q("#nav-project-count").textContent = num(allProjects.length);
    q("#project-source-label").textContent = `${num(filtered.length)} projects · Page ${pageState.projectPage} of ${totalPages} · 15 per page`;
    q("#project-list-body").innerHTML = visible.map((project, index) => `
      <div class="project-list-row ${project.id === selectedId ? "selected" : ""}">
        <span class="project-number">${String(start + index + 1).padStart(2, "0")}</span>
        <span class="project-apk-name">${esc(projectDisplayName(project))}</span>
        <button class="lab-button ${project.id === selectedId ? "primary" : ""}" data-project-open="${esc(project.id)}" data-project-page="overview">Open project</button>
      </div>
    `).join("") || '<div class="project-loading">검색 결과가 없습니다.</div>';

    const pageButtons = [
      `<button type="button" data-project-list-page="${pageState.projectPage - 1}" ${pageState.projectPage === 1 ? "disabled" : ""} aria-label="이전 페이지">‹</button>`,
      ...Array.from({ length: totalPages }, (_, index) => {
        const page = index + 1;
        return `<button type="button" data-project-list-page="${page}" class="${page === pageState.projectPage ? "current" : ""}" ${page === pageState.projectPage ? 'aria-current="page"' : ""}>${page}</button>`;
      }),
      `<button type="button" data-project-list-page="${pageState.projectPage + 1}" ${pageState.projectPage === totalPages ? "disabled" : ""} aria-label="다음 페이지">›</button>`,
    ];
    q("#project-pagination").innerHTML = pageButtons.join("");

    qa("#project-list-body [data-project-open]").forEach((button) => button.addEventListener("click", () => {
      const target = new URL(location.href);
      target.searchParams.set("project", button.dataset.projectOpen);
      target.hash = button.dataset.projectPage;
      location.href = target.toString();
    }));
    qa("#project-pagination [data-project-list-page]").forEach((button) => button.addEventListener("click", () => {
      if (button.disabled) return;
      pageState.projectPage = Number(button.dataset.projectListPage);
      renderProjects();
      q("#projects-page").scrollTo({ top: 0, behavior: "smooth" });
    }));
  }

  function inputSummary(inputs) {
    return (inputs || []).map((input) => {
      const name = input.key ? `${input.field}:${input.key}` : input.field;
      return `${name}=${input.value ?? "null"}`;
    }).join(", ") || "No inputs";
  }

  function renderDynamicFlows() {
    const flows = pageState.dynamicFlows.filter((flow) =>
      pageState.dynamicFlowFilter === "all"
      || Number(flow[`${pageState.dynamicFlowFilter}_count`]) > 0
    );
    q("#dynamic-flow-count").textContent = num(flows.length);
    qa("[data-flow-filter]").forEach((button) => {
      button.setAttribute("aria-pressed", String(button.dataset.flowFilter === pageState.dynamicFlowFilter));
    });
    q("#dynamic-flow-list").innerHTML = flows.map((flow) => `
      <button class="dynamic-flow-item ${pageState.dynamicSelectedFlow === flow.flow_id ? "active" : ""}" data-flow-id="${esc(flow.flow_id)}">
        <strong>${esc(flow.flow_id)}</strong>
        <em class="dynamic-flow-entry" title="${esc(flow.entry_point)}">${esc(flow.entry_point || "Unknown entry point")}</em>
        <span><b class="success-text">${num(flow.success_count)} success</b><i>·</i><b class="failure-text">${num(flow.failure_count)} failed</b></span>
      </button>
    `).join("") || `<div class="dynamic-empty">동적분석 Flow가 없습니다.</div>`;
    qa("#dynamic-flow-list [data-flow-id]").forEach((button) => {
      button.addEventListener("click", () => selectDynamicFlow(button.dataset.flowId));
    });
  }

  async function filterDynamicFlows(status) {
    pageState.dynamicFlowFilter = pageState.dynamicFlowFilter === status ? "all" : status;
    const first = pageState.dynamicFlows.find((flow) =>
      pageState.dynamicFlowFilter === "all"
      || Number(flow[`${pageState.dynamicFlowFilter}_count`]) > 0
    );
    renderDynamicFlows();
    if (first && first.flow_id !== pageState.dynamicSelectedFlow) await selectDynamicFlow(first.flow_id);
  }

  function payloadGroup(title, status, payloads) {
    const values = payloads.filter((payload) => payload.status === status);
    return `
      <section class="dynamic-payload-group ${status}">
        <h3>${esc(title)} <span>${num(values.length)}</span></h3>
        ${values.map((payload) => `
          <button class="dynamic-payload-item ${pageState.dynamicSelectedPayload === payload.payload_id ? "active" : ""}" data-payload-id="${esc(payload.payload_id)}">
            <strong>${esc(payload.payload_id)}</strong>
            <span>${esc(inputSummary(payload.inputs))}</span>
            <b class="status-badge ${statusClass(payload.status)}">${esc(payload.status)}</b>
          </button>
        `).join("") || `<div class="dynamic-group-empty">No ${esc(status)} payloads</div>`}
      </section>
    `;
  }

  function renderDynamicPayloads() {
    q("#dynamic-payload-title").textContent = pageState.dynamicSelectedFlow
      ? `PAYLOADS — ${pageState.dynamicSelectedFlow}`
      : "PAYLOADS";
    q("#dynamic-payload-list").innerHTML = [
      payloadGroup("SUCCEEDED", "success", pageState.dynamicPayloads),
      payloadGroup("FAILED", "failure", pageState.dynamicPayloads),
    ].join("");
    qa("#dynamic-payload-list [data-payload-id]").forEach((button) => {
      button.addEventListener("click", () => selectDynamicPayload(button.dataset.payloadId));
    });
  }

  async function selectDynamicFlow(flowId) {
    pageState.dynamicSelectedFlow = flowId;
    pageState.dynamicSelectedPayload = null;
    renderDynamicFlows();
    pageState.dynamicPayloads = await getJSON(
      `/api/dynamic/flows/${encodeURIComponent(flowId)}/payloads`,
    );
    renderDynamicPayloads();
    const first = pageState.dynamicPayloads[0];
    if (first) await selectDynamicPayload(first.payload_id);
    else q("#dynamic-detail").innerHTML = `<header class="dynamic-column-header"><h2>PAYLOAD DETAIL</h2></header><div class="dynamic-empty">페이로드가 없습니다.</div>`;
  }

  async function selectDynamicPayload(payloadId) {
    pageState.dynamicSelectedPayload = payloadId;
    renderDynamicPayloads();
    const detail = await getJSON(`/api/dynamic/payloads/${encodeURIComponent(payloadId)}`);
    renderDynamicDetail(detail);
  }

  function renderDynamicDetail(payload) {
    const result = payload.result || {};
    const inputs = payload.inputs || [];
    q("#dynamic-detail").innerHTML = `
      <header class="dynamic-column-header"><h2>PAYLOAD DETAIL</h2></header>
      <div class="dynamic-detail-body">
        <div class="dynamic-detail-title">
          <div><small>Payload ID</small><strong>${esc(payload.payload_id)}</strong></div>
          <span class="status-badge ${statusClass(payload.status)}">${esc(payload.status)}</span>
        </div>
        <section class="dynamic-detail-section">
          <h3>ADB Command</h3>
          <pre class="command-block">${esc(payload.command)}</pre>
        </section>
        <section class="dynamic-detail-section">
          <h3>Inputs</h3>
          ${inputs.length ? `<table class="dynamic-input-table"><thead><tr><th>Field</th><th>Key</th><th>Value</th></tr></thead><tbody>${inputs.map((input) => `<tr><td>${esc(input.field)}</td><td>${esc(input.key)}</td><td>${esc(input.value)}</td></tr>`).join("")}</tbody></table>` : `<div class="dynamic-group-empty">No inputs</div>`}
        </section>
        <section class="dynamic-detail-section">
          <h3>Result</h3>
          <div class="dynamic-result ${statusClass(payload.status)}"><b>${esc(result.verdict)}</b><p>${esc(result.detail || result.verdict)}</p></div>
        </section>
      </div>
    `;
  }

  function renderLabOverview(staticData, dynamicData, finalData, findings) {
    q("#lab-project").textContent = staticData.package || "Current project";
    q("#dynamic-package-name").textContent = staticData.package || "Unknown package";
    q("#lab-package").textContent = `JSON 기반 분석 프로젝트 · schema ${staticData.schema_version || "—"}`;
    const cards = [
      ["static", "S", "STATIC ANALYSIS", num(staticData.indexed_graphs), "flow graphs"],
      ["dynamic", "D", "DYNAMIC ANALYSIS", dynamicData.available ? num(dynamicData.payload_count) : "—", dynamicData.available ? "실행 결과" : "JSON 미연결"],
      ["reports", "▤", "REPORTS", "준비 중", "보고서 페이지"]
    ];
    q("#lab-cards").innerHTML = cards.map(([page, icon, label, value, detail]) => `<button class="lab-stat" data-destination="${page}"><span class="lab-stat-icon ${page}">${icon}</span><span><small>${label}</small><b>${esc(value)}</b><em>${esc(detail)}</em></span><span class="lab-arrow">›</span></button>`).join("");
    qa("[data-destination]").forEach(button => button.addEventListener("click", () => switchPage(button.dataset.destination)));
  }

  function bindDashboardControls() {
    qa(".page-nav").forEach((button) => button.addEventListener("click", () => switchPage(button.dataset.page)));
    q("#project-search").addEventListener("input", (event) => {
      pageState.projectQuery = event.currentTarget.value.trim().toLowerCase();
      pageState.projectPage = 1;
      renderProjects();
    });
    qa("[data-flow-filter]").forEach((button) => button.addEventListener("click", () => {
      filterDynamicFlows(button.dataset.flowFilter);
    }));
  }

  async function initializeDashboard() {
    bindDashboardControls();
    qa("[data-open-page]").forEach((button) => button.addEventListener("click", () => switchPage(button.dataset.openPage)));
    window.addEventListener("hashchange", () => switchPage(location.hash.slice(1)));
    switchPage(location.hash.slice(1) || "overview");
    try {
      const [projects, staticOverview, dynamicOverview, dynamicFlows] = await Promise.all([
        getJSON("/api/projects"),
        getJSON("/api/overview"),
        getJSON("/api/dynamic/overview"),
        getJSON("/api/dynamic/flows"),
      ]);
      pageState.dynamicOverview = dynamicOverview;
      pageState.dynamicFlows = dynamicFlows;
      renderProjects(projects);
      q("#nav-static-count").textContent = num(staticOverview.indexed_graphs);
      q("#nav-dynamic-count").textContent = num(dynamicOverview.payload_count);
      renderLabOverview(staticOverview, dynamicOverview);
      renderDynamicFlows();
      if (dynamicFlows.length) await selectDynamicFlow(dynamicFlows[0].flow_id);
    } catch (error) {
      q("#lab-error").hidden = false;
      q("#lab-error").textContent = `결과를 불러오지 못했습니다: ${error.message}`;
      q("#dynamic-detail").innerHTML = `<div class="error-message">${esc(error.message)}</div>`;
    }
  }

  initializeDashboard();
})();
