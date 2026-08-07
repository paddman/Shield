"use strict";

(function () {
  const moduleState = {
    requestJson: null,
    toast: null,
    getTenant: null,
    setTenant: null,
    tenants: [],
    agents: [],
    assignments: [],
    reports: [],
    selectedCustomerId: "",
    selectedReport: null,
    initialized: false,
    syncing: false
  };

  const byId = id => document.getElementById(id);
  const array = value => Array.isArray(value) ? value : [];
  const read = (item, ...keys) => {
    for (const key of keys) {
      if (item?.[key] !== undefined && item[key] !== null) return item[key];
      const pascal = key.charAt(0).toUpperCase() + key.slice(1);
      if (item?.[pascal] !== undefined && item[pascal] !== null) return item[pascal];
    }
    return undefined;
  };
  const escapeHtml = value => String(value ?? "")
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;").replaceAll("'", "&#039;");

  function init(options) {
    if (moduleState.initialized) return;
    moduleState.requestJson = options.requestJson;
    moduleState.toast = options.toast;
    moduleState.getTenant = options.getTenant;
    moduleState.setTenant = options.setTenant;
    moduleState.initialized = true;

    byId("globalTenantSelect")?.addEventListener("change", event => activateTenant(event.target.value));
    byId("newCustomerButton")?.addEventListener("click", newCustomer);
    byId("customerSearch")?.addEventListener("input", renderCustomers);
    byId("customerTable")?.addEventListener("click", selectCustomerFromTable);
    byId("customerForm")?.addEventListener("submit", saveCustomer);
    byId("customerAgentList")?.addEventListener("click", assignAgent);
    byId("reportForm")?.addEventListener("submit", generateReport);
    byId("reportHistory")?.addEventListener("click", selectReportFromHistory);
    byId("reportCsvButton")?.addEventListener("click", downloadCsv);
    byId("reportPrintButton")?.addEventListener("click", printReport);
    setDefaultReportDates();
  }

  async function sync() {
    if (!moduleState.initialized || moduleState.syncing) return;
    moduleState.syncing = true;
    try {
      moduleState.tenants = array(await moduleState.requestJson("/api/v1/tenants"));
      renderTenantOptions();
      const activePage = document.querySelector(".page.active")?.dataset.page;
      if (activePage === "customers") await loadCustomerAgents();
      if (activePage === "reports") await loadReports();
    } catch (error) {
      console.warn("NT Shield tenant context unavailable", error);
    } finally {
      moduleState.syncing = false;
    }
  }

  async function onPage(page) {
    if (!moduleState.initialized) return;
    if (!moduleState.tenants.length) await sync();
    if (page === "customers") {
      await loadCustomerAgents();
      renderCustomers();
    }
    if (page === "reports") {
      await loadReports();
      renderReports();
    }
  }

  function renderTenantOptions() {
    const active = moduleState.getTenant() || "default";
    for (const id of ["globalTenantSelect", "topologyTenant"]) {
      const select = byId(id);
      if (!select) continue;
      select.replaceChildren(...moduleState.tenants.map(tenant => {
        const option = document.createElement("option");
        option.value = read(tenant, "tenantId");
        option.textContent = read(tenant, "name") || option.value;
        return option;
      }));
      if ([...select.options].some(option => option.value === active)) select.value = active;
    }
    const activeTenant = moduleState.tenants.find(item => read(item, "tenantId") === active);
    if (byId("reportTenantBadge")) byId("reportTenantBadge").textContent = read(activeTenant, "name") || active;
  }

  async function activateTenant(tenantId) {
    if (!tenantId || tenantId === moduleState.getTenant()) return;
    await moduleState.setTenant(tenantId);
    renderTenantOptions();
    moduleState.selectedReport = null;
    await loadReports();
  }

  async function loadCustomerAgents() {
    try {
      const data = await moduleState.requestJson("/api/v1/tenants/agents");
      moduleState.agents = array(read(data, "agents"));
      moduleState.assignments = array(read(data, "assignments"));
      renderCustomers();
      renderCustomerAgents();
    } catch (error) {
      if (byId("customerListState")) byId("customerListState").textContent = "โหลด Agent ไม่สำเร็จ";
    }
  }

  function renderCustomers() {
    const host = byId("customerTable");
    if (!host) return;
    const query = (byId("customerSearch")?.value || "").trim().toLowerCase();
    const rows = moduleState.tenants.filter(tenant =>
      [read(tenant, "tenantId"), read(tenant, "name"), read(tenant, "legalName"), read(tenant, "plan")]
        .some(value => String(value || "").toLowerCase().includes(query)));
    host.replaceChildren(...rows.map(tenant => {
      const tenantId = read(tenant, "tenantId");
      const tr = document.createElement("tr");
      tr.dataset.tenantId = tenantId;
      if (tenantId === moduleState.selectedCustomerId) tr.classList.add("selected");
      const count = moduleState.assignments.filter(item => read(item, "tenantId") === tenantId).length;
      const updated = new Date(read(tenant, "updatedAtUtc"));
      tr.innerHTML = `<td><span class="customer-name-cell"><strong>${escapeHtml(read(tenant, "name"))}</strong><small>${escapeHtml(read(tenant, "contactEmail") || read(tenant, "legalName") || "No contact")}</small></span></td><td><code class="tenant-code">${escapeHtml(tenantId)}</code></td><td>${escapeHtml(read(tenant, "plan"))}</td><td><span class="tenant-status ${escapeHtml(read(tenant, "status"))}">${escapeHtml(read(tenant, "status"))}</span></td><td>${count}</td><td>${Number.isNaN(updated.valueOf()) ? "—" : updated.toLocaleDateString("th-TH")}</td>`;
      return tr;
    }));
    byId("customerPageCount").textContent = `${moduleState.tenants.length} customers`;
    byId("customerListState").textContent = `${rows.length} รายการ`;
  }

  function selectCustomerFromTable(event) {
    const row = event.target.closest("tr[data-tenant-id]");
    if (!row) return;
    selectCustomer(row.dataset.tenantId);
  }

  function selectCustomer(tenantId) {
    const tenant = moduleState.tenants.find(item => read(item, "tenantId") === tenantId);
    if (!tenant) return;
    moduleState.selectedCustomerId = tenantId;
    byId("customerFormTitle").textContent = `แก้ไข ${read(tenant, "name")}`;
    byId("customerTenantId").value = tenantId;
    byId("customerTenantId").disabled = true;
    byId("customerName").value = read(tenant, "name") || "";
    byId("customerLegalName").value = read(tenant, "legalName") || "";
    byId("customerPlan").value = read(tenant, "plan") || "standard";
    byId("customerStatus").value = read(tenant, "status") || "active";
    byId("customerContactName").value = read(tenant, "contactName") || "";
    byId("customerContactEmail").value = read(tenant, "contactEmail") || "";
    byId("customerNotes").value = read(tenant, "notes") || "";
    renderCustomers();
    renderCustomerAgents();
  }

  function newCustomer() {
    moduleState.selectedCustomerId = "";
    byId("customerForm").reset();
    byId("customerFormTitle").textContent = "เพิ่มลูกค้า";
    byId("customerTenantId").disabled = false;
    byId("customerPlan").value = "standard";
    byId("customerStatus").value = "active";
    renderCustomers();
    renderCustomerAgents();
    byId("customerTenantId").focus();
  }

  async function saveCustomer(event) {
    event.preventDefault();
    const tenantId = byId("customerTenantId").value.trim().toLowerCase();
    const payload = {
      tenantId,
      name: byId("customerName").value.trim(),
      legalName: byId("customerLegalName").value.trim() || null,
      plan: byId("customerPlan").value,
      status: byId("customerStatus").value,
      contactName: byId("customerContactName").value.trim() || null,
      contactEmail: byId("customerContactEmail").value.trim() || null,
      notes: byId("customerNotes").value.trim() || null
    };
    try {
      const editing = Boolean(moduleState.selectedCustomerId);
      await moduleState.requestJson(editing ? `/api/v1/tenants/${encodeURIComponent(tenantId)}` : "/api/v1/tenants", {
        method: editing ? "PUT" : "POST",
        headers: { "Content-Type": "application/json" },
        body: payload
      });
      moduleState.toast?.("บันทึกลูกค้าแล้ว");
      moduleState.tenants = array(await moduleState.requestJson("/api/v1/tenants"));
      renderTenantOptions();
      selectCustomer(tenantId);
    } catch (error) {
      moduleState.toast?.(`บันทึกลูกค้าไม่สำเร็จ: ${error.message}`);
    }
  }

  function renderCustomerAgents() {
    const host = byId("customerAgentList");
    if (!host) return;
    host.replaceChildren();
    const tenantId = moduleState.selectedCustomerId;
    if (!tenantId) {
      byId("customerAgentState").textContent = "เลือกลูกค้าก่อน";
      host.innerHTML = '<p class="empty-state">เลือก Customer จากตารางด้านซ้าย</p>';
      return;
    }
    const assignmentByAgent = new Map(moduleState.assignments.map(item => [String(read(item, "agentId")), String(read(item, "tenantId"))]));
    const tenantById = new Map(moduleState.tenants.map(item => [String(read(item, "tenantId")), String(read(item, "name"))]));
    for (const agent of moduleState.agents) {
      const agentId = String(read(agent, "agentId") || "");
      const assignedTenant = assignmentByAgent.get(agentId) || "default";
      const row = document.createElement("div");
      row.className = "customer-agent-row";
      row.innerHTML = `<div><strong>${escapeHtml(read(agent, "computerName") || agentId)}</strong><small>${escapeHtml(agentId)} · ${escapeHtml(tenantById.get(assignedTenant) || assignedTenant)}</small></div>`;
      const button = document.createElement("button");
      button.type = "button";
      button.dataset.agentId = agentId;
      button.textContent = assignedTenant === tenantId ? "Assigned" : "Assign here";
      if (assignedTenant === tenantId) button.classList.add("assigned");
      row.append(button);
      host.append(row);
    }
    const assignedCount = moduleState.assignments.filter(item => read(item, "tenantId") === tenantId).length;
    byId("customerAgentState").textContent = `${assignedCount} assigned`;
  }

  async function assignAgent(event) {
    const button = event.target.closest("button[data-agent-id]");
    if (!button || button.classList.contains("assigned") || !moduleState.selectedCustomerId) return;
    try {
      await moduleState.requestJson(`/api/v1/tenants/${encodeURIComponent(moduleState.selectedCustomerId)}/agents/${encodeURIComponent(button.dataset.agentId)}`, { method: "PUT" });
      moduleState.toast?.("ย้าย Agent เข้าลูกค้าแล้ว");
      await loadCustomerAgents();
    } catch (error) {
      moduleState.toast?.(`ผูก Agent ไม่สำเร็จ: ${error.message}`);
    }
  }

  function setDefaultReportDates() {
    const now = new Date();
    const first = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
    const iso = date => date.toISOString().slice(0, 10);
    if (byId("reportStart")) byId("reportStart").value = iso(first);
    if (byId("reportEnd")) byId("reportEnd").value = iso(now);
  }

  async function loadReports() {
    if (!moduleState.initialized) return;
    try {
      moduleState.reports = array(await moduleState.requestJson("/api/v1/reports?take=50"));
      if (moduleState.selectedReport && !moduleState.reports.some(item => read(item, "reportId") === read(moduleState.selectedReport, "reportId"))) {
        moduleState.selectedReport = null;
      }
      renderReports();
    } catch (error) {
      if (byId("reportHistoryState")) byId("reportHistoryState").textContent = "โหลดไม่สำเร็จ";
    }
  }

  function renderReports() {
    const history = byId("reportHistory");
    if (!history) return;
    const activeTenant = moduleState.tenants.find(item => read(item, "tenantId") === moduleState.getTenant());
    byId("reportTenantBadge").textContent = read(activeTenant, "name") || moduleState.getTenant();
    history.replaceChildren(...moduleState.reports.map(report => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "report-history-item";
      button.dataset.reportId = read(report, "reportId");
      if (read(moduleState.selectedReport, "reportId") === button.dataset.reportId) button.classList.add("active");
      const generated = new Date(read(report, "generatedAtUtc"));
      button.innerHTML = `<strong>${escapeHtml(read(report, "title"))}</strong><span>${generated.toLocaleString("th-TH")} · ${escapeHtml(String(read(report, "reportId") || "").slice(0, 10))}</span>`;
      return button;
    }));
    byId("reportHistoryState").textContent = `${moduleState.reports.length} reports`;
    renderReportPreview();
  }

  async function generateReport(event) {
    event.preventDefault();
    const button = byId("generateReportButton");
    button.disabled = true;
    button.textContent = "กำลังสร้าง…";
    try {
      const start = byId("reportStart").value;
      const end = byId("reportEnd").value;
      const report = await moduleState.requestJson("/api/v1/reports", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: {
          title: byId("reportTitle").value.trim() || null,
          periodStartUtc: new Date(`${start}T00:00:00Z`).toISOString(),
          periodEndUtc: new Date(`${end}T23:59:59Z`).toISOString()
        }
      });
      moduleState.selectedReport = report;
      moduleState.toast?.("สร้าง Report แล้ว");
      await loadReports();
    } catch (error) {
      moduleState.toast?.(`สร้าง Report ไม่สำเร็จ: ${error.message}`);
    } finally {
      button.disabled = false;
      button.textContent = "สร้าง Report";
    }
  }

  function selectReportFromHistory(event) {
    const button = event.target.closest("button[data-report-id]");
    if (!button) return;
    moduleState.selectedReport = moduleState.reports.find(item => read(item, "reportId") === button.dataset.reportId) || null;
    renderReports();
  }

  function renderReportPreview() {
    const host = byId("reportPreview");
    const report = moduleState.selectedReport;
    if (!host) return;
    byId("reportCsvButton").disabled = !report;
    byId("reportPrintButton").disabled = !report;
    if (!report) {
      byId("reportPreviewTitle").textContent = "ยังไม่มี Report";
      host.className = "report-preview-empty";
      host.innerHTML = "<span>▤</span><strong>สร้างหรือเลือก Report</strong><small>ข้อมูลทุกส่วนจะถูกกรองตาม Customer ที่เลือกอยู่ด้านบน</small>";
      return;
    }
    byId("reportPreviewTitle").textContent = read(report, "title");
    host.className = "report-document";
    const metrics = read(report, "metrics") || {};
    const severities = read(report, "severityCounts") || {};
    const incidents = array(read(report, "priorityIncidents"));
    const recommendations = array(read(report, "recommendations"));
    host.innerHTML = `<header class="report-document-head"><div><p class="eyebrow">NT SHIELD • TENANT SECURITY REPORT</p><h3>${escapeHtml(read(report, "title"))}</h3><p>${escapeHtml(read(report, "customerName"))} · ${formatDate(read(report, "periodStartUtc"))} – ${formatDate(read(report, "periodEndUtc"))}</p></div><div class="report-score"><b>${Number(read(metrics, "defenseScore") || 0)}%</b><small>DEFENSE SCORE</small></div></header><div class="report-metrics">${metric("Threat Events", read(metrics, "threatEvents"))}${metric("Incidents", read(metrics, "incidents"))}${metric("Campaigns", read(metrics, "threatCampaigns"))}${metric("Agents Online", `${read(metrics, "onlineAgents") || 0}/${read(metrics, "agents") || 0}`)}${metric("Assets", read(metrics, "assets"))}${metric("Open", read(metrics, "openIncidents"))}${metric("Critical", read(severities, "critical") || 0)}${metric("High", read(severities, "high") || 0)}</div><h4>Priority incidents</h4><div class="report-incident-list">${incidents.length ? incidents.map(item => `<div class="report-incident-item"><em>${escapeHtml(read(item, "severity"))}</em><strong>${escapeHtml(read(item, "title"))}</strong><small>${escapeHtml(read(item, "sourceIp") || "—")} → ${escapeHtml(read(item, "destinationIp") || "—")}</small></div>`).join("") : '<p class="empty-state">No incidents in this period</p>'}</div><h4>Recommendations</h4><ol class="report-recommendations">${recommendations.map(item => `<li>${escapeHtml(item)}</li>`).join("")}</ol><p class="report-coverage">${escapeHtml(read(report, "coverageNote"))}</p>`;
  }

  const metric = (label, value) => `<span><b>${escapeHtml(value ?? 0)}</b><small>${escapeHtml(label)}</small></span>`;
  const formatDate = value => {
    const date = new Date(value);
    return Number.isNaN(date.valueOf()) ? "—" : date.toLocaleDateString("th-TH");
  };

  function downloadCsv() {
    const report = moduleState.selectedReport;
    if (!report) return;
    const metrics = read(report, "metrics") || {};
    const lines = [
      "section,key,value",
      `summary,customer,${csv(read(report, "customerName"))}`,
      `summary,period_start,${csv(read(report, "periodStartUtc"))}`,
      `summary,period_end,${csv(read(report, "periodEndUtc"))}`,
      `metric,threat_events,${Number(read(metrics, "threatEvents") || 0)}`,
      `metric,incidents,${Number(read(metrics, "incidents") || 0)}`,
      `metric,threat_campaigns,${Number(read(metrics, "threatCampaigns") || 0)}`,
      "",
      "incident_id,severity,title,source_ip,destination_ip,status,last_seen_utc",
      ...array(read(report, "priorityIncidents")).map(item => ["incidentId", "severity", "title", "sourceIp", "destinationIp", "status", "lastSeenUtc"].map(key => csv(read(item, key))).join(","))
    ];
    saveBlob(lines.join("\r\n"), "text/csv;charset=utf-8", `ntshield-${moduleState.getTenant()}-${String(read(report, "reportId")).slice(0, 10)}.csv`);
  }

  function printReport() {
    const report = moduleState.selectedReport;
    if (!report) return;
    const popup = window.open("", "_blank");
    if (!popup) {
      moduleState.toast?.("Browser บล็อกหน้าต่าง Print กรุณาอนุญาต pop-up");
      return;
    }
    popup.opener = null;
    popup.document.write(printableHtml(report));
    popup.document.close();
  }

  function printableHtml(report) {
    const metrics = read(report, "metrics") || {};
    const incidents = array(read(report, "priorityIncidents"));
    const recommendations = array(read(report, "recommendations"));
    return `<!doctype html><html lang="th"><head><meta charset="utf-8"><title>${escapeHtml(read(report, "title"))}</title><style>body{font:14px/1.55 Arial,sans-serif;color:#252c38;margin:36px}header{border-bottom:3px solid #efb900;padding-bottom:14px}h1{margin:0}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:9px;margin:20px 0}.metrics div{border:1px solid #d9dee6;border-radius:9px;padding:10px}.metrics b{display:block;font-size:22px;color:#aa7800}table{width:100%;border-collapse:collapse}th,td{padding:7px;border-bottom:1px solid #e1e5eb;text-align:left;font-size:11px}small,footer{color:#718090}button{margin-top:10px}@media print{button{display:none}body{margin:15mm}}</style></head><body><header><small>NT SHIELD • TENANT SECURITY REPORT</small><h1>${escapeHtml(read(report, "title"))}</h1><p>${escapeHtml(read(report, "customerName"))} · ${formatDate(read(report, "periodStartUtc"))} – ${formatDate(read(report, "periodEndUtc"))}</p><button onclick="window.print()">Print / Save PDF</button></header><section class="metrics"><div><small>Threat Events</small><b>${read(metrics, "threatEvents") || 0}</b></div><div><small>Incidents</small><b>${read(metrics, "incidents") || 0}</b></div><div><small>Campaigns</small><b>${read(metrics, "threatCampaigns") || 0}</b></div><div><small>Defense Score</small><b>${read(metrics, "defenseScore") || 0}%</b></div></section><h2>Priority incidents</h2><table><thead><tr><th>Severity</th><th>Incident</th><th>Source</th><th>Destination</th><th>Status</th></tr></thead><tbody>${incidents.map(item => `<tr><td>${escapeHtml(read(item, "severity"))}</td><td>${escapeHtml(read(item, "title"))}</td><td>${escapeHtml(read(item, "sourceIp"))}</td><td>${escapeHtml(read(item, "destinationIp"))}</td><td>${escapeHtml(read(item, "status"))}</td></tr>`).join("")}</tbody></table><h2>Recommendations</h2><ol>${recommendations.map(item => `<li>${escapeHtml(item)}</li>`).join("")}</ol><footer>Generated ${escapeHtml(read(report, "generatedAtUtc"))}<br>${escapeHtml(read(report, "coverageNote"))}</footer></body></html>`;
  }

  const csv = value => `"${String(value ?? "").replaceAll('"', '""')}"`;
  function saveBlob(content, type, name) {
    const url = URL.createObjectURL(new Blob([content], { type }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = name;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  globalThis.NTShieldTenantReports = { init, sync, onPage };
})();
