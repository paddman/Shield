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
    syncing: false,
    tenantGeneration: 0,
    syncGeneration: 0,
    customerAgentsGeneration: 0,
    reportsGeneration: 0,
    generateGeneration: 0
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

    globalThis.NTShieldReportStudio?.init({
      requestJson: moduleState.requestJson,
      toast: moduleState.toast,
      getTenant: moduleState.getTenant
    });

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
    if (!moduleState.initialized) return false;
    const generation = ++moduleState.syncGeneration;
    const tenantId = moduleState.getTenant();
    moduleState.syncing = true;
    try {
      const tenants = array(await moduleState.requestJson("/api/v1/tenants", { headers: { "X-NTShield-Tenant": tenantId } }));
      if (generation !== moduleState.syncGeneration || tenantId !== moduleState.getTenant()) return false;
      moduleState.tenants = tenants;
      renderTenantOptions();
      const activePage = document.querySelector(".page.active")?.dataset.page;
      if (activePage === "customers") await loadCustomerAgents();
      if (activePage === "reports") await Promise.all([loadReports(), globalThis.NTShieldReportStudio?.sync?.()]);
      return generation === moduleState.syncGeneration && tenantId === moduleState.getTenant();
    } catch (error) {
      if (generation !== moduleState.syncGeneration || tenantId !== moduleState.getTenant()) return false;
      console.warn("NT Shield tenant context unavailable", error);
      return false;
    } finally {
      if (generation === moduleState.syncGeneration) moduleState.syncing = false;
    }
  }

  function resetTenant() {
    if (!moduleState.initialized) return;
    moduleState.tenantGeneration += 1;
    moduleState.syncGeneration += 1;
    moduleState.customerAgentsGeneration += 1;
    moduleState.reportsGeneration += 1;
    moduleState.generateGeneration += 1;
    moduleState.syncing = false;
    moduleState.agents = [];
    moduleState.assignments = [];
    moduleState.reports = [];
    moduleState.selectedReport = null;
    globalThis.NTShieldReportStudio?.resetTenant?.();
    const generateButton = byId("generateReportButton");
    if (generateButton) {
      generateButton.disabled = false;
      generateButton.textContent = "Generate from template";
    }
    renderTenantOptions();
    renderCustomers();
    renderCustomerAgents();
    renderReports();
  }

  async function onPage(page) {
    if (!moduleState.initialized) return;
    const contextSynced = !moduleState.tenants.length ? await sync() : false;
    if (page === "customers") {
      await loadCustomerAgents();
      renderCustomers();
    }
    if (page === "reports") {
      if (!contextSynced) await Promise.all([loadReports(), globalThis.NTShieldReportStudio?.onPage?.(page)]);
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
    const switched = await moduleState.setTenant(tenantId);
    if (switched === false || tenantId !== moduleState.getTenant()) return;
    renderTenantOptions();
    moduleState.selectedReport = null;
    await Promise.all([loadReports(), globalThis.NTShieldReportStudio?.sync?.()]);
  }

  async function loadCustomerAgents() {
    const generation = ++moduleState.customerAgentsGeneration;
    const tenantId = moduleState.getTenant();
    try {
      const data = await moduleState.requestJson("/api/v1/tenants/agents", { headers: { "X-NTShield-Tenant": tenantId } });
      if (generation !== moduleState.customerAgentsGeneration || tenantId !== moduleState.getTenant()) return false;
      moduleState.agents = array(read(data, "agents"));
      moduleState.assignments = array(read(data, "assignments"));
      renderCustomers();
      renderCustomerAgents();
      return true;
    } catch (error) {
      if (generation !== moduleState.customerAgentsGeneration || tenantId !== moduleState.getTenant()) return false;
      if (byId("customerListState")) byId("customerListState").textContent = "โหลด Agent ไม่สำเร็จ";
      return false;
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
      tr.innerHTML = `<td><button type="button" class="customer-name-cell customer-select-button" data-select-tenant-id="${escapeHtml(tenantId)}"><strong>${escapeHtml(read(tenant, "name"))}</strong><small>${escapeHtml(read(tenant, "contactEmail") || read(tenant, "legalName") || "No contact")}</small></button></td><td><code class="tenant-code">${escapeHtml(tenantId)}</code></td><td>${escapeHtml(read(tenant, "plan"))}</td><td><span class="tenant-status ${escapeHtml(read(tenant, "status"))}">${escapeHtml(read(tenant, "status"))}</span></td><td>${count}</td><td>${Number.isNaN(updated.valueOf()) ? "—" : updated.toLocaleDateString("th-TH")}</td>`;
      return tr;
    }));
    byId("customerPageCount").textContent = `${moduleState.tenants.length} customers`;
    byId("customerListState").textContent = `${rows.length} รายการ`;
  }

  function selectCustomerFromTable(event) {
    const target = event.target.closest("[data-select-tenant-id], tr[data-tenant-id]");
    if (!target) return;
    selectCustomer(target.dataset.selectTenantId || target.dataset.tenantId);
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
    if (!moduleState.initialized) return false;
    const generation = ++moduleState.reportsGeneration;
    const tenantId = moduleState.getTenant();
    try {
      const reports = array(await moduleState.requestJson("/api/v1/reports?take=50", { headers: { "X-NTShield-Tenant": tenantId } }));
      if (generation !== moduleState.reportsGeneration || tenantId !== moduleState.getTenant()) return false;
      moduleState.reports = reports;
      if (moduleState.selectedReport && !moduleState.reports.some(item => read(item, "reportId") === read(moduleState.selectedReport, "reportId"))) {
        moduleState.selectedReport = null;
      }
      renderReports();
      return true;
    } catch (error) {
      if (generation !== moduleState.reportsGeneration || tenantId !== moduleState.getTenant()) return false;
      if (byId("reportHistoryState")) byId("reportHistoryState").textContent = "โหลดไม่สำเร็จ";
      return false;
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
    const generation = moduleState.tenantGeneration;
    const requestGeneration = ++moduleState.generateGeneration;
    const tenantId = moduleState.getTenant();
    const title = byId("reportTitle").value.trim() || null;
    const start = byId("reportStart").value;
    const end = byId("reportEnd").value;
    button.disabled = true;
    button.textContent = "กำลังสร้าง…";
    try {
      const studio = globalThis.NTShieldReportStudio;
      const templateId = await studio?.ensureSaved?.();
      if (generation !== moduleState.tenantGeneration || requestGeneration !== moduleState.generateGeneration || tenantId !== moduleState.getTenant()) return;
      if (!templateId) {
        moduleState.toast?.("บันทึก Template ให้สำเร็จก่อนสร้าง Report");
        return;
      }
      const templateSnapshot = studio?.getTemplateSnapshot?.();
      const templateVersion = Number(read(templateSnapshot, "version"));
      if (!Number.isInteger(templateVersion) || templateVersion < 1) {
        moduleState.toast?.("ไม่พบ Template version ที่ถูกต้อง กรุณา Reload templates แล้วลองอีกครั้ง");
        return;
      }
      const report = await moduleState.requestJson("/api/v1/reports", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-NTShield-Tenant": tenantId },
        body: {
          title,
          templateId,
          templateVersion,
          periodStartUtc: new Date(`${start}T00:00:00Z`).toISOString(),
          periodEndUtc: new Date(`${end}T23:59:59Z`).toISOString()
        }
      });
      if (generation !== moduleState.tenantGeneration || requestGeneration !== moduleState.generateGeneration || tenantId !== moduleState.getTenant()) return;
      if (!read(report, "templateSnapshot") && templateSnapshot) {
        report.templateId = templateId;
        report.templateSnapshot = templateSnapshot;
      }
      moduleState.selectedReport = report;
      moduleState.toast?.("สร้าง Report แล้ว");
      await loadReports();
    } catch (error) {
      if (generation !== moduleState.tenantGeneration || requestGeneration !== moduleState.generateGeneration || tenantId !== moduleState.getTenant()) return;
      if (error?.status === 409) {
        moduleState.toast?.("Template ถูกแก้จากอีกหน้าต่าง — โหลดเวอร์ชันล่าสุดแล้ว กรุณาตรวจและกด Generate อีกครั้ง");
        await globalThis.NTShieldReportStudio?.sync?.();
      } else {
        moduleState.toast?.(`สร้าง Report ไม่สำเร็จ: ${error.message}`);
      }
    } finally {
      if (generation === moduleState.tenantGeneration && requestGeneration === moduleState.generateGeneration && tenantId === moduleState.getTenant()) {
        button.disabled = false;
        button.textContent = "Generate from template";
      }
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
      const icon = document.createElement("span");
      icon.textContent = "▤";
      const title = document.createElement("strong");
      title.textContent = "สร้างหรือเลือก Report";
      const detail = document.createElement("small");
      detail.textContent = "ข้อมูลทุกส่วนจะถูกกรองตาม Customer ที่เลือกอยู่ด้านบน";
      host.replaceChildren(icon, title, detail);
      return;
    }
    byId("reportPreviewTitle").textContent = read(report, "title");
    host.className = "report-document studio-report-preview";
    if (!globalThis.NTShieldReportStudio?.renderReport?.(report, host)) {
      host.className = "report-preview-empty";
      host.replaceChildren(document.createTextNode("Report preview is unavailable."));
    }
  }

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
    globalThis.NTShieldReportStudio?.printReport?.(report);
  }

  const csv = value => {
    let text = String(value ?? "");
    if (/^(?:\s*[=+\-@]|[\t\r\n])/.test(text)) text = `'${text}`;
    return `"${text.replaceAll('"', '""')}"`;
  };
  function saveBlob(content, type, name) {
    const url = URL.createObjectURL(new Blob([content], { type }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = name;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  globalThis.NTShieldTenantReports = { init, sync, onPage, resetTenant };
})();
