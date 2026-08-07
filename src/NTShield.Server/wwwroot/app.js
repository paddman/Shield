"use strict";

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const API_KEY_HEADER = "X-NTShield-Api-Key";
const INCIDENT_FETCH_LIMIT = 250;
const STORE = {
  key: "ntshield.operator.key",
  sessionKey: "ntshield.operator.session-key",
  active: "ntshield.operator.active",
  username: "ntshield.operator.name",
  tenant: "ntshield.operator.tenant"
};

const state = {
  apiKey: "",
  username: "SOC Analyst",
  health: {},
  agents: [],
  incidents: [],
  incidentTotal: null,
  incidentCountCapped: false,
  securityEvents: [],
  threats: [],
  signatures: [],
  llmStatus: {},
  llmTokens: [],
  onlineAgents: 0,
  insights: [],
  tenantId: "default",
  selectedThreatId: "",
  analyst: {
    selectedIncidentId: "",
    report: null,
    source: "deterministic",
    actionStates: {},
    lastQuestion: ""
  }
};

let toastTimer;

document.addEventListener("DOMContentLoaded", () => {
  $("#centralOrigin").textContent = location.origin;
  $("#settingsOrigin").value = location.origin;
  bindLogin();
  bindLoginMotion();
  bindDashboard();

  const rememberedName = localStorage.getItem(STORE.username);
  if (rememberedName) $("#username").value = rememberedName;
  const rememberedTenant = localStorage.getItem(STORE.tenant);
  if (rememberedTenant) state.tenantId = rememberedTenant;
  if ($("#topologyTenant")) $("#topologyTenant").value = state.tenantId;

  const persistedKey = localStorage.getItem(STORE.key);
  const sessionKey = sessionStorage.getItem(STORE.sessionKey);
  const active = sessionStorage.getItem(STORE.active) === "1";
  if (persistedKey !== null || sessionKey !== null || active) {
    state.apiKey = sessionKey ?? persistedKey ?? "";
    state.username = rememberedName || "SOC Analyst";
    $("#rememberKey").checked = persistedKey !== null;
    signIn({ quiet: true });
  }
});

function bindLogin() {
  $("#loginForm").addEventListener("submit", async event => {
    event.preventDefault();
    state.username = $("#username").value.trim() || "SOC Analyst";
    state.apiKey = $("#apiKey").value.trim();
    await signIn({ quiet: false });
  });

  $("#revealKey").addEventListener("click", () => {
    const input = $("#apiKey");
    input.type = input.type === "password" ? "text" : "password";
  });

  $("#ntAccountButton").addEventListener("click", () => {
    toast("NT Account SSO ยังต้องตั้งค่า OIDC/SAML ใน Central ก่อนใช้งาน");
  });
}

function bindLoginMotion() {
  const shell = $("#loginView");
  const card = $("#loginForm");
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const finePointer = window.matchMedia("(pointer: fine)").matches;
  if (!shell || !card || reduceMotion || !finePointer) return;

  let frame = 0;
  shell.addEventListener("pointermove", event => {
    if (frame) cancelAnimationFrame(frame);
    frame = requestAnimationFrame(() => {
      const bounds = shell.getBoundingClientRect();
      const x = (event.clientX - bounds.left) / bounds.width - .5;
      const y = (event.clientY - bounds.top) / bounds.height - .5;
      shell.style.setProperty("--pointer-x", `${(x * 26).toFixed(2)}px`);
      shell.style.setProperty("--pointer-y", `${(y * 22).toFixed(2)}px`);
      card.style.setProperty("--tilt-x", `${(-y * 2.3).toFixed(2)}deg`);
      card.style.setProperty("--tilt-y", `${(x * 3.4).toFixed(2)}deg`);
      frame = 0;
    });
  });

  shell.addEventListener("pointerleave", () => {
    shell.style.setProperty("--pointer-x", "0px");
    shell.style.setProperty("--pointer-y", "0px");
    card.style.setProperty("--tilt-x", "0deg");
    card.style.setProperty("--tilt-y", "0deg");
  });
}

function bindDashboard() {
  $$('[data-nav]').forEach(button => button.addEventListener("click", () => showPage(button.dataset.nav)));
  $$('[data-dashboard-link]').forEach(panel => {
    const openPanel = () => showPage(panel.dataset.dashboardLink);
    panel.addEventListener("click", openPanel);
    panel.addEventListener("keydown", event => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        openPanel();
      }
    });
  });
  $("#refreshButton").addEventListener("click", () => refreshData(true));
  $("#logoutButton").addEventListener("click", logout);
  $("#mobileMenu").addEventListener("click", () => $("#sidebar").classList.toggle("open"));
  $("#incidentSearch").addEventListener("input", renderIncidentTable);
  $("#severityFilter").addEventListener("change", renderIncidentTable);
  $("#assetSearch").addEventListener("input", renderAssetTable);
  $("#threatCampaignList")?.addEventListener("click", selectThreatCampaign);
  $("#threatFilter")?.addEventListener("change", renderThreatCampaigns);
  $("#threatSort")?.addEventListener("change", renderThreatCampaigns);
  $("#threatTimeWindow")?.addEventListener("change", renderThreatCampaigns);
  $("#threatRefresh")?.addEventListener("click", () => refreshData(true));
  $("#threatFitPath")?.addEventListener("click", () => $("#threatGraphViewport")?.scrollTo({ left: 0, behavior: "smooth" }));
  $("#analystSearch").addEventListener("input", renderAnalystIncidentList);
  $("#analystSeverityFilter").addEventListener("change", renderAnalystIncidentList);
  $("#analystIncidentList").addEventListener("click", selectAnalystIncident);
  $("#analystAnalyzeButton").addEventListener("click", analyzeSelectedIncident);
  $("#analystRecommendations").addEventListener("click", handleAnalystRecommendation);
  $("#analystQuestionForm")?.addEventListener("submit", event => {
    event.preventDefault();
    const input = $("#analystQuestionInput");
    const question = input?.value.trim();
    if (!question) return;
    answerAnalystQuestion(question);
    input.value = "";
  });
  $(".analyst-question-chips")?.addEventListener("click", event => {
    const button = event.target.closest("[data-analyst-question]");
    if (button) answerAnalystQuestion(button.dataset.analystQuestion);
  });
  $("#llmTokenForm").addEventListener("submit", createLlmToken);
  $("#llmTestButton").addEventListener("click", testLlmUpstream);
  $("#llmTokenTable").addEventListener("click", revokeLlmToken);
  $("#llmTokenClose").addEventListener("click", closeLlmTokenReveal);
  $("#llmTokenCopy").addEventListener("click", copyLlmToken);
  $("#llmTokenReveal").addEventListener("click", event => {
    if (event.target.id === "llmTokenReveal") closeLlmTokenReveal();
  });
  $("#saveSettings").addEventListener("click", async () => {
    state.apiKey = $("#settingsApiKey").value.trim();
    persistCredential($("#settingsRemember").checked);
    await refreshData(true);
  });
  $("#topologyTenant")?.addEventListener("change", () => switchTenant($("#topologyTenant").value));
  window.NTShieldTopology?.init({ requestJson, toast, getTenant: () => state.tenantId });
  window.NTShieldDefenseMap?.init({ requestJson });
  window.NTShieldTenantReports?.init({
    requestJson,
    toast,
    getTenant: () => state.tenantId,
    setTenant: switchTenant
  });
}

async function switchTenant(tenantId) {
  tenantId = String(tenantId || "default").trim().toLowerCase() || "default";
  if (tenantId === state.tenantId) return;
  state.tenantId = tenantId;
  state.selectedThreatId = "";
  state.analyst.selectedIncidentId = "";
  state.analyst.report = null;
  state.analyst.lastQuestion = "";
  localStorage.setItem(STORE.tenant, tenantId);
  if ($("#topologyTenant")) $("#topologyTenant").value = tenantId;
  if ($("#globalTenantSelect")) $("#globalTenantSelect").value = tenantId;
  await refreshData(false);
  window.NTShieldTopology?.load({ resetSelection: true });
  toast(`เปลี่ยน Customer เป็น ${tenantId} แล้ว`);
}

async function signIn({ quiet }) {
  const button = $("#loginButton");
  const message = $("#loginMessage");
  if (!quiet) {
    button.disabled = true;
    message.className = "form-message";
    message.textContent = "กำลังตรวจสอบกับ Central…";
  }

  try {
    await refreshData(false);
    const remember = $("#rememberKey").checked;
    persistCredential(remember);
    $("#operatorName").textContent = state.username;
    $("#loginView").hidden = true;
    $("#dashboardView").hidden = false;
    showPage("overview");
    if (!quiet) {
      message.className = "form-message ok";
      message.textContent = "เชื่อมต่อสำเร็จ";
    }
  } catch (error) {
    sessionStorage.removeItem(STORE.active);
    $("#loginView").hidden = false;
    $("#dashboardView").hidden = true;
    message.className = "form-message";
    message.textContent = friendlyError(error);
  } finally {
    button.disabled = false;
  }
}

function persistCredential(remember) {
  sessionStorage.setItem(STORE.active, "1");
  localStorage.setItem(STORE.username, state.username);
  if (remember) {
    localStorage.setItem(STORE.key, state.apiKey);
    sessionStorage.removeItem(STORE.sessionKey);
  } else {
    localStorage.removeItem(STORE.key);
    sessionStorage.setItem(STORE.sessionKey, state.apiKey);
  }
}

function logout() {
  sessionStorage.removeItem(STORE.active);
  sessionStorage.removeItem(STORE.sessionKey);
  localStorage.removeItem(STORE.key);
  state.apiKey = "";
  $("#apiKey").value = "";
  $("#dashboardView").hidden = true;
  window.NTShieldDefenseMap?.setActive(false);
  $("#loginView").hidden = false;
  $("#loginMessage").textContent = "ออกจากระบบแล้ว";
}

async function refreshData(notify) {
  setConnection(false, "กำลังเชื่อมต่อ…");
  try {
    const [health, agents, incidents, incidentCount, securityEvents, threats, signatures, llmStatus, llmTokens] = await Promise.all([
      requestJson("/api/v1/health"),
      requestJson("/api/v1/agents"),
      requestJson(`/api/v1/incidents?take=${INCIDENT_FETCH_LIMIT}`),
      requestJson("/api/v1/incidents/count"),
      requestJson("/api/v1/events?take=500"),
      requestJson("/api/v1/threats?take=250"),
      requestJson("/api/v1/signatures"),
      requestJson("/api/v1/llm/status"),
      requestJson("/api/v1/llm/tokens")
    ]);

    state.health = health || {};
    state.agents = asArray(agents);
    state.incidents = asArray(incidents);
    state.incidentTotal = Number.isFinite(Number(incidentCount?.total)) ? Number(incidentCount.total) : null;
    state.incidentCountCapped = state.incidentTotal === null && state.incidents.length >= INCIDENT_FETCH_LIMIT;
    state.securityEvents = asArray(securityEvents);
    state.threats = asArray(threats);
    state.signatures = asArray(signatures);
    state.llmStatus = llmStatus || {};
    state.llmTokens = asArray(llmTokens);
    state.onlineAgents = state.agents.filter(isAgentOnline).length;
    state.insights = buildInsights();
    renderAll();
    void window.NTShieldTenantReports?.sync();
    setConnection(true, "All systems operational");
    if (notify) toast("อัปเดตข้อมูลจาก Central แล้ว");
  } catch (error) {
    setConnection(false, "Central disconnected");
    if (notify) toast(friendlyError(error));
    throw error;
  }
}

async function requestJson(path, options = {}) {
  const headers = { Accept: "application/json" };
  if (state.apiKey) headers[API_KEY_HEADER] = state.apiKey;
  if (state.tenantId) headers["X-NTShield-Tenant"] = state.tenantId;
  if (options.body && typeof options.body !== "string") {
    options = { ...options, body: JSON.stringify(options.body) };
  }
  const response = await fetch(path, {
    ...options,
    headers: { ...headers, ...(options.headers || {}) },
    credentials: "same-origin",
    cache: "no-store"
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    const error = new Error(body.reason || body.error || `HTTP ${response.status}`);
    error.status = response.status;
    throw error;
  }
  if (response.status === 204) return null;
  return response.json();
}

function renderAll() {
  renderOverview();
  renderIncidentTable();
  renderAssetTable();
  renderThreatCampaigns();
  renderFeed();
  renderInsights();
  renderAnalyst();
  renderLlm();

  const incidentCount = state.incidentTotal ?? state.incidents.length;
  const threatCount = state.threats.length;
  const incidentCountSuffix = state.incidentCountCapped ? "+" : "";
  $("#incidentNavCount").textContent = `${state.incidentTotal !== null ? number(incidentCount) : compact(incidentCount)}${incidentCountSuffix}`;
  $("#incidentNavCount").title = state.incidentCountCapped
    ? `แสดงรายการล่าสุด ${number(INCIDENT_FETCH_LIMIT)} รายการขึ้นไป`
    : state.incidentTotal !== null && state.incidents.length < state.incidentTotal
      ? `แสดงรายการล่าสุด ${number(state.incidents.length)} จากทั้งหมด ${number(incidentCount)} incidents`
      : `${number(incidentCount)} incidents`;
  $("#incidentPageCount").textContent = `${number(incidentCount)}${incidentCountSuffix} incidents`;
  $("#threatPageCount").textContent = `${number(threatCount)} campaigns`;
  $("#assetPageCount").textContent = `${number(state.agents.length)} assets`;
  $("#centralVersion").textContent = `Central v${pick(state.health, "version", "productVersion") || "—"}`;
  $("#lastUpdated").textContent = `Updated ${new Intl.DateTimeFormat("th-TH", { dateStyle: "medium", timeStyle: "medium" }).format(new Date())}`;
  $("#feedSignatures").textContent = number(state.signatures.length);
  $("#feedAgents").textContent = number(state.agents.length);
  $("#feedOnline").textContent = number(state.onlineAgents);
}

function renderLlm() {
  const status = state.llmStatus || {};
  const reachable = pick(status, "upstreamReachable");
  const enabled = Boolean(pick(status, "enabled"));
  const badge = $("#llmGatewayBadge");
  const dot = element("i", `live-dot ${reachable === true && enabled ? "" : "offline"}`);
  badge.replaceChildren(dot, document.createTextNode(
    !enabled ? " Gateway ปิดอยู่" : reachable === true ? " Upstream พร้อมใช้งาน" : reachable === false ? " Upstream ยังไม่พร้อม" : " ยังไม่ทดสอบ"
  ));

  const active = numeric(pick(status, "activeTokenCount"));
  $("#llmActiveTokens").textContent = `${number(active)} active tokens`;
  $("#llmProxyUrl").textContent = `${location.origin}${pick(status, "proxyBaseUrl") || "/api/v1/llm/v1"}`;
  $("#llmUpstreamUrl").textContent = pick(status, "upstreamBaseUrl") || "ยังไม่ตั้งค่า";
  $("#llmModel").textContent = pick(status, "model") || "ตาม request";
  $("#llmUpstreamState").textContent = reachable === true ? "พร้อมใช้งาน" : reachable === false ? (pick(status, "upstreamError") || "เชื่อมต่อไม่ได้") : "ยังไม่ทดสอบ";
  $("#llmTokenTableState").textContent = `${number(state.llmTokens.length)} tokens`;

  const table = $("#llmTokenTable");
  table.replaceChildren();
  if (!state.llmTokens.length) {
    const row = element("tr");
    const cell = element("td", "table-empty", "ยังไม่มี LLM token");
    cell.colSpan = 7;
    row.append(cell);
    table.append(row);
    return;
  }

  state.llmTokens.forEach(token => {
    const revoked = Boolean(pick(token, "revokedUtc"));
    const expired = !revoked && dateValue(pick(token, "expiresUtc")) <= new Date();
    const statusText = revoked ? "Revoked" : expired ? "Expired" : "Active";
    const statusClass = revoked || expired ? "offline" : "online";
    const row = element("tr");
    const action = element("button", "table-action", revoked ? "—" : "Revoke");
    if (!revoked) {
      action.type = "button";
      action.dataset.revokeToken = pick(token, "tokenId");
    } else {
      action.disabled = true;
    }
    const statusCell = element("td");
    statusCell.append(element("span", `status-badge ${statusClass}`, statusText));
    row.append(
      element("td", "", pick(token, "name") || "LLM Agent"),
      element("td", "token-prefix", pick(token, "tokenPrefix") || "—"),
      statusCell,
      element("td", "", formatDate(pick(token, "createdUtc"))),
      element("td", "", formatDate(pick(token, "expiresUtc"))),
      element("td", "", number(pick(token, "requestCount"))),
      element("td", "", action)
    );
    table.append(row);
  });
}

async function createLlmToken(event) {
  event.preventDefault();
  const button = $("#llmTokenForm button[type=submit]");
  const name = $("#llmTokenName").value.trim();
  const expiresInDays = Number($("#llmTokenExpiry").value);
  if (!name || !Number.isInteger(expiresInDays) || expiresInDays < 1 || expiresInDays > 3650) {
    toast("กรุณากรอกชื่อและอายุ token ให้ถูกต้อง");
    return;
  }
  button.disabled = true;
  try {
    const result = await requestJson("/api/v1/llm/tokens", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, expiresInDays })
    });
    state.llmTokens = [result.summary, ...state.llmTokens];
    renderLlm();
    $("#llmTokenPlaintext").textContent = result.token;
    $("#llmTokenReveal").hidden = false;
    $("#llmTokenName").value = "";
    toast("สร้าง LLM token แล้ว — คัดลอกก่อนปิดหน้าต่าง");
  } catch (error) {
    toast(friendlyError(error));
  } finally {
    button.disabled = false;
  }
}

async function revokeLlmToken(event) {
  const button = event.target.closest("[data-revoke-token]");
  if (!button || !window.confirm("ยืนยันการ revoke token นี้? Agent ที่ใช้ token จะเชื่อมต่อไม่ได้ทันที")) return;
  button.disabled = true;
  try {
    await requestJson(`/api/v1/llm/tokens/${encodeURIComponent(button.dataset.revokeToken)}`, { method: "DELETE" });
    const token = state.llmTokens.find(item => pick(item, "tokenId") === button.dataset.revokeToken);
    if (token) token.revokedUtc = new Date().toISOString();
    renderLlm();
    toast("Revoke token แล้ว");
  } catch (error) {
    button.disabled = false;
    toast(friendlyError(error));
  }
}

async function testLlmUpstream() {
  const button = $("#llmTestButton");
  button.disabled = true;
  button.textContent = "กำลังทดสอบ…";
  try {
    state.llmStatus = await requestJson("/api/v1/llm/test", { method: "POST" });
    renderLlm();
    toast(pick(state.llmStatus, "upstreamReachable") ? "เชื่อมต่อ LLM upstream สำเร็จ" : "ยังเชื่อมต่อ LLM upstream ไม่ได้");
  } catch (error) {
    toast(friendlyError(error));
  } finally {
    button.disabled = false;
    button.textContent = "ทดสอบ upstream";
  }
}

async function copyLlmToken() {
  const token = $("#llmTokenPlaintext").textContent;
  try {
    await navigator.clipboard.writeText(token);
    toast("คัดลอก LLM token แล้ว");
  } catch {
    const range = document.createRange();
    range.selectNodeContents($("#llmTokenPlaintext"));
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    toast("เลือก token แล้ว กด Ctrl+C เพื่อคัดลอก");
  }
}

function closeLlmTokenReveal() {
  $("#llmTokenReveal").hidden = true;
  $("#llmTokenPlaintext").textContent = "";
}

function renderOverview() {
  const openIncidents = state.incidents.filter(item => !["closed", "resolved"].includes(String(pick(item, "status") || "open").toLowerCase()));
  const counts = severityCounts(state.incidents);
  const offline = Math.max(0, state.agents.length - state.onlineAgents);
  const score = clamp(100 - counts.critical * 8 - counts.high * 3 - counts.medium - offline * 2, 0, 100);
  const threatEvents = state.incidents.reduce((sum, item) => {
    const attempts = numeric(pick(item, "failedAttempts", "failedLogonCount"));
    const evidence = asArray(pick(item, "evidenceEvents")).length;
    return sum + Math.max(1, attempts, evidence);
  }, 0);

  animateMetric("#defenseThreatEvents", threatEvents, value => value >= 1000 ? compact(value) : number(value));
  animateMetric("#defenseCorrelated", state.incidents.length + state.threats.length, value => number(value));
  animateMetric("#defenseScore", score, value => `${number(value)}%`);
  animateMetric("#defenseAssets", state.agents.length, value => number(value));
  $("#defenseMonitoring").textContent = `${number(state.onlineAgents)}/${number(state.agents.length)}`;
  $("#defenseNeutralized").textContent = `${number(score)}%`;
  $("#defenseLastUpdated").textContent = `Updated ${new Intl.DateTimeFormat("th-TH", { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date())}`;

  const posture = score >= 80
    ? { state: "protected", label: "• PROTECTED" }
    : score >= 50
      ? { state: "elevated", label: "• ELEVATED" }
      : { state: "critical", label: "• ACTION REQUIRED" };
  $("#globalDefenseStage").dataset.defenseState = posture.state;
  $("#defenseStatusLabel").textContent = posture.label;

  renderDefenseThreats(openIncidents);
  renderDefenseMiniMap(openIncidents, state.threats);
  renderDefenseImpact(score);

  $("#defenseBehavioralStatus").textContent = state.agents.length ? "Active" : "Waiting";
  $("#defenseIntelStatus").textContent = state.signatures.length ? "Active" : "Loading";
  setDefenseSubsystem("#statusNetwork", counts.critical ? "At Risk" : counts.high ? "Elevated" : "Secure", counts.critical ? "alert" : counts.high ? "warning" : "normal");
  setDefenseSubsystem("#statusEndpoints", offline ? `${number(offline)} Offline` : "Secure", offline ? "warning" : "normal");
  setDefenseSubsystem("#statusApplications", counts.high ? "Watching" : "Secure", counts.high ? "warning" : "normal");
  setDefenseSubsystem("#statusCloud", state.agents.length ? "Monitored" : "Waiting", state.agents.length ? "normal" : "warning");
  setDefenseSubsystem("#statusData", counts.critical ? "Investigate" : "Protected", counts.critical ? "alert" : "normal");

  window.NTShieldDefenseMap?.update({
    events: state.securityEvents,
    onlineAgents: state.onlineAgents,
    score
  });
}

function setDefenseSubsystem(selector, text, tone) {
  const status = $(selector);
  if (!status) return;
  status.textContent = text;
  const item = status.closest("span");
  if (!item) return;
  item.classList.toggle("warning", tone === "warning");
  item.classList.toggle("alert", tone === "alert");
  const icon = item.querySelector("i");
  if (icon) icon.textContent = tone === "alert" ? "!" : tone === "warning" ? "•" : "✓";
}

function renderDefenseThreats(incidents) {
  const host = $("#defenseThreatList");
  if (!host) return;
  host.replaceChildren();
  const rows = [...incidents].sort((a, b) => incidentDate(b) - incidentDate(a)).slice(0, 5);
  if (!rows.length) {
    const empty = element("p", "defense-empty", "ไม่พบ Active Threat — ระบบยังเฝ้าระวังต่อเนื่อง");
    host.append(empty);
    return;
  }
  rows.forEach(item => {
    const severity = severityName(pick(item, "severity"));
    const row = element("div", `defense-threat-row ${severity.toLowerCase()}`);
    const icon = element("span", "defense-threat-icon", severity === "Critical" ? "!" : "△");
    const copy = element("span", "defense-threat-copy");
    copy.append(
      element("b", "", pick(item, "title") || "Suspicious activity"),
      element("small", "", routeText(item))
    );
    const risk = severity === "Critical" || severity === "High" ? "High Risk" : `${severity} Risk`;
    row.append(icon, copy, element("span", "defense-threat-risk", risk));
    host.append(row);
  });
}

function renderDefenseMiniMap(incidents, threats) {
  const host = $("#defenseMapDots");
  if (!host) return;
  host.replaceChildren();
  const signals = [...incidents, ...threats].slice(0, 36);
  signals.forEach((item, index) => {
    const identity = [pick(item, "sourceIp"), pick(item, "sourceHost"), pick(item, "campaignId"), pick(item, "incidentId"), index].join("|");
    const hash = stableHash(identity);
    const dot = element("i", `defense-map-dot ${severityName(pick(item, "severity")).toLowerCase()}`);
    dot.style.left = `${7 + hash % 86}%`;
    dot.style.top = `${18 + Math.floor(hash / 97) % 65}%`;
    dot.style.animationDelay = `${-(hash % 2500)}ms`;
    host.append(dot);
  });
}

function renderDefenseIncidentPins(incidents) {
  const host = $("#defenseIncidentPins");
  if (!host) return;
  host.replaceChildren();
  const seen = new Set();
  const rows = incidents.flatMap(item => {
    const sourceValues = mapIpValues(incidentIp(item, "source"));
    const destinationValues = mapIpValues(incidentIp(item, "destination"));
    const sourceIp = sourceValues[0] || "";
    const destinationIp = destinationValues[0] || "";
    const identity = `${sourceIp}|${destinationIp}`;
    if ((!sourceIp && !destinationIp) || seen.has(identity)) return [];
    seen.add(identity);
    return [{ item, sourceIp, destinationIp, extraDestinations: Math.max(0, destinationValues.length - 1) }];
  }).slice(0, 6);

  const pinSlots = [
    [35, 22], [54, 28], [29, 43], [66, 47], [40, 61], [59, 72]
  ];

  rows.forEach(({ item, sourceIp, destinationIp, extraDestinations }, index) => {
    const route = [sourceIp, destinationIp].filter(Boolean).join(" → ") || "IP unknown";
    const ipLabel = extraDestinations ? `${route} +${extraDestinations}` : route;
    const [left, top] = pinSlots[index];
    const pin = element("span", `defense-incident-pin ${severityName(pick(item, "severity")).toLowerCase()}`);
    pin.style.left = `${left}%`;
    pin.style.top = `${top}%`;
    pin.title = `${feedDetection(item)} • ${routeText(item)}`;
    pin.append(element("i"), element("span", "", ipLabel));
    host.append(pin);
  });
}

function mapIpValues(value) {
  return String(value || "")
    .split(",")
    .map(item => item.trim())
    .filter(Boolean);
}

function renderDefenseImpact(score) {
  const now = new Date();
  const days = [];
  for (let offset = 6; offset >= 0; offset--) {
    const day = new Date(now.getFullYear(), now.getMonth(), now.getDate() - offset);
    days.push({ key: day.toISOString().slice(0, 10), count: 0 });
  }
  state.incidents.forEach(item => {
    const date = incidentDate(item);
    if (!date.getTime()) return;
    const key = new Date(date.getFullYear(), date.getMonth(), date.getDate()).toISOString().slice(0, 10);
    const day = days.find(candidate => candidate.key === key);
    if (day) day.count++;
  });
  const max = Math.max(1, ...days.map(day => day.count));
  const points = days.map((day, index) => {
    const x = 10 + index * (280 / 6);
    const y = 105 - day.count / max * 78;
    return { x, y };
  });
  $("#defenseImpactLine").setAttribute("points", points.map(point => `${point.x.toFixed(1)},${point.y.toFixed(1)}`).join(" "));
  $("#defenseImpactArea").setAttribute("d", `M10 115 L${points.map(point => `${point.x.toFixed(1)} ${point.y.toFixed(1)}`).join(" L")} L290 115 Z`);
  const dots = $("#defenseImpactDots");
  dots.replaceChildren();
  points.forEach(point => {
    const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    circle.setAttribute("cx", point.x); circle.setAttribute("cy", point.y); circle.setAttribute("r", "3");
    dots.append(circle);
  });
  $("#defenseImpactChart").setAttribute("aria-label", `Seven day defense impact, current score ${score} percent`);
}

function animateMetric(selector, target, formatter) {
  const node = $(selector);
  if (!node) return;
  const start = Number(node.dataset.metricValue || 0);
  const end = Math.max(0, Number(target) || 0);
  const started = performance.now();
  const duration = 620;
  if (node._metricFrame) cancelAnimationFrame(node._metricFrame);
  const step = time => {
    const progress = Math.min(1, (time - started) / duration);
    const eased = 1 - Math.pow(1 - progress, 3);
    const current = Math.round(start + (end - start) * eased);
    node.textContent = formatter(current);
    if (progress < 1) node._metricFrame = requestAnimationFrame(step);
    else { node.dataset.metricValue = String(end); node._metricFrame = 0; }
  };
  node._metricFrame = requestAnimationFrame(step);
}

function stableHash(value) {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index++) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

function renderIncidentTable() {
  const table = $("#incidentTable");
  if (!table) return;
  const query = $("#incidentSearch").value.trim().toLowerCase();
  const filter = $("#severityFilter").value.toLowerCase();
  const rows = [...state.incidents]
    .filter(item => {
      const severity = severityName(pick(item, "severity")).toLowerCase();
      const haystack = [pick(item, "title"), pick(item, "sourceIp"), pick(item, "sourceHost"), pick(item, "destinationIp"), pick(item, "destinationHost"), pick(item, "username")].join(" ").toLowerCase();
      return (!filter || severity === filter) && (!query || haystack.includes(query));
    })
    .sort((a, b) => incidentDate(b) - incidentDate(a));
  table.replaceChildren();
  if (!rows.length) {
    const tr = element("tr");
    const td = element("td", "table-empty", "ไม่พบ Incident ตามเงื่อนไข");
    td.colSpan = 5;
    tr.append(td);
    table.append(tr);
    return;
  }
  rows.forEach(item => {
    const severity = severityName(pick(item, "severity"));
    const tr = element("tr");
    const sevTd = element("td");
      sevTd.append(element("span", `severity-badge ${severity.toLowerCase()}`, severity));
    tr.append(
      sevTd,
      element("td", "", pick(item, "title") || "Untitled incident"),
      element("td", "", endpointText(item, "source")),
      element("td", "", endpointText(item, "destination")),
      element("td", "", formatDate(incidentDate(item)))
    );
    table.append(tr);
  });
}

function renderAssetTable() {
  const table = $("#assetTable");
  if (!table) return;
  const query = $("#assetSearch").value.trim().toLowerCase();
  const rows = [...state.agents].filter(item => [pick(item, "computerName"), pick(item, "platform"), pick(item, "agentId"), pick(item, "hostIp")].join(" ").toLowerCase().includes(query));
  table.replaceChildren();
  $("#onlineSummary").textContent = `${number(state.onlineAgents)} online`;
  if (!rows.length) {
    const tr = element("tr");
    const td = element("td", "table-empty", "ยังไม่มี Agent ลงทะเบียน");
    td.colSpan = 6;
    tr.append(td);
    table.append(tr);
    return;
  }
  rows.sort((a, b) => Number(isAgentOnline(b)) - Number(isAgentOnline(a))).forEach(item => {
    const online = isAgentOnline(item);
    const tr = element("tr");
    const statusTd = element("td");
    statusTd.append(element("span", `status-badge ${online ? "online" : "offline"}`, online ? "● Online" : "○ Offline"));
    tr.append(
      statusTd,
      element("td", "", pick(item, "computerName") || pick(item, "agentId") || "Unknown"),
      element("td", "", pick(item, "hostIp") || "—"),
      element("td", "", pick(item, "platform", "osVersion") || "unknown"),
      element("td", "", pick(item, "agentVersion") || "—"),
      element("td", "", relativeTime(dateValue(pick(item, "lastSeenUtc", "timestampUtc"))))
    );
    table.append(tr);
  });
}

function renderThreatCampaigns() {
  const list = $("#threatCampaignList");
  if (!list) return;
  const tenantLabel = $("#globalTenantSelect")?.selectedOptions?.[0]?.textContent || state.tenantId || "default";
  $("#threatTenantName").textContent = tenantLabel;
  const campaigns = threatCampaignsForView();
  const activeId = state.selectedThreatId && campaigns.some(item => String(pick(item, "campaignId")) === state.selectedThreatId)
    ? state.selectedThreatId
    : String(pick(campaigns[0], "campaignId") || "");
  state.selectedThreatId = activeId;
  list.replaceChildren();

  if (!campaigns.length) {
    list.append(element("div", "threat-list-empty", state.threats.length ? "ไม่พบ Campaign ในช่วงเวลานี้" : "ยังไม่มี Threat Campaign"));
    renderThreatPath(null);
    renderThreatInspector(null);
    renderThreatTimeline(null);
    $("#threatRailSummary").textContent = state.threats.length ? "ลองเปลี่ยนช่วงเวลา" : "รอ Central correlation";
    return;
  }

  campaigns.forEach(campaign => {
    const severity = severityName(pick(campaign, "severity"));
    const hosts = asArray(pick(campaign, "involvedHosts"));
    const hops = asArray(pick(campaign, "hops"));
    const stats = threatCampaignStats(campaign, hops);
    const item = element("button", `threat-campaign-item ${severity.toLowerCase()} ${String(pick(campaign, "campaignId")) === activeId ? "active" : ""}`);
    item.type = "button";
    item.dataset.threatId = String(pick(campaign, "campaignId") || "");
    const copy = element("span", "threat-campaign-copy");
    copy.append(
      element("strong", "", pick(campaign, "title") || "Threat campaign"),
      element("small", "", `${number(hops.length)} hops • ${number(stats.hostCount || hosts.length)} hosts • ${number(stats.ipCount)} IPs • ${relativeTime(pick(campaign, "lastSeenUtc"))}`)
    );
    const tags = element("span", "threat-campaign-tags");
    const category = asArray(pick(campaign, "threatCategories"))[0] || "Cross-host";
    tags.append(element("span", "", category));
    const ml = campaignMlInfo(campaign);
    if (ml) tags.append(element("span", `threat-ml-tag ${ml.ready ? "ready" : "learning"}`, ml.ready ? `ML ${Math.round(ml.score * 100)}%` : "ML learning"));
    const marker = element("i");
    item.append(marker, copy, element("strong", "threat-campaign-risk", `Risk ${threatRiskScore(campaign)}`));
    copy.append(tags);
    list.append(item);
  });

  const selected = campaigns.find(item => String(pick(item, "campaignId")) === activeId) || campaigns[0];
  renderThreatPath(selected);
  renderThreatInspector(selected);
  renderThreatTimeline(selected);
  $("#threatRailSummary").textContent = `${number(campaigns.length)} visible • ${number(state.threats.length)} total`;
  $("#threatActiveCount").innerHTML = `<i></i> ${number(campaigns.filter(item => !isThreatClosed(item)).length)} active`;
}

function threatCampaignsForView() {
  const severityFilter = String($("#threatFilter")?.value || "").toLowerCase();
  const sort = $("#threatSort")?.value || "recent";
  const hours = numeric($("#threatTimeWindow")?.value || 0);
  const cutoff = hours ? Date.now() - hours * 60 * 60 * 1000 : 0;
  return [...state.threats]
    .filter(item => !severityFilter || severityName(pick(item, "severity")).toLowerCase() === severityFilter)
    .filter(item => !cutoff || dateValue(pick(item, "lastSeenUtc")).getTime() >= cutoff)
    .sort((a, b) => sort === "risk"
      ? threatRiskScore(b) - threatRiskScore(a)
      : dateValue(pick(b, "lastSeenUtc")) - dateValue(pick(a, "lastSeenUtc")));
}

function selectThreatCampaign(event) {
  const button = event.target.closest("[data-threat-id]");
  if (!button) return;
  state.selectedThreatId = button.dataset.threatId || "";
  renderThreatCampaigns();
}

function renderThreatPath(campaign) {
  const stage = $("#threatGraphStage");
  const empty = $("#threatGraphEmpty");
  const summary = $("#threatCampaignSummary");
  if (!stage || !empty || !summary) return;
  const title = $("#threatPathTitle");
  const meta = $("#threatPathMeta");
  const status = $("#threatPathStatus");
  if (!campaign) {
    stage.hidden = true;
    empty.hidden = false;
    summary.hidden = true;
    title.textContent = "Select a campaign";
    meta.textContent = "เลือก Campaign เพื่อดูเส้นทางโจมตีที่ Central เชื่อมโยงได้";
    status.textContent = "Waiting";
    status.className = "threat-status-chip";
    $("#threatEvidenceSummary").innerHTML = '<i class="graph-legend-dot evidence"></i> Evidence 0';
    return;
  }
  const hops = asArray(pick(campaign, "hops")).sort((a, b) => dateValue(pick(a, "timestampUtc")) - dateValue(pick(b, "timestampUtc")));
  const nodes = buildCampaignNodes(campaign, hops);
  const stats = threatCampaignStats(campaign, hops);
  stage.hidden = false;
  empty.hidden = true;
  summary.hidden = false;
  title.textContent = pick(campaign, "title") || "Threat campaign";
  const ml = campaignMlInfo(campaign);
  const mlMeta = ml ? ` · ML ${Math.round(ml.score * 100)}% · confidence ${Math.round(ml.confidence * 100)}%` : "";
  meta.textContent = `${formatDate(pick(campaign, "firstSeenUtc"))} → ${formatDate(pick(campaign, "lastSeenUtc"))} · ${number(stats.hopCount)} hops · ${number(stats.hostCount)} hosts · ${number(stats.ipCount)} IPs · ${stats.duration}${mlMeta}`;
  const closed = isThreatClosed(campaign);
  status.textContent = closed ? "Closed" : "Active";
  status.className = `threat-status-chip ${closed ? "closed" : threatRiskScore(campaign) >= 70 ? "alert" : ""}`;
  $("#threatEvidenceSummary").replaceChildren(element("i", "graph-legend-dot evidence"), document.createTextNode(` Evidence ${number(stats.evidenceCount)}`));

  const nodeHost = $("#threatGraphNodes");
  const lineGroup = $("#threatGraphLineGroup");
  nodeHost.replaceChildren();
  lineGroup.replaceChildren();
  nodeHost.style.gridTemplateColumns = `repeat(${Math.max(nodes.length, 1)}, minmax(112px, 1fr))`;
  nodes.forEach((node, index) => {
    const item = element("article", `threat-node ${node.kind}`);
    item.dataset.step = String(index + 1);
    const icon = element("span", "threat-node-icon", node.icon);
    item.append(icon, element("b", "", node.label), element("small", "", node.secondary), element("span", "threat-node-chip", node.chip));
    nodeHost.append(item);
  });
  for (let index = 0; index < nodes.length - 1; index++) {
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    const x1 = ((index + .5) / nodes.length) * 1000;
    const x2 = ((index + 1.5) / nodes.length) * 1000;
    line.setAttribute("x1", String(x1));
    line.setAttribute("y1", "150");
    line.setAttribute("x2", String(x2));
    line.setAttribute("y2", "150");
    if (nodes[index + 1]?.inferred) line.classList.add("inferred");
    lineGroup.append(line);
  }
  renderThreatSummary(summary, campaign, stats);
}

function splitThreatEndpoints(value) {
  return String(value || "")
    .split(/[,;\n]+/)
    .map(item => item.trim())
    .filter(Boolean);
}

function threatCampaignStats(campaign, hops) {
  const hosts = new Set(asArray(pick(campaign, "involvedHosts")).map(String).filter(Boolean));
  const ips = new Set(asArray(pick(campaign, "involvedIps")).flatMap(splitThreatEndpoints));
  const destinationCounts = new Map();
  hops.forEach(hop => {
    [pick(hop, "fromIp"), pick(hop, "toIp")].flatMap(splitThreatEndpoints).forEach(value => ips.add(value));
    [pick(hop, "fromHost"), pick(hop, "toHost")].filter(Boolean).forEach(value => hosts.add(String(value)));
    const destinations = splitThreatEndpoints(pick(hop, "toIp"));
    const uniqueDestinations = new Set(destinations.length ? destinations : [pick(hop, "toHost")].filter(Boolean));
    uniqueDestinations.forEach(destination => destinationCounts.set(destination, (destinationCounts.get(destination) || 0) + 1));
  });
  const first = dateValue(pick(campaign, "firstSeenUtc"));
  const last = dateValue(pick(campaign, "lastSeenUtc"));
  const durationMs = first.getTime() && last.getTime() ? Math.max(0, last - first) : 0;
  const duration = durationMs < 60_000
    ? `${Math.max(1, Math.round(durationMs / 1000))} sec`
    : durationMs < 3_600_000
      ? `${Math.round(durationMs / 60_000)} min`
      : `${(durationMs / 3_600_000).toFixed(1)} hr`;
  const topDestinations = [...destinationCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([endpoint, count]) => ({ endpoint, count }));
  const firstSource = hops.flatMap(hop => [pick(hop, "fromHost"), ...splitThreatEndpoints(pick(hop, "fromIp"))]).find(Boolean);
  const firstHost = [...hosts][0] || hops.map(hop => pick(hop, "toHost", "fromHost")).find(Boolean);
  const firstDestination = topDestinations[0]?.endpoint || hops.flatMap(hop => splitThreatEndpoints(pick(hop, "toIp"))).find(Boolean);
  return {
    hopCount: hops.length,
    hostCount: hosts.size,
    ipCount: ips.size,
    evidenceCount: hops.length + asArray(pick(campaign, "relatedIncidentIds")).length,
    duration,
    interpretation: hosts.size >= 2 ? "Cross-host chain" : ips.size > 20 ? "Single-host fan-out" : "Single-host activity",
    needsHostEvidence: hosts.size < 2 && ips.size > 20,
    source: firstSource || "Unknown source",
    host: firstHost || "Unknown host",
    destination: firstDestination || `${number(ips.size)} observed IPs`,
    topDestinations
  };
}

function renderThreatSummary(host, campaign, stats) {
  host.className = "threat-campaign-summary threat-summary-card";
  host.replaceChildren();
  const header = element("div", "threat-summary-header");
  const headerCopy = element("div");
  headerCopy.append(element("strong", "", "Attack path overview"), element("small", "", `${stats.interpretation} • condensed correlated telemetry`));
  header.append(headerCopy, element("span", `threat-summary-compression${stats.needsHostEvidence ? " warning" : ""}`, stats.needsHostEvidence ? "Needs host evidence" : `${number(stats.hopCount)} hops compressed`));
  const metrics = element("div", "threat-summary-metrics");
  [["Hops", stats.hopCount], ["Unique IPs", stats.ipCount], ["Hosts", stats.hostCount], ["Evidence", stats.evidenceCount], ["Duration", stats.duration]].forEach(([label, value]) => {
    const metric = element("div", "threat-summary-metric");
    metric.append(element("b", "", typeof value === "number" ? number(value) : value), element("span", "", label));
    metrics.append(metric);
  });
  const route = element("div", "threat-route-strip");
  [["Source", stats.source, "source"], ["Target host", stats.host, "host"], ["Destinations", stats.destination, "destination"]].forEach(([label, value, kind], index) => {
    if (index) route.append(element("span", "threat-route-arrow", "→"));
    const pill = element("div", `threat-route-pill ${kind}`);
    pill.append(element("small", "", label), element("b", "", value));
    route.append(pill);
  });
  const destinations = element("div", "threat-top-destinations");
  destinations.append(element("strong", "", "Top observed destinations"));
  const destinationList = element("div", "threat-destination-list");
  if (!stats.topDestinations.length) {
    destinationList.append(element("span", "threat-summary-muted", "ยังไม่มี destination ที่แยกรายการได้"));
  } else {
    stats.topDestinations.forEach(item => {
      const row = element("div", "threat-destination-row");
      row.append(element("code", "", item.endpoint), element("span", "", `${number(item.count)} observations`));
      destinationList.append(row);
    });
  }
  destinations.append(destinationList);
  const rawSummary = String(pick(campaign, "summary") || "").trim();
  const note = element("div", "threat-summary-note");
  const noteText = stats.needsHostEvidence
    ? `พบเพียง ${number(stats.hostCount)} host แต่มี ${number(stats.ipCount)} IP จึงจัดเป็น network fan-out ก่อน ยังยืนยัน lateral movement ข้าม host ไม่ได้`
    : rawSummary && rawSummary.length <= 260
      ? rawSummary
      : "เส้นทางมีข้อมูลจำนวนมาก จึงย่อเป็น route และ destination ที่พบซ้ำบ่อยเพื่อให้ตรวจสอบได้เร็วขึ้น";
  note.append(element("span", "", stats.needsHostEvidence ? "Interpretation guard" : "Analyst note"), element("p", "", noteText));
  host.append(header, metrics, route, destinations, note);
}

function buildCampaignNodes(campaign, hops) {
  const nodes = [];
  const seen = new Set();
  const add = (kind, label, secondary, chip, icon, inferred = false) => {
    if (!label) return;
    const key = `${kind}:${String(label).toLowerCase()}`;
    if (seen.has(key)) return;
    seen.add(key);
    nodes.push({ kind, label: String(label), secondary: secondary || "", chip: chip || "", icon, inferred });
  };
  const addEndpoint = (ip, host) => {
    const endpoints = splitThreatEndpoints(ip);
    const label = host || endpoints[0];
    if (!label) return;
    const external = Boolean(endpoints[0] && !isPrivateIp(endpoints[0]) && !host);
    const extra = endpoints.length > 1 ? ` +${number(endpoints.length - 1)} IPs` : "";
    add(external ? "external" : "host", label, host && endpoints[0] ? `${endpoints[0]}${extra}` : external ? "External source" : "Internal host", external ? "External IP" : "Host", external ? "◎" : "▣");
  };
  hops.forEach(hop => {
    addEndpoint(pick(hop, "fromIp"), pick(hop, "fromHost"));
    if (pick(hop, "username")) add("account", pick(hop, "username"), pick(hop, "logonType") ? `Logon type ${pick(hop, "logonType")}` : "Account context", "User", "@", true);
    addEndpoint(pick(hop, "toIp"), pick(hop, "toHost"));
    if (pick(hop, "processName", "processPath")) add("process", pick(hop, "processName", "processPath"), pick(hop, "processId") ? `PID ${pick(hop, "processId")}` : "Process telemetry", "Process", ">_");
    if (pick(hop, "serviceNames")) add("service", pick(hop, "serviceNames"), "Service telemetry", "Service", "S");
  });
  if (!nodes.length) {
    asArray(pick(campaign, "involvedIps")).slice(0, 2).forEach(ip => addEndpoint(ip, ""));
    asArray(pick(campaign, "involvedHosts")).slice(0, 3).forEach(host => addEndpoint("", host));
    asArray(pick(campaign, "involvedUsernames")).slice(0, 1).forEach(user => add("account", user, "Account context", "User", "@", true));
  }
  return nodes.slice(0, 7);
}

function renderThreatInspector(campaign) {
  const body = $("#threatInspectorBody");
  const risk = $("#threatInspectorRisk");
  if (!body || !risk) return;
  body.replaceChildren();
  if (!campaign) {
    risk.textContent = "—";
    risk.className = "severity-badge high";
    body.append(element("div", "threat-inspector-empty", "เลือก Campaign เพื่อดู Context, IP, Host และ User ที่เกี่ยวข้อง"));
    return;
  }
  const severity = severityName(pick(campaign, "severity"));
  risk.textContent = `${severity} · ${threatRiskScore(campaign)}`;
  risk.className = `severity-badge ${severity.toLowerCase()}`;
  const facts = element("dl", "threat-fact-list");
  [["Campaign ID", String(pick(campaign, "campaignId") || "—").slice(0, 18)], ["Status", pick(campaign, "status") || "Open"], ["First seen", formatDate(pick(campaign, "firstSeenUtc"))], ["Last seen", formatDate(pick(campaign, "lastSeenUtc"))], ["Affected hosts", number(asArray(pick(campaign, "involvedHosts")).length)], ["Related incidents", number(asArray(pick(campaign, "relatedIncidentIds")).length)]].forEach(([label, value]) => {
    const row = element("div");
    row.append(element("dt", "", label), element("dd", "", value));
    facts.append(row);
  });
  body.append(facts);
  const ml = campaignMlInfo(campaign);
  if (ml) {
    const mlSection = element("section", "threat-inspector-section threat-ml-section");
    mlSection.append(element("h3", "", "ML anomaly signal"));
    const mlFacts = element("dl", "threat-fact-list threat-ml-facts");
    [["Anomaly score", `${Math.round(ml.score * 100)}%`], ["Confidence", `${Math.round(ml.confidence * 100)}%`], ["Baseline", `${number(ml.samples)} samples`], ["Model", ml.model || "—"]].forEach(([label, value]) => {
      const row = element("div");
      row.append(element("dt", "", label), element("dd", "", value));
      mlFacts.append(row);
    });
    mlSection.append(mlFacts);
    if (ml.signals.length) {
      mlSection.append(element("small", "threat-ml-signals", `Signals: ${ml.signals.join(" · ")}`));
    }
    body.append(mlSection);
  }
  renderThreatMlTrend(body, campaign);
  const sections = [["Key indicators", [
    ...asArray(pick(campaign, "involvedIps")).map(value => ["IP", value]),
    ...asArray(pick(campaign, "involvedHosts")).map(value => ["Host", value]),
    ...asArray(pick(campaign, "involvedUsernames")).map(value => ["User", value])
  ].slice(0, 8)]];
  sections.forEach(([title, items]) => {
    const section = element("section", "threat-inspector-section");
    section.append(element("h3", "", title));
    const list = element("ul", "threat-indicator-list");
    if (!items.length) list.append(element("li", "", "ยังไม่มี indicator แยกรายการ"));
    items.forEach(([kind, value]) => {
      const row = element("li");
      row.append(element("i", "", kind.slice(0, 2).toUpperCase()), element("span", "", value), element("small", "", kind));
      list.append(row);
    });
    section.append(list);
    body.append(section);
  });
  const categories = asArray(pick(campaign, "threatCategories"));
  if (categories.length) {
    const section = element("section", "threat-inspector-section");
    section.append(element("h3", "", "Threat categories"));
    const tags = element("div", "threat-tag-list");
    categories.slice(0, 8).forEach(item => tags.append(element("span", "", item)));
    section.append(tags);
    body.append(section);
  }
}

function renderThreatMlTrend(host, campaign) {
  const history = asArray(pick(campaign, "mlHistory"))
    .map(item => ({
      score: Math.max(0, Math.min(1, Number(pick(item, "score")))),
      confidence: Math.max(0, Math.min(1, Number(pick(item, "confidence")))),
      samples: Number(pick(item, "baselineSamples")),
      observedAt: dateValue(pick(item, "observedAtUtc"))
    }))
    .filter(item => Number.isFinite(item.score) && item.observedAt.getTime())
    .sort((a, b) => a.observedAt - b.observedAt)
    .slice(-12);
  if (!history.length) return;

  const section = element("section", "threat-inspector-section threat-ml-trend-section");
  const heading = element("div", "threat-ml-trend-heading");
  heading.append(element("h3", "", "ML anomaly trend"), element("small", "", `${number(history.length)} latest observations`));
  const chart = element("div", "threat-ml-trend");
  history.forEach(item => {
    const bar = element("span", "threat-ml-bar");
    bar.style.height = `${Math.max(8, Math.round(item.score * 100))}%`;
    bar.title = `${Math.round(item.score * 100)}% · confidence ${Math.round(item.confidence * 100)}% · ${item.samples || 0} samples · ${formatDate(item.observedAt.toISOString())}`;
    if (item.score >= .8) bar.classList.add("alert");
    else if (item.score >= .5) bar.classList.add("elevated");
    chart.append(bar);
  });
  const peak = Math.max(...history.map(item => item.score));
  const latest = history[history.length - 1];
  const footer = element("div", "threat-ml-trend-footer");
  footer.append(element("span", "", `Latest ${Math.round(latest.score * 100)}%`), element("span", "", `Peak ${Math.round(peak * 100)}%`));
  section.append(heading, chart, footer);
  host.append(section);
}

function renderThreatTimeline(campaign) {
  const host = $("#threatTimeline");
  const explain = $("#threatTimelineExplain");
  if (!host) return;
  host.replaceChildren();
  if (explain) {
    explain.hidden = true;
    explain.replaceChildren();
  }
  if (!campaign) {
    host.append(element("div", "threat-timeline-empty", "เลือก Campaign เพื่อดู event sequence"));
    $("#threatTimelineWindow").textContent = "UTC window —";
    return;
  }
  const hops = asArray(pick(campaign, "hops")).sort((a, b) => dateValue(pick(a, "timestampUtc")) - dateValue(pick(b, "timestampUtc")));
  $("#threatTimelineWindow").textContent = `${formatDate(pick(campaign, "firstSeenUtc"))} → ${formatDate(pick(campaign, "lastSeenUtc"))} · ${number(Math.min(8, hops.length))}/${number(hops.length)} sampled`;
  if (!hops.length) {
    host.append(element("div", "threat-timeline-empty", "Campaign นี้ยังไม่มี hop telemetry ให้เรียงลำดับ"));
    return;
  }
  const sampleIndexes = hops.length <= 8
    ? hops.map((_, index) => index)
    : Array.from({ length: 8 }, (_, index) => Math.round(index * (hops.length - 1) / 7));
  const representativeHops = sampleIndexes.map((hopIndex, sampleIndex) => ({ hop: hops[hopIndex], hopIndex, sampleIndex }));
  if (explain) {
    explain.hidden = false;
    const method = hops.length > representativeHops.length
      ? "เก็บ hop แรก, hop สุดท้าย และจุดตรวจที่กระจายตามลำดับเวลา"
      : "แสดง hop ที่มีอยู่ทั้งหมดตามลำดับเวลา";
    explain.append(element("strong", "", `แสดงตัวอย่าง ${number(representativeHops.length)} จาก ${number(hops.length)} hops`), element("span", "", `${method} · หลักฐานจริงยังคงครบ ${number(hops.length)} hops`));
  }
  representativeHops.forEach(({ hop, hopIndex, sampleIndex }) => {
    const event = element("article", `threat-timeline-event ${severityName(pick(campaign, "severity")).toLowerCase()}`);
    const timestamp = dateValue(pick(hop, "timestampUtc"));
    const from = pick(hop, "fromHost") || splitThreatEndpoints(pick(hop, "fromIp"))[0] || "source";
    const to = pick(hop, "toHost") || splitThreatEndpoints(pick(hop, "toIp"))[0] || "destination";
    const meta = element("div", "threat-timeline-event-meta");
    meta.append(element("span", "threat-timeline-hop", `Hop ${number(hopIndex + 1)} / ${number(hops.length)}`), element("time", "", timestamp.getTime() ? timestamp.toLocaleTimeString("th-TH", { hour: "2-digit", minute: "2-digit" }) : `Step ${hopIndex + 1}`));
    const reason = hopIndex === 0 ? "จุดเริ่มต้น" : hopIndex === hops.length - 1 ? "จุดสิ้นสุด" : `จุดตรวจ ${number(sampleIndex)} ของ chain`;
    event.append(element("span", "threat-timeline-point"), meta, element("strong", "", pick(hop, "technique") || "Observed hop"), element("small", "", `${from} → ${to}`), element("span", "threat-timeline-reason", reason));
    host.append(event);
  });
}

function threatRiskScore(campaign) {
  const severity = severityName(pick(campaign, "severity"));
  const base = { Critical: 88, High: 72, Medium: 54, Low: 30, Informational: 12 }[severity] || 12;
  const hops = asArray(pick(campaign, "hops")).length;
  const incidents = asArray(pick(campaign, "relatedIncidentIds")).length;
  const deterministic = base + Math.min(12, hops * 2) + Math.min(8, incidents);
  const ml = campaignMlInfo(campaign);
  if (!ml?.ready) return Math.min(99, deterministic);
  return Math.min(99, Math.round(deterministic * .65 + ml.score * 100 * .35));
}

function campaignMlInfo(campaign) {
  const score = Number(pick(campaign, "mlScore"));
  const confidence = Number(pick(campaign, "mlConfidence"));
  const samples = Number(pick(campaign, "mlBaselineSamples"));
  if (!Number.isFinite(score) || !Number.isFinite(confidence) || !Number.isFinite(samples)) return null;
  return {
    score: Math.max(0, Math.min(1, score)),
    confidence: Math.max(0, Math.min(1, confidence)),
    samples: Math.max(0, samples),
    model: String(pick(campaign, "mlModel") || ""),
    signals: asArray(pick(campaign, "mlSignals")),
    ready: samples >= 20
  };
}

function isThreatClosed(campaign) {
  const status = String(pick(campaign, "status") || "").toLowerCase();
  return status === "closed" || status === "resolved" || status === "contained";
}

function isPrivateIp(value) {
  const ip = String(value || "");
  return /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)/.test(ip);
}

function renderFeed() {
  const host = $("#threatFeed");
  const items = [
    ...state.incidents.map(item => ({
      type: "INC",
      title: `ตรวจพบ: ${feedDetection(item)}`,
      detail: feedDetail(item),
      subtitle: `${severityName(pick(item, "severity"))} • ${routeText(item)}`,
      date: incidentDate(item)
    })),
    ...state.threats.map(item => ({
      type: "THR",
      title: `ตรวจพบ: ${pick(item, "title") || "Threat campaign"}`,
      detail: pick(item, "summary"),
      subtitle: `${severityName(pick(item, "severity"))} • ${asArray(pick(item, "involvedHosts")).length} hosts`,
      date: dateValue(pick(item, "lastSeenUtc"))
    }))
  ].sort((a, b) => b.date - a.date).slice(0, 12);
  host.replaceChildren();
  if (!items.length) {
    host.className = "feed-list empty-state";
    host.textContent = "ยังไม่มี Threat feed";
    return;
  }
  host.className = "feed-list";
  items.forEach(item => {
    const row = element("article", "feed-item");
    const detail = element("div");
    detail.append(element("strong", "", item.title));
    if (item.detail) detail.append(element("small", "feed-evidence", item.detail));
    detail.append(element("small", "", item.subtitle), element("time", "", relativeTime(item.date)));
    row.append(element("span", "feed-icon", item.type), detail);
    host.append(row);
  });
}

function feedDetection(item) {
  const title = String(pick(item, "title") || "").trim();
  const description = String(pick(item, "description") || "").trim();
  const forwarded = forwardedAlertFields(item, title, description);
  return forwarded.title || title || forwarded.description || "เหตุการณ์ผิดปกติ";
}

function feedDetail(item) {
  const title = String(pick(item, "title") || "").trim();
  const description = String(pick(item, "description") || "").trim();
  const forwarded = forwardedAlertFields(item, title, description);
  return forwarded.description || (!forwarded.isGeneric && description && description !== title ? description : "");
}

function forwardedAlertFields(item, title, description) {
  const ruleId = String(pick(item, "ruleId") || "");
  const isGeneric = ruleId.toUpperCase() === "OS-NTSHIELD-ALERT" ||
    /syslog forward|NTShield-ALERT|Open-source signature hit/i.test(`${title} ${description}`);
  if (!isGeneric) return { isGeneric: false, title: "", description: "" };
  return {
    isGeneric: true,
    title: readFeedField(description, "Title"),
    description: readFeedField(description, "Desc")
  };
}

function readFeedField(text, key) {
  if (!text) return "";
  // Keys are internal constants (Title/Desc), so keep the expression readable.
  const pattern = new RegExp(`(?:^|\\s)${key}=([\\s\\S]*?)(?=\\s(?:RuleId|Severity|Title|SourceIp|DestIp|User|Host|AlertId|Desc)=|$)`, "i");
  return (pattern.exec(text)?.[1] || "").trim().replace(/^[-–—]$/, "");
}

function renderInsights() {
  for (const selector of ["#analystInsights", "#analystPageInsights"]) {
    const host = $(selector);
    if (!host) continue;
    host.replaceChildren(...state.insights.map(text => element("li", "", text)));
  }
}

function renderAnalyst() {
  const incidents = [...state.incidents].sort((a, b) => incidentDate(b) - incidentDate(a));
  if (!incidents.length) {
    state.analyst.selectedIncidentId = "";
    state.analyst.report = null;
    renderAnalystIncidentList();
    setAnalystEmptyState();
    return;
  }

  const selected = incidents.find(item => String(pick(item, "incidentId")) === state.analyst.selectedIncidentId) || incidents[0];
  const selectedId = String(pick(selected, "incidentId") || "");
  if (selectedId !== state.analyst.selectedIncidentId) {
    state.analyst.selectedIncidentId = selectedId;
    state.analyst.report = buildAnalystReport(selected);
    state.analyst.source = "deterministic";
  }
  renderAnalystIncidentList();
  renderAnalystReport(selected, state.analyst.report || buildAnalystReport(selected));
}

function renderAnalystIncidentList() {
  const host = $("#analystIncidentList");
  if (!host) return;
  const query = $("#analystSearch").value.trim().toLowerCase();
  const filter = $("#analystSeverityFilter").value.toLowerCase();
  const rows = [...state.incidents]
    .filter(item => {
      const severity = severityName(pick(item, "severity")).toLowerCase();
      const haystack = [pick(item, "title"), pick(item, "ruleId"), pick(item, "sourceIp"), pick(item, "destinationIp"), pick(item, "sourceHost"), pick(item, "destinationHost"), pick(item, "username")].join(" ").toLowerCase();
      return (!filter || severity === filter) && (!query || haystack.includes(query));
    })
    .sort((a, b) => incidentDate(b) - incidentDate(a));
  $("#analystQueueCount").textContent = `${number(rows.length)} รายการ`;
  host.replaceChildren();
  if (!rows.length) {
    host.append(element("div", "empty-state", "ไม่พบ Incident ตามเงื่อนไข"));
    return;
  }
  rows.forEach(item => {
    const id = String(pick(item, "incidentId") || "");
    const severity = severityName(pick(item, "severity"));
    const button = element("button", `analyst-incident-item ${id === state.analyst.selectedIncidentId ? "active" : ""}`);
    button.type = "button";
    button.dataset.incidentId = id;
    const marker = element("span", `analyst-incident-marker ${severity.toLowerCase()}`);
    const copy = element("span", "analyst-incident-copy");
    copy.append(
      element("b", "", pick(item, "title") || "Security incident"),
      element("small", "", `${endpointText(item, "source")} → ${endpointText(item, "destination")}`),
      element("time", "", relativeTime(incidentDate(item)))
    );
    button.append(marker, copy, element("strong", `severity-badge ${severity.toLowerCase()}`, severity));
    host.append(button);
  });
}

function selectAnalystIncident(event) {
  const button = event.target.closest("[data-incident-id]");
  if (!button) return;
  const incident = state.incidents.find(item => String(pick(item, "incidentId")) === button.dataset.incidentId);
  if (!incident) return;
  state.analyst.selectedIncidentId = button.dataset.incidentId;
  state.analyst.report = buildAnalystReport(incident);
  state.analyst.source = "deterministic";
  state.analyst.lastQuestion = "";
  renderAnalyst();
}

async function analyzeSelectedIncident() {
  const incident = state.incidents.find(item => String(pick(item, "incidentId")) === state.analyst.selectedIncidentId);
  const button = $("#analystAnalyzeButton");
  if (!incident) {
    toast("เลือก Incident ก่อนเริ่มวิเคราะห์");
    return;
  }
  button.disabled = true;
  button.textContent = "AI กำลังสืบสวน…";
  try {
    const remote = await requestJson(`/api/v1/incidents/${encodeURIComponent(state.analyst.selectedIncidentId)}/ai/analyze`, { method: "POST" });
    state.analyst.report = mergeRemoteAnalystReport(remote, incident);
    state.analyst.source = "brain";
    toast("วิเคราะห์ด้วย NT Shield Brain สำเร็จ");
  } catch (error) {
    // The local evidence engine keeps the page useful when Brain is not configured.
    // It never claims that an LLM answer was generated.
    state.analyst.report = buildAnalystReport(incident);
    state.analyst.source = "deterministic";
    toast(error?.status === 404 || error?.status === 503
      ? "Brain ยังไม่ถูกตั้งค่า — แสดงผลจาก Evidence engine ของ Central"
      : "Brain ใช้งานไม่ได้ชั่วคราว — แสดงผลจาก Evidence engine ของ Central");
  } finally {
    button.disabled = false;
    button.textContent = "ให้ AI สืบสวนคดีนี้";
    renderAnalyst();
  }
}

function buildAnalystReport(item) {
  const title = feedDetection(item);
  const description = feedDetail(item) || String(pick(item, "description") || "");
  const ruleId = String(pick(item, "ruleId") || "");
  const severity = severityName(pick(item, "severity"));
  const sourceIp = incidentIp(item, "source");
  const destinationIp = incidentIp(item, "destination");
  const evidence = [];
  const signals = [];
  const chain = [];
  const alternatives = [];
  const missing = [];
  const keyword = `${title} ${description} ${ruleId}`.toLowerCase();
  const isCredential = /(password|credential|brute|spray|login|logon|auth)/.test(keyword);
  const isWeb = /(web|http|cms|sql|exploit|request|payload)/.test(keyword);
  const isProcess = Boolean(pick(item, "processName", "processPath", "processId")) || /(process|execution|command)/.test(keyword);
  const isService = asArray(pick(item, "services")).length > 0 || /(service|persistence)/.test(keyword);
  const sourceHostKey = String(pick(item, "sourceHost") || "").trim().toLowerCase();
  const destinationHostKey = String(pick(item, "destinationHost") || "").trim().toLowerCase();
  const sourceAgentKey = String(pick(item, "sourceAgentId") || "").trim().toLowerCase();
  const destinationAgentKey = String(pick(item, "destinationAgentId") || "").trim().toLowerCase();
  const distinctHostHop = Boolean(
    (sourceHostKey && destinationHostKey && sourceHostKey !== destinationHostKey)
    || (sourceAgentKey && destinationAgentKey && sourceAgentKey !== destinationAgentKey)
  );
  const explicitLateralSignal = /(lateral movement|psexec|winrm|remote service|smb execution|wmic)/.test(keyword);
  const isLateral = distinctHostHop || explicitLateralSignal;

  const addEvidence = (label, detail, source = "Central detection") => {
    if (detail === undefined || detail === null || String(detail).trim() === "") return null;
    const refId = `E-${String(evidence.length + 1).padStart(3, "0")}`;
    evidence.push({ refId, label, detail: String(detail).slice(0, 360), source });
    return refId;
  };
  const addSignal = (label, detail, refs, scoreDelta) => signals.push({ label, detail, evidenceIds: refs.filter(Boolean), scoreDelta });
  const addStep = (label, detail, refs, kind = "event") => chain.push({ label, detail, evidenceIds: refs.filter(Boolean), kind });

  const coreRef = addEvidence("Central Incident", `${title} • ${severity} • Rule ${ruleId || "n/a"}`);
  if (sourceIp) {
    const ref = addEvidence("Source", `${sourceIp}${pick(item, "sourceHost") ? ` • ${pick(item, "sourceHost")}` : ""}`, "Agent / Correlator");
    addSignal("Source identity", "ระบบระบุ Source IP หรือ Host จาก Incident จริง", [ref], 8);
    addStep("Source observed", `${sourceIp} เริ่มต้นเหตุการณ์`, [ref]);
  }
  if (destinationIp || pick(item, "destinationHost")) {
    const ref = addEvidence("Destination", `${destinationIp || "unknown"}${pick(item, "destinationHost") ? ` • ${pick(item, "destinationHost")}` : ""}`, "Agent / Correlator");
    addSignal(distinctHostHop ? "Cross-host destination" : "Destination context", distinctHostHop ? "พบ Source และ Destination คนละ Host จาก Telemetry" : "พบปลายทางของเหตุการณ์ แต่ยังไม่เพียงพอยืนยันการเคลื่อนย้ายข้าม Host", [ref], distinctHostHop ? 12 : 5);
    addStep("Destination reached", `${destinationIp || pick(item, "destinationHost")}`, [ref], "hop");
  }
  const failedAttempts = numeric(pick(item, "failedAttempts", "failedLogonCount"));
  if (failedAttempts > 0) {
    const ref = addEvidence("Failed authentication", `${number(failedAttempts)} ครั้ง`, "Authentication telemetry");
    addSignal("Authentication burst", `พบ Login ล้มเหลว ${number(failedAttempts)} ครั้ง`, [ref], Math.min(28, 8 + Math.ceil(failedAttempts / 10)));
    addStep("Authentication burst", `${number(failedAttempts)} failed attempts`, [ref]);
  }
  const distinctUsers = numeric(pick(item, "distinctUsernames"));
  if (distinctUsers > 0) {
    const ref = addEvidence("Distinct usernames", `${number(distinctUsers)} บัญชี`, "Authentication telemetry");
    addSignal("User spread", `พฤติกรรมแตะหลาย Account (${number(distinctUsers)} บัญชี)`, [ref], 10);
  }
  if (Boolean(pick(item, "successfulLoginDetected"))) {
    const ref = addEvidence("Successful login", "พบ Login สำเร็จหลังเหตุการณ์ผิดปกติ", "Authentication telemetry");
    addSignal("Success after failures", "มี Successful Login ต่อเนื่องจากชุดเหตุการณ์นี้", [ref], 22);
    addStep("Authentication succeeded", "มี Login สำเร็จหลังความผิดปกติ", [ref]);
  }
  const username = pick(item, "username", "user");
  if (username) {
    const ref = addEvidence("Account", username, "Endpoint telemetry");
    addSignal("Account context", `เกี่ยวข้องกับ Account ${username}`, [ref], 5);
  }
  const process = pick(item, "processName", "processPath");
  if (process) {
    const processRef = addEvidence("Process", `${process}${pick(item, "processId") ? ` • PID ${pick(item, "processId")}` : ""}`, "Process telemetry");
    addSignal("Process context", "พบ Process ที่ต้องตรวจสอบกับ Baseline ของ Host", [processRef], 12);
    addStep("Process observed", String(process), [processRef], "process");
  }
  const services = asArray(pick(item, "services"));
  if (services.length) {
    const serviceRef = addEvidence("Services", services.slice(0, 6).join(", "), "Service telemetry");
    addSignal("Persistence surface", "พบ Service ที่อาจเกี่ยวข้องกับการคงอยู่ในระบบ", [serviceRef], 14);
    addStep("Service context", services.slice(0, 4).join(", "), [serviceRef], "service");
  }
  const evidenceEvents = asArray(pick(item, "evidenceEvents"));
  evidenceEvents.slice(0, 10).forEach(event => {
    const summary = [pick(event, "status", "eventType", "type"), pick(event, "username", "user"), pick(event, "sourceIp", "ip"), pick(event, "description", "message")].filter(Boolean).join(" • ");
    addEvidence("Event", summary || JSON.stringify(event).slice(0, 260), "Evidence event");
  });
  const secondarySources = [
    ["Web telemetry", asArray(pick(item, "suricataAlerts", "zeekEvents")), "Network / Web telemetry"],
    ["Exposure finding", asArray(pick(item, "asmFindings")), "ASM"],
    ["Threat intelligence", asArray(pick(item, "threatIntel")), "Threat intelligence"]
  ];
  secondarySources.forEach(([label, values, source]) => {
    if (values.length) addEvidence(label, `${values.length} รายการ`, source);
  });
  if (!evidenceEvents.length) missing.push({ label: "Raw event references", detail: "ยังไม่มี Evidence event แยกรายการให้ตรวจย้อนกลับ", impact: "ลดความมั่นใจในการยืนยันลำดับเหตุการณ์" });
  if (isCredential && !Boolean(pick(item, "successfulLoginDetected"))) missing.push({ label: "Successful authentication", detail: "ยังไม่พบหลักฐาน Login สำเร็จจากปลายทาง", impact: "ยังสรุปการเข้าถึงสำเร็จไม่ได้" });
  if (isWeb && !asArray(pick(item, "suricataAlerts", "zeekEvents")).length) missing.push({ label: "HTTP request / response", detail: "ยังไม่มี URL, Payload และ Response Code", impact: "ยังยืนยัน Web Exploitation ไม่ได้" });
  if (isProcess && !pick(item, "executableSha256")) missing.push({ label: "Executable hash", detail: "ไม่มี SHA-256 ของไฟล์ Process", impact: "เทียบ IOC และ Baseline ได้จำกัด" });
  if (isLateral && !destinationIp && !pick(item, "destinationHost")) missing.push({ label: "Destination hop", detail: "ยังไม่พบปลายทางของ Connection", impact: "ยังสร้าง Attack Chain ข้าม Host ไม่ครบ" });

  if (!signals.length) addSignal("Detection context", "ใช้ Title, Severity และ Rule ของ Central เป็นจุดเริ่มต้นการตรวจสอบ", [coreRef], 4);
  if (isCredential) alternatives.push({ label: "Approved administrator automation", detail: "อาจเป็นระบบ Automation หรือ Scanner ที่ได้รับอนุญาต ต้องเทียบ Change Ticket และ Source IP ที่รู้จัก" });
  if (isProcess || isService) alternatives.push({ label: "Legitimate deployment", detail: "Process หรือ Service ใหม่อาจเกิดจากการ Deploy ต้องเทียบ Baseline, ผู้สร้าง และช่วงเวลาเปลี่ยนแปลง" });
  if (!alternatives.length) alternatives.push({ label: "Benign operational anomaly", detail: "อาจเป็นกิจกรรมปฏิบัติการตามปกติ ควรยืนยันกับเจ้าของระบบก่อน Containment" });

  const baseScore = { Critical: 82, High: 68, Medium: 48, Low: 25, Informational: 10 }[severity] || 25;
  const score = clamp(baseScore + signals.reduce((sum, signal) => sum + signal.scoreDelta, 0) - missing.length * 5, 0, 100);
  const confidence = clamp(42 + Math.min(36, evidence.length * 4) + (evidenceEvents.length ? 12 : 0) - missing.length * 8, 10, 98);
  const band = confidence >= 78 ? "High" : confidence >= 55 ? "Medium" : "Low";
  const classification = isLateral ? "Likely lateral movement" : isCredential ? "Credential attack suspected" : isWeb ? "Web exploitation suspected" : isService ? "Persistence / service anomaly" : isProcess ? "Process anomaly" : "Security incident requires review";
  const summary = isLateral && sourceIp
    ? `พบความสัมพันธ์จาก ${sourceIp} ไปยัง ${destinationIp || pick(item, "destinationHost") || "ปลายทางที่ยังไม่ระบุ"} โดยมีหลักฐาน ${number(evidence.length)} รายการ ระบบยังไม่ดำเนินการตอบสนองเอง`
    : isCredential && sourceIp
      ? `พบพฤติกรรม Authentication ผิดปกติจาก ${sourceIp}${username ? ` ต่อบัญชี ${username}` : ""} โดยมีหลักฐาน ${number(evidence.length)} รายการ ${Boolean(pick(item, "successfulLoginDetected")) ? "และพบ Login สำเร็จต่อเนื่อง" : "แต่ยังไม่พบหลักฐานยืนยันว่าเข้าถึงสำเร็จ"}`
    : `ตรวจพบ ${title} จาก Telemetry ของ Central จำนวน ${number(evidence.length)} รายการ ต้องให้ Operator ตรวจสอบหลักฐานก่อนตอบสนอง`;

  const targetAgentId = findTargetAgent(item);
  const recommendations = [];
  if (sourceIp) recommendations.push({
    id: "block-source-ip",
    actionType: "BlockSourceIp",
    label: "Block Source IP ชั่วคราว",
    target: sourceIp,
    targetIp: sourceIp,
    targetAgentId,
    durationMinutes: 15,
    risk: "อาจกระทบผู้ดูแลระบบหรือ Scanner ที่ได้รับอนุญาต",
    rollback: "ยกเลิก Block หลังครบ 15 นาที",
    reason: "ลดการเชื่อมต่อซ้ำระหว่าง Operator ตรวจสอบหลักฐาน",
    evidenceIds: evidence.slice(0, 4).map(item => item.refId)
  });
  recommendations.push({
    id: "collect-diagnostics",
    actionType: "CollectDiagnostics",
    label: "เก็บ Diagnostics เพิ่ม",
    target: pick(item, "destinationHost", "sourceHost") || "Incident host",
    targetAgentId,
    durationMinutes: 10,
    risk: "ใช้ทรัพยากร Agent เล็กน้อย",
    rollback: "ไม่มีการเปลี่ยนแปลงถาวร",
    reason: "เติม Missing Evidence ก่อนตัดสินใจ Containment",
    evidenceIds: evidence.slice(-3).map(item => item.refId)
  });
  return {
    analysisId: `local-${stableHash(String(pick(item, "incidentId") || title)).toString(16)}`,
    incidentId: String(pick(item, "incidentId") || ""),
    classification,
    score,
    confidence,
    confidenceBand: band,
    summary,
    evidence,
    signals,
    chain,
    alternatives,
    missing,
    recommendations,
    model: "Central evidence engine",
    analysisMode: "deterministic",
    createdAt: new Date().toISOString(),
    llmCalls: 0
  };
}

function mergeRemoteAnalystReport(remote, incident) {
  const local = buildAnalystReport(incident);
  const confidence = numeric(pick(remote, "confidence"));
  const remoteEvidence = asArray(pick(remote, "evidence"));
  const remoteSignals = asArray(pick(remote, "riskSignals"));
  const remoteActions = asArray(pick(remote, "recommendedActions"));
  const remoteChain = asArray(pick(remote, "attackChain"));
  const remoteUnknowns = asArray(pick(remote, "unknowns", "analystQuestions"));
  const remoteClassification = String(pick(remote, "classification") || "");
  const guardedLateralClaim = /lateral/i.test(remoteClassification) && local.classification !== "Likely lateral movement";
  const evidenceByRef = new Map(local.evidence.map(item => [item.refId, item]));
  const citations = remoteEvidence.map((item, index) => {
    const refId = String(pick(item, "refId", "evidenceRef") || `E-${String(index + 1).padStart(3, "0")}`);
    return evidenceByRef.get(refId) || { refId, label: "AI citation", detail: String(pick(item, "reason") || "อ้างอิงจาก Evidence ที่ส่งให้ Brain"), source: "NT Shield Brain" };
  });
  const recommendations = remoteActions.map((item, index) => {
    const actionType = String(pick(item, "action", "actionType") || "CollectDiagnostics");
    const target = pick(item, "target") || incidentIp(incident, "source") || pick(incident, "destinationHost");
    return {
      id: `brain-action-${index + 1}`,
      actionType,
      label: actionType,
      target,
      targetIp: target && /^\d{1,3}(?:\.\d{1,3}){3}$/.test(String(target)) ? target : incidentIp(incident, "source"),
      targetAgentId: findTargetAgent(incident),
      durationMinutes: 15,
      risk: "ต้องตรวจผลกระทบก่อนดำเนินการ",
      rollback: "ดำเนินการตาม Runbook และ Approval policy",
      reason: String(pick(item, "reason") || "คำแนะนำจาก NT Shield Brain"),
      evidenceIds: asArray(pick(item, "evidenceRefs")).map(String)
    };
  });
  const mergedMissing = remoteUnknowns.length
    ? remoteUnknowns.map(item => ({ label: "Brain unknown", detail: String(item), impact: "ต้องเก็บข้อมูลเพิ่ม" }))
    : [...local.missing];
  if (guardedLateralClaim) mergedMissing.unshift({
    label: "Cross-host confirmation",
    detail: "Brain เสนอสมมติฐาน Lateral Movement แต่ Telemetry ปัจจุบันยังไม่ยืนยัน Source และ Destination คนละ Host",
    impact: "ระบบลดระดับข้อสรุปเป็น Credential attack จนกว่าจะมี Host-to-host evidence"
  });
  return {
    ...local,
    analysisId: pick(remote, "analysisId") || local.analysisId,
    classification: guardedLateralClaim ? local.classification : remoteClassification || local.classification,
    score: clamp(numeric(pick(remote, "riskScore")), 0, 100) || local.score,
    confidence: clamp(confidence * 100, 0, 100) || local.confidence,
    confidenceBand: confidence >= .78 ? "High" : confidence >= .55 ? "Medium" : "Low",
    summary: guardedLateralClaim ? `${local.summary} ระบบยังไม่รับสมมติฐาน Lateral Movement จนกว่าจะมีหลักฐานข้าม Host` : pick(remote, "summaryTh", "summary") || local.summary,
    chain: remoteChain.length ? remoteChain.map((step, index) => ({ label: `Step ${index + 1}`, detail: String(step), evidenceIds: [], kind: "event" })) : local.chain,
    evidence: citations.length ? citations : local.evidence,
    signals: remoteSignals.length ? remoteSignals.map(item => ({ label: pick(item, "name") || "Risk signal", detail: pick(item, "reason") || "Evidence-grounded signal", evidenceIds: asArray(pick(item, "evidenceRefs")).map(String), scoreDelta: numeric(pick(item, "scoreDelta")) })) : local.signals,
    recommendations: recommendations.length ? recommendations : local.recommendations,
    missing: mergedMissing,
    model: pick(remote, "model") || "NT Shield Brain",
    analysisMode: pick(remote, "analysisMode") || "multi-agent",
    llmCalls: numeric(pick(remote, "llmCalls"))
  };
}

function findTargetAgent(item) {
  const explicit = pick(item, "destinationAgentId", "sourceAgentId");
  if (explicit) return String(explicit);
  const candidates = [pick(item, "destinationHost", "sourceHost"), incidentIp(item, "destination"), incidentIp(item, "source")].filter(Boolean).map(String);
  const agent = state.agents.find(candidate => candidates.includes(String(pick(candidate, "agentId", "computerName", "hostIp"))));
  return agent ? String(pick(agent, "agentId")) : "";
}

function renderAnalystReport(incident, report) {
  const severity = severityName(pick(incident, "severity"));
  $("#analystAnalyzedCount").textContent = number(state.incidents.length);
  $("#analystApprovalCount").textContent = number(report.recommendations.filter(item => state.analyst.actionStates[item.id] !== "approved" && state.analyst.actionStates[item.id] !== "dismissed").length);
  $("#analystEvidenceCount").textContent = number(report.evidence.length);
  $("#analystVerdictTitle").textContent = report.classification;
  $("#analystVerdictSubtitle").textContent = `${pick(incident, "title") || "Security incident"} • ${severity} • ${String(pick(incident, "incidentId") || "")}`;
  const badge = $("#analystVerdictBadge");
  badge.textContent = `${severity} / ${report.score}`;
  badge.className = `analyst-verdict-badge ${severity.toLowerCase()}`;
  $("#analystConfidenceValue").textContent = `${number(report.confidence)}%`;
  $("#analystConfidenceBand").textContent = `${report.confidenceBand} confidence`;
  $("#analystConfidenceReason").textContent = `${number(report.evidence.length)} evidence • ${number(report.missing.length)} unknowns`;
  $("#analystConfidenceRing").style.setProperty("--confidence", `${report.confidence}%`);
  $("#analystSummary").textContent = report.summary;
  $("#analystSourceBadge").textContent = state.analyst.source === "brain" ? `NT Shield Brain • ${report.model}` : "Explainable reasoning • deterministic evidence engine";
  $("#analystWindow").textContent = `Data window ${formatDate(pick(incident, "firstSeen", "firstSeenUtc"))} → ${formatDate(incidentDate(incident))}`;
  $("#analystModelState").textContent = `AI tools: 0 • ${report.llmCalls || 0} LLM calls`;
  renderAnalystMission(report);
  renderAnalystBrief(report);
  renderAnalystChain(report.chain);
  renderAnalystSignals(report.signals);
  renderAnalystEvidence(report.evidence);
  renderAnalystRecommendations(report.recommendations);
  renderAnalystPlainList("#analystAlternatives", report.alternatives, "ยังไม่มี Alternative explanation");
  renderAnalystPlainList("#analystMissing", report.missing, "ไม่มี Missing Evidence ที่ระบุได้");
  renderAnalystCopilot(report);
}

function renderAnalystMission(report) {
  const pending = report.recommendations.filter(item => !state.analyst.actionStates[item.id]).length;
  $("#analystMissionTitle").textContent = `AI กำลังสืบสวน: ${report.classification}`;
  $("#analystMissionCopy").textContent = `เชื่อมโยง ${number(report.evidence.length)} หลักฐานเป็น ${number(report.chain.length)} ขั้นตอน ตรวจ ${number(report.alternatives.length)} สมมติฐานคู่แข่ง และพบ ${number(report.missing.length)} ช่องว่างที่ต้องเก็บเพิ่ม`;
  const order = ["observe", "correlate", "hypothesize", "recommend", "approve"];
  $$('[data-analyst-stage]').forEach(stage => {
    const index = order.indexOf(stage.dataset.analystStage);
    const approvalStage = stage.dataset.analystStage === "approve";
    stage.classList.toggle("complete", !approvalStage || pending === 0);
    stage.classList.toggle("active", approvalStage && pending > 0);
    stage.setAttribute("aria-current", approvalStage && pending > 0 ? "step" : "false");
    if (index < 0) stage.classList.remove("complete", "active");
  });
}

function renderAnalystBrief(report) {
  const focus = report.signals[0];
  const next = report.recommendations.find(item => !state.analyst.actionStates[item.id]) || report.recommendations[0];
  $("#analystFocus").textContent = focus?.label || report.classification;
  $("#analystFocusDetail").textContent = focus?.detail || "ตรวจสอบความสัมพันธ์ของหลักฐานทั้งหมดในคดี";
  $("#analystCoverage").textContent = `${number(report.evidence.length)} citations / ${number(report.missing.length)} gaps`;
  $("#analystNextStep").textContent = next?.label || "ตรวจสอบหลักฐานกับเจ้าของระบบ";
  $("#analystNextStepReason").textContent = next?.reason || "ลดความไม่แน่นอนก่อนตัดสินใจ Containment";
}

function renderAnalystCopilot(report) {
  $("#analystAnswerGrounding").textContent = `Grounded in ${number(report.evidence.length)} citations`;
  if (state.analyst.lastQuestion) {
    answerAnalystQuestion(state.analyst.lastQuestion, { preserveQuestion: true });
    return;
  }
  const answer = $("#analystInvestigationAnswer");
  answer.replaceChildren(
    element("span", "", "AI CASE BRIEF"),
    element("p", "", `${report.classification} — ${report.summary}`),
    element("small", "", `อ้างอิง ${report.evidence.slice(0, 4).map(item => item.refId).join(", ") || "ยังไม่มี citation"} • Confidence ${number(report.confidence)}% • ต้องให้ Operator อนุมัติการตอบสนอง`)
  );
}

function answerAnalystQuestion(question, options = {}) {
  const report = state.analyst.report;
  const host = $("#analystInvestigationAnswer");
  if (!report || !host) {
    toast("เลือก Incident ก่อนถาม AI");
    return;
  }
  if (!options.preserveQuestion) state.analyst.lastQuestion = String(question || "");
  const normalized = String(question || "").trim().toLowerCase();
  let answerText;
  let references = [];
  if (normalized === "evidence" || /(หลักฐาน|ยืนยัน|อ้างอิง|evidence|proof)/.test(normalized)) {
    const items = report.evidence.slice(0, 4);
    references = items.map(item => item.refId);
    answerText = items.length
      ? `หลักฐานหลักคือ ${items.map(item => `${item.refId} ${item.label}: ${item.detail}`).join("; ")}`
      : "ยังไม่มี Evidence ที่อ้างย้อนกลับได้ จึงไม่ควรยืนยันข้อสรุปนี้";
  } else if (normalized === "alternative" || /(อื่น|ทางเลือก|สมมติฐาน|alternative|benign)/.test(normalized)) {
    const items = report.alternatives.slice(0, 3);
    references = report.evidence.slice(0, 2).map(item => item.refId);
    answerText = items.length
      ? `AI ยังไม่ตัดคำอธิบายเหล่านี้ทิ้ง: ${items.map(item => `${item.label} — ${item.detail}`).join("; ")}`
      : "ยังไม่มีสมมติฐานคู่แข่งที่ระบุได้ ควรยืนยันกับเจ้าของระบบก่อนตอบสนอง";
  } else if (normalized === "missing" || /(ขาด|ช่องว่าง|เพิ่ม|missing|unknown|confidence|มั่นใจ)/.test(normalized)) {
    const items = report.missing.slice(0, 4);
    references = report.evidence.slice(0, 2).map(item => item.refId);
    answerText = items.length
      ? `Confidence อยู่ที่ ${number(report.confidence)}% เพราะยังขาด ${items.map(item => `${item.label}: ${item.detail}`).join("; ")}`
      : `ไม่พบ Evidence gap สำคัญในรายงานปัจจุบัน แต่ Confidence ${number(report.confidence)}% ยังต้องผ่านการตรวจของ Operator`;
  } else if (normalized === "action" || /(ทำอะไร|ต่อไป|ตอบสนอง|action|block|isolate|recommend)/.test(normalized)) {
    const item = report.recommendations.find(candidate => !state.analyst.actionStates[candidate.id]) || report.recommendations[0];
    references = item?.evidenceIds || [];
    answerText = item
      ? `ขั้นตอนถัดไปที่ AI แนะนำคือ ${item.label} ที่ ${item.target || "เป้าหมายของ Incident"} เพราะ ${item.reason} ผลกระทบที่ต้องพิจารณา: ${item.risk} และย้อนกลับได้ด้วย ${item.rollback}`
      : "AI ยังไม่มีคำแนะนำตอบสนองจากหลักฐานชุดนี้ ควรเก็บ Diagnostics เพิ่มก่อน";
  } else {
    const signals = report.signals.slice(0, 3);
    references = [...new Set(signals.flatMap(item => item.evidenceIds || []))];
    answerText = `${report.classification} ด้วย Confidence ${number(report.confidence)}% เหตุผลหลักคือ ${signals.map(item => `${item.label}: ${item.detail}`).join("; ") || report.summary}`;
  }
  host.replaceChildren(
    element("span", "", "AI ANSWER · EVIDENCE-GROUNDED"),
    element("p", "", answerText),
    element("small", "", `${references.length ? `อ้างอิง ${references.join(", ")}` : "ยังไม่มี citation โดยตรง"} • คำตอบนี้อธิบายรายงานปัจจุบันและไม่สั่งระบบเอง`)
  );
}

function renderAnalystChain(items) {
  const host = $("#analystChain");
  $("#analystChainCount").textContent = `${number(items.length)} steps`;
  host.replaceChildren();
  if (!items.length) { host.append(element("div", "empty-state", "ยังไม่มี Attack Chain")); return; }
  items.forEach((item, index) => {
    const row = element("div", "analyst-chain-step");
    row.append(element("span", `chain-node ${item.kind || "event"}`, String(index + 1).padStart(2, "0")));
    const copy = element("div", "analyst-chain-copy");
    copy.append(element("b", "", item.label), element("p", "", item.detail));
    if (item.evidenceIds?.length) copy.append(element("small", "citation-row", item.evidenceIds.join("  ")));
    row.append(copy);
    if (index < items.length - 1) row.append(element("i", "chain-line"));
    host.append(row);
  });
}

function renderAnalystSignals(items) {
  const host = $("#analystSignals");
  host.replaceChildren();
  if (!items.length) { host.append(element("div", "empty-state", "ยังไม่มี Risk signal")); return; }
  items.slice(0, 8).forEach(item => {
    const row = element("div", "analyst-signal");
    const score = numeric(item.scoreDelta);
    row.append(element("span", score >= 0 ? "signal-positive" : "signal-negative", score >= 0 ? `+${score}` : String(score)));
    const copy = element("div");
    copy.append(element("b", "", item.label), element("p", "", item.detail));
    if (item.evidenceIds?.length) copy.append(element("small", "citation-row", item.evidenceIds.join("  ")));
    row.append(copy);
    host.append(row);
  });
}

function renderAnalystEvidence(items) {
  const host = $("#analystEvidence");
  $("#analystLedgerState").textContent = `${number(items.length)} citations`;
  host.replaceChildren();
  if (!items.length) { host.append(element("div", "empty-state", "ไม่มี Evidence")); return; }
  items.slice(0, 14).forEach(item => {
    const row = element("div", "analyst-evidence-row");
    row.append(element("code", "evidence-ref", item.refId));
    const copy = element("div");
    copy.append(element("b", "", item.label), element("p", "", item.detail), element("small", "", item.source));
    row.append(copy);
    host.append(row);
  });
}

function renderAnalystRecommendations(items) {
  const host = $("#analystRecommendations");
  host.replaceChildren();
  if (!items.length) { host.append(element("div", "empty-state", "ไม่มีคำแนะนำตอบสนอง")); return; }
  items.forEach(item => {
    const status = state.analyst.actionStates[item.id];
    const card = element("div", `analyst-recommendation ${status || ""}`);
    const header = element("div", "recommendation-head");
    header.append(element("span", "recommendation-type", item.actionType), element("b", "", item.label));
    const statusLabel = status === "approved" ? "ส่งเข้า Action queue แล้ว" : status === "dismissed" ? "ซ่อนไว้แล้ว" : item.targetAgentId ? "รอ Operator" : "ต้องเลือก Agent";
    header.append(element("span", `recommendation-status ${status || ""}`, statusLabel));
    const body = element("div", "recommendation-body");
    body.append(element("p", "", `${item.target || "ไม่ระบุเป้าหมาย"} • ${item.reason}`), element("small", "", `ผลกระทบ: ${item.risk} • Rollback: ${item.rollback}`));
    const actions = element("div", "recommendation-actions");
    const approve = element("button", "button-primary", status === "approved" ? "อนุมัติแล้ว" : "อนุมัติและส่งเข้า Queue");
    approve.type = "button"; approve.dataset.approveRecommendation = item.id; approve.disabled = Boolean(status) || !item.targetAgentId;
    const dismiss = element("button", "button-secondary", status === "dismissed" ? "ซ่อนแล้ว" : "ยังไม่ทำ");
    dismiss.type = "button"; dismiss.dataset.dismissRecommendation = item.id; dismiss.disabled = Boolean(status);
    actions.append(approve, dismiss);
    card.append(header, body, actions);
    host.append(card);
  });
}

function renderAnalystPlainList(selector, items, emptyText) {
  const host = $(selector);
  host.replaceChildren();
  if (!items.length) { host.append(element("div", "empty-state", emptyText)); return; }
  items.slice(0, 6).forEach(item => {
    const row = element("div", "analyst-plain-item");
    row.append(element("b", "", item.label || "Unknown"), element("p", "", item.detail || String(item)));
    if (item.impact) row.append(element("small", "", `Impact: ${item.impact}`));
    host.append(row);
  });
}

async function handleAnalystRecommendation(event) {
  const approveButton = event.target.closest("[data-approve-recommendation]");
  const dismissButton = event.target.closest("[data-dismiss-recommendation]");
  const report = state.analyst.report;
  if (!report) return;
  const recId = approveButton?.dataset.approveRecommendation || dismissButton?.dataset.dismissRecommendation;
  const recommendation = report.recommendations.find(item => item.id === recId);
  const incident = state.incidents.find(item => String(pick(item, "incidentId")) === state.analyst.selectedIncidentId);
  if (!recommendation || !incident) return;
  if (dismissButton) {
    state.analyst.actionStates[recId] = "dismissed";
    renderAnalyst();
    return;
  }
  if (!recommendation.targetAgentId) {
    toast("ยังไม่พบ Agent เป้าหมาย จึงไม่ส่งคำสั่งแบบ broadcast");
    return;
  }
  approveButton.disabled = true;
  try {
    await requestJson("/api/v1/actions", {
      method: "POST",
      body: {
        requester: `operator:${state.username}`,
        targetAgentId: recommendation.targetAgentId,
        actionType: recommendation.actionType,
        reason: `AI Analyst recommendation: ${recommendation.reason}`,
        targetIp: recommendation.targetIp,
        incidentId: String(pick(incident, "incidentId") || ""),
        approved: true,
        approvalId: `human-${stableHash(`${state.username}|${Date.now()}|${recId}`).toString(16)}`,
        durationMinutes: recommendation.durationMinutes || 15
      }
    });
    state.analyst.actionStates[recId] = "approved";
    toast("อนุมัติแล้ว — Action ถูกส่งเข้า Central queue");
  } catch (error) {
    toast(`ส่ง Action ไม่สำเร็จ: ${friendlyError(error)}`);
  } finally {
    renderAnalyst();
  }
}

function setAnalystEmptyState() {
  state.analyst.lastQuestion = "";
  $("#analystAnalyzedCount").textContent = "0";
  $("#analystApprovalCount").textContent = "0";
  $("#analystEvidenceCount").textContent = "0";
  $("#analystVerdictTitle").textContent = "ยังไม่มี Incident";
  $("#analystVerdictSubtitle").textContent = "ระบบจะเริ่มวิเคราะห์เมื่อ Central รับข้อมูลจาก Agent";
  $("#analystVerdictBadge").textContent = "รอข้อมูล";
  $("#analystVerdictBadge").className = "analyst-verdict-badge";
  $("#analystConfidenceValue").textContent = "—";
  $("#analystConfidenceBand").textContent = "ยังไม่วิเคราะห์";
  $("#analystConfidenceReason").textContent = "ไม่มี Incident ที่เลือก";
  $("#analystSummary").textContent = "ยังไม่มีข้อมูลจาก Agent ให้ตรวจสอบ";
  $("#analystMissionTitle").textContent = "AI พร้อมเริ่มสืบสวน";
  $("#analystMissionCopy").textContent = "เลือก Incident แล้วระบบจะเชื่อมเหตุการณ์ ทดสอบสมมติฐาน และจัดลำดับสิ่งที่ควรทำต่อ";
  $("#analystFocus").textContent = "ยังไม่มีคดีที่เลือก";
  $("#analystFocusDetail").textContent = "สิ่งที่ AI กำลังตรวจสอบ";
  $("#analystCoverage").textContent = "0 citations / 0 gaps";
  $("#analystNextStep").textContent = "รอ Incident";
  $("#analystNextStepReason").textContent = "AI จะเสนอขั้นตอนที่ลดความไม่แน่นอนได้มากที่สุด";
  $("#analystAnswerGrounding").textContent = "Grounded in 0 citations";
  $("#analystInvestigationAnswer").replaceChildren(
    element("span", "", "AI CASE BRIEF"),
    element("p", "", "เลือก Incident เพื่อให้ AI อธิบายคดีจากหลักฐานที่มีอยู่"),
    element("small", "", "คำตอบจะไม่สั่งเปลี่ยนแปลงระบบโดยอัตโนมัติ")
  );
  $$('[data-analyst-stage]').forEach(stage => stage.classList.remove("complete", "active"));
  ["#analystChain", "#analystSignals", "#analystEvidence", "#analystRecommendations", "#analystAlternatives", "#analystMissing"].forEach(selector => $(selector)?.replaceChildren(element("div", "empty-state", "ยังไม่มีข้อมูล")));
}

function buildInsights() {
  const counts = severityCounts(state.incidents);
  const offline = Math.max(0, state.agents.length - state.onlineAgents);
  const insights = [];
  if (counts.critical) insights.push(`มี Critical Incident ${number(counts.critical)} รายการ ควรตรวจหลักฐานและผู้ได้รับผลกระทบก่อนดำเนินการตอบสนอง`);
  if (counts.high) insights.push(`มี High Severity ${number(counts.high)} รายการ ให้จัดลำดับตามความใหม่และจำนวนเครื่องที่เกี่ยวข้อง`);
  if (offline) insights.push(`Agent ออฟไลน์ ${number(offline)} เครื่อง ควรตรวจ network, service และ Central URL`);
  if (state.threats.length) insights.push(`Central เชื่อมโยงได้ ${number(state.threats.length)} Threat Campaign ควรตรวจ lateral path และบัญชีผู้ใช้ที่ซ้ำกัน`);
  if (!state.agents.length) insights.push("ยังไม่มี Agent ลงทะเบียน ให้ติดตั้ง Agent และตั้ง Central URL ให้ถูกต้อง");
  if (!state.incidents.length && state.agents.length) insights.push("ยังไม่มี Incident เปิดอยู่ ระบบกำลังรับ telemetry จาก Agent ตามปกติ");
  if (!insights.length) insights.push("ยังไม่มีข้อมูลเพียงพอสำหรับคำแนะนำ");
  return insights.slice(0, 4);
}

function showPage(name) {
  const page = name || "overview";
  $$(".page").forEach(node => node.classList.toggle("active", node.dataset.page === page));
  $$('[data-nav]').forEach(node => node.classList.toggle("active", node.dataset.nav === page));
  $("#sidebar").classList.remove("open");
  $("#dashboardView").classList.toggle("overview-active", page === "overview");
  window.NTShieldDefenseMap?.setActive(page === "overview");
  void window.NTShieldTenantReports?.onPage(page);
  window.scrollTo({ top: 0, behavior: "smooth" });
  if (page === "topology") window.NTShieldTopology?.load();
}

function setConnection(connected, text) {
  $("#connectionDot").classList.toggle("offline", !connected);
  $("#sidebarStatusDot").style.background = connected ? "var(--green)" : "var(--red)";
  $("#sidebarStatus").textContent = text;
}

function severityCounts(items) {
  const result = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  items.forEach(item => {
    const key = severityName(pick(item, "severity")).toLowerCase();
    result[key] = (result[key] || 0) + 1;
  });
  return result;
}

function severityName(value) {
  const values = ["Informational", "Low", "Medium", "High", "Critical"];
  if (Number.isInteger(Number(value)) && Number(value) >= 0 && Number(value) < values.length) return values[Number(value)];
  const normalized = String(value || "Informational").toLowerCase();
  return values.find(item => item.toLowerCase() === normalized) || "Informational";
}

function isAgentOnline(agent) {
  const explicit = pick(agent, "online", "isOnline");
  if (typeof explicit === "boolean") return explicit;
  const status = String(pick(agent, "status") || "").toLowerCase();
  if (status.includes("offline")) return false;
  const lastSeen = dateValue(pick(agent, "lastSeenUtc", "timestampUtc"));
  return Number.isFinite(lastSeen.getTime()) && Date.now() - lastSeen.getTime() < 5 * 60 * 1000;
}

function routeText(item) {
  return `${endpointText(item, "source")} → ${endpointText(item, "destination")}`;
}

function endpointText(item, side) {
  const ip = incidentIp(item, side);
  const host = pick(item, `${side}Host`);
  if (ip && host && ip !== host) return `${ip} • ${host}`;
  return ip || host || "unknown";
}

function incidentIp(item, side) {
  const direct = pick(item, `${side}Ip`);
  if (direct) return direct;
  const field = side === "source" ? "SourceIp" : "DestIp";
  return readFeedField(String(pick(item, "description") || ""), field);
}

function incidentDate(item) {
  return dateValue(pick(item, "lastSeen", "lastSeenUtc", "firstSeen", "firstSeenUtc"));
}

function dateValue(value) {
  const date = value instanceof Date ? value : new Date(value || 0);
  return Number.isNaN(date.getTime()) ? new Date(0) : date;
}

function relativeTime(value) {
  const date = dateValue(value);
  if (!date.getTime()) return "—";
  const seconds = Math.round((date.getTime() - Date.now()) / 1000);
  const ranges = [[31536000, "year"], [2592000, "month"], [604800, "week"], [86400, "day"], [3600, "hour"], [60, "minute"]];
  const formatter = new Intl.RelativeTimeFormat("th-TH", { numeric: "auto" });
  for (const [size, unit] of ranges) if (Math.abs(seconds) >= size) return formatter.format(Math.round(seconds / size), unit);
  return formatter.format(seconds, "second");
}

function formatDate(value) {
  const date = dateValue(value);
  return date.getTime() ? new Intl.DateTimeFormat("th-TH", { dateStyle: "medium", timeStyle: "short" }).format(date) : "—";
}

function friendlyError(error) {
  if (error?.status === 401 || error?.message === "missing_api_key") return "Operator API Key ไม่ถูกต้อง หรือ Central เปิด RequireAuth อยู่";
  if (error?.status === 403) return "บัญชีนี้ไม่มีสิทธิ์เข้าถึงข้อมูล Operator";
  if (error instanceof TypeError) return "ติดต่อ NT Shield Central ไม่ได้ กรุณาตรวจ service และ HTTPS certificate";
  return `เชื่อมต่อไม่สำเร็จ: ${error?.message || "unknown error"}`;
}

function pick(object, ...keys) {
  if (!object || typeof object !== "object") return undefined;
  for (const key of keys) {
    if (object[key] !== undefined && object[key] !== null && object[key] !== "") return object[key];
    const pascal = key.charAt(0).toUpperCase() + key.slice(1);
    if (object[pascal] !== undefined && object[pascal] !== null && object[pascal] !== "") return object[pascal];
  }
  return undefined;
}

function asArray(value) { return Array.isArray(value) ? value : []; }
function numeric(value) { const n = Number(value); return Number.isFinite(n) ? n : 0; }
function clamp(value, min, max) { return Math.min(max, Math.max(min, Math.round(value))); }
function number(value) { return new Intl.NumberFormat("th-TH").format(numeric(value)); }
function compact(value) { return new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 }).format(numeric(value)); }

function element(tag, className = "", text = null) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== null && text !== undefined) node.textContent = String(text);
  return node;
}

function toast(message) {
  const node = $("#toast");
  node.textContent = message;
  node.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => node.classList.remove("show"), 3600);
}
