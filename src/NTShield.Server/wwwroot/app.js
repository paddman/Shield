"use strict";

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const API_KEY_HEADER = "X-NTShield-Api-Key";
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
  threats: [],
  signatures: [],
  onlineAgents: 0,
  insights: [],
  tenantId: "default"
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
  $("#refreshButton").addEventListener("click", () => refreshData(true));
  $("#logoutButton").addEventListener("click", logout);
  $("#mobileMenu").addEventListener("click", () => $("#sidebar").classList.toggle("open"));
  $("#incidentSearch").addEventListener("input", renderIncidentTable);
  $("#severityFilter").addEventListener("change", renderIncidentTable);
  $("#assetSearch").addEventListener("input", renderAssetTable);
  $("#saveSettings").addEventListener("click", async () => {
    state.apiKey = $("#settingsApiKey").value.trim();
    persistCredential($("#settingsRemember").checked);
    await refreshData(true);
  });
  $("#topologyTenant")?.addEventListener("change", () => {
    state.tenantId = $("#topologyTenant").value.trim().toLowerCase() || "default";
    $("#topologyTenant").value = state.tenantId;
    localStorage.setItem(STORE.tenant, state.tenantId);
    window.NTShieldTopology?.load({ resetSelection: true });
  });
  window.NTShieldTopology?.init({ requestJson, toast, getTenant: () => state.tenantId });
  window.NTShieldDefenseMap?.init();
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
    const [health, agents, incidents, threats, signatures] = await Promise.all([
      requestJson("/api/v1/health"),
      requestJson("/api/v1/agents"),
      requestJson("/api/v1/incidents?take=250"),
      requestJson("/api/v1/threats?take=250"),
      requestJson("/api/v1/signatures")
    ]);

    state.health = health || {};
    state.agents = asArray(agents);
    state.incidents = asArray(incidents);
    state.threats = asArray(threats);
    state.signatures = asArray(signatures);
    state.onlineAgents = state.agents.filter(isAgentOnline).length;
    state.insights = buildInsights();
    renderAll();
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
  renderThreatCards();
  renderFeed();
  renderInsights();

  const incidentCount = state.incidents.length;
  const threatCount = state.threats.length;
  $("#incidentNavCount").textContent = compact(incidentCount);
  $("#incidentPageCount").textContent = `${number(incidentCount)} incidents`;
  $("#threatPageCount").textContent = `${number(threatCount)} threats`;
  $("#assetPageCount").textContent = `${number(state.agents.length)} assets`;
  $("#centralVersion").textContent = `Central v${pick(state.health, "version", "productVersion") || "—"}`;
  $("#lastUpdated").textContent = `Updated ${new Intl.DateTimeFormat("th-TH", { dateStyle: "medium", timeStyle: "medium" }).format(new Date())}`;
  $("#feedSignatures").textContent = number(state.signatures.length);
  $("#feedAgents").textContent = number(state.agents.length);
  $("#feedOnline").textContent = number(state.onlineAgents);
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

  renderDefenseThreats(openIncidents);
  renderDefenseMiniMap(openIncidents, state.threats);
  renderDefenseImpact(score);

  $("#defenseBehavioralStatus").textContent = state.agents.length ? "Active" : "Waiting";
  $("#defenseIntelStatus").textContent = state.signatures.length ? "Active" : "Loading";
  $("#statusNetwork").textContent = counts.critical ? "At Risk" : "Secure";
  $("#statusEndpoints").textContent = offline ? `${number(offline)} Offline` : "Secure";
  $("#statusApplications").textContent = counts.high ? "Watching" : "Secure";
  $("#statusCloud").textContent = state.agents.length ? "Monitored" : "Waiting";
  $("#statusData").textContent = counts.critical ? "Investigate" : "Protected";

  window.NTShieldDefenseMap?.update({
    incidents: openIncidents,
    threats: state.threats,
    onlineAgents: state.onlineAgents,
    score
  });
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
      element("td", "", pick(item, "sourceHost", "sourceIp") || "—"),
      element("td", "", pick(item, "destinationHost", "destinationIp") || "—"),
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
    td.colSpan = 5;
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
      element("td", "", pick(item, "platform", "osVersion") || "unknown"),
      element("td", "", pick(item, "agentVersion") || "—"),
      element("td", "", relativeTime(dateValue(pick(item, "lastSeenUtc", "timestampUtc"))))
    );
    table.append(tr);
  });
}

function renderThreatCards() {
  const host = $("#threatCards");
  host.replaceChildren();
  if (!state.threats.length) {
    host.className = "collection-grid empty-state";
    host.textContent = "ยังไม่มี Threat Campaign ที่เชื่อมโยงได้";
    return;
  }
  host.className = "collection-grid";
  [...state.threats].sort((a, b) => dateValue(pick(b, "lastSeenUtc")) - dateValue(pick(a, "lastSeenUtc"))).forEach(item => {
    const severity = severityName(pick(item, "severity"));
    const card = element("article", "card threat-card");
    const header = element("header");
    header.append(element("h2", "", pick(item, "title") || "Threat campaign"), element("span", `severity-badge ${severity.toLowerCase()}`, severity));
    const summary = element("p", "", pick(item, "summary") || "Cross-host activity correlated by NT Shield Central.");
    const footer = element("footer");
    const hosts = asArray(pick(item, "involvedHosts"));
    const hops = asArray(pick(item, "hops"));
    footer.append(element("span", "", `${hosts.length} hosts`), element("span", "", `${hops.length} hops`), element("span", "", relativeTime(dateValue(pick(item, "lastSeenUtc")))));
    card.append(header, summary, footer);
    host.append(card);
  });
}

function renderFeed() {
  const host = $("#threatFeed");
  const items = [
    ...state.incidents.map(item => ({ type: "INC", title: pick(item, "title") || "Incident", subtitle: `${severityName(pick(item, "severity"))} • ${routeText(item)}`, date: incidentDate(item) })),
    ...state.threats.map(item => ({ type: "THR", title: pick(item, "title") || "Threat campaign", subtitle: `${severityName(pick(item, "severity"))} • ${asArray(pick(item, "involvedHosts")).length} hosts`, date: dateValue(pick(item, "lastSeenUtc")) }))
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
    detail.append(element("strong", "", item.title), element("small", "", item.subtitle), element("time", "", relativeTime(item.date)));
    row.append(element("span", "feed-icon", item.type), detail);
    host.append(row);
  });
}

function renderInsights() {
  for (const selector of ["#analystInsights", "#analystPageInsights"]) {
    const host = $(selector);
    if (!host) continue;
    host.replaceChildren(...state.insights.map(text => element("li", "", text)));
  }
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
  const source = pick(item, "sourceHost", "sourceIp") || "unknown";
  const destination = pick(item, "destinationHost", "destinationIp") || "unknown";
  return `${source} → ${destination}`;
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
