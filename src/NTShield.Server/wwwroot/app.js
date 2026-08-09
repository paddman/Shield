"use strict";

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const API_KEY_HEADER = "X-NTShield-Api-Key";
const INCIDENT_FETCH_LIMIT = 250;
const REQUEST_TIMEOUT_MS = 8000;
const THREAT_LIST_LIMIT = 100;
const THREAT_GRAPH_NODE_LIMIT = 12;
const THREAT_GRAPH_EDGE_LIMIT = 48;
const THREAT_TIMELINE_ACCUMULATION_LIMIT = 500;
const THREAT_CONTACT_RENDER_LIMIT = 200;
const THREAT_CONTACT_ACCUMULATION_LIMIT = 200;
const PACKET_SESSION_RENDER_LIMIT = 50;
const ROUTABLE_PAGES = new Set(["overview", "incidents", "threats", "forensics", "assets", "topology", "customers", "reports", "feed", "analyst", "llm", "settings"]);
const STORE = {
  key: "ntshield.operator.key",
  sessionKey: "ntshield.operator.session-key",
  active: "ntshield.operator.active",
  username: "ntshield.operator.name",
  tenant: "ntshield.operator.tenant",
  overviewModePrefix: "ntshield.overview.mode"
};

const state = {
  apiKey: "",
  username: "SOC Analyst",
  session: null,
  activePage: "overview",
  dashboardSummary: null,
  health: {},
  agents: [],
  incidents: [],
  incidentTotal: null,
  incidentCountCapped: false,
  threats: [],
  signatures: [],
  llmStatus: {},
  llmTokens: [],
  onlineAgents: 0,
  insights: [],
  tenantId: "default",
  selectedIncidentRouteId: "",
  selectedThreatId: "",
  selectedThreatEdgeId: "",
  threatRouteWindow: null,
  threatDetail: {
    campaignId: "",
    graph: null,
    timeline: null,
    contacts: null,
    errors: {}
  },
  threatAi: { campaignId: "", status: "idle", result: null, error: null },
  forensics: {
    query: { campaignId: "", edgeId: "", fromUtc: "", toUtc: "" },
    sessions: [],
    nextCursor: null,
    captureHealth: null,
    selectedSessionId: ""
  },
  loading: {},
  errors: {},
  moduleErrors: {},
  loaded: {},
  analyst: {
    selectedIncidentId: "",
    report: null,
    source: "deterministic",
    actionStates: {},
    lastQuestion: ""
  }
};

let toastTimer;
let refreshGeneration = 0;
let sessionGeneration = 0;
let sessionController = null;
let tenantChoicesController = null;
let refreshController = null;
let threatDetailGeneration = 0;
let threatDetailController = null;
let threatPaginationGeneration = 0;
let threatPaginationController = null;
let threatRevisionGeneration = 0;
let threatRevisionController = null;
let threatRevisionTenant = "";
let threatRevisionPollTimer = 0;
let threatRevisionRefreshTimer = 0;
let threatAiGeneration = 0;
let threatAiController = null;
let forensicsActionGeneration = 0;
let forensicsActionController = null;
let currentRouteKey = "";
const loadedScripts = new Map();
const initializedModules = new Set();

document.addEventListener("DOMContentLoaded", () => {
  $("#centralOrigin").textContent = location.origin;
  $("#settingsOrigin").value = location.origin;
  bindLogin();
  bindDashboard();
  bindRouter();

  const rememberedName = localStorage.getItem(STORE.username);
  if (rememberedName) $("#username").value = rememberedName;
  const rememberedTenant = localStorage.getItem(STORE.tenant);
  if (rememberedTenant) state.tenantId = rememberedTenant;
  if ($("#topologyTenant")) $("#topologyTenant").value = state.tenantId;

  const persistedKey = localStorage.getItem(STORE.key);
  const sessionKey = sessionStorage.getItem(STORE.sessionKey);
  const active = sessionStorage.getItem(STORE.active) === "1";
  state.apiKey = sessionKey ?? persistedKey ?? "";
  // One-time migration only: an older Dashboard persisted the operator key.
  // Keep it in memory for this exchange attempt and purge browser storage now.
  localStorage.removeItem(STORE.key);
  sessionStorage.removeItem(STORE.sessionKey);
  state.username = rememberedName || "SOC Analyst";
  $("#rememberKey").checked = persistedKey !== null || Boolean(rememberedName) || active;
  // Always probe the cheap session endpoint: HttpOnly OIDC/local cookies are not
  // visible to JavaScript and must also work in a new tab with empty storage.
  void signIn({ quiet: true, apiKey: state.apiKey, username: state.username });
});

function bindLogin() {
  $("#loginForm").addEventListener("submit", async event => {
    event.preventDefault();
    const username = $("#username").value.trim() || "SOC Analyst";
    const apiKey = $("#apiKey").value.trim();
    await signIn({ quiet: false, apiKey, username });
  });

  $("#revealKey").addEventListener("click", () => {
    const input = $("#apiKey");
    input.type = input.type === "password" ? "text" : "password";
  });

  $("#ntAccountButton").addEventListener("click", beginOidcLogin);
  $("#localLoginButton")?.addEventListener("click", () => {
    const username = $("#username").value.trim();
    const password = $("#localPassword").value;
    const totp = $("#localTotp").value.replace(/\s+/g, "");
    if (!username || !password || !totp) {
      $("#loginMessage").textContent = "กรอก username, local password และ TOTP ให้ครบ";
      return;
    }
    void signIn({ quiet: false, username, localCredentials: { username, password, totp }, remember: $("#rememberKey").checked });
  });
}

function beginOidcLogin() {
  const modes = pick(state.session, "authModes") || {};
  if (pick(modes, "oidc") !== true) {
    toast("Central ยังไม่ได้เปิด NT Account OIDC");
    return;
  }
  const returnUrl = `${location.pathname}${location.search}${location.hash || "#overview"}`;
  location.assign(`/api/v2/session/login?returnUrl=${encodeURIComponent(returnUrl)}`);
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
  $("#refreshButton").addEventListener("click", () => { void refreshData(true).catch(() => {}); });
  $("#logoutButton").addEventListener("click", logout);
  $("#mobileMenu").addEventListener("click", () => $("#sidebar").classList.toggle("open"));
  $("#incidentSearch").addEventListener("input", renderIncidentTable);
  $("#severityFilter").addEventListener("change", renderIncidentTable);
  $("#assetSearch").addEventListener("input", renderAssetTable);
  $("#threatCampaignList")?.addEventListener("click", selectThreatCampaign);
  $("#threatFilter")?.addEventListener("change", () => { void ensurePageData("threats", { force: true, notify: false }).catch(() => {}); });
  $("#threatSort")?.addEventListener("change", renderThreatCampaigns);
  $("#threatTimeWindow")?.addEventListener("change", navigateThreatWindow);
  $("#threatTimeScrubber")?.addEventListener("input", () => {
    const campaign = state.threats.find(item => String(pick(item, "campaignId")) === state.selectedThreatId)
      || (state.selectedThreatId ? { campaignId: state.selectedThreatId } : null);
    renderThreatTimeline(campaign);
  });
  $("#threatRefresh")?.addEventListener("click", () => { void ensurePageData("threats", { force: true, notify: true }).catch(() => {}); });
  $("#threatFitPath")?.addEventListener("click", () => $("#threatGraphViewport")?.scrollTo({ left: 0, behavior: "smooth" }));
  $("#threatAskAi")?.addEventListener("click", askThreatAi);
  $("#threatOpenForensics")?.addEventListener("click", openThreatForensics);
  $("#threatContacts")?.addEventListener("click", event => {
    const edge = event.target.closest("[data-threat-edge]");
    if (edge) openThreatEdgeDrawer(edge.dataset.threatEdge);
  });
  $("#threatTimelineMore")?.addEventListener("click", () => { void loadMoreThreatEvidence("timeline"); });
  $("#threatContactsMore")?.addEventListener("click", () => { void loadMoreThreatEvidence("contacts"); });
  $("#threatEdgeClose")?.addEventListener("click", closeThreatEdgeDrawer);
  $("#threatEdgeForensics")?.addEventListener("click", openSelectedEdgeForensics);
  document.addEventListener("keydown", event => {
    if (event.key === "Escape" && !$("#threatEdgeDrawer")?.hidden) closeThreatEdgeDrawer();
  });
  $("#threatGraphNodes")?.addEventListener("click", event => {
    const node = event.target.closest("[data-threat-focus]");
    if (node) navigateThreatFocus(node.dataset.threatFocus);
  });
  const edgeLineHost = $("#threatGraphLineGroup");
  edgeLineHost?.addEventListener("click", event => {
    const edge = event.target.closest("[data-threat-edge]");
    if (edge) openThreatEdgeDrawer(edge.dataset.threatEdge);
  });
  edgeLineHost?.addEventListener("keydown", event => {
    if (event.key !== "Enter" && event.key !== " ") return;
    const edge = event.target.closest("[data-threat-edge]");
    if (!edge) return;
    event.preventDefault();
    openThreatEdgeDrawer(edge.dataset.threatEdge);
  });
  $("#incidentTable")?.addEventListener("click", event => {
    const button = event.target.closest("[data-open-incident]");
    if (button) navigateHash(`#incidents/${encodeURIComponent(button.dataset.openIncident)}`);
  });
  $("#incidentViewChain")?.addEventListener("click", openSelectedIncidentChain);
  $("#incidentAskAi")?.addEventListener("click", () => {
    if (state.selectedIncidentRouteId) navigateHash(`#analyst/incident/${encodeURIComponent(state.selectedIncidentRouteId)}`);
  });
  $("#forensicsRefresh")?.addEventListener("click", () => { void ensurePageData("forensics", { force: true, notify: true }).catch(() => {}); });
  $("#forensicsApply")?.addEventListener("click", applyForensicsFilters);
  $("#forensicsSessions")?.addEventListener("click", selectPacketSession);
  $("#forensicsAccess")?.addEventListener("click", openPacketPayload);
  $("#forensicsExport")?.addEventListener("click", createPacketExport);
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
    const apiKey = $("#settingsApiKey").value.trim();
    await signIn({ quiet: false, apiKey, username: state.username, remember: $("#settingsRemember").checked });
  });
  $("#topologyTenant")?.addEventListener("change", () => switchTenant($("#topologyTenant").value));
  $("#globalTenantSelect")?.addEventListener("change", () => void switchTenant($("#globalTenantSelect").value));
  $("#defenseThreatList")?.addEventListener("click", event => {
    const button = event.target.closest("[data-threat-route]");
    if (button) navigateHash(button.dataset.threatRoute);
  });
  $("#defenseThreatViewAll")?.addEventListener("click", () => showPage("incidents"));
  $$('[data-overview-mode]').forEach(button => button.addEventListener("click", () => setOverviewMode(button.dataset.overviewMode, { persist: true })));
}

async function switchTenant(tenantId) {
  tenantId = String(tenantId || "default").trim().toLowerCase() || "default";
  if (tenantId === state.tenantId) return true;
  if (window.NTShieldReportStudio?.confirmDiscard?.("Discard unsaved report template changes and switch customer?") === false) {
    if ($("#topologyTenant")) $("#topologyTenant").value = state.tenantId;
    if ($("#globalTenantSelect")) $("#globalTenantSelect").value = state.tenantId;
    return false;
  }
  const previousRoute = parseHashRoute();
  state.tenantId = tenantId;
  localStorage.setItem(STORE.tenant, tenantId);
  if ($("#topologyTenant")) $("#topologyTenant").value = tenantId;
  if ($("#globalTenantSelect")) $("#globalTenantSelect").value = tenantId;
  abortDataLoads();
  clearTenantScopedData();
  resetTenantScopedRoute(previousRoute);
  window.NTShieldTopology?.resetTenant?.();
  window.NTShieldTenantReports?.resetTenant?.();
  setOverviewMode(readRememberedOverviewMode(), { persist: false });

  let applied = false;
  try {
    applied = await refreshData(false, { page: state.activePage, force: true });
  } catch (error) {
    if (state.tenantId === tenantId) toast(`เปลี่ยน Customer แล้ว แต่โหลดข้อมูลไม่สำเร็จ: ${friendlyError(error)}`);
    return false;
  }
  if (!applied || state.tenantId !== tenantId) return false;
  void window.NTShieldTopology?.load({ resetSelection: true });
  toast(`เปลี่ยน Customer เป็น ${tenantId} แล้ว`);
  return true;
}

function resetTenantScopedRoute(previousRoute) {
  const page = state.activePage;
  let route = { page, entityType: "", entityId: "" };
  if (page === "threats") {
    state.threatRouteWindow = normalizedThreatRouteQuery(previousRoute?.query);
    route.query = { ...state.threatRouteWindow, focus: "" };
  } else if (page === "forensics") {
    state.forensics.query = normalizedForensicsRouteQuery({
      fromUtc: previousRoute?.query?.fromUtc,
      toUtc: previousRoute?.query?.toUtc,
      campaignId: "",
      edgeId: ""
    });
    syncForensicsFilterInputs(state.forensics.query);
    route.query = { ...state.forensics.query };
  }
  const hash = serializeRoute(route);
  history.replaceState(null, "", hash);
  currentRouteKey = hash;
}

function clearTenantScopedData() {
  state.dashboardSummary = null;
  state.health = {};
  state.agents = [];
  state.incidents = [];
  state.incidentTotal = null;
  state.incidentCountCapped = false;
  state.threats = [];
  state.signatures = [];
  state.llmStatus = {};
  state.llmTokens = [];
  state.onlineAgents = 0;
  state.insights = [];
  state.selectedThreatId = "";
  closeThreatEdgeDrawer();
  state.selectedIncidentRouteId = "";
  state.threatRouteWindow = null;
  state.threatDetail = { campaignId: "", graph: null, timeline: null, contacts: null, errors: {} };
  state.threatAi = { campaignId: "", status: "idle", result: null, error: null };
  state.forensics = {
    query: { campaignId: "", edgeId: "", fromUtc: "", toUtc: "" },
    sessions: [],
    nextCursor: null,
    captureHealth: null,
    selectedSessionId: ""
  };
  state.loading = {};
  state.errors = {};
  state.moduleErrors = {};
  state.loaded = {};
  state.analyst.selectedIncidentId = "";
  state.analyst.report = null;
  state.analyst.source = "deterministic";
  state.analyst.lastQuestion = "";
  renderAll();
}

async function signIn({ quiet = false, apiKey = "", username = "SOC Analyst", remember = null, localCredentials = null } = {}) {
  const button = $("#loginButton");
  const localButton = $("#localLoginButton");
  const message = $("#loginMessage");
  const generation = ++sessionGeneration;
  sessionController?.abort();
  tenantChoicesController?.abort();
  tenantChoicesController = null;
  abortDataLoads();
  const controller = new AbortController();
  sessionController = controller;
  const candidateKey = String(apiKey || "").trim();
  const candidateName = String(username || "SOC Analyst").trim() || "SOC Analyst";
  button.disabled = true;
  if (localButton) localButton.disabled = true;
  button.setAttribute("aria-busy", "true");
  message.className = "form-message";
  message.textContent = quiet ? "กำลังยืนยัน session เดิมกับ Central…" : "กำลังตรวจสอบกับ Central…";

  try {
    const session = await authenticateSession(candidateKey, controller.signal, localCredentials);
    if (generation !== sessionGeneration || controller.signal.aborted) return false;
    state.session = session || {};
    syncAuthModeUi();
    const authenticated = pick(session, "authenticated");
    const requiresAuth = pick(session, "requireAuth") !== false;
    if (authenticated !== true && requiresAuth) {
      const denied = new Error("session_not_authenticated");
      denied.status = 401;
      throw denied;
    }
    const capabilities = asArray(pick(session, "capabilities"));
    const dashboardAuthorized = capabilities.some(value => String(value).toLowerCase() === "dashboard:view");
    if (authenticated === true && !pick(session, "legacy") && !dashboardAuthorized) {
      const denied = new Error("session_not_authorized");
      denied.status = 403;
      throw denied;
    }

    state.apiKey = pick(session, "legacy") ? candidateKey : "";
    const actor = pick(session, "actor") || {};
    state.username = String(pick(actor, "displayName") || candidateName);
    const tenantIds = asArray(pick(session, "tenantIds")).map(value => String(value).toLowerCase());
    const concreteTenantIds = tenantIds.filter(value => value && value !== "*");
    if (concreteTenantIds.length && !tenantIds.includes("*") && !concreteTenantIds.includes(state.tenantId)) state.tenantId = concreteTenantIds[0];
    clearTenantScopedData();
    localStorage.setItem(STORE.tenant, state.tenantId);
    if ($("#topologyTenant")) $("#topologyTenant").value = state.tenantId;
    if ($("#globalTenantSelect")) $("#globalTenantSelect").value = state.tenantId;
    renderTenantChoices(tenantIds.map(tenantId => ({ tenantId, name: tenantId })));
    const shouldRemember = remember === null ? $("#rememberKey").checked : Boolean(remember);
    persistCredential(shouldRemember);
    $("#operatorName").textContent = state.username;
    $("#loginView").hidden = true;
    $("#dashboardView").hidden = false;
    message.className = "form-message ok";
    message.textContent = "ยืนยันตัวตนแล้ว • กำลังโหลดหน้าปัจจุบัน";
    setConnection(true, "Authenticated • loading telemetry…");
    setOverviewMode(readRememberedOverviewMode(), { persist: false });
    $("#apiKey").value = "";
    $("#settingsApiKey").value = "";
    if ($("#localPassword")) $("#localPassword").value = "";
    if ($("#localTotp")) $("#localTotp").value = "";
    applyRoute(parseHashRoute(), { focus: false });
    void loadTenantChoices(generation);
    return true;
  } catch (error) {
    if (generation !== sessionGeneration || isAbortError(error)) return false;
    sessionStorage.removeItem(STORE.active);
    $("#loginView").hidden = false;
    $("#dashboardView").hidden = true;
    message.className = "form-message";
    message.textContent = friendlyError(error);
    return false;
  } finally {
    if (generation === sessionGeneration) {
      button.disabled = false;
      if (localButton) localButton.disabled = false;
      button.removeAttribute("aria-busy");
      if (sessionController === controller) sessionController = null;
    }
  }
}

async function authenticateSession(apiKey, signal, localCredentials = null) {
  try {
    let session;
    if (localCredentials) {
      session = await requestJson("/api/v2/session/local", {
        method: "POST",
        body: {
          username: String(localCredentials.username || ""),
          password: String(localCredentials.password || ""),
          totp: String(localCredentials.totp || "")
        },
        signal,
        timeoutMs: REQUEST_TIMEOUT_MS,
        apiKeyOverride: ""
      });
    } else if (apiKey) {
      session = await requestJson("/api/v2/session/exchange", {
        method: "POST",
        body: { apiKey },
        signal,
        timeoutMs: REQUEST_TIMEOUT_MS,
        apiKeyOverride: ""
      });
      if (pick(session, "authenticated") === undefined) {
        session = await requestJson("/api/v2/session", { signal, timeoutMs: REQUEST_TIMEOUT_MS, apiKeyOverride: "" });
      }
    } else {
      session = await requestJson("/api/v2/session", { signal, timeoutMs: REQUEST_TIMEOUT_MS, apiKeyOverride: "" });
    }
    return session || {};
  } catch (error) {
    if (localCredentials) throw error;
    if (![404, 405, 501].includes(error?.status)) throw error;
    if (!apiKey) {
      const missingKey = new Error("missing_api_key");
      missingKey.status = 401;
      throw missingKey;
    }
    // A public health response proves reachability, not operator identity. On an
    // older Central, validate the in-memory key against a protected endpoint.
    await requestJson("/api/v1/tenants", { signal, timeoutMs: REQUEST_TIMEOUT_MS, apiKeyOverride: apiKey });
    return {
      authenticated: true,
      actor: { id: "legacy-operator", displayName: state.username || "SOC Analyst", authType: "legacy-key" },
      roles: ["operator"],
      capabilities: [],
      tenantIds: [state.tenantId],
      requireAuth: Boolean(apiKey),
      // The protected compatibility probe has no version contract. Do not fall
      // back to public health here: reachability must never be confused with auth.
      version: null,
      legacy: true
    };
  }
}

function syncAuthModeUi() {
  const modes = pick(state.session, "authModes") || {};
  const localEnabled = pick(modes, "local") === true;
  const oidcEnabled = pick(modes, "oidc") === true;
  const localPanel = $("#localLoginPanel");
  if (localPanel) localPanel.hidden = !localEnabled;
  const oidcButton = $("#ntAccountButton");
  if (oidcButton) {
    oidcButton.disabled = !oidcEnabled;
    oidcButton.title = oidcEnabled ? "เข้าสู่ระบบผ่าน NT Account" : "Central ยังไม่ได้เปิด OIDC";
  }
}

function renderTenantChoices(items) {
  const choices = [];
  const seen = new Set();
  asArray(items).forEach(item => {
    const tenantId = String(pick(item, "tenantId") || "").trim().toLowerCase();
    if (!tenantId || tenantId === "*" || seen.has(tenantId)) return;
    seen.add(tenantId);
    choices.push({ tenantId, name: boundedText(pick(item, "name") || tenantId, 120) });
  });
  if (!seen.has(state.tenantId)) choices.unshift({ tenantId: state.tenantId, name: state.tenantId });
  ["#globalTenantSelect", "#topologyTenant"].forEach(selector => {
    const select = $(selector);
    if (!select) return;
    select.replaceChildren(...choices.map(item => {
      const option = element("option", "", item.name);
      option.value = item.tenantId;
      return option;
    }));
    select.value = state.tenantId;
  });
}

async function loadTenantChoices(sessionOwner) {
  const controller = new AbortController();
  tenantChoicesController?.abort();
  tenantChoicesController = controller;
  try {
    const result = await requestJson("/api/v1/tenants", { signal: controller.signal, timeoutMs: REQUEST_TIMEOUT_MS });
    if (sessionOwner !== sessionGeneration || controller.signal.aborted || $("#dashboardView")?.hidden) return;
    renderTenantChoices(asArray(result));
  } catch (error) {
    if (!isAbortError(error)) console.warn("Tenant selector is using session fallback choices", error);
  } finally {
    if (tenantChoicesController === controller) tenantChoicesController = null;
  }
}

function persistCredential(remember) {
  sessionStorage.setItem(STORE.active, "1");
  if (remember) localStorage.setItem(STORE.username, state.username);
  else localStorage.removeItem(STORE.username);
  // Cookie sessions are preferred. On an old server, a legacy key remains
  // in-memory for this tab only and must be entered again after reload.
  localStorage.removeItem(STORE.key);
  sessionStorage.removeItem(STORE.sessionKey);
}

async function logout() {
  if (window.NTShieldReportStudio?.confirmDiscard?.("Discard unsaved report template changes and log out?") === false) return false;
  const generation = ++sessionGeneration;
  sessionController?.abort();
  const controller = new AbortController();
  sessionController = controller;
  const modes = pick(state.session, "authModes") || {};
  const button = $("#logoutButton");
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  try {
    if (state.session && !pick(state.session, "legacy")) {
      await requestJson("/api/v2/session/logout", {
        method: "POST",
        timeoutMs: REQUEST_TIMEOUT_MS,
        apiKeyOverride: "",
        signal: controller.signal
      });
    }
  } catch (error) {
    if (generation === sessionGeneration && !isAbortError(error)) {
      toast("Central ยังไม่ยืนยันการออกจากระบบ • คง session และ Dashboard เดิมไว้ กรุณาลองใหม่");
    }
    return false;
  } finally {
    if (generation === sessionGeneration) {
      button.disabled = false;
      button.removeAttribute("aria-busy");
    }
    if (sessionController === controller) sessionController = null;
  }

  if (generation !== sessionGeneration || controller.signal.aborted) return false;
  tenantChoicesController?.abort();
  tenantChoicesController = null;
  abortDataLoads();
  sessionStorage.removeItem(STORE.active);
  sessionStorage.removeItem(STORE.sessionKey);
  localStorage.removeItem(STORE.key);
  state.apiKey = "";
  state.session = { authenticated: false, authModes: modes };
  clearTenantScopedData();
  window.NTShieldTenantReports?.resetTenant?.();
  $("#apiKey").value = "";
  $("#localPassword").value = "";
  $("#localTotp").value = "";
  $("#dashboardView").hidden = true;
  window.NTShieldDefenseMap?.setActive(false);
  $("#loginView").hidden = false;
  $("#loginMessage").className = "form-message ok";
  $("#loginMessage").textContent = "ออกจากระบบและเพิกถอน session แล้ว";
  syncAuthModeUi();
  return true;
}

function abortDataLoads() {
  stopThreatRevisionUpdates();
  refreshGeneration++;
  threatDetailGeneration++;
  threatAiGeneration++;
  threatPaginationGeneration++;
  forensicsActionGeneration++;
  refreshController?.abort();
  threatDetailController?.abort();
  threatAiController?.abort();
  threatPaginationController?.abort();
  forensicsActionController?.abort();
  refreshController = null;
  threatDetailController = null;
  threatAiController = null;
  threatPaginationController = null;
  forensicsActionController = null;
}

async function refreshData(notify = false, { page = state.activePage, force = true } = {}) {
  return ensurePageData(page, { force, notify });
}

async function ensurePageData(page, { force = false, notify = false } = {}) {
  page = ROUTABLE_PAGES.has(page) ? page : "overview";
  void ensurePageModule(page).then(() => {
    delete state.moduleErrors[page];
    if (state.activePage === page) updatePageLoadStatus(page);
  }).catch(error => {
    if (state.activePage === page) {
      state.moduleErrors[page] = error;
      updatePageLoadStatus(page);
    }
  });
  if (!force && state.loaded[page] && !state.errors[page]) {
    renderActivePage();
    return true;
  }

  const generation = ++refreshGeneration;
  const tenantId = state.tenantId;
  refreshController?.abort();
  const controller = new AbortController();
  refreshController = controller;
  const isCurrent = () => generation === refreshGeneration && tenantId === state.tenantId && !controller.signal.aborted;
  state.loading[page] = true;
  delete state.errors[page];
  updatePageLoadStatus(page);
  setConnection(true, `Loading ${page}…`);
  const specs = pageRequestSpecs(page, tenantId, controller.signal);

  if (!specs.length) {
    if (!isCurrent()) return false;
    state.loading[page] = false;
    state.loaded[page] = true;
    updatePageLoadStatus(page);
    renderActivePage();
    if (refreshController === controller) refreshController = null;
    return true;
  }

  const tasks = specs.map(spec => Promise.resolve()
    .then(spec.load)
    .then(value => {
      if (!isCurrent()) return;
      spec.apply(value);
      renderChrome();
      if (state.activePage === page) renderActivePage();
    }));
  const results = await Promise.allSettled(tasks);
  if (!isCurrent()) return false;

  state.loading[page] = false;
  const failures = results.filter(result => result.status === "rejected").map(result => result.reason).filter(error => !isAbortError(error));
  const successes = results.length - failures.length;
  state.loaded[page] = successes > 0;
  if (failures.length) state.errors[page] = failures;
  else delete state.errors[page];
  updatePageLoadStatus(page);
  renderChrome();
  renderActivePage();
  if (refreshController === controller) refreshController = null;

  if (successes) {
    const partial = failures.length ? ` • ${number(failures.length)} widget unavailable` : "";
    setConnection(true, `Telemetry current${partial}`);
    if (notify) toast(failures.length ? "อัปเดตบางส่วนแล้ว • บาง widget ยังไม่พร้อม" : "อัปเดตข้อมูลจาก Central แล้ว");
    return true;
  }

  const error = failures[0] || new Error("page_load_failed");
  setConnection(false, "Telemetry unavailable");
  if (notify) toast(friendlyError(error));
  throw error;
}

async function requestJson(path, options = {}) {
  const { timeoutMs = REQUEST_TIMEOUT_MS, apiKeyOverride, signal: callerSignal, ...fetchOptions } = options;
  const headers = new Headers({ Accept: "application/json" });
  const credential = apiKeyOverride !== undefined ? apiKeyOverride : state.apiKey;
  if (credential) headers.set(API_KEY_HEADER, credential);
  if (state.tenantId) headers.set("X-NTShield-Tenant", state.tenantId);
  new Headers(fetchOptions.headers || {}).forEach((value, key) => headers.set(key, value));
  const method = String(fetchOptions.method || "GET").toUpperCase();
  const csrfToken = pick(state.session, "csrfToken");
  const csrfExempt = path === "/api/v2/session/exchange" || path === "/api/v2/session/local";
  if (csrfToken && !csrfExempt && !["GET", "HEAD", "OPTIONS"].includes(method) && !headers.has("X-NTShield-CSRF")) {
    headers.set("X-NTShield-CSRF", csrfToken);
  }
  let body = fetchOptions.body;
  if (body && typeof body !== "string") {
    body = JSON.stringify(body);
    if (!headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  }
  const controller = new AbortController();
  let timedOut = false;
  const abortFromCaller = () => controller.abort(callerSignal?.reason);
  if (callerSignal?.aborted) abortFromCaller();
  else callerSignal?.addEventListener("abort", abortFromCaller, { once: true });
  const timer = timeoutMs > 0 ? setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs) : 0;
  try {
    const response = await fetch(path, {
      ...fetchOptions,
      body,
      headers,
      signal: controller.signal,
      credentials: "same-origin",
      cache: "no-store"
    });
    if (!response.ok) {
      const responseBody = await response.json().catch(() => ({}));
      const error = new Error(responseBody.reason || responseBody.detail || responseBody.error || `HTTP ${response.status}`);
      error.status = response.status;
      error.code = responseBody.error || "";
      error.detail = responseBody.detail;
      error.currentVersion = responseBody.currentVersion;
      throw error;
    }
    if (response.status === 204) return null;
    return response.json();
  } catch (error) {
    if (timedOut) {
      const timeoutError = new Error("request_timeout");
      timeoutError.name = "TimeoutError";
      timeoutError.timeoutMs = timeoutMs;
      throw timeoutError;
    }
    throw error;
  } finally {
    if (timer) clearTimeout(timer);
    callerSignal?.removeEventListener("abort", abortFromCaller);
  }
}

function renderAll() {
  renderChrome();
  renderActivePage();
}

function renderActivePage() {
  switch (state.activePage) {
    case "overview": renderOverview(); break;
    case "incidents": renderIncidentTable(); break;
    case "assets": renderAssetTable(); break;
    case "threats": renderThreatCampaigns(); break;
    case "forensics": renderForensics(); break;
    case "feed": renderFeed(); break;
    case "analyst": renderAnalyst(); break;
    case "llm": renderLlm(); break;
    default: break;
  }
}

function renderChrome() {
  const summaryCount = numeric(pick(pick(state.dashboardSummary, "counts"), "incidentsTotal"));
  const incidentCount = state.dashboardSummary ? summaryCount : state.incidentTotal ?? state.incidents.length;
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
  const sessionVersion = pick(state.session, "version");
  $("#centralVersion").textContent = `Central v${sessionVersion || pick(state.health, "version", "productVersion") || "—"}`;
  $("#lastUpdated").textContent = `Updated ${new Intl.DateTimeFormat("th-TH", { dateStyle: "medium", timeStyle: "medium" }).format(new Date())}`;
  $("#feedSignatures").textContent = number(state.signatures.length);
  $("#feedAgents").textContent = number(state.agents.length);
  $("#feedOnline").textContent = number(state.onlineAgents);
  renderFeed();
}

function pageRequestSpecs(page, tenantId, signal) {
  const tenantOptions = { headers: { "X-NTShield-Tenant": tenantId }, signal, timeoutMs: REQUEST_TIMEOUT_MS };
  const get = path => requestJson(path, tenantOptions);
  const incidentSpec = {
    load: () => get(`/api/v1/incidents?take=${INCIDENT_FETCH_LIMIT}`),
    apply: incidents => {
      const rows = asArray(incidents);
      const selectedId = state.selectedIncidentRouteId || state.analyst.selectedIncidentId;
      const selected = selectedId
        ? state.incidents.find(item => String(pick(item, "incidentId")) === selectedId)
        : null;
      state.incidents = selected && !rows.some(item => String(pick(item, "incidentId")) === selectedId)
        ? [selected, ...rows]
        : rows;
      state.incidentCountCapped = state.incidentTotal === null && state.incidents.length >= INCIDENT_FETCH_LIMIT;
      state.insights = buildInsights();
    }
  };
  const countSpec = {
    load: () => get("/api/v1/incidents/count"),
    apply: result => {
      const total = Number(pick(result, "total"));
      state.incidentTotal = Number.isFinite(total) ? total : null;
      state.incidentCountCapped = state.incidentTotal === null && state.incidents.length >= INCIDENT_FETCH_LIMIT;
    }
  };
  const agentSpec = {
    load: () => get("/api/v1/agents"),
    apply: agents => {
      state.agents = asArray(agents);
      state.onlineAgents = state.agents.filter(isAgentOnline).length;
      state.insights = buildInsights();
    }
  };

  switch (page) {
    case "overview": return [{
      load: () => loadDashboardSummary(tenantId, signal),
      apply: result => applyDashboardSummary(result)
    }];
    case "incidents": {
      const requestedIncidentId = state.selectedIncidentRouteId;
      const specs = [incidentSpec, countSpec];
      if (requestedIncidentId) specs.push({
        load: () => get(`/api/v1/incidents/${encodeURIComponent(requestedIncidentId)}`),
        apply: incident => {
          if (!incident) return;
          const incidentId = String(pick(incident, "incidentId") || requestedIncidentId);
          state.incidents = [incident, ...state.incidents.filter(item => String(pick(item, "incidentId")) !== incidentId)];
          state.selectedIncidentRouteId = incidentId;
        }
      });
      return specs;
    }
    case "assets": return [agentSpec];
    case "threats": {
      const requestedCampaignId = state.selectedThreatId;
      const specs = [{
        load: () => loadThreatCampaignList(tenantId, signal),
        apply: result => {
          const items = asArray(pick(result, "items"));
          const direct = state.threats.find(item => String(pick(item, "campaignId")) === state.selectedThreatId);
          state.threats = direct && !items.some(item => String(pick(item, "campaignId")) === state.selectedThreatId)
            ? [direct, ...items]
            : items;
          if (!state.selectedThreatId && state.threats.length) state.selectedThreatId = String(pick(state.threats[0], "campaignId") || "");
          const detailAlreadyLoading = state.loading.threatDetail && state.threatDetail.campaignId === state.selectedThreatId;
          if (state.selectedThreatId && !detailAlreadyLoading) void loadThreatDetails(state.selectedThreatId);
        }
      }];
      if (requestedCampaignId) specs.push({
        load: () => get(`/api/v2/threats/${encodeURIComponent(requestedCampaignId)}`),
        apply: campaign => {
          if (!campaign) return;
          const campaignId = String(pick(campaign, "campaignId") || requestedCampaignId);
          state.threats = [campaign, ...state.threats.filter(item => String(pick(item, "campaignId")) !== campaignId)];
          state.selectedThreatId = campaignId;
        }
      });
      return specs;
    }
    case "forensics": {
      const packetQuery = { ...state.forensics.query };
      return [{
        load: () => get("/api/v2/capture-health"),
        apply: health => { state.forensics.captureHealth = health || {}; }
      }, {
        load: () => get(packetSessionListPath(packetQuery)),
        apply: result => {
          state.forensics.sessions = asArray(pick(result, "items")).slice(0, PACKET_SESSION_RENDER_LIMIT);
          state.forensics.nextCursor = pick(result, "nextCursor") || null;
          if (!state.forensics.sessions.some(item => packetSessionId(item) === state.forensics.selectedSessionId)) {
            state.forensics.selectedSessionId = state.forensics.sessions.length ? packetSessionId(state.forensics.sessions[0]) : "";
          }
        }
      }];
    }
    case "feed": return [incidentSpec, agentSpec, {
      load: () => get("/api/v1/signatures"),
      apply: signatures => { state.signatures = asArray(signatures); }
    }];
    case "analyst": {
      const requestedIncidentId = state.analyst.selectedIncidentId;
      const specs = [incidentSpec, countSpec];
      if (requestedIncidentId) specs.push({
        load: () => get(`/api/v1/incidents/${encodeURIComponent(requestedIncidentId)}`),
        apply: incident => {
          if (!incident) return;
          const incidentId = String(pick(incident, "incidentId") || requestedIncidentId);
          state.incidents = [incident, ...state.incidents.filter(item => String(pick(item, "incidentId")) !== incidentId)];
          state.analyst.selectedIncidentId = incidentId;
          state.analyst.report = buildAnalystReport(incident);
          state.analyst.source = "deterministic";
        }
      });
      return specs;
    }
    case "llm": return [{
      load: () => get("/api/v1/llm/status"),
      apply: status => { state.llmStatus = status || {}; }
    }, {
      load: () => get("/api/v1/llm/tokens"),
      apply: tokens => { state.llmTokens = asArray(tokens); }
    }];
    default: return [];
  }
}

async function loadDashboardSummary(tenantId, signal) {
  try {
    const summary = await requestJson("/api/v2/dashboard/summary", {
      headers: { "X-NTShield-Tenant": tenantId },
      signal,
      timeoutMs: REQUEST_TIMEOUT_MS
    });
    return { summary, legacy: null };
  } catch (error) {
    if (![404, 405, 501].includes(error?.status)) throw error;
    return loadLegacyDashboardSummary(tenantId, signal);
  }
}

async function loadLegacyDashboardSummary(tenantId, signal) {
  const options = { headers: { "X-NTShield-Tenant": tenantId }, signal, timeoutMs: REQUEST_TIMEOUT_MS };
  const results = await Promise.allSettled([
    requestJson("/api/v1/agents", options),
    requestJson(`/api/v1/incidents?take=${INCIDENT_FETCH_LIMIT}`, options),
    requestJson("/api/v1/incidents/count", options),
    requestJson("/api/v1/threats?take=100", options)
  ]);
  const value = index => results[index].status === "fulfilled" ? results[index].value : null;
  if (results.every(result => result.status === "rejected")) throw results[0].reason;
  const agents = asArray(value(0));
  const incidents = asArray(value(1));
  const incidentCount = Number(pick(value(2), "total"));
  const threats = asArray(value(3));
  const openIncidents = incidents.filter(item => !["closed", "resolved", "contained"].includes(String(pick(item, "status") || "open").toLowerCase()));
  const openThreats = threats.filter(isThreatActive);
  const severities = severityCounts(openIncidents);
  const online = agents.filter(isAgentOnline).length;
  const latestIncident = openIncidents.reduce((latest, item) => Math.max(latest, incidentDate(item).getTime()), 0);
  const latestHeartbeat = agents.reduce((latest, item) => Math.max(latest, dateValue(pick(item, "lastSeenUtc", "timestampUtc")).getTime()), 0);
  const latest = Math.max(latestIncident, latestHeartbeat);
  const queue = [
    ...openIncidents.map(item => ({
      kind: "incident",
      id: String(pick(item, "incidentId") || ""),
      incidentId: String(pick(item, "incidentId") || ""),
      title: pick(item, "title") || "Open incident",
      severity: severityName(pick(item, "severity")),
      confidence: pick(item, "confidence"),
      recurrenceCount: 0,
      firstObservedAtUtc: pick(item, "firstSeenUtc", "firstSeen"),
      lastObservedAtUtc: pick(item, "lastSeenUtc", "lastSeen"),
      affectedAssetCount: 1,
      sourceIp: incidentIp(item, "source"),
      sourceHost: pick(item, "sourceHost"),
      reason: routeText(item),
      status: pick(item, "status") || "Open"
    })),
    ...openThreats.map(item => ({
      kind: "campaign",
      id: String(pick(item, "campaignId") || ""),
      campaignId: String(pick(item, "campaignId") || ""),
      title: pick(item, "title") || "Active campaign",
      severity: severityName(pick(item, "severity")),
      confidence: pick(item, "confidence", "mlConfidence"),
      recurrenceCount: numeric(pick(item, "recurrenceCount")),
      firstObservedAtUtc: pick(item, "firstObservedAtUtc", "firstSeenUtc"),
      lastObservedAtUtc: pick(item, "lastObservedAtUtc", "lastSeenUtc"),
      affectedAssetCount: asArray(pick(item, "involvedHosts")).length,
      reason: pick(item, "summary") || "Correlated temporal chain",
      status: pick(item, "status") || "Active"
    }))
  ].sort((a, b) => dateValue(b.lastObservedAtUtc) - dateValue(a.lastObservedAtUtc)).slice(0, 10);
  return {
    legacy: { agents, incidents, incidentCount: Number.isFinite(incidentCount) ? incidentCount : null, threats },
    summary: {
      schemaVersion: 1,
      generatedAtUtc: new Date().toISOString(),
      window: { label: "Legacy compatibility" },
      posture: {
        state: severities.critical ? "critical" : severities.high ? "elevated" : latest ? "protected" : "unknown",
        reason: "Compatibility summary from bounded legacy lists; totals may be incomplete."
      },
      counts: {
        incidentsTotal: Number.isFinite(incidentCount) ? incidentCount : incidents.length,
        openIncidents: openIncidents.length,
        criticalOpen: severities.critical,
        highOpen: severities.high,
        activeCampaigns: openThreats.length,
        affectedAssets: new Set(openIncidents.flatMap(item => [pick(item, "sourceHost"), pick(item, "destinationHost")]).filter(Boolean)).size,
        agentsTotal: agents.length,
        agentsOnline: online,
        agentsOffline: Math.max(0, agents.length - online)
      },
      telemetry: {
        latestEventAtUtc: latestIncident ? new Date(latestIncident).toISOString() : null,
        latestHeartbeatAtUtc: latestHeartbeat ? new Date(latestHeartbeat).toISOString() : null,
        freshnessSeconds: latest ? Math.max(0, Math.round((Date.now() - latest) / 1000)) : null,
        state: latest ? "unknown" : "no-data"
      },
      trends: legacyTrendBuckets(incidents, threats),
      threatQueue: queue
    }
  };
}

function legacyTrendBuckets(incidents, threats) {
  const buckets = [];
  for (let offset = 6; offset >= 0; offset--) {
    const date = new Date();
    date.setUTCHours(0, 0, 0, 0);
    date.setUTCDate(date.getUTCDate() - offset);
    const end = date.getTime() + 86400000;
    buckets.push({
      bucketStartUtc: date.toISOString(),
      incidents: incidents.filter(item => {
        const time = incidentDate(item).getTime();
        return time >= date.getTime() && time < end;
      }).length,
      campaigns: threats.filter(item => {
        const time = threatObservedDate(item).getTime();
        return time >= date.getTime() && time < end;
      }).length
    });
  }
  return buckets;
}

function applyDashboardSummary(result) {
  state.dashboardSummary = pick(result, "summary") || null;
  const legacy = pick(result, "legacy");
  if (legacy) {
    state.agents = asArray(pick(legacy, "agents"));
    state.onlineAgents = state.agents.filter(isAgentOnline).length;
    state.incidents = asArray(pick(legacy, "incidents"));
    state.incidentTotal = pick(legacy, "incidentCount") ?? null;
    state.incidentCountCapped = state.incidentTotal === null && state.incidents.length >= INCIDENT_FETCH_LIMIT;
    state.threats = asArray(pick(legacy, "threats"));
  } else {
    const counts = pick(state.dashboardSummary, "counts") || {};
    const total = Number(pick(counts, "incidentsTotal"));
    state.incidentTotal = Number.isFinite(total) ? total : state.incidentTotal;
    state.onlineAgents = numeric(pick(counts, "agentsOnline"));
  }
}

async function loadThreatCampaignList(tenantId, signal) {
  const { from, to } = threatWindowRange();
  const params = new URLSearchParams({ from, to, limit: String(THREAT_LIST_LIMIT) });
  const severity = String($("#threatFilter")?.value || "").toLowerCase();
  if (severity) params.set("severity", severity);
  try {
    return await requestJson(`/api/v2/threats?${params}`, {
      headers: { "X-NTShield-Tenant": tenantId }, signal, timeoutMs: REQUEST_TIMEOUT_MS
    });
  } catch (error) {
    if (![404, 405, 501].includes(error?.status)) throw error;
    const items = asArray(await requestJson(`/api/v1/threats?take=${THREAT_LIST_LIMIT}`, {
      headers: { "X-NTShield-Tenant": tenantId }, signal, timeoutMs: REQUEST_TIMEOUT_MS
    })).filter(item => threatObservedDate(item).getTime() >= dateValue(from).getTime());
    return { schemaVersion: 1, items, nextCursor: null, watermarkUtc: new Date().toISOString() };
  }
}

function threatWindowRange({ ignoreOverride = false, preset = "" } = {}) {
  if (!ignoreOverride && state.threatRouteWindow?.from && state.threatRouteWindow?.to) {
    return { from: state.threatRouteWindow.from, to: state.threatRouteWindow.to };
  }
  preset = preset || String($("#threatTimeWindow")?.value || "24h");
  const milliseconds = { "15m": 15 * 60000, "1h": 3600000, "24h": 86400000, "7d": 7 * 86400000, "30d": 30 * 86400000 }[preset] || 86400000;
  const to = new Date();
  return { from: new Date(to.getTime() - milliseconds).toISOString(), to: to.toISOString() };
}

function updatePageLoadStatus(page) {
  const host = $("#pageLoadStatus");
  if (!host || state.activePage !== page) return;
  const errors = [...asArray(state.errors[page]), ...(state.moduleErrors[page] ? [state.moduleErrors[page]] : [])];
  if (state.loading[page]) {
    host.hidden = false;
    host.className = "page-load-status loading";
    host.textContent = `กำลังโหลด ${page} • แต่ละส่วนจะแสดงทันทีเมื่อพร้อม`;
  } else if (errors.length) {
    host.hidden = false;
    host.className = "page-load-status warning";
    host.textContent = state.loaded[page]
      ? `โหลดได้บางส่วน • ${number(errors.length)} request ไม่พร้อม กด Refresh เพื่อลองใหม่`
      : `โหลด ${page} ไม่สำเร็จ • Central ตอบไม่ทันหรือ endpoint ยังไม่พร้อม กด Refresh เพื่อลองใหม่`;
  } else {
    host.hidden = true;
    host.textContent = "";
  }
}

async function ensurePageModule(page) {
  const pageIsActive = () => !$("#dashboardView")?.hidden && state.activePage === page;
  if (page === "overview") {
    if (!window.NTShieldDefenseMap) {
      await loadScriptOnce("d3", "vendor/d3.v7.min.js?v=7.9.0");
      if (!pageIsActive()) return;
      await loadScriptOnce("topojson", "vendor/topojson-client.min.js?v=3.1.0");
      if (!pageIsActive()) return;
      await loadScriptOnce("defense-map", "defense-map.js?v=20260808-phase1-2");
    }
    if (!pageIsActive()) return;
    if (!initializedModules.has("defense-map")) {
      window.NTShieldDefenseMap?.init({ requestJson, getTenant: () => state.tenantId });
      initializedModules.add("defense-map");
    }
    window.NTShieldDefenseMap?.setActive(state.activePage === "overview");
    if (state.activePage === "overview") renderOverview();
    return;
  }
  if (page === "topology") {
    await loadScriptOnce("topology", "topology.js?v=20260808-phase1-1");
    if (!pageIsActive()) return;
    if (!initializedModules.has("topology")) {
      window.NTShieldTopology?.init({ requestJson, toast, getTenant: () => state.tenantId });
      initializedModules.add("topology");
    }
    if (state.activePage === "topology") await window.NTShieldTopology?.load?.();
    return;
  }
  if (page === "customers" || page === "reports") {
    await loadScriptOnce("report-studio", "report-studio.js?v=20260808-studio-1");
    if (!pageIsActive()) return;
    await loadScriptOnce("tenant-report", "tenant-report.js?v=20260808-studio-1");
    if (!pageIsActive()) return;
    if (!initializedModules.has("tenant-reports")) {
      window.NTShieldTenantReports?.init({ requestJson, toast, getTenant: () => state.tenantId, setTenant: switchTenant });
      initializedModules.add("tenant-reports");
    }
    if (state.activePage === page) await window.NTShieldTenantReports?.onPage?.(page);
  }
}

function loadScriptOnce(key, source) {
  if (loadedScripts.has(key)) return loadedScripts.get(key);
  const promise = new Promise((resolve, reject) => {
    const existing = document.querySelector(`script[data-lazy-module="${key}"]`);
    if (existing?.dataset.loaded === "true") { resolve(); return; }
    const script = existing || document.createElement("script");
    const timer = setTimeout(() => {
      loadedScripts.delete(key);
      script.remove();
      reject(new Error(`module_load_timeout:${key}`));
    }, REQUEST_TIMEOUT_MS);
    const onLoad = () => { clearTimeout(timer); script.dataset.loaded = "true"; resolve(); };
    const onError = () => { clearTimeout(timer); loadedScripts.delete(key); script.remove(); reject(new Error(`module_load_failed:${key}`)); };
    script.addEventListener("load", onLoad, { once: true });
    script.addEventListener("error", onError, { once: true });
    if (!existing) {
      script.src = source;
      script.async = true;
      script.dataset.lazyModule = key;
      document.head.append(script);
    }
  });
  loadedScripts.set(key, promise);
  return promise;
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
  const summary = state.dashboardSummary;
  const counts = pick(summary, "counts") || {};
  const telemetry = pick(summary, "telemetry") || {};
  const postureData = pick(summary, "posture") || {};
  const postureState = normalizePostureState(pick(postureData, "state"));
  const postureReason = String(pick(postureData, "reason") || (summary ? "Central did not provide a posture explanation." : "กำลังตรวจ posture และความสดของ telemetry จาก Central…"));
  const openIncidents = numeric(pick(counts, "openIncidents"));
  const activeCampaigns = numeric(pick(counts, "activeCampaigns"));
  const criticalOpen = numeric(pick(counts, "criticalOpen"));
  const highOpen = numeric(pick(counts, "highOpen"));
  const affectedAssets = numeric(pick(counts, "affectedAssets"));
  const agentsTotal = numeric(pick(counts, "agentsTotal"));
  const agentsOnline = numeric(pick(counts, "agentsOnline"));
  const agentsOffline = numeric(pick(counts, "agentsOffline"));
  const visibilityGaps = asArray(pick(telemetry, "visibilityGaps"))
    .map(value => boundedText(value, 120))
    .filter(Boolean)
    .slice(0, 8);
  const queue = asArray(pick(summary, "threatQueue")).slice(0, 12);
  const trends = asArray(pick(summary, "trends"));

  if (summary) {
    animateMetric("#defenseThreatEvents", openIncidents, value => number(value));
    animateMetric("#defenseCorrelated", activeCampaigns, value => number(value));
    $("#defenseScore").textContent = `${number(criticalOpen)} / ${number(highOpen)}`;
    animateMetric("#defenseAssets", affectedAssets, value => number(value));
    $("#defenseMonitoring").textContent = `${number(agentsOnline)}/${number(agentsTotal)}`;
  } else {
    [["#defenseThreatEvents", "—"], ["#defenseCorrelated", "—"], ["#defenseScore", "—"], ["#defenseAssets", "—"], ["#defenseMonitoring", "—/—"]].forEach(([selector, text]) => {
      const node = $(selector);
      if (node?._metricFrame) cancelAnimationFrame(node._metricFrame);
      if (node) { node._metricFrame = 0; node.textContent = text; delete node.dataset.metricValue; }
    });
  }
  $("#overviewPostureReason").textContent = postureReason;
  const gapStatus = $("#overviewVisibilityGaps");
  if (gapStatus) {
    gapStatus.hidden = !visibilityGaps.length;
    gapStatus.textContent = visibilityGaps.length
      ? `VISIBILITY GAP • ${visibilityGaps.map(formatVisibilityGap).join(" • ")}`
      : "";
  }
  $("#defenseNeutralized").textContent = postureLabel(postureState);
  $("#defenseLastUpdated").textContent = summary
    ? `Generated ${relativeTime(pick(summary, "generatedAtUtc"))}`
    : "Waiting for dashboard summary";
  $("#globalDefenseStage").dataset.defenseState = postureState;
  $("#defenseStatusLabel").textContent = `• ${postureLabel(postureState).toUpperCase()}`;

  renderDefenseThreats(queue);
  renderDefenseMiniMap(queue, []);
  renderDefenseImpact(trends, postureState);
  renderExecutiveOverview(summary);

  const telemetryState = String(pick(telemetry, "state") || "unknown").toLowerCase();
  $("#defenseBehavioralStatus").textContent = ["live", "current", "fresh"].includes(telemetryState) ? "Current" : visibilityGaps.length ? "Visibility gap" : summary ? "Check" : "Waiting";
  $("#defenseIntelStatus").textContent = activeCampaigns ? "Correlating" : summary ? "Watching" : "Waiting";
  const networkGap = visibilityGaps.some(value => value.startsWith("network_connections_"));
  const eventGap = visibilityGaps.some(value => value.startsWith("security_events_"));
  const heartbeatGap = visibilityGaps.some(value => value.startsWith("agent_heartbeats_"));
  setDefenseSubsystem("#statusNetwork", criticalOpen ? "At Risk" : networkGap ? "Visibility gap" : highOpen ? "Elevated" : summary ? "Observed" : "Waiting", criticalOpen ? "alert" : networkGap || highOpen ? "warning" : "normal");
  setDefenseSubsystem("#statusEndpoints", agentsOffline ? `${number(agentsOffline)} Offline` : heartbeatGap ? "Visibility gap" : summary ? "Covered" : "Waiting", agentsOffline || heartbeatGap ? "warning" : "normal");
  setDefenseSubsystem("#statusApplications", highOpen ? "Investigate" : eventGap ? "Visibility gap" : summary ? "Observed" : "Waiting", highOpen || eventGap ? "warning" : "normal");
  const cloudUncertain = Boolean(summary) && ["stale", "degraded", "unknown"].includes(telemetryState);
  setDefenseSubsystem("#statusCloud", !summary ? "Waiting" : cloudUncertain ? telemetryState === "stale" ? "Stale" : "Degraded" : "Monitored", cloudUncertain ? "warning" : "normal");
  setDefenseSubsystem("#statusData", criticalOpen ? "Prioritize" : summary ? "Observed" : "Waiting", criticalOpen ? "alert" : "normal");

  const confirmedIncidentQueue = queue.filter(item => String(pick(item, "kind") || "").toLowerCase() === "incident");
  window.NTShieldDefenseMap?.update({ incidents: confirmedIncidentQueue, onlineAgents: agentsOnline });
}

function normalizePostureState(value) {
  const normalized = String(value || "unknown").toLowerCase();
  if (["protected", "healthy", "normal", "secure", "stable"].includes(normalized)) return "protected";
  if (["elevated", "warning", "degraded"].includes(normalized)) return "elevated";
  if (["critical", "action-required", "at-risk"].includes(normalized)) return "critical";
  return "unknown";
}

function postureLabel(value) {
  return { protected: "Protected", elevated: "Elevated", critical: "Action required", unknown: "Unknown" }[normalizePostureState(value)];
}

function overviewModeKey() {
  const actor = pick(pick(state.session, "actor"), "id") || "anonymous";
  return `${STORE.overviewModePrefix}.${encodeURIComponent(String(actor))}.${encodeURIComponent(state.tenantId)}`;
}

function readRememberedOverviewMode() {
  try {
    return localStorage.getItem(overviewModeKey()) === "executive" ? "executive" : "soc";
  } catch {
    return "soc";
  }
}

function setOverviewMode(mode, { persist = false } = {}) {
  mode = mode === "executive" ? "executive" : "soc";
  const stage = $("#globalDefenseStage");
  if (stage) stage.dataset.overviewMode = mode;
  $$('[data-overview-mode]').forEach(button => {
    const active = button.dataset.overviewMode === mode;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
  if (persist) {
    try { localStorage.setItem(overviewModeKey(), mode); } catch { /* Storage may be disabled. */ }
  }
}

function renderExecutiveOverview(summary) {
  const counts = pick(summary, "counts") || {};
  const telemetry = pick(summary, "telemetry") || {};
  const posture = pick(summary, "posture") || {};
  const executive = pick(summary, "executive") || {};
  const stateName = normalizePostureState(pick(posture, "state"));
  $("#executivePostureState").textContent = postureLabel(stateName);
  $("#executivePostureState").dataset.tone = stateName;
  $("#executivePostureReason").textContent = pick(posture, "reason") || "Central has not supplied a posture reason.";
  $("#executiveCriticalOpen").textContent = summary ? number(pick(counts, "criticalOpen")) : "—";
  $("#executiveHighOpen").textContent = summary ? number(pick(counts, "highOpen")) : "—";
  $("#executiveCampaigns").textContent = summary ? number(pick(counts, "activeCampaigns")) : "—";
  $("#executiveAffectedAssets").textContent = summary ? number(pick(counts, "affectedAssets")) : "—";
  const total = numeric(pick(counts, "agentsTotal"));
  const online = numeric(pick(counts, "agentsOnline"));
  const suppliedCoverage = nullableNumber(pick(executive, "coveragePercent"));
  $("#executiveCoverage").textContent = suppliedCoverage !== null ? `${Math.round(suppliedCoverage)}%` : total ? `${Math.round(online / total * 100)}%` : "—";
  $("#executiveCoverageMeta").textContent = suppliedCoverage !== null
    ? "Measured managed-asset coverage"
    : total ? `${number(online)} of ${number(total)} online` : "No enrolled agent data";
  const mttd = nullableNumber(pick(executive, "meanTimeToDetectSeconds", "mttdSeconds"));
  const mttr = nullableNumber(pick(executive, "meanTimeToRespondSeconds", "mttrSeconds"));
  const rawSlaTracked = pick(executive, "slaTracked");
  const rawSlaBreached = pick(executive, "slaBreached");
  const slaTracked = typeof rawSlaTracked === "boolean" ? (rawSlaTracked ? 1 : null) : nullableNumber(rawSlaTracked);
  const slaBreached = typeof rawSlaBreached === "boolean" ? (rawSlaBreached ? 1 : 0) : nullableNumber(rawSlaBreached);
  $("#executiveMttd").textContent = mttd === null ? "—" : operationalDuration(mttd);
  $("#executiveMttdMeta").textContent = mttd === null ? "Not measured" : "Detection lifecycle";
  $("#executiveMttr").textContent = mttr === null ? "—" : operationalDuration(mttr);
  $("#executiveMttrMeta").textContent = mttr === null ? "Not measured" : "Response lifecycle";
  $("#executiveSla").textContent = slaTracked === null ? "—" : `${number(slaBreached ?? 0)}/${number(slaTracked)}`;
  $("#executiveSlaMeta").textContent = slaTracked === null ? "Not tracked" : "breached / tracked";
  const metricGap = $("#executiveMetricGap");
  const gaps = [
    ...asArray(pick(executive, "measurementGaps")),
    ...asArray(pick(telemetry, "visibilityGaps"))
  ].slice(0, 8).map(value => boundedText(value, 220)).filter(Boolean);
  metricGap.hidden = mttd !== null && mttr !== null && slaTracked !== null && slaTracked > 0 && slaBreached !== null && !gaps.length;
  if (!metricGap.hidden) metricGap.textContent = gaps.length
    ? `Telemetry gaps: ${gaps.join(" • ")}`
    : "Telemetry gap: detection, acknowledgement, response and SLA lifecycle timestamps are incomplete. NT Shield will not infer MTTD/MTTR from First Seen → Last Seen.";
  $("#executiveFreshness").textContent = summary
    ? `${String(pick(telemetry, "state") || "unknown")} • ${freshnessText(pick(telemetry, "freshnessSeconds"))}`
    : "Waiting for telemetry";
  renderExecutiveTrend(asArray(pick(summary, "trends")));
}

function formatVisibilityGap(value) {
  return String(value || "unknown")
    .replace(/_/g, " ")
    .replace(/\b\w/g, character => character.toUpperCase());
}

function nullableNumber(value) {
  if (value === null || value === undefined || value === "") return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
}

function operationalDuration(seconds) {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(seconds < 7200 ? 1 : 0)}h`;
  return `${(seconds / 86400).toFixed(1)}d`;
}

function freshnessText(value) {
  const seconds = Number(value);
  if (!Number.isFinite(seconds)) return "freshness unknown";
  if (seconds < 60) return `${number(seconds)} sec old`;
  if (seconds < 3600) return `${number(Math.round(seconds / 60))} min old`;
  return `${number(Math.round(seconds / 3600))} hr old`;
}

function renderExecutiveTrend(trends) {
  const incidentLine = $("#executiveIncidentTrend");
  const campaignLine = $("#executiveCampaignTrend");
  const grid = $("#executiveTrendGrid");
  if (!incidentLine || !campaignLine || !grid) return;
  grid.replaceChildren();
  [30, 80, 130].forEach(y => {
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", "0"); line.setAttribute("x2", "700"); line.setAttribute("y1", String(y)); line.setAttribute("y2", String(y));
    grid.append(line);
  });
  const rows = trends.slice(-30);
  if (!rows.length) {
    incidentLine.setAttribute("points", "");
    campaignLine.setAttribute("points", "");
    return;
  }
  const max = Math.max(1, ...rows.flatMap(item => [numeric(pick(item, "incidents")), numeric(pick(item, "campaigns"))]));
  const points = key => rows.map((item, index) => {
    const x = rows.length === 1 ? 350 : 12 + index * (676 / (rows.length - 1));
    const y = 158 - numeric(pick(item, key)) / max * 136;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");
  incidentLine.setAttribute("points", points("incidents"));
  campaignLine.setAttribute("points", points("campaigns"));
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

function renderDefenseThreats(queue) {
  const host = $("#defenseThreatList");
  if (!host) return;
  host.replaceChildren();
  // Central already ranks this queue by severity, recurrence and recency. Keep
  // that order so a new low-risk item cannot jump ahead of a critical campaign.
  const rows = [...queue].slice(0, 8);
  if (!rows.length) {
    const empty = element("p", "defense-empty", state.loading.overview ? "กำลังโหลด Active Threat Queue…" : state.errors.overview ? "Threat Queue ยังไม่พร้อม • กด Refresh" : "ไม่มีรายการเปิดใน Threat Queue");
    host.append(empty);
    return;
  }
  rows.forEach(item => {
    const severity = severityName(pick(item, "severity"));
    const row = element("button", `defense-threat-row ${severity.toLowerCase()}`);
    row.type = "button";
    row.dataset.threatRoute = threatQueueRoute(item);
    row.setAttribute("aria-label", `${severity}: ${pick(item, "title") || "Threat investigation"}`);
    const icon = element("span", "defense-threat-icon", severity === "Critical" ? "!" : "△");
    const copy = element("span", "defense-threat-copy");
    const reason = String(pick(item, "reason") || pick(item, "status") || "Investigation context available");
    copy.append(
      element("b", "", pick(item, "title") || "Threat investigation"),
      element("small", "", `${reason} • ${relativeTime(pick(item, "lastObservedAtUtc"))}`)
    );
    const recurrence = numeric(pick(item, "recurrenceCount"));
    const confidence = Number(pick(item, "confidence"));
    const confidenceText = Number.isFinite(confidence) ? `${Math.round(confidence <= 1 ? confidence * 100 : confidence)}%` : "—";
    const facts = recurrence ? `${number(recurrence)}× · ${confidenceText}` : confidenceText;
    row.append(icon, copy, element("span", "defense-threat-risk", facts));
    host.append(row);
  });
}

function threatQueueDate(item) {
  return dateValue(pick(item, "lastObservedAtUtc", "firstObservedAtUtc"));
}

function threatQueueRoute(item) {
  const kind = String(pick(item, "kind") || "").toLowerCase();
  const campaignId = String(pick(item, "campaignId") || (kind === "campaign" ? pick(item, "id") : "") || "");
  const incidentId = String(pick(item, "incidentId") || (kind === "incident" ? pick(item, "id") : "") || "");
  if (kind === "campaign" && campaignId) return threatCampaignHash(campaignId);
  if (incidentId) return `#incidents/${encodeURIComponent(incidentId)}`;
  if (campaignId) return threatCampaignHash(campaignId);
  return "#incidents";
}

function renderDefenseMiniMap(incidents, threats) {
  const host = $("#defenseMapDots");
  if (!host) return;
  host.replaceChildren();
  const signals = [...incidents, ...threats].slice(0, 36);
  signals.forEach((item, index) => {
    const identity = [pick(item, "sourceIp"), pick(item, "sourceHost"), pick(item, "campaignId"), pick(item, "incidentId"), index].join("|");
    const hash = stableHash(identity);
    const dot = element("i", `defense-map-dot ${severityName(pick(item, "severity")).toLowerCase()} defense-map-slot-${hash % 24} defense-map-delay-${hash % 5}`);
    host.append(dot);
  });
}

function renderDefenseImpact(trends, postureState) {
  const rows = trends.slice(-14);
  const max = Math.max(1, ...rows.map(item => numeric(pick(item, "incidents")) + numeric(pick(item, "campaigns"))));
  const points = rows.map((item, index) => {
    const x = rows.length === 1 ? 150 : 10 + index * (280 / (rows.length - 1));
    const y = 105 - (numeric(pick(item, "incidents")) + numeric(pick(item, "campaigns"))) / max * 78;
    return { x, y };
  });
  $("#defenseImpactLine").setAttribute("points", points.map(point => `${point.x.toFixed(1)},${point.y.toFixed(1)}`).join(" "));
  $("#defenseImpactArea").setAttribute("d", points.length ? `M10 115 L${points.map(point => `${point.x.toFixed(1)} ${point.y.toFixed(1)}`).join(" L")} L290 115 Z` : "M10 115 L290 115 Z");
  const dots = $("#defenseImpactDots");
  dots.replaceChildren();
  points.forEach(point => {
    const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    circle.setAttribute("cx", point.x); circle.setAttribute("cy", point.y); circle.setAttribute("r", "3");
    dots.append(circle);
  });
  $("#defenseImpactChart").setAttribute("aria-label", `${number(rows.length)} trend buckets, posture ${postureLabel(postureState)}`);
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
  renderIncidentDrilldown();
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
    const incidentId = String(pick(item, "incidentId") || "");
    const severity = severityName(pick(item, "severity"));
    const tr = element("tr");
    if (incidentId && incidentId === state.selectedIncidentRouteId) tr.classList.add("selected-row");
    const sevTd = element("td");
      sevTd.append(element("span", `severity-badge ${severity.toLowerCase()}`, severity));
    const titleTd = element("td");
    const open = element("button", "incident-title-button", pick(item, "title") || "Untitled incident");
    open.type = "button";
    open.dataset.openIncident = incidentId;
    titleTd.append(open);
    tr.append(
      sevTd,
      titleTd,
      element("td", "", endpointText(item, "source")),
      element("td", "", endpointText(item, "destination")),
      element("td", "", formatDate(incidentDate(item)))
    );
    table.append(tr);
  });
}

function renderIncidentDrilldown() {
  const host = $("#incidentDrilldown");
  if (!host) return;
  const incidentId = state.selectedIncidentRouteId;
  host.hidden = !incidentId;
  if (!incidentId) return;
  const incident = state.incidents.find(item => String(pick(item, "incidentId")) === incidentId);
  const queueItem = asArray(pick(state.dashboardSummary, "threatQueue")).find(item => String(pick(item, "incidentId")) === incidentId);
  $("#incidentDrilldownTitle").textContent = pick(incident, "title") || pick(queueItem, "title") || `Incident ${incidentId}`;
  $("#incidentDrilldownMeta").textContent = incident
    ? `${severityName(pick(incident, "severity"))} • ${routeText(incident)} • ${formatDate(incidentDate(incident))}`
    : state.loading.incidents ? "กำลังโหลด Incident โดย ID…" : "Incident อยู่นอก bounded list หรือไม่พบใน tenant นี้";
  const chain = $("#incidentViewChain");
  const campaignId = String(pick(queueItem, "campaignId") || pick(incident, "campaignId", "threatCampaignId") || "");
  chain.disabled = !campaignId;
  chain.dataset.campaignId = campaignId;
  chain.title = campaignId ? "เปิด Temporal Chain ที่สัมพันธ์กับ Incident" : "Central ยังไม่ได้เชื่อม Incident นี้กับ Campaign";
  $("#incidentAskAi").disabled = !incident;
}

function openSelectedIncidentChain() {
  const campaignId = $("#incidentViewChain")?.dataset.campaignId || "";
  if (campaignId) navigateHash(threatCampaignHash(campaignId));
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

async function loadThreatDetails(campaignId) {
  campaignId = String(campaignId || "");
  if (!campaignId) return false;
  const generation = ++threatDetailGeneration;
  threatPaginationGeneration++;
  threatPaginationController?.abort();
  threatPaginationController = null;
  state.loading.threatTimelineMore = false;
  state.loading.threatContactsMore = false;
  closeThreatEdgeDrawer();
  if (state.threatDetail.campaignId !== campaignId && $("#threatTimeScrubber")) {
    $("#threatTimeScrubber").value = "100";
    $("#threatTimeScrubberValue").textContent = "100%";
  }
  const tenantId = state.tenantId;
  threatDetailController?.abort();
  const controller = new AbortController();
  threatDetailController = controller;
  if (state.threatAi.campaignId !== campaignId) {
    threatAiGeneration++;
    threatAiController?.abort();
    threatAiController = null;
    state.threatAi = { campaignId, status: "idle", result: null, error: null };
  }
  state.threatDetail = { campaignId, graph: null, timeline: null, contacts: null, errors: {} };
  state.loading.threatDetail = true;
  if (state.activePage === "threats") renderThreatCampaigns();
  const isCurrent = () => generation === threatDetailGeneration
    && tenantId === state.tenantId
    && state.selectedThreatId === campaignId
    && !controller.signal.aborted;
  const { from, to } = threatWindowRange();
  const base = `/api/v2/threats/${encodeURIComponent(campaignId)}`;
  const query = new URLSearchParams({ from, to, limit: String(THREAT_GRAPH_EDGE_LIMIT) });
  const options = { headers: { "X-NTShield-Tenant": tenantId }, signal: controller.signal, timeoutMs: REQUEST_TIMEOUT_MS };
  const requests = [
    ["graph", () => requestJson(`${base}/graph?${query}`, options)],
    ["timeline", () => requestJson(`${base}/timeline?${new URLSearchParams({ from, to, limit: "100" })}`, options)],
    ["contacts", () => requestJson(`${base}/contacts?${new URLSearchParams({ from, to, limit: "100" })}`, options)]
  ];
  const tasks = requests.map(([key, load]) => Promise.resolve().then(load).then(value => {
    if (!isCurrent()) return;
    state.threatDetail[key] = value || {};
    if (state.activePage === "threats") renderThreatCampaigns();
  }).catch(error => {
    if (!isCurrent() || isAbortError(error)) return;
    const legacy = legacyThreatDetail(key, campaignId);
    if ([404, 405, 501].includes(error?.status) && legacy) state.threatDetail[key] = legacy;
    else state.threatDetail.errors[key] = error;
    if (state.activePage === "threats") renderThreatCampaigns();
    throw error;
  }));
  await Promise.allSettled(tasks);
  if (!isCurrent()) return false;
  state.loading.threatDetail = false;
  if (threatDetailController === controller) threatDetailController = null;
  if (state.activePage === "threats") renderThreatCampaigns();
  return Object.keys(state.threatDetail.errors).length < requests.length;
}

async function loadMoreThreatEvidence(kind) {
  if (kind !== "timeline" && kind !== "contacts") return false;
  const campaignId = state.selectedThreatId;
  const tenantId = state.tenantId;
  const current = state.threatDetail.campaignId === campaignId ? state.threatDetail[kind] : null;
  const cursor = String(pick(current, "nextCursor") || "");
  const maxItems = kind === "timeline" ? THREAT_TIMELINE_ACCUMULATION_LIMIT : THREAT_CONTACT_ACCUMULATION_LIMIT;
  const existingItems = asArray(pick(current, "items"));
  if (!campaignId || !cursor || existingItems.length >= maxItems) return false;

  const generation = ++threatPaginationGeneration;
  threatPaginationController?.abort();
  const controller = new AbortController();
  threatPaginationController = controller;
  const loadingKey = kind === "timeline" ? "threatTimelineMore" : "threatContactsMore";
  state.loading[loadingKey] = true;
  delete state.threatDetail.errors[`${kind}Page`];
  renderThreatCampaigns();

  try {
    const { from, to } = threatWindowRange();
    const query = new URLSearchParams({ from, to, limit: "100", cursor });
    const page = await requestJson(`/api/v2/threats/${encodeURIComponent(campaignId)}/${kind}?${query}`, {
      headers: { "X-NTShield-Tenant": tenantId },
      signal: controller.signal,
      timeoutMs: REQUEST_TIMEOUT_MS
    });
    const isCurrent = generation === threatPaginationGeneration
      && !controller.signal.aborted
      && tenantId === state.tenantId
      && campaignId === state.selectedThreatId
      && state.threatDetail.campaignId === campaignId;
    if (!isCurrent) return false;

    const identity = kind === "timeline"
      ? item => String(pick(item, "observationId") || `${pick(item, "observedAtUtc")}|${pick(item, "evidenceId")}`)
      : item => String(pick(item, "contactKey", "contactId") || `${pick(item, "sourceNodeId")}|${pick(item, "destinationNodeId")}`);
    const combined = [];
    const seen = new Set();
    [...existingItems, ...asArray(pick(page, "items"))].forEach(item => {
      const key = identity(item);
      if (!key || seen.has(key) || combined.length >= maxItems) return;
      seen.add(key);
      combined.push(item);
    });
    state.threatDetail[kind] = {
      ...(current || {}),
      ...(page || {}),
      items: combined,
      // Stop at the client cap even if Central has more. The operator can
      // narrow the time window without allowing an unbounded browser model.
      nextCursor: combined.length >= maxItems ? null : pick(page, "nextCursor") || null,
      clientCapped: combined.length >= maxItems && Boolean(pick(page, "nextCursor"))
    };
    return true;
  } catch (error) {
    if (generation !== threatPaginationGeneration || isAbortError(error)) return false;
    state.threatDetail.errors[`${kind}Page`] = error;
    toast(`${kind === "timeline" ? "Timeline" : "Contacts"} page ถัดไปยังโหลดไม่สำเร็จ: ${friendlyError(error)}`);
    return false;
  } finally {
    if (generation === threatPaginationGeneration) {
      state.loading[loadingKey] = false;
      if (state.activePage === "threats") renderThreatCampaigns();
    }
    if (threatPaginationController === controller) threatPaginationController = null;
  }
}

function legacyThreatDetail(key, campaignId) {
  const campaign = state.threats.find(item => String(pick(item, "campaignId")) === campaignId);
  if (!campaign) return null;
  const hops = asArray(pick(campaign, "hops"));
  if (key === "timeline") {
    return {
      items: hops.map((hop, index) => ({
        observationId: `${campaignId}-hop-${index + 1}`,
        episodeId: campaignId,
        kind: "hop",
        observedAtUtc: pick(hop, "timestampUtc"),
        timeQuality: "legacy",
        summary: `${pick(hop, "technique") || "Observed hop"}: ${pick(hop, "fromHost", "fromIp") || "source"} → ${pick(hop, "toHost", "toIp") || "destination"}`,
        evidenceRefs: []
      })),
      buckets: [], total: hops.length, truncated: false, nextCursor: null
    };
  }
  if (key === "contacts") return { items: [], total: 0, nextCursor: null };
  if (key === "graph") {
    const legacyNodes = buildCampaignNodes(campaign, hops).map((node, index) => ({
      nodeId: `legacy-${index}`,
      type: node.kind,
      label: node.label,
      risk: pick(campaign, "severity"),
      observed: !node.inferred
    }));
    return {
      nodes: legacyNodes,
      edges: legacyNodes.slice(1).map((node, index) => ({
        edgeId: `legacy-edge-${index}`,
        fromNodeId: legacyNodes[index].nodeId,
        toNodeId: node.nodeId,
        relation: "observed-hop",
        technique: pick(hops[index], "technique") || "Observed hop",
        inferred: !node.observed,
        evidenceCount: 1,
        observationCount: 1
      }))
    };
  }
  return null;
}

function renderThreatCampaigns() {
  const list = $("#threatCampaignList");
  if (!list) return;
  const tenantLabel = $("#globalTenantSelect")?.selectedOptions?.[0]?.textContent || state.tenantId || "default";
  $("#threatTenantName").textContent = tenantLabel;
  const campaigns = threatCampaignsForView();
  const activeId = state.selectedThreatId || String(pick(campaigns[0], "campaignId") || "");
  state.selectedThreatId = activeId;
  list.replaceChildren();

  if (!campaigns.length) {
    list.append(element("div", "threat-list-empty", state.loading.threats ? "กำลังโหลด Temporal Chains…" : state.errors.threats ? "โหลด Campaign ไม่สำเร็จ • กด Refresh" : state.threats.length ? "ไม่พบ Campaign ในช่วงเวลานี้" : "ยังไม่มี Threat Campaign"));
    const direct = activeId ? { campaignId: activeId, title: `Campaign ${activeId}` } : null;
    renderThreatPath(direct);
    renderThreatInspector(direct);
    renderThreatTimeline(direct);
    renderThreatContacts(direct);
    renderThreatAi(direct);
    $("#threatRailSummary").textContent = activeId ? "Direct campaign route" : state.threats.length ? "ลองเปลี่ยนช่วงเวลา" : "รอ Central correlation";
    return;
  }

  campaigns.forEach(campaign => {
    const severity = severityName(pick(campaign, "severity"));
    const hosts = asArray(pick(campaign, "involvedHosts"));
    const observations = numeric(pick(campaign, "observationCount")) || asArray(pick(campaign, "hops")).length;
    const contacts = numeric(pick(campaign, "contactCount"));
    const item = element("button", `threat-campaign-item ${severity.toLowerCase()} ${String(pick(campaign, "campaignId")) === activeId ? "active" : ""}`);
    item.type = "button";
    item.dataset.threatId = String(pick(campaign, "campaignId") || "");
    const copy = element("span", "threat-campaign-copy");
    copy.append(
      element("strong", "", pick(campaign, "title") || "Threat campaign"),
      element("small", "", `${number(observations)} observations • ${number(hosts.length)} hosts • ${number(contacts)} contacts • ${relativeTime(pick(campaign, "lastObservedAtUtc", "lastSeenUtc"))}`)
    );
    const tags = element("span", "threat-campaign-tags");
    tags.append(element("span", "", String(pick(campaign, "status") || "Open")));
    const recurrence = numeric(pick(campaign, "recurrenceCount"));
    if (recurrence) tags.append(element("span", "threat-ml-tag ready", `${number(recurrence)} recurrences`));
    const marker = element("i");
    item.append(marker, copy, element("strong", "threat-campaign-risk", `Risk ${threatRiskScore(campaign)}`));
    copy.append(tags);
    list.append(item);
  });

  const selected = campaigns.find(item => String(pick(item, "campaignId")) === activeId)
    || (activeId ? { campaignId: activeId, title: `Campaign ${activeId}`, status: "Open" } : campaigns[0]);
  renderThreatPath(selected);
  renderThreatInspector(selected);
  renderThreatTimeline(selected);
  renderThreatContacts(selected);
  renderThreatAi(selected);
  $("#threatRailSummary").textContent = `${number(campaigns.length)} visible • ${number(state.threats.length)} total`;
  $("#threatActiveCount").replaceChildren(element("i"), document.createTextNode(` ${number(campaigns.filter(isThreatActive).length)} active`));
}

function threatCampaignsForView() {
  const severityFilter = String($("#threatFilter")?.value || "").toLowerCase();
  const sort = $("#threatSort")?.value || "recent";
  return [...state.threats]
    .filter(item => !severityFilter || severityName(pick(item, "severity")).toLowerCase() === severityFilter)
    .sort((a, b) => sort === "risk"
      ? threatRiskScore(b) - threatRiskScore(a)
      : threatObservedDate(b) - threatObservedDate(a))
    .slice(0, THREAT_LIST_LIMIT);
}

function selectThreatCampaign(event) {
  const button = event.target.closest("[data-threat-id]");
  if (!button) return;
  const campaignId = button.dataset.threatId || "";
  if (campaignId) navigateHash(threatCampaignHash(campaignId));
}

function renderThreatPath(campaign) {
  const stage = $("#threatGraphStage");
  const empty = $("#threatGraphEmpty");
  const summary = $("#threatCampaignSummary");
  if (!stage || !empty || !summary) return;
  const title = $("#threatPathTitle");
  const meta = $("#threatPathMeta");
  const status = $("#threatPathStatus");
  const forensicsButton = $("#threatOpenForensics");
  if (forensicsButton) forensicsButton.disabled = !String(pick(campaign, "campaignId") || "");
  if (!campaign) {
    stage.hidden = true;
    empty.hidden = false;
    summary.hidden = true;
    title.textContent = "Select a campaign";
    meta.textContent = "เลือก Campaign เพื่อดูเส้นทางโจมตีที่ Central เชื่อมโยงได้";
    status.textContent = "Waiting";
    status.className = "threat-status-chip";
    $("#threatEvidenceSummary").replaceChildren(element("i", "graph-legend-dot evidence"), document.createTextNode(" Evidence 0"));
    return;
  }
  const campaignId = String(pick(campaign, "campaignId") || "");
  const detail = state.threatDetail.campaignId === campaignId ? state.threatDetail : null;
  if (detail?.graph) {
    renderThreatGraphV2(campaign, detail.graph);
    return;
  }
  if (state.loading.threatDetail && campaignId === state.selectedThreatId && !asArray(pick(campaign, "hops")).length) {
    stage.hidden = true;
    empty.hidden = false;
    empty.replaceChildren(element("div", "threat-empty-mark", "⌁"), element("h3", "", "กำลังสร้าง Temporal Chain"), element("p", "", "Graph, timeline และ recurring contacts จะแสดงทีละส่วนเมื่อพร้อม"));
    summary.hidden = true;
    title.textContent = pick(campaign, "title") || "Threat campaign";
    meta.textContent = "Loading bounded evidence from Central…";
    status.textContent = "Loading";
    status.className = "threat-status-chip";
    $("#threatEvidenceSummary").replaceChildren(element("i", "graph-legend-dot evidence"), document.createTextNode(" Evidence —"));
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
  const candidate = isThreatCandidate(campaign);
  status.textContent = candidate ? "Candidate" : closed ? "Closed" : "Active";
  status.className = `threat-status-chip ${candidate ? "candidate" : closed ? "closed" : threatRiskScore(campaign) >= 70 ? "alert" : ""}`;
  $("#threatEvidenceSummary").replaceChildren(element("i", "graph-legend-dot evidence"), document.createTextNode(` Evidence ${number(stats.evidenceCount)}`));

  const nodeHost = $("#threatGraphNodes");
  const lineGroup = $("#threatGraphLineGroup");
  nodeHost.replaceChildren();
  lineGroup.replaceChildren();
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

function renderThreatGraphV2(campaign, graph) {
  const stage = $("#threatGraphStage");
  const empty = $("#threatGraphEmpty");
  const summary = $("#threatCampaignSummary");
  const title = $("#threatPathTitle");
  const meta = $("#threatPathMeta");
  const status = $("#threatPathStatus");
  const ordered = orderedThreatGraph(graph);
  const nodes = ordered.nodes;
  const edges = ordered.edges;
  title.textContent = pick(campaign, "title") || "Threat campaign";
  meta.textContent = `${formatDate(pick(campaign, "firstObservedAtUtc", "firstSeenUtc"))} → ${formatDate(pick(campaign, "lastObservedAtUtc", "lastSeenUtc"))} · ${number(pick(campaign, "observationCount"))} observations · ${number(pick(campaign, "episodeCount"))} episodes · ${number(pick(campaign, "recurrenceCount"))} recurrences`;
  const closed = isThreatClosed(campaign);
  const candidate = isThreatCandidate(campaign);
  status.textContent = candidate ? "Candidate" : closed ? "Closed" : "Active";
  status.className = `threat-status-chip ${candidate ? "candidate" : closed ? "closed" : threatRiskScore(campaign) >= 70 ? "alert" : ""}`;
  const evidenceCount = edges.reduce((sum, edge) => {
    const explicit = Number(pick(edge, "evidenceCount"));
    return sum + (Number.isFinite(explicit) ? explicit : asArray(pick(edge, "evidenceRefs")).length);
  }, 0);
  $("#threatEvidenceSummary").replaceChildren(element("i", "graph-legend-dot evidence"), document.createTextNode(` Evidence ${number(evidenceCount)}`));
  if (!nodes.length) {
    stage.hidden = true;
    empty.hidden = false;
    empty.replaceChildren(element("div", "threat-empty-mark", "⌁"), element("h3", "", "ยังไม่มี graph node ในช่วงเวลานี้"), element("p", "", "ลองขยาย Time window หรือกด Refresh เพื่อดึง revision ล่าสุด"));
    summary.hidden = true;
    return;
  }
  stage.hidden = false;
  empty.hidden = true;
  summary.hidden = false;
  const nodeHost = $("#threatGraphNodes");
  const lineGroup = $("#threatGraphLineGroup");
  nodeHost.replaceChildren();
  lineGroup.replaceChildren();
  const position = new Map(nodes.map((node, index) => [String(pick(node, "nodeId")), index]));
  nodes.forEach((node, index) => {
    const type = normalizeThreatNodeType(pick(node, "type"));
    const nodeId = String(pick(node, "nodeId") || "");
    const focused = nodeId && state.threatRouteWindow?.focus === nodeId;
    const item = element("button", `threat-node ${type}${pick(node, "observed") === false ? " inferred" : ""}${focused ? " focused" : ""}`);
    item.type = "button";
    item.dataset.threatFocus = nodeId;
    item.setAttribute("aria-pressed", String(focused));
    item.dataset.step = String(index + 1);
    const label = pick(node, "label", "host", "ip") || "Unknown node";
    const secondary = [pick(node, "ip"), pick(node, "host"), pick(node, "agentId")].filter(value => value && value !== label).slice(0, 2).join(" • ") || type;
    const chip = `${pick(node, "observed") === false ? "Inferred" : "Observed"}${pick(node, "risk") ? ` • ${pick(node, "risk")}` : ""}`;
    item.append(element("span", "threat-node-icon", threatNodeIcon(type)), element("b", "", label), element("small", "", secondary), element("span", "threat-node-chip", chip));
    nodeHost.append(item);
  });
  edges.forEach(edge => {
    const fromIndex = position.get(String(pick(edge, "fromNodeId")));
    const toIndex = position.get(String(pick(edge, "toNodeId")));
    if (!Number.isInteger(fromIndex) || !Number.isInteger(toIndex) || fromIndex === toIndex) return;
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", String(((fromIndex + .5) / nodes.length) * 1000));
    line.setAttribute("y1", "150");
    line.setAttribute("x2", String(((toIndex + .5) / nodes.length) * 1000));
    line.setAttribute("y2", "150");
    const contactCount = Math.max(1, numeric(pick(edge, "observationCount")));
    line.dataset.threatEdge = String(pick(edge, "edgeId") || "");
    line.dataset.weight = contactCount >= 64 ? "5" : contactCount >= 16 ? "4" : contactCount >= 4 ? "3" : contactCount >= 2 ? "2" : "1";
    if (numeric(pick(edge, "recurrenceCount")) > 1) line.classList.add("recurring");
    if (pick(edge, "inferred")) line.classList.add("inferred");
    const label = [pick(edge, "relation"), pick(edge, "technique"), `${number(pick(edge, "observationCount"))} observations`].filter(Boolean).join(" • ");
    line.setAttribute("tabindex", "0");
    line.setAttribute("role", "button");
    line.setAttribute("aria-label", `Inspect edge: ${label}`);
    const svgTitle = document.createElementNS("http://www.w3.org/2000/svg", "title");
    svgTitle.textContent = label;
    line.append(svgTitle);
    lineGroup.append(line);
  });
  renderThreatSummaryV2(summary, campaign, nodes, edges, evidenceCount);
}

function orderedThreatGraph(graph) {
  const allNodes = asArray(pick(graph, "nodes"));
  const allEdges = asArray(pick(graph, "edges")).slice(0, THREAT_GRAPH_EDGE_LIMIT).sort((a, b) => dateValue(pick(a, "firstObservedAtUtc")) - dateValue(pick(b, "firstObservedAtUtc")));
  const byId = new Map(allNodes.map(node => [String(pick(node, "nodeId")), node]));
  const ids = [];
  const add = id => { id = String(id || ""); if (id && byId.has(id) && !ids.includes(id)) ids.push(id); };
  allEdges.forEach(edge => { add(pick(edge, "fromNodeId")); add(pick(edge, "toNodeId")); });
  allNodes.forEach(node => add(pick(node, "nodeId")));
  const nodes = ids.slice(0, THREAT_GRAPH_NODE_LIMIT).map(id => byId.get(id));
  const visible = new Set(nodes.map(node => String(pick(node, "nodeId"))));
  return { nodes, edges: allEdges.filter(edge => visible.has(String(pick(edge, "fromNodeId"))) && visible.has(String(pick(edge, "toNodeId"))) ) };
}

function normalizeThreatNodeType(value) {
  const type = String(value || "host").toLowerCase();
  if (["external", "ip", "source"].includes(type)) return "external";
  if (["user", "account", "identity"].includes(type)) return "account";
  if (["process", "service", "host"].includes(type)) return type;
  return "host";
}

function threatNodeIcon(type) {
  return { external: "◎", account: "@", process: ">_", service: "S", host: "▣" }[type] || "▣";
}

function renderThreatSummaryV2(host, campaign, nodes, edges, evidenceCount) {
  host.className = "threat-campaign-summary threat-summary-card";
  host.replaceChildren();
  const header = element("div", "threat-summary-header");
  const copy = element("div");
  copy.append(element("strong", "", "Temporal chain overview"), element("small", "", `${number(nodes.length)} of ${number(pick(campaign, "edgeCount") ? numeric(pick(campaign, "edgeCount")) + 1 : nodes.length)} nodes rendered • bounded for operator clarity`));
  header.append(copy, element("span", "threat-summary-compression", `${number(edges.length)} explicit edges`));
  const metrics = element("div", "threat-summary-metrics");
  [["Observations", pick(campaign, "observationCount")], ["Episodes", pick(campaign, "episodeCount")], ["Contacts", pick(campaign, "contactCount")], ["Evidence", evidenceCount], ["Recurrences", pick(campaign, "recurrenceCount")]].forEach(([label, value]) => {
    const metric = element("div", "threat-summary-metric");
    metric.append(element("b", "", number(value)), element("span", "", label));
    metrics.append(metric);
  });
  const note = element("div", "threat-summary-note");
  note.append(element("span", "", "Analyst context"), element("p", "", String(pick(campaign, "summary") || "Graph edges are explicit Central correlations; dashed edges are inferred and should be verified against evidence.")));
  host.append(header, metrics, note);
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
  [["Campaign ID", String(pick(campaign, "campaignId") || "—").slice(0, 24)], ["Revision", number(pick(campaign, "revision"))], ["Status", pick(campaign, "status") || "Open"], ["First observed", formatDate(pick(campaign, "firstObservedAtUtc", "firstSeenUtc"))], ["Last observed", formatDate(pick(campaign, "lastObservedAtUtc", "lastSeenUtc"))], ["Observations", number(pick(campaign, "observationCount") || asArray(pick(campaign, "hops")).length)], ["Episodes", number(pick(campaign, "episodeCount"))], ["Recurring contacts", number(pick(campaign, "contactCount"))]].forEach(([label, value]) => {
    const row = element("div");
    row.append(element("dt", "", label), element("dd", "", value));
    facts.append(row);
  });
  body.append(facts);
  const ml = pick(campaign, "schemaVersion") === 2 ? null : campaignMlInfo(campaign);
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
    const level = Math.max(1, Math.min(10, Math.ceil(item.score * 10)));
    const bar = element("span", `threat-ml-bar threat-ml-level-${level}`);
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
  const more = $("#threatTimelineMore");
  if (!host) return;
  if (more) more.hidden = true;
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
  const campaignId = String(pick(campaign, "campaignId") || "");
  const detail = state.threatDetail.campaignId === campaignId ? state.threatDetail : null;
  if (detail?.timeline) {
    renderThreatTimelineV2(campaign, detail.timeline);
    return;
  }
  if (state.loading.threatDetail && campaignId === state.selectedThreatId && !asArray(pick(campaign, "hops")).length) {
    host.append(element("div", "threat-timeline-empty", "กำลังโหลด observation timeline…"));
    $("#threatTimelineWindow").textContent = "Loading bounded sequence";
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

function renderThreatTimelineV2(campaign, timeline) {
  const host = $("#threatTimeline");
  const explain = $("#threatTimelineExplain");
  const sourceItems = [...asArray(pick(timeline, "items"))].sort((a, b) => dateValue(pick(a, "observedAtUtc")) - dateValue(pick(b, "observedAtUtc")));
  const scrubber = $("#threatTimeScrubber");
  const scrubPercent = clamp(scrubber?.value || 100, 5, 100);
  if ($("#threatTimeScrubberValue")) $("#threatTimeScrubberValue").textContent = `${scrubPercent}%`;
  const sourceFirst = dateValue(pick(sourceItems[0], "observedAtUtc"));
  const sourceLast = dateValue(pick(sourceItems[sourceItems.length - 1], "observedAtUtc"));
  const cutoff = sourceFirst.getTime() && sourceLast.getTime()
    ? sourceFirst.getTime() + (sourceLast - sourceFirst) * scrubPercent / 100
    : Number.POSITIVE_INFINITY;
  const allItems = sourceItems.filter(item => dateValue(pick(item, "observedAtUtc")).getTime() <= cutoff);
  const total = Number.isFinite(Number(pick(timeline, "total"))) ? Number(pick(timeline, "total")) : allItems.length;
  syncThreatMoreButton("timeline", timeline, sourceItems.length, total);
  const items = allItems.slice(0, THREAT_TIMELINE_ACCUMULATION_LIMIT);
  host.replaceChildren();
  const first = items[0];
  const last = items[items.length - 1];
  $("#threatTimelineWindow").textContent = items.length
    ? `${formatDate(pick(first, "observedAtUtc"))} → ${formatDate(pick(last, "observedAtUtc"))} · ${number(items.length)}/${number(total)} rendered`
    : "UTC window — no observations";
  if (explain) {
    explain.hidden = false;
    explain.replaceChildren(
      element("strong", "", `${number(items.length)} exact loaded observations`),
      element("span", "", `${pick(timeline, "truncated") || total > sourceItems.length ? "More evidence remains server-side • " : ""}Every loaded record is inspectable in event-time order; the browser model is capped at ${number(THREAT_TIMELINE_ACCUMULATION_LIMIT)} records.`)
    );
  }
  if (!items.length) {
    host.append(element("div", "threat-timeline-empty", state.threatDetail.errors.timeline ? "Timeline unavailable • retry Refresh" : "ไม่มี observation ในช่วงเวลานี้"));
    return;
  }
  const nodeMap = threatNodeLabelMap();
  items.forEach((item, index) => {
    const event = element("article", `threat-timeline-event ${severityName(pick(campaign, "severity")).toLowerCase()}`);
    const timestamp = dateValue(pick(item, "observedAtUtc"));
    const source = nodeMap.get(String(pick(item, "sourceNodeId"))) || pick(item, "sourceNodeId") || "source";
    const destination = nodeMap.get(String(pick(item, "destinationNodeId"))) || pick(item, "destinationNodeId") || "destination";
    const meta = element("div", "threat-timeline-event-meta");
    meta.append(element("span", "threat-timeline-hop", `${String(pick(item, "kind") || "event")} ${number(index + 1)}`), element("time", "", timestamp.getTime() ? timestamp.toLocaleTimeString("th-TH", { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "Time unknown"));
    const evidenceCount = asArray(pick(item, "evidenceRefs")).length || (pick(item, "evidenceId") ? 1 : 0);
    event.append(
      element("span", "threat-timeline-point"),
      meta,
      element("strong", "", boundedText(pick(item, "summary") || [pick(item, "kind"), pick(item, "relation"), pick(item, "technique"), pick(item, "evidenceType")].filter(Boolean).join(" • ") || "Observed activity", 240)),
      element("small", "", `${source} → ${destination}`),
      element("span", "threat-timeline-reason", `${pick(item, "timeQuality", "timestampQuality") || "time unknown"} • ${number(evidenceCount)} evidence`)
    );
    host.append(event);
  });
}

function threatNodeLabelMap() {
  if (!state.threatDetail.graph) return new Map();
  return new Map(asArray(pick(state.threatDetail.graph, "nodes")).map(node => [String(pick(node, "nodeId")), String(pick(node, "label", "host", "ip") || pick(node, "nodeId") || "node")]));
}

function renderThreatContacts(campaign) {
  const host = $("#threatContacts");
  const count = $("#threatContactsCount");
  const more = $("#threatContactsMore");
  if (!host || !count) return;
  if (more) more.hidden = true;
  host.replaceChildren();
  if (!campaign) {
    count.textContent = "0 contacts";
    host.append(element("div", "threat-timeline-empty", "เลือก Campaign เพื่อดู contact sequence"));
    return;
  }
  const campaignId = String(pick(campaign, "campaignId") || "");
  const detail = state.threatDetail.campaignId === campaignId ? state.threatDetail : null;
  if (!detail?.contacts) {
    count.textContent = state.loading.threatDetail ? "Loading…" : "Unavailable";
    host.append(element("div", "threat-timeline-empty", detail?.errors?.contacts ? "Contacts unavailable • retry Refresh" : "กำลังโหลด recurring contacts…"));
    return;
  }
  const allItems = asArray(pick(detail.contacts, "items"));
  const total = Number.isFinite(Number(pick(detail.contacts, "total"))) ? Number(pick(detail.contacts, "total")) : allItems.length;
  const items = allItems.slice(0, THREAT_CONTACT_RENDER_LIMIT);
  syncThreatMoreButton("contacts", detail.contacts, allItems.length, total);
  count.textContent = `${number(items.length)}/${number(total)} contacts`;
  if (!items.length) {
    host.append(element("div", "threat-timeline-empty", "ไม่พบ recurring network contact ในช่วงเวลานี้"));
    return;
  }
  const labels = threatNodeLabelMap();
  items.forEach(item => {
    const row = element("button", "threat-contact-row");
    row.type = "button";
    row.dataset.threatEdge = String(pick(item, "contactKey", "contactId") || "");
    row.setAttribute("aria-label", `Inspect contact ${row.dataset.threatEdge || "evidence"}`);
    const sourceId = String(pick(item, "sourceNodeId") || "");
    const destinationId = String(pick(item, "destinationNodeId") || "");
    const route = element("div", "threat-contact-route");
    route.append(
      element("strong", "", `${labels.get(sourceId) || sourceId || "source"} → ${labels.get(destinationId) || destinationId || "destination"}`),
      element("small", "", `${pick(item, "protocol") || "protocol unknown"}${pick(item, "destinationPort") ? `/${pick(item, "destinationPort")}` : ""} • ${formatDate(pick(item, "lastObservedAtUtc"))}`)
    );
    const stats = element("div", "threat-contact-stats");
    [["Observed", pick(item, "observationCount")], ["Recurrences", pick(item, "recurrenceCount", "reconnectCount")], ["Beacon", formatConfidence(pick(item, "beaconScore"))], ["Evidence", asArray(pick(item, "evidenceRefs")).length]].forEach(([label, value]) => {
      const fact = element("span");
      fact.append(element("b", "", typeof value === "number" ? number(value) : value), element("small", "", label));
      stats.append(fact);
    });
    row.append(route, stats);
    host.append(row);
  });
  if (total > items.length) host.append(element("p", "threat-contact-more", `${number(total - items.length)} more contacts kept server-side • narrow the time window to inspect them`));
}

function syncThreatMoreButton(kind, response, loaded, total) {
  const timeline = kind === "timeline";
  const button = $(timeline ? "#threatTimelineMore" : "#threatContactsMore");
  if (!button) return;
  const loading = Boolean(state.loading[timeline ? "threatTimelineMore" : "threatContactsMore"]);
  const cursor = String(pick(response, "nextCursor") || "");
  const capped = pick(response, "clientCapped") === true;
  button.hidden = !loading && !cursor && !capped;
  button.disabled = loading || !cursor || capped;
  button.textContent = loading
    ? "Loading…"
    : capped
      ? `Browser cap ${number(loaded)}/${number(total)} • narrow window`
      : `Load more (${number(loaded)}/${number(total)})`;
}

function openThreatEdgeDrawer(edgeId) {
  const contacts = asArray(pick(state.threatDetail.contacts, "items"));
  const graphEdges = asArray(pick(state.threatDetail.graph, "edges"));
  const edge = contacts.find(item => String(pick(item, "contactKey", "contactId") || "") === String(edgeId || ""))
    || graphEdges.find(item => String(pick(item, "edgeId") || "") === String(edgeId || ""));
  if (!edge) return;
  state.selectedThreatEdgeId = String(edgeId || "");
  const drawer = $("#threatEdgeDrawer");
  const body = $("#threatEdgeBody");
  if (!drawer || !body) return;
  const labels = threatNodeLabelMap();
  const sourceId = String(pick(edge, "sourceNodeId", "fromNodeId") || "");
  const destinationId = String(pick(edge, "destinationNodeId", "toNodeId") || "");
  $("#threatEdgeDrawerTitle").textContent = `${labels.get(sourceId) || sourceId || "source"} → ${labels.get(destinationId) || destinationId || "destination"}`;
  body.replaceChildren();
  const facts = element("dl", "threat-edge-facts");
  const firstObserved = dateValue(pick(edge, "firstObservedAtUtc"));
  const lastObserved = dateValue(pick(edge, "lastObservedAtUtc"));
  const suppliedDuration = Number(pick(edge, "durationSeconds"));
  const duration = Number.isFinite(suppliedDuration)
    ? suppliedDuration
    : firstObserved.getTime() && lastObserved.getTime()
      ? Math.max(0, Math.round((lastObserved - firstObserved) / 1000))
      : NaN;
  [
    ["Protocol / ports", [pick(edge, "protocol"), pick(edge, "localPort"), pick(edge, "destinationPort", "remotePort", "port")].filter(value => value !== null && value !== undefined && value !== "").join(" / ") || "Unknown"],
    ["First observed", formatDate(pick(edge, "firstObservedAtUtc"))],
    ["Last observed", formatDate(pick(edge, "lastObservedAtUtc"))],
    ["Observations", number(pick(edge, "observationCount"))],
    ["Reconnects", number(pick(edge, "reconnectCount", "recurrenceCount"))],
    ["Duration", Number.isFinite(Number(duration)) ? `${number(duration)} sec` : "Unknown"],
    ["Median / p95 gap", `${Number.isFinite(Number(pick(edge, "medianGapSeconds"))) ? `${number(pick(edge, "medianGapSeconds"))}s` : "—"} / ${Number.isFinite(Number(pick(edge, "p95GapSeconds"))) ? `${number(pick(edge, "p95GapSeconds"))}s` : "—"}`],
    ["Beacon score", formatConfidence(pick(edge, "beaconScore"))],
    ["Confidence", formatConfidence(pick(edge, "confidence"))],
    ["Evidence type", pick(edge, "inferred") ? "Inferred candidate" : "Observed"],
    ["Process / user", [pick(edge, "processName"), pick(edge, "username"), pick(edge, "serviceNames")].filter(Boolean).join(" • ") || "Not observed"]
  ].forEach(([label, value]) => {
    const wrapper = element("div");
    wrapper.append(element("dt", "", label), element("dd", "", value));
    facts.append(wrapper);
  });
  body.append(facts);
  const evidence = asArray(pick(edge, "evidenceRefs")).slice(0, 20);
  const evidenceSection = element("section", "threat-edge-evidence");
  evidenceSection.append(element("h3", "", `Evidence citations (${number(evidence.length)})`));
  if (evidence.length) {
    const list = element("ul");
    evidence.forEach(reference => list.append(element("li", "", boundedText(reference, 240))));
    evidenceSection.append(list);
  } else {
    evidenceSection.append(element("p", "", "No bounded evidence reference is available for this aggregate."));
  }
  body.append(evidenceSection);
  drawer.hidden = false;
  $("#threatEdgeClose")?.focus({ preventScroll: true });
}

function closeThreatEdgeDrawer() {
  state.selectedThreatEdgeId = "";
  const drawer = $("#threatEdgeDrawer");
  if (drawer) drawer.hidden = true;
}

function openSelectedEdgeForensics() {
  if (!state.selectedThreatEdgeId || !state.selectedThreatId) return;
  const edgeId = state.selectedThreatEdgeId;
  const campaignId = state.selectedThreatId;
  const range = threatWindowRange();
  closeThreatEdgeDrawer();
  navigateHash(serializeRoute({
    page: "forensics",
    query: {
      campaignId,
      edgeId,
      fromUtc: range.from,
      toUtc: range.to
    }
  }));
}

function formatConfidence(value) {
  const score = Number(value);
  if (!Number.isFinite(score)) return "—";
  return `${Math.round(score <= 1 ? score * 100 : score)}%`;
}

async function askThreatAi() {
  const campaignId = state.selectedThreatId;
  if (!campaignId || state.threatAi.status === "loading") return;
  const generation = ++threatAiGeneration;
  const tenantId = state.tenantId;
  threatAiController?.abort();
  const controller = new AbortController();
  threatAiController = controller;
  state.threatAi = { campaignId, status: "loading", result: null, error: null };
  renderThreatAi(state.threats.find(item => String(pick(item, "campaignId")) === campaignId) || { campaignId });
  try {
    const result = await requestJson(`/api/v2/threats/${encodeURIComponent(campaignId)}/ai/explain`, {
      method: "POST",
      headers: { "X-NTShield-Tenant": tenantId },
      timeoutMs: REQUEST_TIMEOUT_MS,
      signal: controller.signal
    });
    if (generation !== threatAiGeneration || tenantId !== state.tenantId || campaignId !== state.selectedThreatId) return;
    state.threatAi = { campaignId, status: "ready", result: result || {}, error: null };
  } catch (error) {
    if (generation !== threatAiGeneration || tenantId !== state.tenantId || campaignId !== state.selectedThreatId || isAbortError(error)) return;
    state.threatAi = { campaignId, status: "error", result: null, error };
  } finally {
    if (threatAiController === controller) threatAiController = null;
  }
  if (state.activePage === "threats") renderThreatAi(state.threats.find(item => String(pick(item, "campaignId")) === campaignId) || { campaignId });
}

function renderThreatAi(campaign) {
  const host = $("#threatAiExplain");
  const button = $("#threatAskAi");
  if (!host || !button) return;
  const campaignId = String(pick(campaign, "campaignId") || "");
  const ai = state.threatAi.campaignId === campaignId ? state.threatAi : { status: "idle", result: null, error: null };
  button.disabled = !campaignId || ai.status === "loading";
  button.textContent = ai.status === "loading" ? "AI analyzing…" : ai.status === "ready" ? "Refresh AI" : "Ask AI";
  host.replaceChildren();
  host.hidden = ai.status === "idle" || !campaignId;
  if (host.hidden) return;
  if (ai.status === "loading") {
    host.append(element("p", "threat-ai-state", "Brain กำลังอธิบาย bounded observations และ contact citations • timeout 8 วินาที"));
    return;
  }
  if (ai.status === "error") {
    const reason = ai.error?.status === 503 ? "Brain ยังไม่ได้ตั้งค่า" : ai.error?.name === "TimeoutError" || ai.error?.status === 504 ? "Brain ตอบช้ากว่า 8 วินาที" : "Brain ยังไม่พร้อมใช้งาน";
    host.append(element("p", "threat-ai-state error", `${reason} • Temporal Chain และหลักฐานจาก Central ยังใช้งานได้`));
    return;
  }
  const result = ai.result || {};
  const header = element("header", "threat-ai-header");
  const copy = element("div");
  copy.append(
    element("span", "section-kicker", "AI EXPLANATION • EVIDENCE BOUNDED"),
    element("h3", "", boundedText(pick(result, "classification") || "Threat chain assessment", 300)),
    element("p", "", boundedText(pick(result, "summaryTh", "summary_th", "summaryEn", "summary_en") || "Brain returned no narrative summary.", 2200))
  );
  const risk = nullableNumber(pick(result, "riskScore", "risk_score"));
  const confidence = nullableNumber(pick(result, "confidence"));
  const badge = element("strong", "threat-ai-risk", risk === null ? "Risk —" : `Risk ${number(risk)}`);
  badge.append(element("small", "", confidence === null ? "confidence —" : `${formatConfidence(confidence)} confidence`));
  header.append(copy, badge);
  host.append(header);
  const chain = asArray(pick(result, "attackChain", "attack_chain")).slice(0, 12);
  const techniques = asArray(pick(result, "mitreTechniques", "mitre_techniques")).slice(0, 20);
  if (chain.length || techniques.length) {
    const tags = element("div", "threat-ai-tags");
    chain.forEach(value => tags.append(element("span", "", boundedText(value, 120))));
    techniques.forEach(value => tags.append(element("code", "", boundedText(value, 80))));
    host.append(tags);
  }
  const actions = asArray(pick(result, "recommendedActions", "recommended_actions")).slice(0, 8);
  if (actions.length) {
    const section = element("section", "threat-ai-actions");
    section.append(element("h4", "", "Recommended actions • Operator approval required"));
    const list = element("ul");
    actions.forEach(item => {
      const row = element("li");
      row.append(
        element("strong", "", boundedText(pick(item, "action") || "Review", 100)),
        element("span", "", boundedText(pick(item, "target") || "No target supplied", 180)),
        element("small", "", boundedText(pick(item, "reason") || "No reason supplied", 500))
      );
      list.append(row);
    });
    section.append(list);
    host.append(section);
  }
  const fallback = pick(result, "deterministicFallback", "deterministic_fallback") === true;
  host.append(element("small", "threat-ai-footnote", `${fallback ? "Deterministic fallback" : boundedText(pick(result, "model") || "Brain", 100)} • ${number(asArray(pick(result, "evidence")).length)} cited evidence items • no action was executed`));
}

function boundedText(value, maxLength) {
  return String(value ?? "").replace(/[\r\n\t]+/g, " ").trim().slice(0, maxLength);
}

function packetSessionListPath(query) {
  const params = new URLSearchParams({ take: String(PACKET_SESSION_RENDER_LIMIT) });
  const values = {
    campaignId: query?.campaignId,
    edgeId: query?.edgeId,
    fromUtc: query?.fromUtc,
    toUtc: query?.toUtc
  };
  Object.entries(values).forEach(([key, value]) => {
    const bounded = boundedText(value, 200);
    if (bounded) params.set(key, bounded);
  });
  return `/api/v2/packet-sessions?${params}`;
}

function packetSessionId(item) {
  return String(pick(item, "sessionId") || "");
}

function hasSessionCapability(capability) {
  const expected = String(capability || "").toLowerCase();
  return asArray(pick(state.session, "capabilities")).some(value => String(value).toLowerCase() === expected);
}

function openThreatForensics() {
  const campaignId = String(state.selectedThreatId || "");
  if (!campaignId) return;
  const range = threatWindowRange();
  navigateHash(serializeRoute({
    page: "forensics",
    query: { campaignId, edgeId: "", fromUtc: range.from, toUtc: range.to }
  }));
}

function applyForensicsFilters() {
  const campaignId = boundedText($("#forensicsCampaign")?.value, 200);
  const edgeId = boundedText($("#forensicsEdge")?.value, 200);
  const fromUtc = utcInputToIso($("#forensicsFrom")?.value);
  const toUtc = utcInputToIso($("#forensicsTo")?.value);
  if (!fromUtc || !toUtc) {
    toast("ระบุ From UTC และ To UTC ให้ครบ");
    return;
  }
  const from = dateValue(fromUtc);
  const to = dateValue(toUtc);
  if (!(from < to) || to - from > 31 * 86400000) {
    toast("Time window ต้องเรียงจากเก่าไปใหม่และไม่เกิน 31 วัน");
    return;
  }
  navigateHash(serializeRoute({ page: "forensics", query: { campaignId, edgeId, fromUtc, toUtc } }));
}

function renderForensics() {
  const list = $("#forensicsSessions");
  const preview = $("#forensicsPreview");
  if (!list || !preview) return;
  renderCaptureHealth();
  const canView = hasSessionCapability("packets:view");
  const canExport = hasSessionCapability("packets:export");
  const purposeField = $("#forensicsPurpose")?.closest("label");
  if (purposeField) purposeField.hidden = !canView && !canExport;
  const capability = $("#forensicsCapability");
  capability.textContent = canView || canExport
    ? `สิทธิ์ปัจจุบัน: ${[canView ? "view audited payload" : "", canExport ? "export packet capture" : ""].filter(Boolean).join(" • ")} • ทุก action ต้องระบุ purpose`
    : "Metadata only • บัญชี Executive และผู้ใช้ที่ไม่มี packets:view / packets:export จะไม่เห็น payload controls";

  const sessions = state.forensics.sessions.slice(0, PACKET_SESSION_RENDER_LIMIT);
  list.replaceChildren();
  $("#forensicsSessionCount").textContent = `${number(sessions.length)} sessions${state.forensics.nextCursor ? " • more available" : ""}`;
  if (!sessions.length) {
    const message = state.loading.forensics
      ? "กำลังค้นหา bounded packet metadata…"
      : state.errors.forensics
        ? "Packet metadata unavailable • ตรวจ Capture health หรือกด Refresh"
        : "ไม่พบ packet session ตาม Campaign และ Time window นี้";
    list.append(element("div", "empty-state", message));
  } else {
    sessions.forEach(item => list.append(renderPacketSessionButton(item)));
  }

  const selected = sessions.find(item => packetSessionId(item) === state.forensics.selectedSessionId) || null;
  renderPacketSessionPreview(selected, { canView, canExport });
}

function renderCaptureHealth() {
  const node = $("#captureHealth");
  if (!node) return;
  const health = state.forensics.captureHealth;
  if (!health) {
    node.textContent = state.loading.forensics ? "Capture health loading…" : "Capture health unavailable";
    node.dataset.tone = state.loading.forensics ? "loading" : "unknown";
    return;
  }
  const providerValue = pick(health, "providers", "items");
  const providers = asArray(providerValue);
  const gaps = numeric(pick(health, "openVisibilityGaps"));
  const degradedProviders = providers.filter(provider => String(pick(provider, "state") || "unknown").toLowerCase() !== "healthy").length;
  const healthy = providers.length > 0 && !gaps && !degradedProviders;
  const status = !providers.length ? "No capture providers" : healthy ? "Healthy" : "Degraded";
  node.textContent = `${status} • ${number(providers.length)} providers${gaps ? ` • ${number(gaps)} visibility gaps` : ""}`;
  node.dataset.tone = healthy ? "healthy" : "degraded";
}

function renderPacketSessionButton(item) {
  const id = packetSessionId(item);
  const button = element("button", `forensics-session-item${id === state.forensics.selectedSessionId ? " active" : ""}`);
  button.type = "button";
  button.dataset.packetSession = id;
  button.setAttribute("aria-pressed", String(id === state.forensics.selectedSessionId));
  const route = element("span", "forensics-session-route");
  route.append(
    element("strong", "", `${packetEndpoint(item, "source")} → ${packetEndpoint(item, "destination")}`),
    element("small", "", `${pick(item, "protocol") || "protocol unknown"}${pick(item, "application") ? ` • ${pick(item, "application")}` : ""} • ${formatDate(pick(item, "startedAtUtc"))}`)
  );
  const stats = element("span", "forensics-session-stats");
  stats.append(
    element("b", "", formatByteCount(pick(item, "byteCount"))),
    element("small", pick(item, "payloadAvailable") === true ? "payload-ready" : "", pick(item, "payloadAvailable") === true ? "Payload available" : "Metadata only")
  );
  button.append(route, stats);
  return button;
}

function packetEndpoint(item, side) {
  const ip = String(pick(item, `${side}Ip`) || "unknown");
  const port = pick(item, `${side}Port`);
  const host = pick(item, `${side}Host`);
  const addressIp = ip.includes(":") && !ip.startsWith("[") ? `[${ip}]` : ip;
  const address = port !== undefined && port !== null ? `${addressIp}:${port}` : ip;
  return host ? `${host} (${address})` : address;
}

function selectPacketSession(event) {
  const button = event.target.closest("[data-packet-session]");
  if (!button) return;
  state.forensics.selectedSessionId = button.dataset.packetSession || "";
  renderForensics();
}

function renderPacketSessionPreview(session, { canView, canExport }) {
  const preview = $("#forensicsPreview");
  const actions = $("#forensicsPayloadActions");
  const access = $("#forensicsAccess");
  const exportButton = $("#forensicsExport");
  const exportField = $("#forensicsExportFormat")?.closest("label");
  preview.replaceChildren();
  if (!session) {
    preview.append(element("div", "empty-state", "เลือก session เพื่อดู flow/TLS metadata"));
    $("#forensicsPayloadState").textContent = "No selection";
    actions.hidden = true;
    return;
  }

  const payloadAvailable = pick(session, "payloadAvailable") === true;
  $("#forensicsPayloadState").textContent = payloadAvailable ? "Payload available" : "Metadata only";
  const facts = element("dl", "forensics-fact-list");
  const tls = pick(session, "tls") || {};
  const values = [
    ["Session", packetSessionId(session)],
    ["Flow", pick(session, "flowId")],
    ["Correlation / incident", [pick(session, "correlationId"), pick(session, "incidentId")].filter(Boolean).join(" / ")],
    ["Campaign / edge", [pick(session, "campaignId"), pick(session, "edgeId")].filter(Boolean).join(" / ")],
    ["Window", `${formatDate(pick(session, "startedAtUtc"))} → ${formatDate(pick(session, "endedAtUtc"))}`],
    ["Source", packetEndpoint(session, "source")],
    ["Destination", packetEndpoint(session, "destination")],
    ["Agent attribution", [pick(session, "sourceAgentId"), pick(session, "destinationAgentId")].filter(Boolean).join(" → ")],
    ["Process / user", [pick(session, "processName", "processPath"), pick(session, "processId") ? `PID ${pick(session, "processId")}` : "", pick(session, "userName")].filter(Boolean).join(" • ")],
    ["Protocol / app", [pick(session, "protocol"), pick(session, "application")].filter(Boolean).join(" / ")],
    ["Packets / bytes", `${number(pick(session, "packetCount"))} / ${formatByteCount(pick(session, "byteCount"))}`],
    ["Provider / sensor", [pick(session, "providerId"), pick(session, "sensorId")].filter(Boolean).join(" / ")],
    ["Storage", [pick(session, "storageTier"), pick(session, "storagePoolId")].filter(Boolean).join(" / ")],
    ["Retention", `${formatDate(pick(session, "hotUntilUtc"))} hot • ${formatDate(pick(session, "retainUntilUtc"))} retained`],
    ["TLS", pick(tls, "isTls") === true ? [pick(tls, "version"), pick(tls, "serverName"), pick(tls, "alpn")].filter(Boolean).join(" • ") || "Detected" : "Not detected"],
    ["TLS decryption", pick(tls, "decryptionState")],
    ["TLS fingerprints", [pick(tls, "ja3"), pick(tls, "ja4"), pick(tls, "certificateSha256")].filter(Boolean).join(" • ")],
    ["Tags", asArray(pick(session, "tags")).slice(0, 12).join(" • ")],
    ["Payload SHA-256", pick(session, "payloadSha256")]
  ];
  values.forEach(([label, value]) => {
    const row = element("div");
    row.append(element("dt", "", label), element("dd", "", boundedText(value || "—", 300)));
    facts.append(row);
  });
  preview.append(facts, element("p", "forensics-preview-note", payloadAvailable
    ? "Payload bytes are never loaded automatically. Open requires a short-lived audited grant; export creates a separate audited job."
    : "Central returned safe flow metadata only. Payload access is unavailable for this session/provider."));

  actions.hidden = !payloadAvailable || (!canView && !canExport);
  access.hidden = !canView;
  access.disabled = state.loading.forensicsAction === true;
  if (exportField) exportField.hidden = !canExport;
  exportButton.hidden = !canExport;
  exportButton.disabled = state.loading.forensicsAction === true;
}

async function openPacketPayload() {
  const session = selectedPacketSession();
  if (!session || pick(session, "payloadAvailable") !== true || !hasSessionCapability("packets:view")) return;
  const purpose = forensicsPurpose();
  if (!purpose) return;
  // Reserve the user-initiated tab before awaiting the audited grant. Only the
  // validated grant URL is assigned after Central returns successfully.
  const popup = window.open("about:blank", "_blank");
  if (popup) popup.opener = null;
  const operation = beginForensicsAction();
  try {
    const result = await requestJson(`/api/v2/packet-sessions/${encodeURIComponent(packetSessionId(session))}/access`, {
      method: "POST",
      body: { purpose, ttlSeconds: 300 },
      signal: operation.controller.signal
    });
    if (!isCurrentForensicsAction(operation)) {
      popup?.close();
      return;
    }
    const rawUrl = String(pick(result, "accessUrl") || "");
    if (!rawUrl) throw new Error("invalid_access_url");
    let accessUrl;
    try { accessUrl = new URL(rawUrl, location.origin); } catch { throw new Error("invalid_access_url"); }
    if (!["http:", "https:"].includes(accessUrl.protocol)) throw new Error("invalid_access_url");
    let opened = false;
    if (popup && !popup.closed) {
      popup.location.replace(accessUrl.href);
      opened = true;
    } else {
      opened = Boolean(window.open(accessUrl.href, "_blank", "noopener,noreferrer"));
    }
    toast(opened ? "เปิด audited payload grant ในแท็บใหม่แล้ว" : "Grant พร้อมแล้ว แต่ browser บล็อก popup • อนุญาต popup แล้วขอใหม่");
  } catch (error) {
    if (popup && !popup.closed) popup.close();
    if (isCurrentForensicsAction(operation) && !isAbortError(error)) toast(`เปิด payload ไม่สำเร็จ: ${friendlyError(error)}`);
  } finally {
    endForensicsAction(operation);
  }
}

async function createPacketExport() {
  const session = selectedPacketSession();
  if (!session || pick(session, "payloadAvailable") !== true || !hasSessionCapability("packets:export")) return;
  const purpose = forensicsPurpose();
  if (!purpose) return;
  const format = $("#forensicsExportFormat")?.value === "pcap" ? "pcap" : "pcapng";
  const operation = beginForensicsAction();
  try {
    const result = await requestJson(`/api/v2/packet-sessions/${encodeURIComponent(packetSessionId(session))}/exports`, {
      method: "POST",
      body: { format, purpose, retentionHours: 24 },
      signal: operation.controller.signal
    });
    if (!isCurrentForensicsAction(operation)) return;
    const job = pick(result, "jobId", "exportId");
    toast(`สร้าง ${format.toUpperCase()} export job แล้ว${job ? ` • ${boundedText(job, 80)}` : ""}`);
  } catch (error) {
    if (isCurrentForensicsAction(operation) && !isAbortError(error)) toast(`สร้าง export ไม่สำเร็จ: ${friendlyError(error)}`);
  } finally {
    endForensicsAction(operation);
  }
}

function selectedPacketSession() {
  return state.forensics.sessions.find(item => packetSessionId(item) === state.forensics.selectedSessionId) || null;
}

function forensicsPurpose() {
  const value = boundedText($("#forensicsPurpose")?.value, 500);
  if (!value) toast("ระบุ purpose ก่อนขอ payload access หรือ export");
  return value;
}

function beginForensicsAction() {
  const generation = ++forensicsActionGeneration;
  forensicsActionController?.abort();
  const controller = new AbortController();
  forensicsActionController = controller;
  state.loading.forensicsAction = true;
  renderForensics();
  return { generation, tenantId: state.tenantId, sessionId: state.forensics.selectedSessionId, controller };
}

function isCurrentForensicsAction(operation) {
  return operation.generation === forensicsActionGeneration
    && operation.tenantId === state.tenantId
    && operation.sessionId === state.forensics.selectedSessionId
    && !operation.controller.signal.aborted;
}

function endForensicsAction(operation) {
  if (!isCurrentForensicsAction(operation)) return;
  if (forensicsActionController === operation.controller) forensicsActionController = null;
  state.loading.forensicsAction = false;
  if (state.activePage === "forensics") renderForensics();
}

function utcInputToIso(value) {
  const text = String(value || "");
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(text)) return "";
  const parsed = new Date(`${text}:00Z`);
  return Number.isNaN(parsed.getTime()) ? "" : parsed.toISOString();
}

function isoToUtcInput(value) {
  const date = dateValue(value);
  return date.getTime() ? date.toISOString().slice(0, 16) : "";
}

function formatByteCount(value) {
  const bytes = numeric(value);
  if (bytes < 1024) return `${number(bytes)} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KiB`;
  if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MiB`;
  return `${(bytes / 1073741824).toFixed(1)} GiB`;
}

function threatRiskScore(campaign) {
  const severity = severityName(pick(campaign, "severity"));
  const base = { Critical: 88, High: 72, Medium: 54, Low: 30, Informational: 12 }[severity] || 12;
  const confidence = Number(pick(campaign, "confidence"));
  if (pick(campaign, "observationCount") !== undefined) {
    return Number.isFinite(confidence) ? clamp(confidence <= 1 ? confidence * 100 : confidence, 0, 100) : base;
  }
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

function isThreatCandidate(campaign) {
  const status = String(pick(campaign, "status") || "").toLowerCase();
  return status === "candidate" || status === "inferred";
}

function isThreatActive(campaign) {
  return !isThreatClosed(campaign) && !isThreatCandidate(campaign);
}

function threatObservedDate(campaign) {
  return dateValue(pick(campaign, "lastObservedAtUtc", "updatedAtUtc", "lastSeenUtc", "firstObservedAtUtc", "firstSeenUtc"));
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
  navigateHash(`#analyst/incident/${encodeURIComponent(button.dataset.incidentId)}`);
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
  const candidates = [pick(item, "destinationHost"), pick(item, "sourceHost"), incidentIp(item, "destination"), incidentIp(item, "source")]
    .map(normalizeAgentIdentifier)
    .filter(Boolean);
  for (const candidate of candidates) {
    const agent = state.agents.find(item => [pick(item, "agentId"), pick(item, "computerName"), pick(item, "hostIp")]
      .map(normalizeAgentIdentifier)
      .some(identifier => identifier && identifier === candidate));
    if (agent) return String(pick(agent, "agentId") || "");
  }
  return "";
}

function normalizeAgentIdentifier(value) {
  return String(value || "").trim().toLowerCase();
}

function recommendationStateKey(recommendationId, incidentId = state.analyst.selectedIncidentId, tenantId = state.tenantId) {
  return JSON.stringify([String(tenantId || "default"), String(incidentId || ""), String(recommendationId || "")]);
}

function getRecommendationState(recommendationId, incidentId = state.analyst.selectedIncidentId, tenantId = state.tenantId) {
  return state.analyst.actionStates[recommendationStateKey(recommendationId, incidentId, tenantId)];
}

function setRecommendationState(recommendationId, status, incidentId = state.analyst.selectedIncidentId, tenantId = state.tenantId) {
  state.analyst.actionStates[recommendationStateKey(recommendationId, incidentId, tenantId)] = status;
}

function renderAnalystReport(incident, report) {
  const severity = severityName(pick(incident, "severity"));
  const incidentId = String(pick(incident, "incidentId") || "");
  $("#analystAnalyzedCount").textContent = number(state.incidents.length);
  $("#analystApprovalCount").textContent = number(report.recommendations.filter(item => getRecommendationState(item.id, incidentId) !== "approved" && getRecommendationState(item.id, incidentId) !== "dismissed").length);
  $("#analystEvidenceCount").textContent = number(report.evidence.length);
  $("#analystVerdictTitle").textContent = report.classification;
  $("#analystVerdictSubtitle").textContent = `${pick(incident, "title") || "Security incident"} • ${severity} • ${String(pick(incident, "incidentId") || "")}`;
  const badge = $("#analystVerdictBadge");
  badge.textContent = `${severity} / ${report.score}`;
  badge.className = `analyst-verdict-badge ${severity.toLowerCase()}`;
  $("#analystConfidenceValue").textContent = `${number(report.confidence)}%`;
  $("#analystConfidenceBand").textContent = `${report.confidenceBand} confidence`;
  $("#analystConfidenceReason").textContent = `${number(report.evidence.length)} evidence • ${number(report.missing.length)} unknowns`;
  $("#analystConfidenceRing").dataset.confidenceLevel = String(Math.max(0, Math.min(10, Math.round(numeric(report.confidence) / 10))));
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
  const pending = report.recommendations.filter(item => !getRecommendationState(item.id, report.incidentId)).length;
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
  const next = report.recommendations.find(item => !getRecommendationState(item.id, report.incidentId)) || report.recommendations[0];
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
    const item = report.recommendations.find(candidate => !getRecommendationState(candidate.id, report.incidentId)) || report.recommendations[0];
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
    const status = getRecommendationState(item.id);
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
  const incidentId = String(pick(incident, "incidentId") || "");
  const tenantId = state.tenantId;
  if (dismissButton) {
    setRecommendationState(recId, "dismissed", incidentId, tenantId);
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
    setRecommendationState(recId, "approved", incidentId, tenantId);
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
  $("#analystConfidenceRing").dataset.confidenceLevel = "0";
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

function syncThreatRevisionUpdates() {
  const eligible = !$("#dashboardView")?.hidden && (state.activePage === "overview" || state.activePage === "threats");
  if (!eligible) {
    stopThreatRevisionUpdates();
    return;
  }
  if (threatRevisionController && threatRevisionTenant === state.tenantId) return;
  stopThreatRevisionUpdates();
  const generation = ++threatRevisionGeneration;
  const tenantId = state.tenantId;
  const controller = new AbortController();
  threatRevisionController = controller;
  threatRevisionTenant = tenantId;
  void consumeThreatRevisionStream(generation, tenantId, controller);
}

function stopThreatRevisionUpdates() {
  threatRevisionGeneration++;
  threatRevisionController?.abort();
  threatRevisionController = null;
  threatRevisionTenant = "";
  if (threatRevisionPollTimer) clearInterval(threatRevisionPollTimer);
  if (threatRevisionRefreshTimer) clearTimeout(threatRevisionRefreshTimer);
  threatRevisionPollTimer = 0;
  threatRevisionRefreshTimer = 0;
}

async function consumeThreatRevisionStream(generation, tenantId, controller) {
  const headers = new Headers({ Accept: "text/event-stream", "X-NTShield-Tenant": tenantId });
  if (state.apiKey) headers.set(API_KEY_HEADER, state.apiKey);
  let handshakeTimedOut = false;
  const handshakeTimer = setTimeout(() => {
    handshakeTimedOut = true;
    controller.abort();
  }, REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch("/api/v2/threats/stream", {
      method: "GET",
      headers,
      credentials: "same-origin",
      cache: "no-store",
      signal: controller.signal
    });
    clearTimeout(handshakeTimer);
    if (!response.ok || !response.body?.getReader) {
      const error = new Error(`threat_stream_http_${response.status || "unsupported"}`);
      error.status = response.status;
      throw error;
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    while (generation === threatRevisionGeneration && tenantId === state.tenantId && !controller.signal.aborted) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer = (buffer + decoder.decode(value, { stream: true })).replace(/\r\n/g, "\n");
      let boundary;
      while ((boundary = buffer.indexOf("\n\n")) >= 0) {
        const block = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        handleThreatRevisionBlock(block, generation, tenantId);
      }
    }
    if (generation === threatRevisionGeneration && !controller.signal.aborted) startThreatRevisionPolling(generation, tenantId);
  } catch (error) {
    clearTimeout(handshakeTimer);
    if (generation !== threatRevisionGeneration || controller.signal.aborted && !handshakeTimedOut) return;
    console.warn("Threat revision stream unavailable; using 15 second polling", error);
    startThreatRevisionPolling(generation, tenantId);
  }
}

function handleThreatRevisionBlock(block, generation, tenantId) {
  if (generation !== threatRevisionGeneration || tenantId !== state.tenantId) return;
  const lines = String(block || "").split("\n");
  const eventName = lines.find(line => line.startsWith("event:"))?.slice(6).trim() || "message";
  if (eventName !== "threat-revision") return;
  const payload = lines.filter(line => line.startsWith("data:")).map(line => line.slice(5).trimStart()).join("\n");
  if (!payload) return;
  try {
    const notification = JSON.parse(payload);
    scheduleThreatRevisionRefresh(generation, tenantId, String(pick(notification, "campaignId") || ""), true);
  } catch (error) {
    console.warn("Ignoring malformed threat revision notification", error);
  }
}

function startThreatRevisionPolling(generation, tenantId) {
  if (generation !== threatRevisionGeneration || tenantId !== state.tenantId || threatRevisionPollTimer) return;
  threatRevisionController = null;
  threatRevisionPollTimer = setInterval(() => {
    if (generation !== threatRevisionGeneration || tenantId !== state.tenantId || document.hidden) return;
    scheduleThreatRevisionRefresh(generation, tenantId, "", false);
  }, 15000);
}

function scheduleThreatRevisionRefresh(generation, tenantId, campaignId, respectSummaryCache = false) {
  if (generation !== threatRevisionGeneration || tenantId !== state.tenantId || document.hidden) return;
  if (state.activePage !== "overview" && state.activePage !== "threats") return;
  if (campaignId && state.activePage === "threats" && state.selectedThreatId && campaignId !== state.selectedThreatId) {
    // The ranked campaign list still needs refreshing; selected detail does not
    // need an extra immediate request for an unrelated campaign.
  }
  if (threatRevisionRefreshTimer) return;
  // A stream event can arrive just after a cached Overview was generated. Wait
  // through the 10-second server cache window so the one refresh cannot return
  // the old queue and then remain stale indefinitely. Threat-chain detail and
  // fallback polling refresh immediately.
  const delay = respectSummaryCache && state.activePage === "overview" ? 10500 : 350;
  threatRevisionRefreshTimer = setTimeout(() => {
    threatRevisionRefreshTimer = 0;
    if (generation !== threatRevisionGeneration || tenantId !== state.tenantId) return;
    void ensurePageData(state.activePage, { force: true, notify: false }).catch(error => {
      if (!isAbortError(error)) console.warn("Threat revision refresh failed", error);
    });
  }, delay);
}

function bindRouter() {
  let routeFrame = 0;
  const applyBrowserRoute = () => {
    if (routeFrame || $("#dashboardView")?.hidden) return;
    routeFrame = requestAnimationFrame(() => {
      routeFrame = 0;
      if (!$("#dashboardView")?.hidden) applyRoute(parseHashRoute(), { focus: true });
    });
  };
  window.addEventListener("popstate", applyBrowserRoute);
  window.addEventListener("hashchange", applyBrowserRoute);
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) {
      syncThreatRevisionUpdates();
      if (state.activePage === "overview" || state.activePage === "threats") {
        const generation = threatRevisionGeneration;
        scheduleThreatRevisionRefresh(generation, state.tenantId, "", false);
      }
    }
  });
}

function parseHashRoute() {
  const raw = location.hash.replace(/^#\/?/, "");
  const [path, queryString = ""] = raw.split("?", 2);
  const params = new URLSearchParams(queryString);
  const parts = path.split("/").filter(Boolean).map(part => {
    try { return decodeURIComponent(part); } catch { return ""; }
  });
  const page = ROUTABLE_PAGES.has(parts[0]) ? parts[0] : "overview";
  const threatQuery = page === "threats" ? {
    from: params.get("from") || "",
    to: params.get("to") || "",
    preset: params.get("preset") || "",
    focus: params.get("focus") || ""
  } : null;
  const forensicsQuery = page === "forensics" ? {
    campaignId: params.get("campaignId") || "",
    edgeId: params.get("edgeId") || "",
    fromUtc: params.get("fromUtc") || "",
    toUtc: params.get("toUtc") || ""
  } : null;
  if (page === "threats" && parts[1]) return { page, entityType: "campaign", entityId: parts[1], query: threatQuery };
  if (page === "threats") return { page, entityType: "", entityId: "", query: threatQuery };
  if (page === "forensics") return { page, entityType: "", entityId: "", query: forensicsQuery };
  if (page === "analyst" && parts[1] === "incident" && parts[2]) return { page, entityType: "incident", entityId: parts[2] };
  if (page === "incidents" && parts[1]) return { page, entityType: "incident", entityId: parts[1] };
  return { page, entityType: "", entityId: "" };
}

function serializeRoute(route) {
  if (route.page === "threats") {
    const path = route.entityId ? `#threats/${encodeURIComponent(route.entityId)}` : "#threats";
    const query = route.query || {};
    const params = new URLSearchParams();
    if (query.from) params.set("from", query.from);
    if (query.to) params.set("to", query.to);
    if (query.preset) params.set("preset", query.preset);
    if (query.focus) params.set("focus", query.focus);
    const queryString = params.toString();
    return `${path}${queryString ? `?${queryString}` : ""}`;
  }
  if (route.page === "forensics") {
    const query = route.query || {};
    const params = new URLSearchParams();
    ["campaignId", "edgeId", "fromUtc", "toUtc"].forEach(key => {
      const value = boundedText(query[key], 200);
      if (value) params.set(key, value);
    });
    const queryString = params.toString();
    return `#forensics${queryString ? `?${queryString}` : ""}`;
  }
  if (route.page === "analyst" && route.entityType === "incident" && route.entityId) return `#analyst/incident/${encodeURIComponent(route.entityId)}`;
  if (route.page === "incidents" && route.entityId) return `#incidents/${encodeURIComponent(route.entityId)}`;
  return `#${ROUTABLE_PAGES.has(route.page) ? route.page : "overview"}`;
}

function navigateHash(hash, { replace = false } = {}) {
  const nextUrl = String(hash || "#overview").startsWith("#") ? String(hash || "#overview") : `#${hash}`;
  if (location.hash === nextUrl) {
    applyRoute(parseHashRoute(), { focus: true });
    return;
  }
  if (replace) history.replaceState(null, "", nextUrl);
  else history.pushState(null, "", nextUrl);
  applyRoute(parseHashRoute(), { focus: true });
}

function showPage(name) {
  if (name === "threats") {
    const preset = String($("#threatTimeWindow")?.value || "24h");
    const range = state.activePage === "threats"
      ? threatWindowRange()
      : threatWindowRange({ ignoreOverride: true, preset });
    navigateHash(serializeRoute({ page: "threats", entityType: "", entityId: "", query: { ...range, preset, focus: "" } }));
    return;
  }
  if (name === "forensics") {
    navigateHash(serializeRoute({ page: "forensics", query: normalizedForensicsRouteQuery(state.forensics.query) }));
    return;
  }
  navigateHash(serializeRoute({ page: name || "overview", entityType: "", entityId: "" }));
}

function applyRoute(route, { focus = true } = {}) {
  const page = ROUTABLE_PAGES.has(route?.page) ? route.page : "overview";
  const previousPage = state.activePage;
  state.activePage = page;
  let threatWindowChanged = false;
  if (page === "threats") {
    const previousWindow = state.threatRouteWindow;
    state.threatRouteWindow = normalizedThreatRouteQuery(route.query);
    threatWindowChanged = `${previousWindow?.from || ""}|${previousWindow?.to || ""}` !== `${state.threatRouteWindow?.from || ""}|${state.threatRouteWindow?.to || ""}`;
    const preset = state.threatRouteWindow?.preset;
    if (preset && $("#threatTimeWindow")?.querySelector(`option[value="${preset}"]`)) $("#threatTimeWindow").value = preset;
    if (threatWindowChanged) {
      state.loaded.threats = false;
      threatDetailGeneration++;
      threatAiGeneration++;
      threatPaginationGeneration++;
      threatDetailController?.abort();
      threatAiController?.abort();
      threatPaginationController?.abort();
      threatDetailController = null;
      threatAiController = null;
      threatPaginationController = null;
      state.loading.threatDetail = false;
      state.loading.threatTimelineMore = false;
      state.loading.threatContactsMore = false;
      state.threatDetail = {
        campaignId: route.entityId || state.selectedThreatId,
        graph: null,
        timeline: null,
        contacts: null,
        errors: {}
      };
      state.threatAi = { campaignId: route.entityId || state.selectedThreatId, status: "idle", result: null, error: null };
    }
    if (state.threatRouteWindow && (!route.query?.from || !route.query?.to)) {
      route.query = { ...state.threatRouteWindow };
      history.replaceState(null, "", serializeRoute({ page, entityType: route.entityType, entityId: route.entityId, query: route.query }));
    }
  }
  if (page === "forensics") {
    const previous = state.forensics.query;
    const query = normalizedForensicsRouteQuery(route.query);
    const changed = forensicsQueryKey(previous) !== forensicsQueryKey(query);
    state.forensics.query = query;
    if (changed) {
      state.loaded.forensics = false;
      state.forensics.sessions = [];
      state.forensics.nextCursor = null;
      state.forensics.selectedSessionId = "";
      forensicsActionGeneration++;
      forensicsActionController?.abort();
      forensicsActionController = null;
      state.loading.forensicsAction = false;
    }
    syncForensicsFilterInputs(query);
    if (!route.query?.fromUtc || !route.query?.toUtc) {
      route.query = { ...query };
      history.replaceState(null, "", serializeRoute({ page, query }));
    }
  }
  if (page === "threats" && route.entityType === "campaign" && route.entityId) {
    const changed = state.selectedThreatId !== route.entityId;
    if (changed) {
      closeThreatEdgeDrawer();
      // A direct/hash route may point outside the currently loaded first page.
      // Force the bounded list + exact summary request so the URL never renders
      // a synthetic placeholder as if it were authoritative campaign metadata.
      state.loaded.threats = false;
    }
    state.selectedThreatId = route.entityId;
    if (changed || state.threatDetail.campaignId !== route.entityId) void loadThreatDetails(route.entityId);
  }
  if (page === "incidents" && route.entityType === "incident" && route.entityId) {
    if (state.selectedIncidentRouteId !== route.entityId) state.loaded.incidents = false;
    state.selectedIncidentRouteId = route.entityId;
  }
  else if (page === "incidents") state.selectedIncidentRouteId = "";
  if (page === "analyst" && route.entityType === "incident" && route.entityId) {
    if (state.analyst.selectedIncidentId !== route.entityId) state.loaded.analyst = false;
    state.analyst.selectedIncidentId = route.entityId;
  }
  if (previousPage === "threats" && page !== "threats") {
    closeThreatEdgeDrawer();
    threatDetailGeneration++;
    threatAiGeneration++;
    threatPaginationGeneration++;
    threatDetailController?.abort();
    threatAiController?.abort();
    threatPaginationController?.abort();
    threatDetailController = null;
    threatAiController = null;
    threatPaginationController = null;
    state.loading.threatDetail = false;
    state.loading.threatTimelineMore = false;
    state.loading.threatContactsMore = false;
    if (state.threatAi.status === "loading") state.threatAi = { campaignId: state.selectedThreatId, status: "idle", result: null, error: null };
  }
  if (previousPage === "forensics" && page !== "forensics") {
    forensicsActionGeneration++;
    forensicsActionController?.abort();
    forensicsActionController = null;
    state.loading.forensicsAction = false;
  }
  $$(".page").forEach(node => node.classList.toggle("active", node.dataset.page === page));
  $$('[data-nav]').forEach(node => {
    const active = node.dataset.nav === page;
    node.classList.toggle("active", active);
    if (active) node.setAttribute("aria-current", "page");
    else node.removeAttribute("aria-current");
  });
  $("#sidebar").classList.remove("open");
  $("#dashboardView").classList.toggle("overview-active", page === "overview");
  window.NTShieldDefenseMap?.setActive(page === "overview");
  updatePageLoadStatus(page);
  renderChrome();
  renderActivePage();
  const key = serializeRoute({ page, entityType: route.entityType, entityId: route.entityId, query: route.query });
  const changedRoute = currentRouteKey !== key;
  currentRouteKey = key;
  const heading = $(`[data-page="${page}"] h1`);
  if (heading) {
    heading.tabIndex = -1;
    if (focus && changedRoute) requestAnimationFrame(() => heading.focus({ preventScroll: true }));
  }
  document.title = `${heading?.textContent?.trim() || page} • NT Shield`;
  window.scrollTo({ top: 0, behavior: changedRoute ? "smooth" : "auto" });
  syncThreatRevisionUpdates();
  void ensurePageData(page, { force: false, notify: false }).catch(error => {
    if (!isAbortError(error) && state.activePage === page) updatePageLoadStatus(page);
  });
}

function normalizedThreatRouteQuery(query) {
  if (!query) return null;
  const presets = new Set(["15m", "1h", "24h", "7d", "30d"]);
  const fromDate = dateValue(query.from);
  const toDate = dateValue(query.to);
  const validWindow = fromDate.getTime() && toDate.getTime() && fromDate < toDate && toDate - fromDate <= 31 * 86400000;
  const selectedPreset = presets.has(query.preset) ? query.preset : String($("#threatTimeWindow")?.value || "24h");
  const fallback = threatWindowRange({ ignoreOverride: true, preset: selectedPreset });
  return {
    from: validWindow ? fromDate.toISOString() : fallback.from,
    to: validWindow ? toDate.toISOString() : fallback.to,
    preset: selectedPreset,
    focus: String(query.focus || "").slice(0, 128)
  };
}

function normalizedForensicsRouteQuery(query) {
  const from = dateValue(query?.fromUtc);
  const to = dateValue(query?.toUtc);
  const validWindow = from.getTime() && to.getTime() && from < to && to - from <= 31 * 86400000;
  const fallbackTo = new Date();
  const fallbackFrom = new Date(fallbackTo.getTime() - 24 * 3600000);
  return {
    campaignId: boundedText(query?.campaignId, 200),
    edgeId: boundedText(query?.edgeId, 200),
    fromUtc: validWindow ? from.toISOString() : fallbackFrom.toISOString(),
    toUtc: validWindow ? to.toISOString() : fallbackTo.toISOString()
  };
}

function forensicsQueryKey(query) {
  return [query?.campaignId, query?.edgeId, query?.fromUtc, query?.toUtc].map(value => String(value || "")).join("|");
}

function syncForensicsFilterInputs(query) {
  if ($("#forensicsCampaign")) $("#forensicsCampaign").value = query.campaignId || "";
  if ($("#forensicsEdge")) $("#forensicsEdge").value = query.edgeId || "";
  if ($("#forensicsFrom")) $("#forensicsFrom").value = isoToUtcInput(query.fromUtc);
  if ($("#forensicsTo")) $("#forensicsTo").value = isoToUtcInput(query.toUtc);
}

function navigateThreatWindow() {
  if ($("#threatTimeScrubber")) $("#threatTimeScrubber").value = "100";
  if ($("#threatTimeScrubberValue")) $("#threatTimeScrubberValue").textContent = "100%";
  const preset = String($("#threatTimeWindow")?.value || "24h");
  const range = threatWindowRange({ ignoreOverride: true, preset });
  navigateHash(serializeRoute({
    page: "threats",
    entityType: state.selectedThreatId ? "campaign" : "",
    entityId: state.selectedThreatId,
    query: { ...range, preset, focus: "" }
  }));
}

function navigateThreatFocus(nodeId) {
  const range = threatWindowRange();
  navigateHash(serializeRoute({
    page: "threats",
    entityType: "campaign",
    entityId: state.selectedThreatId,
    query: { ...range, preset: state.threatRouteWindow?.preset || String($("#threatTimeWindow")?.value || "24h"), focus: String(nodeId || "").slice(0, 128) }
  }));
}

function threatCampaignHash(campaignId) {
  const preset = state.threatRouteWindow?.preset || String($("#threatTimeWindow")?.value || "24h");
  const range = state.activePage === "threats"
    ? threatWindowRange()
    : threatWindowRange({ ignoreOverride: true, preset });
  return serializeRoute({
    page: "threats",
    entityType: "campaign",
    entityId: String(campaignId || ""),
    query: { ...range, preset, focus: "" }
  });
}

function setConnection(connected, text) {
  $("#connectionDot").classList.toggle("offline", !connected);
  $("#sidebarStatusDot").classList.toggle("offline", !connected);
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
  if (error?.status === 429) return "มีการลองเข้าสู่ระบบถี่เกินไป กรุณารอแล้วลองใหม่";
  if (error?.code === "invalid_credentials" || error?.message === "invalid_credentials") return "ชื่อผู้ใช้, password หรือ TOTP ไม่ถูกต้อง";
  if (error?.status === 401 || error?.message === "missing_api_key") return "Operator API Key ไม่ถูกต้อง หรือ Central เปิด RequireAuth อยู่";
  if (error?.status === 403) return "บัญชีนี้ไม่มีสิทธิ์เข้าถึงข้อมูล Operator";
  if (error?.name === "TimeoutError" || error?.message === "request_timeout") return "Central ตอบกลับช้ากว่า 8 วินาที กรุณาลองใหม่ โดยหน้า Dashboard จะไม่รอ request นี้ค้างไว้";
  if (error instanceof TypeError) return "ติดต่อ NT Shield Central ไม่ได้ กรุณาตรวจ service และ HTTPS certificate";
  return `เชื่อมต่อไม่สำเร็จ: ${error?.message || "unknown error"}`;
}

function isAbortError(error) {
  return error?.name === "AbortError" || error?.code === "ABORT_ERR";
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
