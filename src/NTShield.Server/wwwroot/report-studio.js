"use strict";

/* CSP-safe, dependency-free report layout editor. Templates are data, never HTML/CSS. */
(function () {
  const TEMPLATE_API = "/api/v1/report-templates";
  const DATA_SOURCE_API = "/api/v1/report-template-data-sources";
  const LEGACY_DATA_SOURCE_API = "/api/v1/report-data-sources";
  const MAX_BLOCKS = 24;
  const MAX_HISTORY = 50;
  const TYPES = ["header", "metrics", "severity", "incidents", "topSources", "topEvents", "recommendations", "coverage", "divider", "text"];
  const BLOCK_SOURCE_IDS = {
    header: "report.identity",
    metrics: "report.metrics",
    severity: "report.severityCounts",
    incidents: "report.priorityIncidents",
    topSources: "report.topSourceIps",
    topEvents: "report.topEventIds",
    recommendations: "report.recommendations",
    coverage: "report.coverage"
  };
  const BLOCK_LIMITS = { header: 1, metrics: 12, severity: 4, incidents: 50, topSources: 50, topEvents: 50, recommendations: 20, coverage: 1, divider: 1, text: 1 };
  const WIDTHS = ["full", "half", "third"];
  const BLOCK_STYLES = ["default", "card", "plain", "accent"];
  const PRESETS = ["executive", "technical", "midnight", "signal", "minimal", "classic", "custom"];
  const FONTS = ["system", "arial", "georgia", "mono"];
  const PAGE_SIZES = ["a4", "letter"];
  const ORIENTATIONS = ["portrait", "landscape"];
  const MARGINS = ["compact", "normal", "spacious"];
  const DENSITIES = ["compact", "comfortable"];
  const METRIC_KEYS = ["agents", "onlineAgents", "assets", "threatEvents", "incidents", "openIncidents", "threatCampaigns", "defenseScore", "critical", "high", "medium", "low"];
  const METRIC_LABELS = {
    agents: "Agents",
    onlineAgents: "Agents online",
    assets: "Assets",
    threatEvents: "Threat events",
    incidents: "Incidents",
    openIncidents: "Open incidents",
    threatCampaigns: "Campaigns",
    defenseScore: "Defense score",
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low"
  };
  const TYPE_META = {
    header: { icon: "HDR", label: "Report identity", width: "full" },
    metrics: { icon: "123", label: "Metric cards", width: "full" },
    severity: { icon: "RISK", label: "Severity distribution", width: "half" },
    incidents: { icon: "INC", label: "Priority incidents", width: "full" },
    topSources: { icon: "IP", label: "Top source IPs", width: "half" },
    topEvents: { icon: "EVT", label: "Top event IDs", width: "half" },
    recommendations: { icon: "REC", label: "Recommendations", width: "full" },
    coverage: { icon: "TXT", label: "Coverage note", width: "full" },
    divider: { icon: "—", label: "Divider", width: "full" },
    text: { icon: "Aa", label: "Text note", width: "full" }
  };

  const COLOR_GROUPS = {
    primary: ["#18202B", "#123B5D", "#0F172A", "#334155", "#6B4F00"],
    accent: ["#EFB900", "#2F80ED", "#16A36A", "#E25944", "#8B5CF6"],
    background: ["#FFFFFF", "#F7F8FA", "#FFF9E5", "#0F172A"],
    text: ["#252C38", "#475569", "#F8FAFC"]
  };
  const COLOR_TOKENS = {
    "#18202B": "ink",
    "#123B5D": "navy",
    "#0F172A": "midnight",
    "#334155": "slate",
    "#6B4F00": "bronze",
    "#EFB900": "gold",
    "#2F80ED": "blue",
    "#16A36A": "green",
    "#E25944": "coral",
    "#8B5CF6": "purple",
    "#FFFFFF": "white",
    "#F7F8FA": "soft",
    "#FFF9E5": "cream",
    "#252C38": "ink",
    "#475569": "slate",
    "#F8FAFC": "white"
  };
  const PRESET_THEMES = {
    executive: { preset: "executive", primaryColor: "#18202B", accentColor: "#EFB900", backgroundColor: "#FFFFFF", textColor: "#252C38", fontFamily: "system" },
    technical: { preset: "technical", primaryColor: "#123B5D", accentColor: "#2F80ED", backgroundColor: "#F7F8FA", textColor: "#252C38", fontFamily: "mono" },
    midnight: { preset: "midnight", primaryColor: "#0F172A", accentColor: "#8B5CF6", backgroundColor: "#0F172A", textColor: "#F8FAFC", fontFamily: "system" },
    signal: { preset: "signal", primaryColor: "#123B5D", accentColor: "#2F80ED", backgroundColor: "#FFFFFF", textColor: "#252C38", fontFamily: "arial" },
    minimal: { preset: "minimal", primaryColor: "#334155", accentColor: "#16A36A", backgroundColor: "#FFFFFF", textColor: "#252C38", fontFamily: "system" },
    classic: { preset: "classic", primaryColor: "#6B4F00", accentColor: "#EFB900", backgroundColor: "#FFF9E5", textColor: "#252C38", fontFamily: "georgia" },
    custom: { preset: "custom", primaryColor: "#18202B", accentColor: "#EFB900", backgroundColor: "#FFFFFF", textColor: "#252C38", fontFamily: "system" }
  };

  const fallbackDataSources = [
    source("report.identity", "Report identity", "Customer, title and reporting period", "identity", ["header"], 1),
    source("report.metrics", "Security metrics", "Tenant KPIs and defense score", "metrics", ["metrics"], 12, METRIC_KEYS),
    source("report.severityCounts", "Severity distribution", "Critical, high, medium and low incidents", "risk", ["severity"], 4),
    source("report.priorityIncidents", "Priority incidents", "Highest priority incidents in the period", "incidents", ["incidents"], 20),
    source("report.topSourceIps", "Top source IPs", "Ranked source addresses", "rankings", ["topSources"], 20),
    source("report.topEventIds", "Top event IDs", "Most frequent security event IDs", "rankings", ["topEvents"], 20),
    source("report.recommendations", "Recommendations", "Recommended follow-up actions", "guidance", ["recommendations"], 20),
    source("report.coverage", "Coverage note", "Collection and visibility caveats", "narrative", ["coverage"], 1),
    source("studio.text", "Text note", "Operator-authored narrative", "narrative", ["text"], 1),
    source("studio.divider", "Section divider", "Visual separation between sections", "narrative", ["divider"], 1)
  ];

  const studioState = {
    initialized: false,
    api: null,
    toast: null,
    getTenant: () => "default",
    templates: [],
    dataSources: fallbackDataSources,
    current: null,
    selectedBlockId: "",
    history: [],
    future: [],
    dirty: false,
    isDraft: false,
    tenantGeneration: 0,
    syncGeneration: 0,
    templatesOnline: false,
    busy: false,
    busyToken: 0,
    drag: null,
    dropTargetId: "",
    dropAfter: false,
    contrastNotice: ""
  };

  const byId = id => document.getElementById(id);
  const list = value => Array.isArray(value) ? value : [];
  const clone = value => value === undefined ? undefined : JSON.parse(JSON.stringify(value));
  const read = (item, ...keys) => {
    for (const key of keys) {
      if (item?.[key] !== undefined && item[key] !== null) return item[key];
      const pascal = key.charAt(0).toUpperCase() + key.slice(1);
      if (item?.[pascal] !== undefined && item[pascal] !== null) return item[pascal];
    }
    return undefined;
  };
  const text = (value, maximum = 500) => String(value ?? "").replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, "").slice(0, maximum);
  const oneOf = (value, allowed, fallback) => allowed.includes(String(value)) ? String(value) : fallback;
  const integer = (value, minimum, maximum, fallback) => {
    const number = Number(value);
    return Number.isInteger(number) ? Math.min(maximum, Math.max(minimum, number)) : fallback;
  };

  function source(dataSourceId, label, description, category, allowedBlockTypes, maxLimit, metricKeys = []) {
    return { dataSourceId, label, description, category, allowedBlockTypes, maxLimit, metricKeys };
  }

  function id(prefix = "block") {
    const token = globalThis.crypto?.randomUUID?.() || `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
    return `${prefix}-${token}`.replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 64);
  }

  function normalizeHex(value, group, fallback) {
    const candidate = String(value || "").trim().toUpperCase();
    const valid = /^#[0-9A-F]{6}$/.test(candidate) ? candidate : fallback;
    return nearestColor(valid, COLOR_GROUPS[group]);
  }

  function nearestColor(value, palette) {
    if (palette.includes(value)) return value;
    const rgb = hexRgb(value) || hexRgb(palette[0]);
    return palette.reduce((best, candidate) => {
      const next = hexRgb(candidate);
      const distance = (rgb[0] - next[0]) ** 2 + (rgb[1] - next[1]) ** 2 + (rgb[2] - next[2]) ** 2;
      return distance < best.distance ? { value: candidate, distance } : best;
    }, { value: palette[0], distance: Number.POSITIVE_INFINITY }).value;
  }

  function hexRgb(value) {
    const match = /^#([0-9A-F]{2})([0-9A-F]{2})([0-9A-F]{2})$/i.exec(String(value || ""));
    return match ? match.slice(1).map(part => Number.parseInt(part, 16)) : null;
  }

  function contrastRatio(first, second) {
    const luminance = value => {
      const rgb = hexRgb(value).map(channel => {
        const normalized = channel / 255;
        return normalized <= .03928 ? normalized / 12.92 : ((normalized + .055) / 1.055) ** 2.4;
      });
      return .2126 * rgb[0] + .7152 * rgb[1] + .0722 * rgb[2];
    };
    const one = luminance(first);
    const two = luminance(second);
    return (Math.max(one, two) + .05) / (Math.min(one, two) + .05);
  }

  function ensureContrast(backgroundColor, textColor) {
    if (contrastRatio(backgroundColor, textColor) >= 4.5) return textColor;
    return ["#252C38", "#F8FAFC"].sort((a, b) => contrastRatio(backgroundColor, b) - contrastRatio(backgroundColor, a))[0];
  }

  function normalizeTheme(raw = {}) {
    const preset = oneOf(read(raw, "preset"), PRESETS, "executive");
    const defaults = PRESET_THEMES[preset] || PRESET_THEMES.executive;
    const backgroundColor = normalizeHex(read(raw, "backgroundColor"), "background", defaults.backgroundColor);
    const requestedText = normalizeHex(read(raw, "textColor"), "text", defaults.textColor);
    return {
      preset,
      primaryColor: normalizeHex(read(raw, "primaryColor"), "primary", defaults.primaryColor),
      accentColor: normalizeHex(read(raw, "accentColor"), "accent", defaults.accentColor),
      backgroundColor,
      textColor: ensureContrast(backgroundColor, requestedText),
      fontFamily: oneOf(read(raw, "fontFamily"), FONTS, defaults.fontFamily)
    };
  }

  function normalizePage(raw = {}) {
    return {
      size: oneOf(read(raw, "size"), PAGE_SIZES, "a4"),
      orientation: oneOf(read(raw, "orientation"), ORIENTATIONS, "portrait"),
      margin: oneOf(read(raw, "margin"), MARGINS, "normal"),
      columns: integer(read(raw, "columns"), 1, 2, 2),
      density: oneOf(read(raw, "density"), DENSITIES, "comfortable"),
      showHeader: read(raw, "showHeader") !== false,
      showFooter: read(raw, "showFooter") !== false
    };
  }

  function normalizeBlock(raw = {}, usedIds = new Set()) {
    let blockId = text(read(raw, "blockId"), 64).replace(/[^a-zA-Z0-9_-]/g, "") || id();
    if (!/^[a-zA-Z0-9]/.test(blockId)) blockId = `block-${blockId}`.slice(0, 64);
    if (usedIds.has(blockId.toLowerCase())) blockId = id();
    usedIds.add(blockId.toLowerCase());
    const type = oneOf(read(raw, "type"), TYPES, "text");
    const meta = TYPE_META[type];
    const defaultLimit = type === "incidents" ? 8 : type === "metrics" ? 6 : Math.min(5, BLOCK_LIMITS[type]);
    return {
      blockId,
      type,
      dataSourceId: BLOCK_SOURCE_IDS[type] || null,
      title: text(read(raw, "title") || meta.label, 120),
      width: oneOf(read(raw, "width"), WIDTHS, meta.width),
      style: oneOf(read(raw, "style"), BLOCK_STYLES, "default"),
      limit: integer(read(raw, "limit"), 1, BLOCK_LIMITS[type], defaultLimit),
      visible: read(raw, "visible") !== false,
      pageBreakBefore: read(raw, "pageBreakBefore") === true,
      metricKeys: [...new Set(list(read(raw, "metricKeys")).map(String).filter(key => METRIC_KEYS.includes(key)))].slice(0, 12),
      text: text(read(raw, "text"), 2000)
    };
  }

  function normalizeTemplate(raw = {}) {
    const usedIds = new Set();
    const blocks = list(read(raw, "blocks")).slice(0, MAX_BLOCKS).map(block => normalizeBlock(block, usedIds));
    return {
      templateId: text(read(raw, "templateId"), 128) || id("draft"),
      tenantId: text(read(raw, "tenantId"), 128) || studioState.getTenant(),
      name: text(read(raw, "name") || "Untitled report", 100),
      description: text(read(raw, "description"), 500),
      isBuiltIn: read(raw, "isBuiltIn") === true,
      version: integer(read(raw, "version"), 1, 1000000, 1),
      theme: normalizeTheme(read(raw, "theme") || {}),
      page: normalizePage(read(raw, "page") || {}),
      blocks,
      createdAtUtc: text(read(raw, "createdAtUtc"), 64),
      updatedAtUtc: text(read(raw, "updatedAtUtc"), 64)
    };
  }

  function normalizeDataSource(raw) {
    const dataSourceId = text(read(raw, "dataSourceId"), 128);
    if (!dataSourceId) return null;
    const allowedBlockTypes = list(read(raw, "allowedBlockTypes")).map(String).filter(type => TYPES.includes(type));
    if (!allowedBlockTypes.length) return null;
    return {
      dataSourceId,
      label: text(read(raw, "label") || dataSourceId, 120),
      description: text(read(raw, "description"), 300),
      category: text(read(raw, "category") || "narrative", 40),
      allowedBlockTypes,
      maxLimit: integer(read(raw, "maxLimit"), 1, 100, 20),
      metricKeys: list(read(raw, "metricKeys")).map(String).filter(key => METRIC_KEYS.includes(key)).slice(0, 12)
    };
  }

  function templateBlock(blockId, type, dataSourceId, title, width, options = {}) {
    return normalizeBlock({ blockId, type, dataSourceId, title, width, ...options });
  }

  function builtInTemplate(templateId, name, description, preset, blocks, page = {}) {
    return normalizeTemplate({
      templateId,
      tenantId: "default",
      name,
      description,
      isBuiltIn: true,
      version: 1,
      theme: PRESET_THEMES[preset],
      page: { size: "a4", orientation: "portrait", margin: "normal", columns: 2, density: "comfortable", showHeader: true, showFooter: true, ...page },
      blocks
    });
  }

  function fallbackTemplates() {
    return [
      builtInTemplate("builtin-executive", "Executive Security Brief", "Board-ready posture, impact and next actions", "executive", [
        templateBlock("exec-identity", "header", "report.identity", "Executive security brief", "full", { style: "plain" }),
        templateBlock("exec-metrics", "metrics", "report.metrics", "Security posture at a glance", "full", { style: "card", metricKeys: ["defenseScore", "threatEvents", "incidents", "onlineAgents"] }),
        templateBlock("exec-severity", "severity", "report.severityCounts", "Risk distribution", "half", { style: "accent" }),
        templateBlock("exec-sources", "topSources", "report.topSourceIps", "Top external sources", "half"),
        templateBlock("exec-incidents", "incidents", "report.priorityIncidents", "Priority incidents", "full", { limit: 6 }),
        templateBlock("exec-actions", "recommendations", "report.recommendations", "Recommended decisions", "full", { style: "accent" }),
        templateBlock("exec-coverage", "coverage", "report.coverage", "Coverage & confidence", "full", { style: "plain" })
      ]),
      builtInTemplate("builtin-technical", "Technical SOC Review", "Dense operational detail for SOC and engineering", "technical", [
        templateBlock("tech-identity", "header", "report.identity", "SOC technical review", "full", { style: "plain" }),
        templateBlock("tech-metrics", "metrics", "report.metrics", "Operational metrics", "full", { metricKeys: ["agents", "onlineAgents", "assets", "threatEvents", "incidents", "openIncidents"] }),
        templateBlock("tech-events", "topEvents", "report.topEventIds", "Top event IDs", "half", { limit: 10 }),
        templateBlock("tech-sources", "topSources", "report.topSourceIps", "Top source IPs", "half", { limit: 10 }),
        templateBlock("tech-severity", "severity", "report.severityCounts", "Severity profile", "full"),
        templateBlock("tech-incidents", "incidents", "report.priorityIncidents", "Incident ledger", "full", { limit: 12 }),
        templateBlock("tech-coverage", "coverage", "report.coverage", "Telemetry coverage", "full", { style: "plain" })
      ], { density: "compact" }),
      builtInTemplate("builtin-compact", "Compact Monthly", "Clean one-page customer summary", "minimal", [
        templateBlock("compact-identity", "header", "report.identity", "Monthly security summary", "full", { style: "plain" }),
        templateBlock("compact-metrics", "metrics", "report.metrics", "Key outcomes", "full", { metricKeys: ["defenseScore", "incidents", "threatCampaigns", "assets"] }),
        templateBlock("compact-severity", "severity", "report.severityCounts", "Severity", "half"),
        templateBlock("compact-actions", "recommendations", "report.recommendations", "Next steps", "half", { limit: 5 }),
        templateBlock("compact-incidents", "incidents", "report.priorityIncidents", "Priority incidents", "full", { limit: 5 }),
        templateBlock("compact-coverage", "coverage", "report.coverage", "Coverage", "full", { style: "plain" })
      ], { margin: "compact", density: "compact" }),
      builtInTemplate("builtin-risk-exposure", "Risk & Exposure", "Threat origins, severity and exposure narrative", "midnight", [
        templateBlock("risk-identity", "header", "report.identity", "Risk and exposure review", "full", { style: "plain" }),
        templateBlock("risk-score", "metrics", "report.metrics", "Exposure indicators", "full", { style: "accent", metricKeys: ["defenseScore", "critical", "high", "openIncidents"] }),
        templateBlock("risk-severity", "severity", "report.severityCounts", "Risk concentration", "third"),
        templateBlock("risk-sources", "topSources", "report.topSourceIps", "Threat origins", "third"),
        templateBlock("risk-events", "topEvents", "report.topEventIds", "Detection signals", "third"),
        templateBlock("risk-incidents", "incidents", "report.priorityIncidents", "Material incidents", "full", { limit: 8 }),
        templateBlock("risk-actions", "recommendations", "report.recommendations", "Risk treatment", "full", { style: "accent" })
      ], { orientation: "landscape" }),
      builtInTemplate("builtin-client-review", "Client Service Review", "Polished customer-facing outcomes and guidance", "signal", [
        templateBlock("client-identity", "header", "report.identity", "Customer security review", "full", { style: "plain" }),
        templateBlock("client-metrics", "metrics", "report.metrics", "Protection outcomes", "full", { style: "card", metricKeys: ["defenseScore", "threatEvents", "incidents", "onlineAgents"] }),
        templateBlock("client-note", "text", null, "Service narrative", "full", { style: "accent", text: "NT Shield monitored the customer environment throughout this reporting period. The sections below summarize material detections and recommended follow-up." }),
        templateBlock("client-incidents", "incidents", "report.priorityIncidents", "What required attention", "full", { limit: 6 }),
        templateBlock("client-actions", "recommendations", "report.recommendations", "Recommended next steps", "half"),
        templateBlock("client-coverage", "coverage", "report.coverage", "Monitoring coverage", "half", { style: "plain" })
      ])
    ];
  }

  function init(options = {}) {
    if (studioState.initialized) return globalThis.NTShieldReportStudio;
    studioState.api = options.requestJson;
    studioState.toast = options.toast;
    studioState.getTenant = options.getTenant || (() => "default");
    studioState.templates = fallbackTemplates();
    studioState.dataSources = fallbackDataSources;
    studioState.initialized = true;
    bindStudio();
    selectTemplate(studioState.templates[0].templateId, { quiet: true });
    renderPalette();
    return globalThis.NTShieldReportStudio;
  }

  async function sync() {
    if (!studioState.initialized || !studioState.api || studioState.busy) return false;
    const generation = ++studioState.syncGeneration;
    const tenantId = studioState.getTenant();
    const headers = { "X-NTShield-Tenant": tenantId };
    setTemplateState("Loading templates…");
    setDataSourceState("Loading");
    const [templateResult, sourceResult] = await Promise.allSettled([
      studioState.api(TEMPLATE_API, { headers }),
      loadDataSources(headers)
    ]);
    if (generation !== studioState.syncGeneration || tenantId !== studioState.getTenant()) return false;

    if (templateResult.status === "fulfilled") {
      const remote = list(templateResult.value).map(normalizeTemplate);
      studioState.templates = mergeBuiltIns(remote);
      studioState.templatesOnline = true;
      setTemplateState(`${studioState.templates.length} templates`);
    } else {
      studioState.templates = fallbackTemplates();
      studioState.templatesOnline = false;
      setTemplateState("Built-ins · server unavailable", "error");
    }

    if (sourceResult.status === "fulfilled") {
      const remote = list(sourceResult.value).map(normalizeDataSource).filter(Boolean);
      studioState.dataSources = mergeLocalSources(remote.length ? remote : fallbackDataSources);
      setDataSourceState(`${studioState.dataSources.length} sources`);
    } else {
      studioState.dataSources = fallbackDataSources;
      setDataSourceState("Built-in sources");
    }

    if (!studioState.dirty && !studioState.isDraft) {
      const selectedId = studioState.current?.templateId;
      const next = studioState.templates.find(item => item.templateId === selectedId) || studioState.templates[0];
      if (next) selectTemplate(next.templateId, { quiet: true });
    } else {
      renderEditor();
    }
    renderTemplates();
    renderPalette();
    return true;
  }

  async function loadDataSources(headers) {
    try {
      return await studioState.api(DATA_SOURCE_API, { headers });
    } catch (error) {
      if (error?.status !== 404) throw error;
      return studioState.api(LEGACY_DATA_SOURCE_API, { headers });
    }
  }

  function mergeBuiltIns(remote) {
    const byId = new Map(remote.map(item => [item.templateId, item]));
    fallbackTemplates().forEach(item => { if (!byId.has(item.templateId)) byId.set(item.templateId, item); });
    return [...byId.values()].sort((a, b) => Number(b.isBuiltIn) - Number(a.isBuiltIn) || a.name.localeCompare(b.name));
  }

  function mergeLocalSources(remote) {
    const byId = new Map(remote.map(item => [item.dataSourceId, item]));
    fallbackDataSources.filter(item => item.dataSourceId.startsWith("studio.")).forEach(item => byId.set(item.dataSourceId, item));
    return [...byId.values()];
  }

  function resetTenant() {
    if (!studioState.initialized) return;
    studioState.tenantGeneration += 1;
    studioState.syncGeneration += 1;
    studioState.templatesOnline = false;
    studioState.busyToken += 1;
    setStudioBusy(false);
    studioState.templates = fallbackTemplates();
    studioState.dataSources = fallbackDataSources;
    selectTemplate(studioState.templates[0].templateId, { quiet: true });
    setTemplateState("Built-ins ready");
    setDataSourceState("Built-in sources");
    renderTemplates();
    renderPalette();
  }

  async function onPage(page) {
    if (page !== "reports") return false;
    return sync();
  }

  function bindStudio() {
    byId("reportStudioTemplates")?.addEventListener("click", event => {
      const button = event.target.closest("button[data-template-id]");
      if (button) selectTemplate(button.dataset.templateId);
    });
    byId("reportNewTemplate")?.addEventListener("click", newBlankTemplate);
    byId("reportSaveTemplate")?.addEventListener("click", () => void saveTemplate());
    byId("reportDuplicateTemplate")?.addEventListener("click", () => void duplicateTemplate());
    byId("reportDeleteTemplate")?.addEventListener("click", () => void deleteTemplate());
    byId("reportExportTemplate")?.addEventListener("click", exportTemplate);
    byId("reportUndo")?.addEventListener("click", undo);
    byId("reportRedo")?.addEventListener("click", redo);
    byId("reportDuplicateBlock")?.addEventListener("click", duplicateSelectedBlock);
    byId("reportDeleteBlock")?.addEventListener("click", deleteSelectedBlock);
    byId("reportTemplateName")?.addEventListener("change", event => {
      const name = text(event.target.value.trim() || "Untitled report", 100);
      if (name === studioState.current?.name) return;
      mutate("Template name changed", template => { template.name = name; });
    });

    byId("reportPaletteSearch")?.addEventListener("input", renderPalette);
    byId("reportStudioPalette")?.addEventListener("click", event => {
      const button = event.target.closest("button[data-source-id]");
      if (button) addBlockFromSource(button.dataset.sourceId);
    });
    byId("reportStudioPalette")?.addEventListener("dragstart", event => {
      const button = event.target.closest("button[data-source-id]");
      if (!button) return;
      studioState.drag = { kind: "source", id: button.dataset.sourceId };
      event.dataTransfer?.setData("text/plain", `studio-source:${button.dataset.sourceId}`);
      if (event.dataTransfer) event.dataTransfer.effectAllowed = "copy";
    });
    byId("reportStudioPalette")?.addEventListener("dragend", clearDropIndicators);

    globalThis.addEventListener("beforeunload", event => {
      if (!hasUnsavedChanges()) return;
      event.preventDefault();
      event.returnValue = "";
    });

    const canvas = byId("reportStudioCanvas");
    canvas?.addEventListener("dragover", handleCanvasDragOver);
    canvas?.addEventListener("drop", handleCanvasDrop);
    canvas?.addEventListener("dragleave", event => {
      if (!canvas.contains(event.relatedTarget)) clearDropIndicators();
    });
    canvas?.addEventListener("keydown", event => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "z") {
        event.preventDefault();
        if (event.shiftKey) redo(); else undo();
      }
    });

    byId("reportStudioBlocks")?.addEventListener("click", event => {
      const resize = event.target.closest("button[data-resize-block]");
      if (resize) {
        resizeBlock(resize.dataset.resizeBlock);
        return;
      }
      const block = event.target.closest("[data-block-id]");
      if (block) selectBlock(block.dataset.blockId);
    });
    byId("reportStudioBlocks")?.addEventListener("keydown", event => {
      const block = event.target.closest("[data-block-id]");
      if (!block) return;
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        selectBlock(block.dataset.blockId);
      } else if (event.altKey && ["ArrowUp", "ArrowDown"].includes(event.key)) {
        event.preventDefault();
        moveBlock(block.dataset.blockId, event.key === "ArrowUp" ? -1 : 1);
      } else if (event.shiftKey && ["ArrowLeft", "ArrowRight"].includes(event.key)) {
        event.preventDefault();
        resizeBlock(block.dataset.blockId, event.key === "ArrowLeft" ? -1 : 1);
      }
    });
    byId("reportStudioBlocks")?.addEventListener("dragstart", event => {
      const block = event.target.closest("[data-block-id]");
      if (!block) return;
      studioState.drag = { kind: "block", id: block.dataset.blockId };
      block.classList.add("dragging");
      event.dataTransfer?.setData("text/plain", `studio-block:${block.dataset.blockId}`);
      if (event.dataTransfer) event.dataTransfer.effectAllowed = "move";
    });
    byId("reportStudioBlocks")?.addEventListener("dragend", clearDropIndicators);

    byId("reportStudioLayers")?.addEventListener("click", event => {
      const button = event.target.closest("button[data-layer-id]");
      if (button) selectBlock(button.dataset.layerId);
    });
    byId("reportBlockForm")?.addEventListener("submit", applyBlockInspector);
    byId("reportBlockDataSource")?.addEventListener("change", updateInspectorDataSourceRules);
    byId("reportMoveBlockUp")?.addEventListener("click", () => moveBlock(studioState.selectedBlockId, -1));
    byId("reportMoveBlockDown")?.addEventListener("click", () => moveBlock(studioState.selectedBlockId, 1));

    byId("reportThemePreset")?.addEventListener("change", event => {
      const preset = oneOf(event.target.value, PRESETS, "executive");
      mutate("Theme changed", template => {
        template.theme = clone(PRESET_THEMES[preset]);
        studioState.contrastNotice = "";
      });
    });
    byId("reportFontFamily")?.addEventListener("change", event => mutate("Typography changed", template => { template.theme.fontFamily = oneOf(event.target.value, FONTS, "system"); }));
    byId("reportPageSize")?.addEventListener("change", event => mutate("Page size changed", template => { template.page.size = oneOf(event.target.value, PAGE_SIZES, "a4"); }));
    byId("reportOrientation")?.addEventListener("change", event => mutate("Orientation changed", template => { template.page.orientation = oneOf(event.target.value, ORIENTATIONS, "portrait"); }));
    byId("reportMargin")?.addEventListener("change", event => mutate("Margin changed", template => { template.page.margin = oneOf(event.target.value, MARGINS, "normal"); }));
    byId("reportColumns")?.addEventListener("change", event => mutate("Columns changed", template => { template.page.columns = integer(event.target.value, 1, 2, 2); }));
    byId("reportDensity")?.addEventListener("change", event => mutate("Density changed", template => { template.page.density = oneOf(event.target.value, DENSITIES, "comfortable"); }));
    byId("reportShowHeader")?.addEventListener("change", event => mutate("Page header changed", template => { template.page.showHeader = event.target.checked; }));
    byId("reportShowFooter")?.addEventListener("change", event => mutate("Page footer changed", template => { template.page.showFooter = event.target.checked; }));
    [
      ["reportPrimaryColor", "primaryColor", "primary"],
      ["reportAccentColor", "accentColor", "accent"],
      ["reportBackgroundColor", "backgroundColor", "background"],
      ["reportTextColor", "textColor", "text"]
    ].forEach(([controlId, property, group]) => byId(controlId)?.addEventListener("change", event => {
      const snapped = normalizeHex(event.target.value, group, PRESET_THEMES.custom[property]);
      mutate("Brand color changed", template => {
        template.theme.preset = "custom";
        template.theme[property] = snapped;
        const requestedText = template.theme.textColor;
        const adjustedText = ensureContrast(template.theme.backgroundColor, requestedText);
        template.theme.textColor = adjustedText;
        studioState.contrastNotice = adjustedText === requestedText
          ? "สีถูกจำกัดเป็น #RRGGBB ใน CSP allowlist"
          : "ปรับสีตัวอักษรอัตโนมัติเพื่อให้ contrast อย่างน้อย 4.5:1";
      });
    }));
  }

  function selectTemplate(templateId, options = {}) {
    if (studioState.busy && !options.force) return false;
    const template = studioState.templates.find(item => item.templateId === templateId);
    if (!template) return false;
    if (studioState.dirty && !options.quiet && !globalThis.confirm("Discard unsaved template changes?")) return false;
    studioState.current = clone(template);
    studioState.selectedBlockId = studioState.current.blocks[0]?.blockId || "";
    studioState.history = [];
    studioState.future = [];
    studioState.dirty = false;
    studioState.isDraft = false;
    studioState.contrastNotice = "";
    renderEditor();
    renderTemplates();
    setSaveState(template.isBuiltIn ? "Built-in · edit to create a copy" : "Saved");
    return true;
  }

  function newBlankTemplate() {
    if (studioState.busy) return;
    if (studioState.dirty && !globalThis.confirm("Discard unsaved template changes?")) return;
    studioState.current = normalizeTemplate({
      templateId: id("draft"),
      tenantId: studioState.getTenant(),
      name: "Untitled report",
      description: "Custom report template",
      isBuiltIn: false,
      theme: PRESET_THEMES.executive,
      page: { size: "a4", orientation: "portrait", margin: "normal", columns: 2, density: "comfortable", showHeader: true, showFooter: true },
      blocks: []
    });
    studioState.selectedBlockId = "";
    studioState.history = [];
    studioState.future = [];
    studioState.dirty = true;
    studioState.isDraft = true;
    studioState.contrastNotice = "";
    renderEditor();
    renderTemplates();
    setSaveState("Unsaved blank template", "dirty");
  }

  function mutate(label, operation) {
    if (!studioState.current || studioState.busy) return;
    studioState.history.push(clone(studioState.current));
    if (studioState.history.length > MAX_HISTORY) studioState.history.shift();
    studioState.future = [];
    operation(studioState.current);
    studioState.current = normalizeTemplate(studioState.current);
    studioState.dirty = true;
    if (!studioState.current.blocks.some(item => item.blockId === studioState.selectedBlockId)) studioState.selectedBlockId = studioState.current.blocks[0]?.blockId || "";
    renderEditor();
    renderTemplates();
    setSaveState(label, "dirty");
  }

  function undo() {
    if (studioState.busy) return;
    const previous = studioState.history.pop();
    if (!previous || !studioState.current) return;
    studioState.future.push(clone(studioState.current));
    studioState.current = normalizeTemplate(previous);
    studioState.dirty = true;
    if (!studioState.current.blocks.some(item => item.blockId === studioState.selectedBlockId)) studioState.selectedBlockId = studioState.current.blocks[0]?.blockId || "";
    renderEditor();
    setSaveState("Undo applied", "dirty");
  }

  function redo() {
    if (studioState.busy) return;
    const next = studioState.future.pop();
    if (!next || !studioState.current) return;
    studioState.history.push(clone(studioState.current));
    studioState.current = normalizeTemplate(next);
    studioState.dirty = true;
    if (!studioState.current.blocks.some(item => item.blockId === studioState.selectedBlockId)) studioState.selectedBlockId = studioState.current.blocks[0]?.blockId || "";
    renderEditor();
    setSaveState("Redo applied", "dirty");
  }

  function templatePayload(template) {
    const safe = normalizeTemplate(template);
    return {
      version: safe.version,
      name: safe.name,
      description: safe.description,
      theme: safe.theme,
      page: safe.page,
      blocks: safe.blocks
    };
  }

  async function saveTemplate() {
    const current = studioState.current;
    if (!current || !studioState.api || studioState.busy) return null;
    if (!current.blocks.length) {
      setSaveState("Add at least 1 block before saving", "error");
      studioState.toast?.("เพิ่มอย่างน้อย 1 block ก่อนบันทึก Template");
      return null;
    }
    const tenantId = studioState.getTenant();
    const generation = studioState.tenantGeneration;
    const create = current.isBuiltIn || studioState.isDraft;
    const path = create ? TEMPLATE_API : `${TEMPLATE_API}/${encodeURIComponent(current.templateId)}`;
    studioState.syncGeneration += 1;
    const operationToken = beginStudioOperation();
    setSaveState("Saving…", "saving");
    try {
      const saved = await studioState.api(path, {
        method: create ? "POST" : "PUT",
        headers: { "X-NTShield-Tenant": tenantId },
        body: templatePayload(current)
      });
      if (generation !== studioState.tenantGeneration || tenantId !== studioState.getTenant()) return null;
      const normalized = normalizeTemplate(saved);
      studioState.templates = [...studioState.templates.filter(item => item.templateId !== normalized.templateId), normalized]
        .sort((a, b) => Number(b.isBuiltIn) - Number(a.isBuiltIn) || a.name.localeCompare(b.name));
      studioState.current = clone(normalized);
      studioState.selectedBlockId = normalized.blocks.some(item => item.blockId === studioState.selectedBlockId) ? studioState.selectedBlockId : normalized.blocks[0]?.blockId || "";
      studioState.history = [];
      studioState.future = [];
      studioState.dirty = false;
      studioState.isDraft = false;
      studioState.templatesOnline = true;
      renderEditor();
      renderTemplates();
      setSaveState("Saved to Central");
      studioState.toast?.("บันทึก Report template แล้ว");
      return clone(normalized);
    } catch (error) {
      if (generation !== studioState.tenantGeneration || tenantId !== studioState.getTenant()) return null;
      if (error?.status === 409 && /version_conflict/i.test(error?.message || "")) {
        setSaveState("Version conflict · reload or duplicate", "error");
        studioState.toast?.("Template ถูกแก้จากอีกหน้าต่าง — Reload templates หรือ Duplicate ก่อนบันทึก ห้ามเขียนทับอัตโนมัติ");
      } else {
        setSaveState(`Save failed · ${text(error?.message || "Central unavailable", 90)}`, "error");
        studioState.toast?.(`บันทึก Template ไม่สำเร็จ: ${error?.message || "Central unavailable"}`);
      }
      return null;
    } finally {
      finishStudioOperation(operationToken);
    }
  }

  async function ensureSaved() {
    if (!studioState.current) return null;
    if (!studioState.dirty && !studioState.isDraft && (studioState.templatesOnline || !studioState.current.isBuiltIn)) return studioState.current.templateId;
    const saved = await saveTemplate();
    return saved?.templateId || null;
  }

  async function duplicateTemplate() {
    const current = studioState.current;
    if (!current || studioState.busy) return;
    const copyName = text(`${current.name} Copy`, 100);
    if (!studioState.dirty && !studioState.isDraft && studioState.templatesOnline && studioState.api) {
      const tenantId = studioState.getTenant();
      const generation = studioState.tenantGeneration;
      studioState.syncGeneration += 1;
      const operationToken = beginStudioOperation();
      setSaveState("Duplicating…", "saving");
      try {
        const saved = normalizeTemplate(await studioState.api(`${TEMPLATE_API}/${encodeURIComponent(current.templateId)}/duplicate`, {
          method: "POST",
          headers: { "X-NTShield-Tenant": tenantId },
          body: { name: copyName }
        }));
        if (generation !== studioState.tenantGeneration || tenantId !== studioState.getTenant()) return;
        studioState.templates.push(saved);
        selectTemplate(saved.templateId, { quiet: true, force: true });
        studioState.toast?.("Duplicate template แล้ว");
        return;
      } catch (error) {
        if (generation !== studioState.tenantGeneration || tenantId !== studioState.getTenant()) return;
        studioState.toast?.(`Duplicate บน Central ไม่สำเร็จ — สร้าง Local draft แทน: ${error?.message || "unknown error"}`);
      } finally {
        finishStudioOperation(operationToken);
      }
    }
    const local = normalizeTemplate({ ...clone(current), templateId: id("draft"), name: copyName, isBuiltIn: false, version: 1, tenantId: studioState.getTenant(), createdAtUtc: "", updatedAtUtc: "" });
    studioState.current = local;
    studioState.selectedBlockId = local.blocks[0]?.blockId || "";
    studioState.history = [];
    studioState.future = [];
    studioState.dirty = true;
    studioState.isDraft = true;
    renderEditor();
    renderTemplates();
    setSaveState("Local copy · save to Central", "dirty");
  }

  async function deleteTemplate() {
    const current = studioState.current;
    if (!current || studioState.busy) return;
    if (current.isBuiltIn) {
      studioState.toast?.("Built-in template เป็น Read-only — Duplicate ก่อนแก้หรือลบ");
      return;
    }
    if (!globalThis.confirm(`Delete template “${current.name}”?`)) return;
    if (studioState.isDraft) {
      selectTemplate(studioState.templates[0].templateId, { quiet: true });
      return;
    }
    const tenantId = studioState.getTenant();
    const generation = studioState.tenantGeneration;
    studioState.syncGeneration += 1;
    const operationToken = beginStudioOperation();
    setSaveState("Deleting…", "saving");
    try {
      await studioState.api(`${TEMPLATE_API}/${encodeURIComponent(current.templateId)}`, { method: "DELETE", headers: { "X-NTShield-Tenant": tenantId } });
      if (generation !== studioState.tenantGeneration || tenantId !== studioState.getTenant()) return;
      studioState.templates = studioState.templates.filter(item => item.templateId !== current.templateId);
      selectTemplate(studioState.templates[0]?.templateId, { quiet: true, force: true });
      studioState.toast?.("ลบ Custom template แล้ว");
    } catch (error) {
      if (generation !== studioState.tenantGeneration || tenantId !== studioState.getTenant()) return;
      setSaveState(`Delete failed · ${text(error?.message, 90)}`, "error");
      studioState.toast?.(`ลบ Template ไม่สำเร็จ: ${error?.message || "Central unavailable"}`);
    } finally {
      finishStudioOperation(operationToken);
    }
  }

  function selectBlock(blockId) {
    if (!studioState.current?.blocks.some(item => item.blockId === blockId)) return;
    studioState.selectedBlockId = blockId;
    renderCanvas();
    renderLayers();
    renderInspector();
    updateActionControls();
  }

  function addBlockFromSource(sourceId, index = studioState.current?.blocks.length || 0) {
    const sourceItem = studioState.dataSources.find(item => item.dataSourceId === sourceId);
    if (!sourceItem || !studioState.current || studioState.current.blocks.length >= MAX_BLOCKS) {
      if (studioState.current?.blocks.length >= MAX_BLOCKS) studioState.toast?.(`Template รองรับสูงสุด ${MAX_BLOCKS} blocks`);
      return;
    }
    const type = sourceItem.allowedBlockTypes[0];
    const block = normalizeBlock({
      blockId: id(),
      type,
      dataSourceId: sourceId.startsWith("studio.") ? null : sourceId,
      title: sourceItem.label,
      width: TYPE_META[type].width,
      style: type === "header" || type === "coverage" || type === "divider" ? "plain" : "default",
      limit: Math.min(sourceItem.maxLimit, type === "incidents" ? 8 : 5),
      visible: true,
      metricKeys: sourceItem.metricKeys,
      text: type === "text" ? "Add an evidence-grounded narrative for this customer report." : ""
    });
    mutate(`${sourceItem.label} added`, template => template.blocks.splice(Math.max(0, Math.min(index, template.blocks.length)), 0, block));
    studioState.selectedBlockId = block.blockId;
    renderEditor();
  }

  function duplicateSelectedBlock() {
    const index = studioState.current?.blocks.findIndex(item => item.blockId === studioState.selectedBlockId) ?? -1;
    if (index < 0 || studioState.current.blocks.length >= MAX_BLOCKS) return;
    const copy = normalizeBlock({ ...clone(studioState.current.blocks[index]), blockId: id(), title: text(`${studioState.current.blocks[index].title} Copy`, 120) });
    mutate("Block duplicated", template => template.blocks.splice(index + 1, 0, copy));
    studioState.selectedBlockId = copy.blockId;
    renderEditor();
  }

  function deleteSelectedBlock() {
    const blockId = studioState.selectedBlockId;
    if (!blockId || !studioState.current) return;
    const index = studioState.current.blocks.findIndex(item => item.blockId === blockId);
    if (index < 0) return;
    mutate("Block deleted", template => template.blocks.splice(index, 1));
    studioState.selectedBlockId = studioState.current.blocks[Math.min(index, studioState.current.blocks.length - 1)]?.blockId || "";
    renderEditor();
  }

  function moveBlock(blockId, delta) {
    const index = studioState.current?.blocks.findIndex(item => item.blockId === blockId) ?? -1;
    const target = index + delta;
    if (index < 0 || target < 0 || target >= studioState.current.blocks.length) return;
    mutate("Block moved", template => {
      const [block] = template.blocks.splice(index, 1);
      template.blocks.splice(target, 0, block);
    });
    studioState.selectedBlockId = blockId;
    renderEditor();
  }

  function resizeBlock(blockId, direction = 1) {
    const block = studioState.current?.blocks.find(item => item.blockId === blockId);
    if (!block) return;
    const order = ["third", "half", "full"];
    const current = order.indexOf(block.width);
    const next = order[(current + direction + order.length) % order.length];
    mutate(`Width snapped to ${next}`, template => { template.blocks.find(item => item.blockId === blockId).width = next; });
    studioState.selectedBlockId = blockId;
    renderEditor();
  }

  function handleCanvasDragOver(event) {
    if (!studioState.drag && !event.dataTransfer?.types?.includes("text/plain")) return;
    event.preventDefault();
    if (event.dataTransfer) event.dataTransfer.dropEffect = studioState.drag?.kind === "source" ? "copy" : "move";
    const target = event.target.closest(".studio-block[data-block-id]");
    clearDropIndicators({ preserveDrag: true });
    byId("reportStudioPage")?.classList.add("drag-active");
    if (!target) {
      studioState.dropTargetId = "";
      studioState.dropAfter = true;
      return;
    }
    const bounds = target.getBoundingClientRect();
    const verticalRatio = bounds.height ? (event.clientY - bounds.top) / bounds.height : .5;
    const after = verticalRatio > .65 || (verticalRatio >= .35 && event.clientX > bounds.left + bounds.width / 2);
    studioState.dropTargetId = target.dataset.blockId;
    studioState.dropAfter = after;
    target.classList.add(after ? "drop-after" : "drop-before");
  }

  function handleCanvasDrop(event) {
    event.preventDefault();
    if (!studioState.current) return;
    const raw = event.dataTransfer?.getData("text/plain") || "";
    const drag = studioState.drag || (raw.startsWith("studio-source:")
      ? { kind: "source", id: raw.slice(14) }
      : raw.startsWith("studio-block:") ? { kind: "block", id: raw.slice(13) } : null);
    const targetIndex = studioState.dropTargetId
      ? studioState.current.blocks.findIndex(item => item.blockId === studioState.dropTargetId)
      : studioState.current.blocks.length;
    let insertIndex = targetIndex < 0 ? studioState.current.blocks.length : targetIndex + (studioState.dropAfter ? 1 : 0);
    if (drag?.kind === "source") {
      addBlockFromSource(drag.id, insertIndex);
    } else if (drag?.kind === "block") {
      const sourceIndex = studioState.current.blocks.findIndex(item => item.blockId === drag.id);
      if (sourceIndex >= 0) {
        if (sourceIndex < insertIndex) insertIndex -= 1;
        if (sourceIndex !== insertIndex) {
          mutate("Block reordered", template => {
            const [block] = template.blocks.splice(sourceIndex, 1);
            template.blocks.splice(Math.max(0, Math.min(insertIndex, template.blocks.length)), 0, block);
          });
          studioState.selectedBlockId = drag.id;
          renderEditor();
        }
      }
    }
    clearDropIndicators();
  }

  function clearDropIndicators(options = {}) {
    byId("reportStudioBlocks")?.querySelectorAll(".drop-before,.drop-after,.dragging").forEach(item => item.classList.remove("drop-before", "drop-after", "dragging"));
    byId("reportStudioPage")?.classList.remove("drag-active");
    studioState.dropTargetId = "";
    studioState.dropAfter = false;
    if (!options.preserveDrag) studioState.drag = null;
  }

  function applyBlockInspector(event) {
    event.preventDefault();
    const blockId = studioState.selectedBlockId;
    const block = studioState.current?.blocks.find(item => item.blockId === blockId);
    if (!block) return;
    const sourceId = byId("reportBlockDataSource")?.value || "";
    const sourceItem = studioState.dataSources.find(item => item.dataSourceId === sourceId && item.allowedBlockTypes.includes(block.type));
    const maxLimit = sourceItem?.maxLimit || 20;
    const metricKeys = [...(byId("reportMetricKeys")?.querySelectorAll("input[type=checkbox]:checked") || [])]
      .map(input => input.value).filter(key => METRIC_KEYS.includes(key)).slice(0, 12);
    mutate("Block properties applied", template => {
      const target = template.blocks.find(item => item.blockId === blockId);
      target.title = text(byId("reportBlockTitle")?.value.trim() || TYPE_META[target.type].label, 120);
      target.dataSourceId = sourceId.startsWith("studio.") || !sourceItem ? null : sourceId;
      target.width = oneOf(byId("reportBlockWidth")?.value, WIDTHS, target.width);
      target.style = oneOf(byId("reportBlockStyle")?.value, BLOCK_STYLES, target.style);
      target.limit = integer(byId("reportBlockLimit")?.value, 1, maxLimit, target.limit);
      target.visible = byId("reportBlockVisible")?.value !== "false";
      target.pageBreakBefore = byId("reportBlockPageBreak")?.checked === true;
      target.metricKeys = target.type === "metrics" ? metricKeys : [];
      target.text = target.type === "text" ? text(byId("reportBlockText")?.value, 2000) : target.text;
    });
    studioState.selectedBlockId = blockId;
    renderEditor();
  }

  function updateInspectorDataSourceRules() {
    const block = studioState.current?.blocks.find(item => item.blockId === studioState.selectedBlockId);
    if (!block) return;
    const sourceId = byId("reportBlockDataSource")?.value || "";
    const sourceItem = studioState.dataSources.find(item => item.dataSourceId === sourceId && item.allowedBlockTypes.includes(block.type));
    const limit = byId("reportBlockLimit");
    if (limit) {
      limit.max = String(sourceItem?.maxLimit || 20);
      if (Number(limit.value) > Number(limit.max)) limit.value = limit.max;
    }
    renderMetricKeyOptions(block, sourceItem);
  }

  function renderTemplates() {
    const host = byId("reportStudioTemplates");
    if (!host) return;
    host.replaceChildren();
    studioState.templates.forEach(template => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = `studio-template-card${!studioState.isDraft && template.templateId === studioState.current?.templateId ? " active" : ""}`;
      button.dataset.templateId = template.templateId;
      button.setAttribute("aria-pressed", !studioState.isDraft && template.templateId === studioState.current?.templateId ? "true" : "false");
      const thumb = document.createElement("span");
      const thumbKind = template.templateId.includes("technical") ? "technical"
        : template.templateId.includes("compact") ? "compact"
          : template.templateId.includes("risk") ? "risk"
            : template.templateId.includes("client") ? "client" : "executive";
      thumb.className = `studio-template-thumb ${thumbKind}`;
      thumb.setAttribute("aria-hidden", "true");
      for (let index = 0; index < 7; index += 1) thumb.append(document.createElement("i"));
      const copy = document.createElement("span");
      copy.className = "studio-template-copy";
      const label = document.createElement("strong");
      label.textContent = template.name;
      const description = document.createElement("small");
      description.textContent = template.description || `${template.blocks.length} report blocks`;
      const kind = document.createElement("em");
      kind.textContent = template.isBuiltIn ? "Built-in" : `Custom · v${template.version}`;
      copy.append(label, description, kind);
      button.append(thumb, copy);
      host.append(button);
    });
  }

  function renderPalette() {
    const host = byId("reportStudioPalette");
    if (!host) return;
    const query = String(byId("reportPaletteSearch")?.value || "").trim().toLowerCase();
    const visible = studioState.dataSources.filter(item => !query || `${item.label} ${item.description} ${item.category}`.toLowerCase().includes(query));
    const groups = new Map();
    visible.forEach(item => {
      if (!groups.has(item.category)) groups.set(item.category, []);
      groups.get(item.category).push(item);
    });
    host.replaceChildren();
    groups.forEach((items, category) => {
      const group = document.createElement("section");
      group.className = "studio-palette-group";
      const heading = document.createElement("h3");
      heading.textContent = category;
      group.append(heading);
      items.forEach(item => {
        const type = item.allowedBlockTypes[0];
        const button = document.createElement("button");
        button.type = "button";
        button.className = "studio-palette-item";
        button.draggable = true;
        button.dataset.sourceId = item.dataSourceId;
        const icon = document.createElement("span");
        icon.className = "studio-palette-icon";
        icon.textContent = TYPE_META[type]?.icon || "DATA";
        const copy = document.createElement("span");
        copy.className = "studio-palette-copy";
        const label = document.createElement("strong");
        label.textContent = item.label;
        const detail = document.createElement("small");
        detail.textContent = item.description;
        copy.append(label, detail);
        const add = document.createElement("em");
        add.textContent = "+";
        button.append(icon, copy, add);
        group.append(button);
      });
      host.append(group);
    });
    if (!visible.length) {
      const empty = document.createElement("p");
      empty.className = "studio-output-empty";
      empty.textContent = "No data blocks match this search";
      host.append(empty);
    }
  }

  function renderEditor() {
    if (!studioState.current) return;
    const name = byId("reportTemplateName");
    if (name && document.activeElement !== name) name.value = studioState.current.name;
    applyPageData(byId("reportStudioPage"), studioState.current);
    renderThemeControls();
    renderCanvas();
    renderLayers();
    renderInspector();
    updateActionControls();
    const count = studioState.current.blocks.length;
    if (byId("reportCanvasBlockCount")) byId("reportCanvasBlockCount").textContent = `${count} blocks`;
    if (byId("reportLayerCount")) byId("reportLayerCount").textContent = String(count);
    if (byId("reportStudioStatus")) byId("reportStudioStatus").textContent = studioState.isDraft ? "Local draft · save before generation" : studioState.dirty ? "Unsaved layout changes" : `Template v${studioState.current.version}`;
  }

  function applyPageData(element, template) {
    if (!element || !template) return;
    const theme = normalizeTheme(template.theme);
    const page = normalizePage(template.page);
    element.dataset.theme = oneOf(theme.preset, PRESETS, "executive");
    element.dataset.font = oneOf(theme.fontFamily, FONTS, "system");
    element.dataset.size = oneOf(page.size, PAGE_SIZES, "a4");
    element.dataset.orientation = oneOf(page.orientation, ORIENTATIONS, "portrait");
    element.dataset.margin = oneOf(page.margin, MARGINS, "normal");
    element.dataset.columns = String(integer(page.columns, 1, 2, 2));
    element.dataset.density = oneOf(page.density, DENSITIES, "comfortable");
    element.dataset.primary = COLOR_TOKENS[theme.primaryColor] || "ink";
    element.dataset.accent = COLOR_TOKENS[theme.accentColor] || "gold";
    element.dataset.bg = COLOR_TOKENS[theme.backgroundColor] || "white";
    element.dataset.text = COLOR_TOKENS[theme.textColor] || "ink";
    const chrome = element.querySelector(":scope > .studio-page-chrome, :scope > .studio-output-header");
    if (chrome) chrome.hidden = !page.showHeader;
    const footer = element.querySelector(":scope > .studio-page-footer, :scope > .studio-output-footer");
    if (footer) footer.hidden = !page.showFooter;
  }

  function renderThemeControls() {
    const theme = studioState.current.theme;
    const page = studioState.current.page;
    setControlValue("reportThemePreset", theme.preset);
    setControlValue("reportFontFamily", theme.fontFamily);
    setControlValue("reportPageSize", page.size);
    setControlValue("reportOrientation", page.orientation);
    setControlValue("reportMargin", page.margin);
    setControlValue("reportColumns", String(page.columns));
    setControlValue("reportDensity", page.density);
    setControlValue("reportPrimaryColor", theme.primaryColor.toLowerCase());
    setControlValue("reportAccentColor", theme.accentColor.toLowerCase());
    setControlValue("reportBackgroundColor", theme.backgroundColor.toLowerCase());
    setControlValue("reportTextColor", theme.textColor.toLowerCase());
    if (byId("reportShowHeader")) byId("reportShowHeader").checked = page.showHeader;
    if (byId("reportShowFooter")) byId("reportShowFooter").checked = page.showFooter;
    const contrastState = byId("reportContrastState");
    if (contrastState) {
      const ratio = contrastRatio(theme.backgroundColor, theme.textColor);
      contrastState.textContent = studioState.contrastNotice || `Text / paper contrast ${ratio.toFixed(1)}:1 · รับเฉพาะสี #RRGGBB`;
    }
  }

  function setControlValue(controlId, value) {
    const control = byId(controlId);
    if (control && document.activeElement !== control) control.value = value;
  }

  function renderCanvas() {
    const host = byId("reportStudioBlocks");
    const empty = byId("reportStudioEmpty");
    if (!host || !studioState.current) return;
    host.replaceChildren();
    studioState.current.blocks.forEach(block => {
      const card = document.createElement("article");
      card.className = `studio-block${block.blockId === studioState.selectedBlockId ? " selected" : ""}`;
      card.dataset.blockId = block.blockId;
      card.dataset.width = oneOf(block.width, WIDTHS, "full");
      card.dataset.blockStyle = oneOf(block.style, BLOCK_STYLES, "default");
      card.dataset.visible = String(block.visible);
      card.dataset.type = oneOf(block.type, TYPES, "text");
      card.draggable = true;
      card.tabIndex = 0;
      card.setAttribute("role", "listitem");
      card.setAttribute("aria-selected", block.blockId === studioState.selectedBlockId ? "true" : "false");
      card.setAttribute("aria-label", `${block.title}, ${block.width} width${block.visible ? "" : ", hidden"}`);
      const head = document.createElement("header");
      head.className = "studio-block-head";
      const copy = document.createElement("div");
      const type = document.createElement("small");
      type.textContent = block.type;
      const title = document.createElement("strong");
      title.textContent = block.title;
      copy.append(type, title);
      const controls = document.createElement("span");
      controls.className = "studio-block-controls";
      const resize = document.createElement("button");
      resize.type = "button";
      resize.className = "studio-resize-handle";
      resize.dataset.resizeBlock = block.blockId;
      resize.title = `Resize block. Current width: ${block.width}`;
      resize.setAttribute("aria-label", `Resize ${block.title}. Current width ${block.width}`);
      resize.textContent = "↔";
      controls.append(resize);
      head.append(copy, controls);
      card.append(head);
      renderDesignBlockBody(block, card);
      host.append(card);
    });
    if (empty) {
      empty.hidden = studioState.current.blocks.length > 0;
      host.append(empty);
    }
  }

  function renderLayers() {
    const host = byId("reportStudioLayers");
    if (!host || !studioState.current) return;
    host.replaceChildren();
    studioState.current.blocks.forEach((block, index) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = `studio-layer-item${block.blockId === studioState.selectedBlockId ? " active" : ""}`;
      button.dataset.layerId = block.blockId;
      button.setAttribute("role", "option");
      button.setAttribute("aria-selected", block.blockId === studioState.selectedBlockId ? "true" : "false");
      const order = document.createElement("span");
      order.className = "studio-layer-index";
      order.textContent = String(index + 1).padStart(2, "0");
      const copy = document.createElement("span");
      copy.className = "studio-layer-copy";
      const label = document.createElement("strong");
      label.textContent = block.title;
      const detail = document.createElement("small");
      detail.textContent = `${block.type} · ${block.width}`;
      copy.append(label, detail);
      const state = document.createElement("em");
      state.textContent = block.visible ? "●" : "○";
      button.append(order, copy, state);
      host.append(button);
    });
    if (!studioState.current.blocks.length) {
      const empty = document.createElement("p");
      empty.className = "studio-output-empty";
      empty.textContent = "No layers yet";
      host.append(empty);
    }
  }

  function renderInspector() {
    const block = studioState.current?.blocks.find(item => item.blockId === studioState.selectedBlockId);
    const form = byId("reportBlockForm");
    const empty = byId("reportBlockEmpty");
    if (!form || !empty) return;
    form.hidden = !block;
    empty.hidden = Boolean(block);
    if (byId("reportSelectionState")) byId("reportSelectionState").textContent = block ? block.type : "None";
    if (!block) return;
    byId("reportBlockTitle").value = block.title;
    byId("reportBlockWidth").value = block.width;
    byId("reportBlockStyle").value = block.style;
    byId("reportBlockLimit").value = String(block.limit);
    byId("reportBlockVisible").value = String(block.visible);
    byId("reportBlockPageBreak").checked = block.pageBreakBefore;
    byId("reportBlockText").value = block.text;
    byId("reportBlockTextField").hidden = block.type !== "text";
    const select = byId("reportBlockDataSource");
    select.replaceChildren();
    const sources = studioState.dataSources.filter(item => item.allowedBlockTypes.includes(block.type));
    sources.forEach(item => select.append(new Option(item.label, item.dataSourceId)));
    if (!sources.length || ["text", "divider"].includes(block.type)) {
      const sourceId = block.type === "divider" ? "studio.divider" : "studio.text";
      if (![...select.options].some(option => option.value === sourceId)) select.append(new Option(block.type === "divider" ? "Section divider" : "Operator text", sourceId));
    }
    const selectedSource = block.dataSourceId || (block.type === "divider" ? "studio.divider" : block.type === "text" ? "studio.text" : "");
    if ([...select.options].some(option => option.value === selectedSource)) select.value = selectedSource;
    updateInspectorDataSourceRules();
  }

  function renderMetricKeyOptions(block, sourceItem) {
    const field = byId("reportMetricKeyField");
    const host = byId("reportMetricKeys");
    if (!field || !host) return;
    field.hidden = block.type !== "metrics";
    host.replaceChildren();
    if (block.type !== "metrics") return;
    const allowed = sourceItem?.metricKeys?.length ? sourceItem.metricKeys : METRIC_KEYS;
    allowed.slice(0, 12).forEach(key => {
      const label = document.createElement("label");
      const input = document.createElement("input");
      input.type = "checkbox";
      input.value = key;
      input.checked = block.metricKeys.includes(key);
      label.append(input, document.createTextNode(METRIC_LABELS[key] || key));
      host.append(label);
    });
  }

  function updateActionControls() {
    const hasBlock = Boolean(studioState.current?.blocks.some(item => item.blockId === studioState.selectedBlockId));
    if (byId("reportUndo")) byId("reportUndo").disabled = !studioState.history.length;
    if (byId("reportRedo")) byId("reportRedo").disabled = !studioState.future.length;
    if (byId("reportDuplicateBlock")) byId("reportDuplicateBlock").disabled = !hasBlock || studioState.current.blocks.length >= MAX_BLOCKS;
    if (byId("reportDeleteBlock")) byId("reportDeleteBlock").disabled = !hasBlock;
    if (byId("reportDeleteTemplate")) byId("reportDeleteTemplate").disabled = Boolean(studioState.current?.isBuiltIn);
    if (byId("reportSaveTemplate")) byId("reportSaveTemplate").textContent = studioState.current?.isBuiltIn || studioState.isDraft ? "Save as custom" : "Save template";
    const index = studioState.current?.blocks.findIndex(item => item.blockId === studioState.selectedBlockId) ?? -1;
    if (byId("reportMoveBlockUp")) byId("reportMoveBlockUp").disabled = index <= 0;
    if (byId("reportMoveBlockDown")) byId("reportMoveBlockDown").disabled = index < 0 || index >= studioState.current.blocks.length - 1;
  }

  function setSaveState(message, tone = "") {
    const node = byId("reportStudioSaveState");
    if (!node) return;
    node.textContent = message;
    node.className = `studio-save-state${tone ? ` ${tone}` : ""}`;
  }

  function setTemplateState(message, tone = "") {
    const node = byId("reportTemplateState");
    if (!node) return;
    node.textContent = message;
    node.className = tone;
  }

  function setDataSourceState(message) {
    if (byId("reportDataSourceState")) byId("reportDataSourceState").textContent = message;
  }

  function setStudioBusy(busy) {
    studioState.busy = Boolean(busy);
    const workbench = document.querySelector(".report-studio-workbench");
    if (workbench) workbench.inert = studioState.busy;
    if (byId("reportStudioTemplates")) byId("reportStudioTemplates").inert = studioState.busy;
    if (byId("reportNewTemplate")) byId("reportNewTemplate").disabled = studioState.busy;
    if (byId("reportSaveTemplate")) byId("reportSaveTemplate").disabled = studioState.busy;
    if (byId("reportStudioCanvas")) byId("reportStudioCanvas").setAttribute("aria-busy", String(studioState.busy));
  }

  function beginStudioOperation() {
    const token = ++studioState.busyToken;
    setStudioBusy(true);
    return token;
  }

  function finishStudioOperation(token) {
    if (token !== studioState.busyToken) return false;
    setStudioBusy(false);
    return true;
  }

  function renderDesignBlockBody(block, card) {
    const doc = card.ownerDocument;
    if (block.type === "divider") {
      const divider = doc.createElement("hr");
      divider.className = "studio-block-divider";
      card.append(divider);
      return;
    }
    if (["text", "coverage", "header"].includes(block.type)) {
      const copy = doc.createElement("p");
      copy.className = "studio-block-text";
      copy.textContent = block.type === "text"
        ? block.text || "Operator-authored narrative"
        : block.type === "header" ? "Customer · reporting period · report title" : "Collection coverage and confidence note";
      card.append(copy);
      return;
    }
    if (block.type === "metrics") {
      const metrics = doc.createElement("div");
      metrics.className = "studio-placeholder-metrics";
      const keys = block.metricKeys.length ? block.metricKeys : ["defenseScore", "threatEvents", "incidents", "onlineAgents"];
      keys.slice(0, 8).forEach(key => {
        const metric = doc.createElement("span");
        const value = doc.createElement("b");
        value.textContent = key === "defenseScore" ? "—%" : "—";
        const label = doc.createElement("small");
        label.textContent = METRIC_LABELS[key] || key;
        metric.append(value, label);
        metrics.append(metric);
      });
      card.append(metrics);
      return;
    }
    if (block.type === "severity") {
      const bars = doc.createElement("div");
      bars.className = "studio-severity-bars";
      ["critical", "high", "medium", "low"].forEach((severity, index) => {
        const row = doc.createElement("div");
        row.className = `studio-severity-row ${severity}`;
        const label = doc.createElement("span");
        label.textContent = severity;
        const track = doc.createElement("span");
        track.className = "studio-severity-track";
        track.append(doc.createElement("i"));
        const value = doc.createElement("b");
        value.textContent = String([8, 15, 23, 31][index]);
        row.append(label, track, value);
        bars.append(row);
      });
      card.append(bars);
      return;
    }
    const preview = doc.createElement("ul");
    preview.className = "studio-placeholder-list";
    const samples = block.type === "recommendations"
      ? ["Validate containment", "Review exposed assets", "Confirm owner and due date"]
      : block.type === "topSources" ? ["203.0.113.24", "198.51.100.7", "192.0.2.18"]
        : block.type === "topEvents" ? ["4625", "4688", "4104"]
          : ["Credential access investigation", "Suspicious PowerShell activity", "Repeated authentication failures"];
    samples.slice(0, Math.min(3, block.limit)).forEach((sample, index) => {
      const item = doc.createElement("li");
      const order = doc.createElement("span");
      order.textContent = String(index + 1).padStart(2, "0");
      const label = doc.createElement("strong");
      label.textContent = sample;
      const state = doc.createElement("small");
      state.textContent = block.type === "recommendations" ? "Action" : "Live data";
      item.append(order, label, state);
      preview.append(item);
    });
    card.append(preview);
  }

  function resolveReportTemplate(report) {
    const snapshot = read(report, "templateSnapshot");
    if (snapshot && typeof snapshot === "object") return normalizeTemplate(snapshot);
    const templateId = text(read(report, "templateId"), 128);
    const known = studioState.templates.find(item => item.templateId === templateId);
    return clone(known || fallbackTemplates()[0]);
  }

  function renderReport(report, host) {
    if (!report || !host) return null;
    const template = resolveReportTemplate(report);
    const doc = host.ownerDocument;
    const output = doc.createElement("article");
    output.className = "studio-report-output";
    output.setAttribute("aria-label", `${text(read(report, "title"), 200) || "Security report"} preview`);

    const chrome = doc.createElement("header");
    chrome.className = "studio-output-header";
    const brand = doc.createElement("span");
    brand.textContent = "NT SHIELD";
    const kind = doc.createElement("small");
    kind.textContent = "SECURITY REPORT";
    chrome.append(brand, kind);

    const grid = doc.createElement("main");
    grid.className = "studio-output-grid";
    template.blocks.filter(block => block.visible).forEach(block => {
      const card = doc.createElement("section");
      card.className = "studio-output-block";
      card.dataset.width = oneOf(block.width, WIDTHS, "full");
      card.dataset.blockStyle = oneOf(block.style, BLOCK_STYLES, "default");
      card.dataset.pageBreak = String(block.pageBreakBefore);
      card.dataset.type = oneOf(block.type, TYPES, "text");
      renderOutputBlock(report, block, card);
      grid.append(card);
    });
    if (!grid.childElementCount) grid.append(emptyOutput(doc, "This template has no visible blocks."));

    const footer = doc.createElement("footer");
    footer.className = "studio-output-footer";
    const confidentiality = doc.createElement("span");
    confidentiality.textContent = "CONFIDENTIAL";
    const generated = doc.createElement("span");
    generated.textContent = `Generated ${formatDateTime(read(report, "generatedAtUtc"))} · ${text(read(report, "reportId"), 64)}`;
    footer.append(confidentiality, generated);
    output.append(chrome, grid, footer);
    applyPageData(output, template);
    host.replaceChildren(output);
    return clone(template);
  }

  function renderOutputBlock(report, block, card) {
    const doc = card.ownerDocument;
    if (block.type === "divider") {
      const divider = doc.createElement("hr");
      divider.className = "studio-output-divider";
      card.append(divider);
      return;
    }
    if (block.type === "header") {
      const identity = doc.createElement("header");
      identity.className = "studio-output-identity";
      const title = doc.createElement("h1");
      title.textContent = text(read(report, "title"), 200) || "Security operations report";
      const context = doc.createElement("p");
      context.textContent = `${text(read(report, "customerName"), 200) || "Customer"} · ${formatDate(read(report, "periodStartUtc"))} – ${formatDate(read(report, "periodEndUtc"))} UTC`;
      identity.append(title, context);
      card.append(identity);
      return;
    }

    appendOutputTitle(doc, card, block.title);
    if (block.type === "metrics") renderOutputMetrics(report, block, card);
    else if (block.type === "severity") renderOutputSeverity(report, card);
    else if (block.type === "incidents") renderOutputIncidents(report, block.limit, card);
    else if (block.type === "topSources") renderOutputRanking(read(report, "topSourceIps"), block.limit, card);
    else if (block.type === "topEvents") renderOutputRanking(read(report, "topEventIds"), block.limit, card);
    else if (block.type === "recommendations") renderOutputRecommendations(read(report, "recommendations"), block.limit, card);
    else if (block.type === "coverage") appendOutputCopy(doc, card, read(report, "coverageNote") || "No coverage note was recorded.");
    else if (block.type === "text") appendOutputCopy(doc, card, block.text || "");
  }

  function appendOutputTitle(doc, card, value) {
    const heading = doc.createElement("h2");
    heading.className = "studio-output-title";
    heading.textContent = text(value, 120);
    card.append(heading);
  }

  function appendOutputCopy(doc, card, value) {
    const copy = doc.createElement("p");
    copy.className = "studio-output-copy";
    copy.textContent = text(value, 2000);
    card.append(copy);
  }

  function renderOutputMetrics(report, block, card) {
    const doc = card.ownerDocument;
    const host = doc.createElement("div");
    host.className = "studio-output-metrics";
    const keys = block.metricKeys.length
      ? block.metricKeys
      : ["threatEvents", "incidents", "threatCampaigns", "defenseScore", "onlineAgents", "assets"];
    keys.slice(0, block.limit).forEach(key => {
      const item = metricItem(report, key);
      if (!item) return;
      const metric = doc.createElement("span");
      const value = doc.createElement("b");
      value.textContent = item.value;
      const label = doc.createElement("small");
      label.textContent = item.label;
      metric.append(value, label);
      host.append(metric);
    });
    card.append(host.childElementCount ? host : emptyOutput(doc, "No metrics selected."));
  }

  function metricItem(report, key) {
    const metrics = read(report, "metrics") || {};
    const severities = read(report, "severityCounts") || {};
    if (!METRIC_KEYS.includes(key)) return null;
    if (key === "onlineAgents") return { label: METRIC_LABELS[key], value: `${number(read(metrics, "onlineAgents"))}/${number(read(metrics, "agents"))}` };
    if (key === "defenseScore") return { label: METRIC_LABELS[key], value: `${number(read(metrics, key))}%` };
    const severityMetric = ["critical", "high", "medium", "low"].includes(key);
    return { label: METRIC_LABELS[key], value: formatNumber(number(read(severityMetric ? severities : metrics, key))) };
  }

  function renderOutputSeverity(report, card) {
    const doc = card.ownerDocument;
    const listNode = doc.createElement("ul");
    listNode.className = "studio-output-list studio-output-severity";
    const severities = read(report, "severityCounts") || {};
    ["critical", "high", "medium", "low"].forEach((key, index) => {
      const row = doc.createElement("li");
      const order = doc.createElement("span");
      order.textContent = String(index + 1).padStart(2, "0");
      const label = doc.createElement("strong");
      label.textContent = METRIC_LABELS[key];
      const value = doc.createElement("b");
      value.textContent = formatNumber(number(read(severities, key)));
      row.append(order, label, value);
      listNode.append(row);
    });
    card.append(listNode);
  }

  function renderOutputIncidents(report, limit, card) {
    const doc = card.ownerDocument;
    const incidents = list(read(report, "priorityIncidents")).slice(0, limit);
    if (!incidents.length) {
      card.append(emptyOutput(doc, "No priority incidents in this period."));
      return;
    }
    const table = doc.createElement("table");
    table.className = "studio-output-table";
    const caption = doc.createElement("caption");
    caption.className = "sr-only";
    caption.textContent = "Priority incidents";
    const head = doc.createElement("thead");
    const headRow = doc.createElement("tr");
    ["Severity", "Incident", "Source", "Destination", "Status", "Last seen"].forEach(label => {
      const cell = doc.createElement("th");
      cell.scope = "col";
      cell.textContent = label;
      headRow.append(cell);
    });
    head.append(headRow);
    const body = doc.createElement("tbody");
    incidents.forEach(incident => {
      const row = doc.createElement("tr");
      [severityLabel(read(incident, "severity")), read(incident, "title"), read(incident, "sourceIp") || "—", read(incident, "destinationIp") || "—", read(incident, "status"), formatDateTime(read(incident, "lastSeenUtc"))]
        .forEach(value => {
          const cell = doc.createElement("td");
          cell.textContent = text(value, 300);
          row.append(cell);
        });
      body.append(row);
    });
    table.append(caption, head, body);
    card.append(table);
  }

  function renderOutputRanking(rawItems, limit, card) {
    const doc = card.ownerDocument;
    const items = list(rawItems).slice(0, limit);
    if (!items.length) {
      card.append(emptyOutput(doc, "No ranked values in this period."));
      return;
    }
    const listNode = doc.createElement("ol");
    listNode.className = "studio-output-list studio-output-ranking";
    items.forEach((item, index) => {
      const row = doc.createElement("li");
      const order = doc.createElement("span");
      order.textContent = String(index + 1).padStart(2, "0");
      const value = doc.createElement("code");
      value.textContent = text(read(item, "value"), 200);
      const count = doc.createElement("b");
      count.textContent = formatNumber(number(read(item, "count")));
      row.append(order, value, count);
      listNode.append(row);
    });
    card.append(listNode);
  }

  function renderOutputRecommendations(rawItems, limit, card) {
    const doc = card.ownerDocument;
    const items = list(rawItems).slice(0, limit);
    if (!items.length) {
      card.append(emptyOutput(doc, "No recommendations were generated."));
      return;
    }
    const recommendations = doc.createElement("ol");
    recommendations.className = "studio-output-recommendations";
    items.forEach(item => {
      const row = doc.createElement("li");
      row.textContent = text(item, 1000);
      recommendations.append(row);
    });
    card.append(recommendations);
  }

  function emptyOutput(doc, message) {
    const empty = doc.createElement("p");
    empty.className = "studio-output-empty";
    empty.textContent = message;
    return empty;
  }

  function number(value) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : 0;
  }

  function formatNumber(value) {
    return new Intl.NumberFormat("en-US", { maximumFractionDigits: 0 }).format(value);
  }

  function formatDate(value) {
    const date = new Date(value);
    return Number.isNaN(date.valueOf()) ? "—" : date.toLocaleDateString("en-GB", { timeZone: "UTC", year: "numeric", month: "short", day: "2-digit" });
  }

  function formatDateTime(value) {
    const date = new Date(value);
    return Number.isNaN(date.valueOf()) ? "—" : `${date.toLocaleString("en-GB", { timeZone: "UTC", year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" })} UTC`;
  }

  function severityLabel(value) {
    const numeric = Number(value);
    if (Number.isInteger(numeric) && numeric >= 0 && numeric <= 4) return ["Informational", "Low", "Medium", "High", "Critical"][numeric];
    return text(value || "Unknown", 32);
  }

  function exportTemplate() {
    if (!studioState.current) return;
    const content = JSON.stringify(normalizeTemplate(studioState.current), null, 2);
    const filename = `${studioState.current.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "report-template"}.json`;
    downloadBlob(content, "application/json;charset=utf-8", filename);
  }

  function downloadBlob(content, type, filename) {
    const url = URL.createObjectURL(new Blob([content], { type }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    globalThis.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function printReport(report) {
    if (!report) return false;
    const popup = globalThis.open("", "_blank");
    if (!popup) {
      studioState.toast?.("Browser บล็อกหน้าต่าง Print กรุณาอนุญาต pop-up");
      return false;
    }
    const popupDocument = popup.document;
    popup.opener = null;
    popupDocument.documentElement.lang = "th";
    const charset = popupDocument.createElement("meta");
    charset.setAttribute("charset", "utf-8");
    const viewport = popupDocument.createElement("meta");
    viewport.name = "viewport";
    viewport.content = "width=device-width,initial-scale=1";
    const title = popupDocument.createElement("title");
    title.textContent = text(read(report, "title"), 200) || "NT Shield report";
    const studioStyles = popupDocument.createElement("link");
    studioStyles.rel = "stylesheet";
    studioStyles.href = new URL("report-studio.css?v=20260808-studio-1", document.baseURI).href;
    const printStyles = popupDocument.createElement("link");
    printStyles.rel = "stylesheet";
    printStyles.href = new URL("tenant-report-print.css?v=20260808-studio-1", document.baseURI).href;
    popupDocument.head.replaceChildren(charset, viewport, title, studioStyles, printStyles);

    const template = resolveReportTemplate(report);
    popupDocument.body.className = `studio-print-shell studio-print-${template.page.size}-${template.page.orientation}`;
    const actions = popupDocument.createElement("div");
    actions.className = "studio-print-actions";
    const printButton = popupDocument.createElement("button");
    printButton.type = "button";
    printButton.textContent = "Print / Save PDF";
    printButton.addEventListener("click", () => popup.print());
    actions.append(printButton);
    const host = popupDocument.createElement("div");
    host.className = "studio-print-document";
    popupDocument.body.replaceChildren(actions, host);
    renderReport(report, host);
    popup.focus();
    return true;
  }

  function hasUnsavedChanges() {
    return Boolean(studioState.dirty || studioState.isDraft);
  }

  function confirmDiscard(message = "Discard unsaved report template changes?") {
    return !hasUnsavedChanges() || globalThis.confirm(message);
  }

  function getSelectedTemplateId() {
    return studioState.current?.templateId || null;
  }

  function getTemplateSnapshot() {
    return studioState.current ? clone(normalizeTemplate(studioState.current)) : null;
  }

  globalThis.NTShieldReportStudio = {
    init,
    sync,
    onPage,
    resetTenant,
    ensureSaved,
    getSelectedTemplateId,
    getTemplateSnapshot,
    hasUnsavedChanges,
    confirmDiscard,
    renderReport,
    printReport
  };
})();
