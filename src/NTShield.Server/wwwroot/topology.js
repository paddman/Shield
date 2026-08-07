"use strict";

/*
 * Small dependency-free graph editor for the Central Control Center. It keeps
 * the UI deliberately native (HTML/SVG/pointer events) so an installed Central
 * server does not need a second frontend build pipeline.
 */
(function () {
  const CENTRAL_NODE_ID = "ntshield-central";
  const fallbackKinds = [
    ["internet", "Internet", "edge", "◎"], ["dns", "DNS", "edge", "D"], ["cdn", "CDN", "edge", "◌"],
    ["waf", "WAF / AI-WAF", "security", "W"], ["api-gateway", "API Gateway", "application", "A"],
    ["load-balancer", "Load Balancer", "network", "⇄"], ["web-server", "Web Server", "application", "WEB"],
    ["application", "Application / API", "application", "APP"], ["database", "Database", "data", "DB"],
    ["cache", "Cache / Queue", "data", "C"], ["endpoint", "Endpoint / Server", "endpoint", "EP"],
    ["kubernetes", "Kubernetes / Container", "endpoint", "K8S"], ["router", "Router", "network", "R"],
    ["switch", "Switch", "network", "SW"], ["firewall", "Firewall", "security", "FW"],
    ["vpn", "VPN", "security", "VPN"], ["mikrotik", "Mikrotik", "network", "MT"],
    ["identity", "AD / LDAP / IdP", "identity", "ID"], ["sensor", "Suricata / Zeek / EDR", "security", "S"],
    ["central", "NT Shield Central", "security", "NT"],
    ["cloud", "Cloud / SaaS", "cloud", "☁"], ["backup", "Backup / Storage", "data", "B"], ["custom", "Custom", "custom", "◇"]
  ].map(([kind, label, category, icon]) => ({ kind, label, category, icon }));

  const workflowKinds = [
    { type: "trigger", label: "Trigger", icon: "▶", description: "event / telemetry" },
    { type: "filter", label: "Filter", icon: "≡", description: "rule / threshold" },
    { type: "enrich", label: "Enrich", icon: "+", description: "asset / IOC context" },
    { type: "correlate", label: "Correlate", icon: "↗", description: "cross-host / sequence" },
    { type: "ai", label: "AI Analyst", icon: "AI", description: "explain / score" },
    { type: "approval", label: "Operator Approval", icon: "✓", description: "human gate" },
    { type: "response", label: "Response proposal", icon: "!", description: "block / isolate / ticket" },
    { type: "notify", label: "Notify / Report", icon: "✦", description: "SOC / customer report" }
  ];

  const topologyState = {
    initialized: false,
    loading: false,
    api: null,
    toast: null,
    getTenant: () => "default",
    kinds: fallbackKinds,
    workflowKinds,
    assets: [],
    topologies: [],
    workflows: [],
    topology: null,
    workflow: null,
    topologySelected: null,
    workflowSelected: null,
    topologyMode: "select",
    workflowMode: "select",
    topologyZoom: 1,
    workflowZoom: 1,
    topologyDirty: false,
    workflowDirty: false
  };

  const $ = selector => document.querySelector(selector);

  function value(object, ...keys) {
    if (!object) return undefined;
    for (const key of keys) {
      if (object[key] !== undefined && object[key] !== null) return object[key];
      const pascal = key.charAt(0).toUpperCase() + key.slice(1);
      if (object[pascal] !== undefined && object[pascal] !== null) return object[pascal];
    }
    return undefined;
  }

  function clone(object) {
    return object ? JSON.parse(JSON.stringify(object)) : object;
  }

  function id() {
    return (globalThis.crypto?.randomUUID?.() || `${Date.now().toString(36)}${Math.random().toString(36).slice(2)}`).replaceAll("-", "");
  }

  function asList(object) { return Array.isArray(object) ? object : []; }

  function normalizeTopology(raw) {
    const nodes = asList(value(raw, "nodes")).map(node => ({
      nodeId: value(node, "nodeId") || id(),
      label: value(node, "label") || "New asset",
      kind: value(node, "kind") || "custom",
      category: value(node, "category") || categoryFor(value(node, "kind")),
      assetId: value(node, "assetId") || null,
      x: Number(value(node, "x")) || 40,
      y: Number(value(node, "y")) || 40,
      status: value(node, "status") || "unknown",
      telemetrySourceIds: asList(value(node, "telemetrySourceIds")),
      metadata: value(node, "metadata") || {}
    }));
    return {
      topologyId: value(raw, "topologyId") || id(),
      tenantId: value(raw, "tenantId") || topologyState.getTenant(),
      name: value(raw, "name") || "Infrastructure map",
      description: value(raw, "description") || "",
      version: Number(value(raw, "version")) || 1,
      nodes: ensureCentralNode(nodes),
      edges: asList(value(raw, "edges")).map(edge => ({
        edgeId: value(edge, "edgeId") || id(),
        sourceNodeId: value(edge, "sourceNodeId") || "",
        targetNodeId: value(edge, "targetNodeId") || "",
        label: value(edge, "label") || "",
        protocol: value(edge, "protocol") || "",
        bidirectional: Boolean(value(edge, "bidirectional"))
      })),
      createdAtUtc: value(raw, "createdAtUtc") || new Date().toISOString(),
      updatedAtUtc: value(raw, "updatedAtUtc") || new Date().toISOString()
    };
  }

  function normalizeWorkflow(raw) {
    return {
      workflowId: value(raw, "workflowId") || id(),
      tenantId: value(raw, "tenantId") || topologyState.getTenant(),
      name: value(raw, "name") || "New detection workflow",
      description: value(raw, "description") || "",
      topologyId: value(raw, "topologyId") || null,
      enabled: Boolean(value(raw, "enabled")),
      version: Number(value(raw, "version")) || 1,
      nodes: asList(value(raw, "nodes")).map(node => ({
        nodeId: value(node, "nodeId") || id(),
        type: value(node, "type") || "trigger",
        label: value(node, "label") || "New step",
        x: Number(value(node, "x")) || 40,
        y: Number(value(node, "y")) || 40,
        config: value(node, "config") || {}
      })),
      edges: asList(value(raw, "edges")).map(edge => ({
        edgeId: value(edge, "edgeId") || id(),
        sourceNodeId: value(edge, "sourceNodeId") || "",
        targetNodeId: value(edge, "targetNodeId") || "",
        label: value(edge, "label") || ""
      })),
      createdAtUtc: value(raw, "createdAtUtc") || new Date().toISOString(),
      updatedAtUtc: value(raw, "updatedAtUtc") || new Date().toISOString()
    };
  }

  function categoryFor(kind) {
    return topologyState.kinds.find(item => item.kind === kind)?.category || "custom";
  }

  function iconFor(kind) {
    return topologyState.kinds.find(item => item.kind === kind)?.icon || "◇";
  }

  function init(dependencies) {
    if (topologyState.initialized) return;
    topologyState.api = dependencies.requestJson;
    topologyState.toast = dependencies.toast;
    topologyState.getTenant = dependencies.getTenant || (() => "default");
    topologyState.initialized = true;
    bindTabs();
    bindTopologyControls();
    bindWorkflowControls();
    renderKinds();
    renderWorkflowKinds();
    populateWorkflowTypeSelect();
  }

  async function load(options = {}) {
    if (!topologyState.initialized || topologyState.loading) return;
    topologyState.loading = true;
    setText("#topologyStatus", "กำลังโหลดข้อมูลจาก Central…");
    setText("#workflowStatus", "กำลังโหลดข้อมูลจาก Central…");
    try {
      const [kinds, topologies, assets, workflows] = await Promise.all([
        topologyState.api("/api/v1/topology/kinds"),
        topologyState.api("/api/v1/topologies"),
        topologyState.api("/api/v1/assets"),
        topologyState.api("/api/v1/workflows")
      ]);
      const receivedKinds = asList(kinds).map(item => ({
        kind: value(item, "kind") || "custom",
        label: value(item, "label") || value(item, "kind") || "Custom",
        category: value(item, "category") || "custom",
        icon: value(item, "icon") || "◇"
      }));
      if (receivedKinds.length) topologyState.kinds = receivedKinds;
      topologyState.topologies = asList(topologies).map(normalizeTopology);
      topologyState.assets = asList(assets);
      topologyState.workflows = asList(workflows).map(normalizeWorkflow);
      if (options.resetSelection || !topologyState.topology || !topologyState.topologies.some(item => item.topologyId === topologyState.topology.topologyId)) {
        topologyState.topology = topologyState.topologies.length ? clone(topologyState.topologies[0]) : newTopologyModel();
        topologyState.topologySelected = null;
      }
      if (options.resetSelection || !topologyState.workflow || !topologyState.workflows.some(item => item.workflowId === topologyState.workflow.workflowId)) {
        topologyState.workflow = topologyState.workflows.length ? clone(topologyState.workflows[0]) : newWorkflowModel();
        topologyState.workflowSelected = null;
      }
      topologyState.topologyDirty = false;
      topologyState.workflowDirty = false;
      renderKinds();
      renderWorkflowKinds();
      populateNodeKindSelect();
      populateAssetSelect();
      populateTopologySelect();
      populateWorkflowSelect();
      renderTopology();
      renderWorkflow();
    } catch (error) {
      topologyState.toast?.(`โหลด Topology ไม่สำเร็จ: ${error?.message || "Central unavailable"}`);
      setText("#topologyStatus", "โหลดข้อมูลไม่สำเร็จ");
      setText("#workflowStatus", "โหลดข้อมูลไม่สำเร็จ");
    } finally {
      topologyState.loading = false;
    }
  }

  function newTopologyModel() {
    return { topologyId: id(), tenantId: topologyState.getTenant(), name: "Infrastructure map", description: "", version: 1, nodes: [createCentralNode()], edges: [], createdAtUtc: new Date().toISOString(), updatedAtUtc: new Date().toISOString() };
  }

  function createCentralNode() {
    return {
      nodeId: CENTRAL_NODE_ID,
      label: "NT Shield Central",
      kind: "central",
      category: "security",
      assetId: null,
      x: 250,
      y: 245,
      status: "healthy",
      telemetrySourceIds: [],
      metadata: {
        address: "/api/v1",
        description: "Central correlation, telemetry and response control plane",
        systemManaged: "true"
      }
    };
  }

  function ensureCentralNode(nodes) {
    const central = nodes.find(isCentralNode);
    if (central) {
      central.category = "security";
      central.metadata = { ...(central.metadata || {}), systemManaged: "true" };
      return nodes;
    }
    return [createCentralNode(), ...nodes];
  }

  function newWorkflowModel() {
    const linkedTopology = topologyState.topology && topologyState.topologies.some(item => item.topologyId === topologyState.topology.topologyId)
      ? topologyState.topology.topologyId
      : null;
    return { workflowId: id(), tenantId: topologyState.getTenant(), name: "New detection workflow", description: "", topologyId: linkedTopology, enabled: false, version: 1, nodes: [], edges: [], createdAtUtc: new Date().toISOString(), updatedAtUtc: new Date().toISOString() };
  }

  function bindTabs() {
    document.querySelectorAll("[data-topology-tab]").forEach(button => button.addEventListener("click", () => {
      const tab = button.dataset.topologyTab;
      document.querySelectorAll("[data-topology-tab]").forEach(item => item.classList.toggle("active", item === button));
      $("#topologyCanvasPanel").hidden = tab !== "canvas";
      $("#workflowPanel").hidden = tab !== "workflow";
      if (tab === "canvas") renderTopology(); else renderWorkflow();
    }));
  }

  function bindTopologyControls() {
    $("#newTopology")?.addEventListener("click", () => {
      topologyState.topology = newTopologyModel();
      topologyState.topologySelected = null;
      topologyState.topologyDirty = true;
      populateTopologySelect();
      renderTopology();
    });
    $("#saveTopology")?.addEventListener("click", saveTopology);
    $("#topologySelect")?.addEventListener("change", event => {
      const selected = topologyState.topologies.find(item => item.topologyId === event.target.value);
      if (!selected) return;
      topologyState.topology = clone(selected);
      topologyState.topologySelected = null;
      topologyState.topologyDirty = false;
      renderTopology();
    });
    $("#topologyKindSearch")?.addEventListener("input", renderKinds);
    $("#topologyName")?.addEventListener("input", event => {
      if (!topologyState.topology) return;
      topologyState.topology.name = event.target.value;
      topologyState.topologyDirty = true;
      setText("#topologyStatus", "ชื่อ Map เปลี่ยนแล้ว • กดบันทึก Map");
    });
    $("#topologyNodeForm")?.addEventListener("submit", event => { event.preventDefault(); applyTopologyInspector(); });
    $("#topologyNodeRemove")?.addEventListener("click", () => removeTopologyNode(topologyState.topologySelected));
    bindModeButtons("topology", ["Select", "Connect", "Delete"]);
    $("#topologyZoomOut")?.addEventListener("click", () => changeZoom("topology", -.1));
    $("#topologyZoomIn")?.addEventListener("click", () => changeZoom("topology", .1));
    $("#topologyFit")?.addEventListener("click", () => fitGraph("topology"));
    bindCanvasDrop("#topologyCanvas", kind => addTopologyNode(kind));
    $("#topologyCanvas")?.addEventListener("click", event => {
      if (event.target.id === "topologyCanvas") {
        topologyState.topologySelected = null;
        renderTopologyInspector();
        renderTopology();
      }
    });
    $("#topologyCanvas")?.addEventListener("keydown", event => {
      if (event.key === "Delete" || event.key === "Backspace") removeTopologyNode(topologyState.topologySelected);
    });
  }

  function bindWorkflowControls() {
    $("#newWorkflow")?.addEventListener("click", () => {
      topologyState.workflow = newWorkflowModel();
      topologyState.workflowSelected = null;
      topologyState.workflowDirty = true;
      populateWorkflowSelect();
      renderWorkflow();
    });
    $("#saveWorkflow")?.addEventListener("click", saveWorkflow);
    $("#workflowSelect")?.addEventListener("change", event => {
      const selected = topologyState.workflows.find(item => item.workflowId === event.target.value);
      if (!selected) return;
      topologyState.workflow = clone(selected);
      topologyState.workflowSelected = null;
      topologyState.workflowDirty = false;
      renderWorkflow();
    });
    $("#workflowNodeForm")?.addEventListener("submit", event => { event.preventDefault(); applyWorkflowInspector(); });
    $("#workflowName")?.addEventListener("input", event => {
      if (!topologyState.workflow) return;
      topologyState.workflow.name = event.target.value;
      topologyState.workflowDirty = true;
      setText("#workflowStatus", "ชื่อ Workflow เปลี่ยนแล้ว • กดบันทึก Workflow");
    });
    $("#workflowEnabled")?.addEventListener("change", event => {
      if (!topologyState.workflow) return;
      topologyState.workflow.enabled = event.target.value === "true";
      topologyState.workflowDirty = true;
      setText("#workflowStatus", "สถานะ Workflow เปลี่ยนแล้ว • กดบันทึก Workflow");
    });
    $("#workflowNodeRemove")?.addEventListener("click", () => removeWorkflowNode(topologyState.workflowSelected));
    bindModeButtons("workflow", ["Select", "Connect", "Delete"]);
    bindCanvasDrop("#workflowCanvas", type => addWorkflowNode(type));
    $("#workflowCanvas")?.addEventListener("click", event => {
      if (event.target.id === "workflowCanvas") {
        topologyState.workflowSelected = null;
        renderWorkflowInspector();
        renderWorkflow();
      }
    });
    $("#workflowCanvas")?.addEventListener("keydown", event => {
      if (event.key === "Delete" || event.key === "Backspace") removeWorkflowNode(topologyState.workflowSelected);
    });
  }

  function bindModeButtons(prefix, names) {
    names.forEach(name => $(`#${prefix}${name}Mode`)?.addEventListener("click", () => {
      const mode = name.toLowerCase();
      if (prefix === "topology") topologyState.topologyMode = mode; else topologyState.workflowMode = mode;
      names.forEach(item => $(`#${prefix}${item}Mode`)?.classList.toggle("active", item.toLowerCase() === mode));
      $(`#${prefix}Canvas`)?.classList.toggle("connect-mode", mode === "connect");
      renderTopology(); renderWorkflow();
    }));
  }

  function bindCanvasDrop(selector, add) {
    const canvas = $(selector);
    if (!canvas) return;
    canvas.addEventListener("dragover", event => { event.preventDefault(); });
    canvas.addEventListener("drop", event => {
      event.preventDefault();
      const kind = event.dataTransfer?.getData("text/plain");
      if (!kind) return;
      add(kind, event);
    });
  }

  function renderKinds() {
    const host = $("#topologyKinds");
    if (!host) return;
    const query = ($("#topologyKindSearch")?.value || "").trim().toLowerCase();
    host.replaceChildren();
    topologyState.kinds.filter(item => `${item.label} ${item.kind} ${item.category}`.toLowerCase().includes(query)).forEach(item => {
      const button = document.createElement("button");
      button.type = "button"; button.className = "topology-kind"; button.draggable = true; button.dataset.category = item.category;
      button.innerHTML = `<span class="topology-kind-icon"></span><span class="topology-kind-label"></span>`;
      button.querySelector(".topology-kind-icon").textContent = item.icon;
      button.querySelector(".topology-kind-label").append(document.createTextNode(item.label), Object.assign(document.createElement("small"), { textContent: item.kind }));
      button.addEventListener("click", () => addTopologyNode(item.kind));
      button.addEventListener("dragstart", event => event.dataTransfer?.setData("text/plain", item.kind));
      host.append(button);
    });
  }

  function renderWorkflowKinds() {
    const host = $("#workflowKinds");
    if (!host) return;
    host.replaceChildren();
    topologyState.workflowKinds.forEach(item => {
      const button = document.createElement("button");
      button.type = "button"; button.className = "workflow-kind"; button.draggable = true; button.dataset.type = item.type;
      button.innerHTML = `<span class="workflow-kind-icon"></span><span class="workflow-kind-label"></span>`;
      button.querySelector(".workflow-kind-icon").textContent = item.icon;
      button.querySelector(".workflow-kind-label").append(document.createTextNode(item.label), Object.assign(document.createElement("small"), { textContent: item.description }));
      button.addEventListener("click", () => addWorkflowNode(item.type));
      button.addEventListener("dragstart", event => event.dataTransfer?.setData("text/plain", item.type));
      host.append(button);
    });
  }

  function populateTopologySelect() {
    const select = $("#topologySelect"); if (!select) return;
    select.replaceChildren();
    topologyState.topologies.forEach(item => select.append(new Option(item.name, item.topologyId)));
    if (!topologyState.topologies.length) select.append(new Option("New unsaved map", ""));
    select.value = topologyState.topology && topologyState.topologies.some(item => item.topologyId === topologyState.topology.topologyId) ? topologyState.topology.topologyId : "";
  }

  function populateWorkflowSelect() {
    const select = $("#workflowSelect"); if (!select) return;
    select.replaceChildren();
    topologyState.workflows.forEach(item => select.append(new Option(`${item.name}${item.enabled ? " • enabled" : ""}`, item.workflowId)));
    if (!topologyState.workflows.length) select.append(new Option("New unsaved workflow", ""));
    select.value = topologyState.workflow && topologyState.workflows.some(item => item.workflowId === topologyState.workflow.workflowId) ? topologyState.workflow.workflowId : "";
  }

  function populateNodeKindSelect() {
    const select = $("#topologyNodeKind"); if (!select) return;
    select.replaceChildren(...topologyState.kinds.map(item => new Option(item.label, item.kind)));
  }

  function populateWorkflowTypeSelect() {
    const select = $("#workflowNodeType"); if (!select) return;
    select.replaceChildren(...topologyState.workflowKinds.map(item => new Option(item.label, item.type)));
  }

  function populateAssetSelect() {
    const select = $("#topologyNodeAsset"); if (!select) return;
    select.replaceChildren(new Option("ไม่ผูก asset", ""));
    topologyState.assets.forEach(item => select.append(new Option(`${value(item, "name") || "Unnamed"} • ${value(item, "kind") || "custom"}`, value(item, "assetId"))));
  }

  function addTopologyNode(kind, event) {
    if (!topologyState.topology) topologyState.topology = newTopologyModel();
    const def = topologyState.kinds.find(item => item.kind === kind) || { kind, label: kind, category: categoryFor(kind), icon: iconFor(kind) };
    const point = event ? pointFromEvent(event, "topology") : { x: 70 + (topologyState.topology.nodes.length % 3) * 185, y: 70 + Math.floor(topologyState.topology.nodes.length / 3) * 105 };
    const node = { nodeId: id(), label: def.label, kind: def.kind, category: def.category, assetId: null, x: Math.max(10, point.x - 77), y: Math.max(10, point.y - 30), status: "unknown", telemetrySourceIds: [], metadata: {} };
    topologyState.topology.nodes.push(node);
    topologyState.topologySelected = node.nodeId;
    topologyState.topologyDirty = true;
    renderTopology();
  }

  function addWorkflowNode(type, event) {
    if (!topologyState.workflow) topologyState.workflow = newWorkflowModel();
    const def = topologyState.workflowKinds.find(item => item.type === type) || { type, label: type, icon: "◇" };
    const point = event ? pointFromEvent(event, "workflow") : { x: 75 + (topologyState.workflow.nodes.length % 3) * 195, y: 80 + Math.floor(topologyState.workflow.nodes.length / 3) * 105 };
    const node = { nodeId: id(), type: def.type, label: def.label, x: Math.max(10, point.x - 85), y: Math.max(10, point.y - 30), config: { requiresApproval: ["approval", "response"].includes(def.type) ? "true" : "false" } };
    topologyState.workflow.nodes.push(node);
    topologyState.workflowSelected = node.nodeId;
    topologyState.workflowDirty = true;
    renderWorkflow();
  }

  function pointFromEvent(event, graph) {
    const canvas = graph === "topology" ? $("#topologyCanvas") : $("#workflowCanvas");
    const rect = canvas.getBoundingClientRect();
    const zoom = graph === "topology" ? topologyState.topologyZoom : topologyState.workflowZoom;
    return { x: (event.clientX - rect.left) / zoom, y: (event.clientY - rect.top) / zoom };
  }

  function renderTopology() {
    const graph = topologyState.topology;
    const layer = $("#topologyNodeLayer");
    if (!graph || !layer) return;
    const central = graph.nodes.find(isCentralNode);
    if (central) positionCentralNode(central);
    layer.style.transform = `scale(${topologyState.topologyZoom})`;
    layer.replaceChildren();
    graph.nodes.forEach(node => layer.append(createTopologyNode(node)));
    renderEdges("topology");
    $("#topologyCanvasEmpty").hidden = graph.nodes.length > 0;
    setText("#topologyNodeCount", `${graph.nodes.length} nodes`);
    setText("#topologyZoomValue", `${Math.round(topologyState.topologyZoom * 100)}%`);
    setText("#topologyStatus", `${topologyState.topologyDirty ? "ยังไม่บันทึก • " : "บันทึกแล้ว • "}${graph.nodes.length} nodes • ${graph.edges.length} connections`);
    if ($("#topologyName") && document.activeElement !== $("#topologyName")) $("#topologyName").value = graph.name;
    renderTopologyInspector();
    populateTopologySelect();
  }

  function createTopologyNode(node) {
    const element = document.createElement("div");
    element.className = "topology-node";
    element.dataset.nodeId = node.nodeId; element.dataset.kind = node.kind; element.dataset.category = node.category || categoryFor(node.kind);
    element.innerHTML = `<span class="topology-node-icon"></span><span class="topology-node-copy"><strong></strong><small></small></span><i class="topology-node-status"></i>`;
    element.querySelector(".topology-node-icon").textContent = iconFor(node.kind);
    element.querySelector("strong").textContent = node.label;
    element.querySelector("small").textContent = node.metadata?.address || node.kind;
    element.querySelector(".topology-node-status").className = `topology-node-status ${node.status || "unknown"}`;
    if (node.nodeId === topologyState.topologySelected) element.classList.add("selected");
    bindGraphNode(element, node, "topology");
    positionNode(element, node, "topology");
    return element;
  }

  function renderWorkflow() {
    const graph = topologyState.workflow;
    const layer = $("#workflowNodeLayer");
    if (!graph || !layer) return;
    layer.style.transform = `scale(${topologyState.workflowZoom})`;
    layer.replaceChildren();
    graph.nodes.forEach(node => layer.append(createWorkflowNode(node)));
    renderEdges("workflow");
    $("#workflowCanvasEmpty").hidden = graph.nodes.length > 0;
    setText("#workflowStatus", `${topologyState.workflowDirty ? "ยังไม่บันทึก • " : "บันทึกแล้ว • "}${graph.nodes.length} steps • ${graph.edges.length} transitions`);
    if ($("#workflowName") && document.activeElement !== $("#workflowName")) $("#workflowName").value = graph.name;
    if ($("#workflowEnabled") && document.activeElement !== $("#workflowEnabled")) $("#workflowEnabled").value = String(Boolean(graph.enabled));
    renderWorkflowInspector();
    populateWorkflowSelect();
  }

  function createWorkflowNode(node) {
    const def = topologyState.workflowKinds.find(item => item.type === node.type) || { icon: "◇" };
    const element = document.createElement("div");
    element.className = "topology-node workflow-node"; element.dataset.nodeId = node.nodeId; element.dataset.type = node.type;
    element.innerHTML = `<span class="topology-node-icon"></span><span class="topology-node-copy"><strong></strong><small></small></span>`;
    element.querySelector(".topology-node-icon").textContent = def.icon;
    element.querySelector("strong").textContent = node.label;
    element.querySelector("small").textContent = node.config?.rule || node.type;
    if (node.nodeId === topologyState.workflowSelected) element.classList.add("selected");
    bindGraphNode(element, node, "workflow");
    positionNode(element, node, "workflow");
    return element;
  }

  function positionNode(element, node, graph) {
    element.style.left = `${node.x}px`;
    element.style.top = `${node.y}px`;
  }

  function positionCentralNode(node) {
    if (node.metadata?.positionedByOperator === "true") return;
    const canvas = $("#topologyCanvas");
    const zoom = topologyState.topologyZoom || 1;
    const width = canvas?.clientWidth || 654;
    const height = canvas?.clientHeight || 550;
    node.x = Math.max(12, width / zoom / 2 - 77);
    node.y = Math.max(12, height / zoom / 2 - 30);
  }

  function isCentralNode(node) {
    return node?.nodeId === CENTRAL_NODE_ID || node?.kind === "central" || node?.metadata?.systemManaged === "true";
  }

  function bindGraphNode(element, node, graph) {
    element.addEventListener("pointerdown", event => {
      if (event.button !== 0) return;
      event.stopPropagation();
      const mode = graph === "topology" ? topologyState.topologyMode : topologyState.workflowMode;
      if (mode === "delete") {
        if (graph === "topology") removeTopologyNode(node.nodeId); else removeWorkflowNode(node.nodeId);
        return;
      }
      if (mode === "connect") {
        connectNode(graph, node.nodeId);
        return;
      }
      if (graph === "topology") topologyState.topologySelected = node.nodeId; else topologyState.workflowSelected = node.nodeId;
      const layer = graph === "topology" ? $("#topologyNodeLayer") : $("#workflowNodeLayer");
      layer?.querySelectorAll(".selected").forEach(item => item.classList.remove("selected"));
      element.classList.add("selected");
      if (graph === "topology") renderTopologyInspector(); else renderWorkflowInspector();
      const point = pointFromEvent(event, graph);
      const offsetX = point.x - node.x; const offsetY = point.y - node.y;
      element.setPointerCapture?.(event.pointerId);
      const move = moveEvent => {
        const next = pointFromEvent(moveEvent, graph);
        node.x = Math.max(8, next.x - offsetX); node.y = Math.max(8, next.y - offsetY);
        if (graph === "topology" && isCentralNode(node)) {
          node.metadata = { ...(node.metadata || {}), positionedByOperator: "true" };
        }
        positionNode(element, node, graph);
        if (graph === "topology") { topologyState.topologyDirty = true; } else { topologyState.workflowDirty = true; }
        renderEdges(graph);
      };
      const up = upEvent => {
        element.releasePointerCapture?.(upEvent.pointerId);
        element.removeEventListener("pointermove", move);
        element.removeEventListener("pointerup", up);
        if (graph === "topology") setText("#topologyStatus", "ตำแหน่งเปลี่ยนแล้ว • กดบันทึก Map"); else setText("#workflowStatus", "ตำแหน่งเปลี่ยนแล้ว • กดบันทึก Workflow");
      };
      element.addEventListener("pointermove", move);
      element.addEventListener("pointerup", up, { once: true });
    });
  }

  function connectNode(graph, nodeId) {
    const stateKey = graph === "topology" ? "topologySelected" : "workflowSelected";
    const graphData = graph === "topology" ? topologyState.topology : topologyState.workflow;
    const first = topologyState[stateKey];
    if (!first) {
      topologyState[stateKey] = nodeId;
      if (graph === "topology") renderTopology(); else renderWorkflow();
      setText(graph === "topology" ? "#topologyStatus" : "#workflowStatus", "เลือก node ปลายทางเพื่อสร้าง connection");
      return;
    }
    if (first === nodeId) return;
    const exists = graphData.edges.some(edge => edge.sourceNodeId === first && edge.targetNodeId === nodeId);
    if (!exists) {
      graphData.edges.push(graph === "topology"
        ? { edgeId: id(), sourceNodeId: first, targetNodeId: nodeId, label: "", protocol: "", bidirectional: false }
        : { edgeId: id(), sourceNodeId: first, targetNodeId: nodeId, label: "" });
      if (graph === "topology") topologyState.topologyDirty = true; else topologyState.workflowDirty = true;
    }
    topologyState[stateKey] = nodeId;
    if (graph === "topology") renderTopology(); else renderWorkflow();
  }

  function renderEdges(graph) {
    const data = graph === "topology" ? topologyState.topology : topologyState.workflow;
    const svg = graph === "topology" ? $("#topologyEdgeSvg") : $("#workflowEdgeSvg");
    const layer = graph === "topology" ? $("#topologyEdgeLayer") : $("#workflowEdgeLayer");
    const zoom = graph === "topology" ? topologyState.topologyZoom : topologyState.workflowZoom;
    if (!data || !svg || !layer) return;
    const canvas = svg.parentElement;
    svg.setAttribute("viewBox", `0 0 ${Math.max(1, canvas.clientWidth)} ${Math.max(1, canvas.clientHeight)}`);
    layer.replaceChildren();
    const lookup = new Map(data.nodes.map(node => [node.nodeId, node]));
    data.edges.forEach(edge => {
      const source = lookup.get(edge.sourceNodeId); const target = lookup.get(edge.targetNodeId);
      if (!source || !target) return;
      const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
      line.setAttribute("x1", `${(source.x + (graph === "workflow" ? 85 : 77)) * zoom}`);
      line.setAttribute("y1", `${(source.y + 30) * zoom}`);
      line.setAttribute("x2", `${(target.x + (graph === "workflow" ? 85 : 77)) * zoom}`);
      line.setAttribute("y2", `${(target.y + 30) * zoom}`);
      line.setAttribute("marker-end", `url(#${graph === "workflow" ? "workflowArrow" : "topologyArrow"})`);
      layer.append(line);
      if (edge.label) {
        const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
        label.setAttribute("x", `${((source.x + target.x) / 2 + (graph === "workflow" ? 85 : 77)) * zoom}`);
        label.setAttribute("y", `${((source.y + target.y) / 2 + 25) * zoom}`);
        label.textContent = edge.label;
        layer.append(label);
      }
    });
  }

  function renderTopologyInspector() {
    const node = topologyState.topology?.nodes.find(item => item.nodeId === topologyState.topologySelected);
    $("#topologyInspectorEmpty").hidden = Boolean(node);
    $("#topologyNodeForm").hidden = !node;
    setText("#topologySelectionState", node ? "Selected" : "None");
    if (!node) return;
    $("#topologyNodeLabel").value = node.label;
    $("#topologyNodeKind").value = node.kind;
    $("#topologyNodeAddress").value = node.metadata?.address || "";
    $("#topologyNodeAsset").value = node.assetId || "";
    $("#topologyNodeStatus").value = node.status || "unknown";
    $("#topologyNodeDescription").value = node.metadata?.description || "";
  }

  function applyTopologyInspector() {
    const node = topologyState.topology?.nodes.find(item => item.nodeId === topologyState.topologySelected);
    if (!node) return;
    const central = isCentralNode(node);
    const kind = central ? "central" : $("#topologyNodeKind").value;
    node.label = central ? "NT Shield Central" : $("#topologyNodeLabel").value.trim() || "New asset";
    node.kind = kind; node.category = categoryFor(kind); node.assetId = $("#topologyNodeAsset").value || null; node.status = $("#topologyNodeStatus").value;
    node.metadata = { ...(node.metadata || {}), address: $("#topologyNodeAddress").value.trim(), description: $("#topologyNodeDescription").value.trim() };
    if (central) {
      node.nodeId = CENTRAL_NODE_ID;
      node.category = "security";
      node.status = "healthy";
      node.metadata.systemManaged = "true";
    }
    topologyState.topologyDirty = true;
    renderTopology();
  }

  function removeTopologyNode(nodeId) {
    if (!nodeId || !topologyState.topology) return;
    const node = topologyState.topology.nodes.find(item => item.nodeId === nodeId);
    if (isCentralNode(node)) {
      topologyState.toast?.("ไม่สามารถลบ NT Shield Central จาก Infrastructure Map ได้");
      return;
    }
    topologyState.topology.nodes = topologyState.topology.nodes.filter(node => node.nodeId !== nodeId);
    topologyState.topology.edges = topologyState.topology.edges.filter(edge => edge.sourceNodeId !== nodeId && edge.targetNodeId !== nodeId);
    topologyState.topologySelected = null; topologyState.topologyDirty = true; renderTopology();
  }

  function renderWorkflowInspector() {
    const node = topologyState.workflow?.nodes.find(item => item.nodeId === topologyState.workflowSelected);
    $("#workflowInspectorEmpty").hidden = Boolean(node);
    $("#workflowNodeForm").hidden = !node;
    setText("#workflowSelectionState", node ? "Selected" : "None");
    if (!node) return;
    $("#workflowNodeLabel").value = node.label;
    $("#workflowNodeType").value = node.type;
    $("#workflowNodeRule").value = node.config?.rule || "";
    $("#workflowNodeApproval").value = node.config?.requiresApproval || "false";
  }

  function applyWorkflowInspector() {
    const node = topologyState.workflow?.nodes.find(item => item.nodeId === topologyState.workflowSelected);
    if (!node) return;
    node.label = $("#workflowNodeLabel").value.trim() || "New step";
    node.type = $("#workflowNodeType").value;
    node.config = { ...(node.config || {}), rule: $("#workflowNodeRule").value.trim(), requiresApproval: $("#workflowNodeApproval").value };
    topologyState.workflowDirty = true; renderWorkflow();
  }

  function removeWorkflowNode(nodeId) {
    if (!nodeId || !topologyState.workflow) return;
    topologyState.workflow.nodes = topologyState.workflow.nodes.filter(node => node.nodeId !== nodeId);
    topologyState.workflow.edges = topologyState.workflow.edges.filter(edge => edge.sourceNodeId !== nodeId && edge.targetNodeId !== nodeId);
    topologyState.workflowSelected = null; topologyState.workflowDirty = true; renderWorkflow();
  }

  async function saveTopology() {
    if (!topologyState.topology) return;
    topologyState.topology.name = $("#topologyName")?.value.trim() || topologyState.topology.name;
    const known = topologyState.topologies.some(item => item.topologyId === topologyState.topology.topologyId);
    try {
      const path = known ? `/api/v1/topologies/${encodeURIComponent(topologyState.topology.topologyId)}` : "/api/v1/topologies";
      const saved = normalizeTopology(await topologyState.api(path, { method: known ? "PUT" : "POST", headers: { "Content-Type": "application/json" }, body: topologyState.topology }));
      topologyState.topology = saved; topologyState.topologyDirty = false;
      topologyState.topologies = [...topologyState.topologies.filter(item => item.topologyId !== saved.topologyId), saved].sort((a, b) => a.name.localeCompare(b.name));
      populateTopologySelect(); renderTopology(); topologyState.toast?.("บันทึก Infrastructure Map แล้ว");
    } catch (error) { topologyState.toast?.(`บันทึก Map ไม่สำเร็จ: ${error?.message || "validation error"}`); }
  }

  async function saveWorkflow() {
    if (!topologyState.workflow) return;
    topologyState.workflow.name = $("#workflowName")?.value.trim() || topologyState.workflow.name;
    topologyState.workflow.enabled = $("#workflowEnabled")?.value === "true";
    const known = topologyState.workflows.some(item => item.workflowId === topologyState.workflow.workflowId);
    try {
      const path = known ? `/api/v1/workflows/${encodeURIComponent(topologyState.workflow.workflowId)}` : "/api/v1/workflows";
      const saved = normalizeWorkflow(await topologyState.api(path, { method: known ? "PUT" : "POST", headers: { "Content-Type": "application/json" }, body: topologyState.workflow }));
      topologyState.workflow = saved; topologyState.workflowDirty = false;
      topologyState.workflows = [...topologyState.workflows.filter(item => item.workflowId !== saved.workflowId), saved].sort((a, b) => a.name.localeCompare(b.name));
      populateWorkflowSelect(); renderWorkflow(); topologyState.toast?.("บันทึก Detection Workflow แล้ว");
    } catch (error) { topologyState.toast?.(`บันทึก Workflow ไม่สำเร็จ: ${error?.message || "validation error"}`); }
  }

  function changeZoom(graph, amount) {
    const key = graph === "topology" ? "topologyZoom" : "workflowZoom";
    topologyState[key] = Math.min(1.6, Math.max(.55, Number((topologyState[key] + amount).toFixed(2))));
    if (graph === "topology") renderTopology(); else renderWorkflow();
  }

  function fitGraph(graph) {
    const data = graph === "topology" ? topologyState.topology : topologyState.workflow;
    if (!data?.nodes.length) return;
    const canvas = graph === "topology" ? $("#topologyCanvas") : $("#workflowCanvas");
    const maxX = Math.max(...data.nodes.map(node => node.x + 180), 1);
    const maxY = Math.max(...data.nodes.map(node => node.y + 90), 1);
    const zoom = Math.min(1, canvas.clientWidth / maxX, canvas.clientHeight / maxY);
    if (graph === "topology") topologyState.topologyZoom = Math.min(1.2, Math.max(.55, zoom)); else topologyState.workflowZoom = Math.min(1.2, Math.max(.55, zoom));
    if (graph === "topology") renderTopology(); else renderWorkflow();
  }

  function setText(selector, text) { const node = $(selector); if (node) node.textContent = text; }

  globalThis.NTShieldTopology = { init, load };
})();
