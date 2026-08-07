"use strict";

/*
 * NT Shield demo-safe Global Defense map.
 * Demo mode intentionally serves synthetic telemetry so the UI never needs
 * customer/personal data while the visual prototype is being refined.
 */
(function () {
  const DEMO_MODE = true;
  const nativeFetch = globalThis.fetch?.bind(globalThis);
  const demoState = createDemoState();

  installDemoFetch();
  installVisualFixes();

  const mapState = {
    canvas: null,
    ctx: null,
    width: 0,
    height: 0,
    dpr: 1,
    active: false,
    initialized: false,
    frame: 0,
    lastTime: 0,
    rotation: -0.42,
    reduceMotion: false,
    attackCount: 4,
    defenseCount: 3,
    landPoints: createLandPoints()
  };

  const attackRoutes = [
    { origin: [0.02, 0.27], target: [35, 108], bend: -0.18, phase: 0.08, label: "198.51.100.24 → 10.20.10.21:443" },
    { origin: [0.01, 0.43], target: [22, 100], bend: -0.08, phase: 0.39, label: "203.0.113.77 → 10.20.20.15:443" },
    { origin: [0.05, 0.62], target: [14, 86], bend: 0.05, phase: 0.66, label: "192.0.2.88 → 10.20.30.12:3389" },
    { origin: [0.13, 0.80], target: [-6, 72], bend: 0.15, phase: 0.86, label: "198.51.100.91 → 10.20.40.9:22" },
    { origin: [0.22, 0.91], target: [-24, 115], bend: 0.24, phase: 0.21, label: "203.0.113.144 → 10.20.50.17:3306" }
  ];

  const defenseRoutes = [
    { target: [42, 105], end: [0.91, 0.26], bend: -0.16, phase: 0.12 },
    { target: [18, 118], end: [0.96, 0.52], bend: -0.03, phase: 0.48 },
    { target: [-15, 110], end: [0.88, 0.76], bend: 0.17, phase: 0.78 }
  ];

  function installVisualFixes() {
    if (document.getElementById("ntshield-demo-visual-fixes")) return;
    const style = document.createElement("style");
    style.id = "ntshield-demo-visual-fixes";
    style.textContent = `
      @media (min-width: 1101px) {
        .active-threat-panel { align-self: end !important; }
        .defense-copy > p:last-child { max-width: 225px !important; margin-top: 12px !important; }
      }
      .defense-globe-wrap { overflow: hidden; }
      #defenseGlobeCanvas { display: block; }
    `;
    document.head.append(style);
  }

  function installDemoFetch() {
    if (!DEMO_MODE || !nativeFetch || globalThis.__ntShieldDemoFetchInstalled) return;
    globalThis.__ntShieldDemoFetchInstalled = true;
    globalThis.NTShieldDemo = { enabled: true, source: "synthetic-only" };

    globalThis.fetch = async function demoFetch(input, init = {}) {
      const raw = typeof input === "string" ? input : input?.url;
      if (!raw) return nativeFetch(input, init);
      const url = new URL(raw, location.origin);
      if (url.origin !== location.origin || !url.pathname.startsWith("/api/v1/")) {
        return nativeFetch(input, init);
      }

      const method = String(init?.method || (typeof input !== "string" ? input?.method : "GET") || "GET").toUpperCase();
      const result = handleDemoApi(url.pathname, method, init?.body);
      if (!result.handled) return nativeFetch(input, init);
      await delay(70 + Math.floor(Math.random() * 90));
      if (result.status === 204) return new Response(null, { status: 204 });
      return jsonResponse(result.body, result.status || 200);
    };
  }

  function handleDemoApi(path, method, rawBody) {
    if (method === "GET" && path === "/api/v1/health") return handled(demoState.health);
    if (method === "GET" && path === "/api/v1/agents") return handled(demoState.agents);
    if (method === "GET" && path === "/api/v1/assets") return handled(demoState.assets);
    if (method === "GET" && path === "/api/v1/incidents") return handled(demoState.incidents);
    if (method === "GET" && path === "/api/v1/threats") return handled(demoState.threats);
    if (method === "GET" && path === "/api/v1/signatures") return handled(demoState.signatures);
    if (method === "GET" && path === "/api/v1/llm/status") return handled(demoState.llmStatus);
    if (method === "GET" && path === "/api/v1/llm/tokens") return handled(demoState.llmTokens);
    if (method === "POST" && path === "/api/v1/llm/test") return handled({ ...demoState.llmStatus, upstreamReachable: true, upstreamError: null });

    if (method === "POST" && path === "/api/v1/llm/tokens") {
      const body = parseBody(rawBody);
      const now = new Date();
      const days = Math.max(1, Math.min(3650, Number(body.expiresInDays) || 90));
      const summary = {
        tokenId: `demo-${Date.now().toString(36)}`,
        name: body.name || "Demo LLM Agent",
        tokenPrefix: "nts_demo_••••",
        createdUtc: now.toISOString(),
        expiresUtc: new Date(now.getTime() + days * 86400000).toISOString(),
        requestCount: 0,
        revokedUtc: null
      };
      demoState.llmTokens.unshift(summary);
      return handled({ summary, token: `nts_demo_${cryptoRandom(32)}` }, 201);
    }

    if (method === "DELETE" && path.startsWith("/api/v1/llm/tokens/")) {
      const tokenId = decodeURIComponent(path.split("/").pop() || "");
      const token = demoState.llmTokens.find(item => item.tokenId === tokenId);
      if (token) token.revokedUtc = new Date().toISOString();
      return handled(null, 204);
    }

    if (method === "GET" && path === "/api/v1/topology/kinds") return handled(demoState.kinds);
    if (method === "GET" && path === "/api/v1/topologies") return handled(demoState.topologies);
    if (method === "GET" && path === "/api/v1/workflows") return handled(demoState.workflows);

    if ((method === "POST" || method === "PUT") && path.startsWith("/api/v1/topologies")) {
      const body = parseBody(rawBody);
      const saved = { ...body, topologyId: body.topologyId || `topo-${Date.now().toString(36)}`, updatedAtUtc: new Date().toISOString() };
      upsert(demoState.topologies, "topologyId", saved);
      return handled(saved, method === "POST" ? 201 : 200);
    }
    if (method === "DELETE" && path.startsWith("/api/v1/topologies/")) {
      removeById(demoState.topologies, "topologyId", decodeURIComponent(path.split("/").pop() || ""));
      return handled(null, 204);
    }
    if ((method === "POST" || method === "PUT") && path.startsWith("/api/v1/workflows")) {
      const body = parseBody(rawBody);
      const saved = { ...body, workflowId: body.workflowId || `flow-${Date.now().toString(36)}`, updatedAtUtc: new Date().toISOString() };
      upsert(demoState.workflows, "workflowId", saved);
      return handled(saved, method === "POST" ? 201 : 200);
    }
    if (method === "DELETE" && path.startsWith("/api/v1/workflows/")) {
      removeById(demoState.workflows, "workflowId", decodeURIComponent(path.split("/").pop() || ""));
      return handled(null, 204);
    }

    return { handled: false };
  }

  function handled(body, status = 200) { return { handled: true, body, status }; }
  function jsonResponse(body, status = 200) {
    return new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-NTShield-Demo": "1" }
    });
  }
  function delay(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }
  function parseBody(rawBody) {
    if (!rawBody) return {};
    if (typeof rawBody === "object" && !(rawBody instanceof String)) return rawBody;
    try { return JSON.parse(String(rawBody)); } catch { return {}; }
  }
  function upsert(list, key, item) {
    const index = list.findIndex(existing => existing[key] === item[key]);
    if (index >= 0) list[index] = item; else list.unshift(item);
  }
  function removeById(list, key, id) {
    const index = list.findIndex(item => item[key] === id);
    if (index >= 0) list.splice(index, 1);
  }
  function cryptoRandom(length) {
    const chars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    const bytes = new Uint8Array(length);
    globalThis.crypto?.getRandomValues?.(bytes);
    return [...bytes].map((value, index) => chars[(value || index * 17) % chars.length]).join("");
  }

  function createDemoState() {
    const now = Date.now();
    const isoAgo = minutes => new Date(now - minutes * 60000).toISOString();
    const agents = [
      ["agent-web-01", "WEB-GOV-01", "10.20.10.21", "Windows Server 2022", true, 1],
      ["agent-web-02", "WEB-GOV-02", "10.20.10.22", "Ubuntu 24.04 LTS", true, 2],
      ["agent-api-01", "API-GOV-01", "10.20.20.15", "Ubuntu 24.04 LTS", true, 1],
      ["agent-db-01", "DB-CORE-01", "10.20.50.17", "Rocky Linux 9", true, 3],
      ["agent-ad-01", "AD-PRIMARY-01", "10.20.30.12", "Windows Server 2022", true, 2],
      ["agent-fw-01", "FW-EDGE-01", "10.20.1.1", "Network Appliance", true, 1],
      ["agent-soc-01", "SOC-COLLECTOR-01", "10.20.60.10", "Ubuntu 24.04 LTS", true, 2],
      ["agent-backup-01", "BACKUP-01", "10.20.70.8", "Windows Server 2022", false, 17]
    ].map(([agentId, computerName, hostIp, platform, online, seen]) => ({
      agentId, computerName, hostIp, platform, online, status: online ? "Online" : "Offline",
      agentVersion: "1.1.0-demo", lastSeenUtc: isoAgo(seen)
    }));

    const incidentSeed = [
      ["Suspicious PowerShell chain", "High", "198.51.100.24", "10.20.10.21", 2],
      ["Web exploit behavior blocked", "High", "203.0.113.77", "10.20.20.15", 4],
      ["Repeated privileged logon", "Medium", "192.0.2.88", "10.20.30.12", 6],
      ["Unusual SQL enumeration", "Medium", "198.51.100.91", "10.20.50.17", 9],
      ["Firewall scan burst", "Medium", "203.0.113.144", "10.20.1.1", 13],
      ["Encoded command observed", "Medium", "198.51.100.62", "10.20.10.22", 18],
      ["Abnormal API request sequence", "Medium", "192.0.2.121", "10.20.20.15", 24],
      ["New service installation", "Low", "10.20.30.12", "10.20.10.21", 31],
      ["Outbound connection anomaly", "Low", "10.20.10.22", "203.0.113.28", 48],
      ["Account permission changed", "Low", "10.20.30.12", "10.20.60.10", 72],
      ["Backup service heartbeat missed", "Low", "10.20.70.8", "10.20.60.10", 96],
      ["Rare process-to-network pattern", "Low", "10.20.10.21", "198.51.100.180", 138]
    ];
    const incidents = incidentSeed.map(([title, severity, sourceIp, destinationIp, age], index) => ({
      incidentId: `demo-inc-${String(index + 1).padStart(3, "0")}`,
      title, severity, sourceIp, destinationIp, sourceHost: sourceIp.startsWith("10.") ? hostForIp(sourceIp, agents) : null,
      destinationHost: destinationIp.startsWith("10.") ? hostForIp(destinationIp, agents) : null,
      username: index % 4 === 0 ? "svc-web-demo" : index % 5 === 0 ? "admin-demo" : "",
      status: index < 7 ? "Open" : "Investigating",
      failedAttempts: [18, 14, 11, 9, 8, 6, 5, 4, 3, 2, 2, 1][index],
      firstSeenUtc: isoAgo(age + 4),
      lastSeenUtc: isoAgo(age),
      evidenceEvents: Array.from({ length: 2 + index % 4 }, (_, evidenceIndex) => ({ id: `${index}-${evidenceIndex}` }))
    }));

    const threats = [
      { campaignId: "demo-thr-01", title: "Web-to-API exploit chain", severity: "High", summary: "Behavioral correlation linked exploit-like HTTP activity with a suspicious child process on the API tier.", involvedHosts: ["WEB-GOV-01", "API-GOV-01"], hops: ["WAF", "WEB-GOV-01", "API-GOV-01"], lastSeenUtc: isoAgo(4) },
      { campaignId: "demo-thr-02", title: "Credential probing and lateral path", severity: "Medium", summary: "Repeated authentication failures were followed by a rare privileged logon path. Human approval remains required for response.", involvedHosts: ["AD-PRIMARY-01", "WEB-GOV-01"], hops: ["VPN", "AD-PRIMARY-01", "WEB-GOV-01"], lastSeenUtc: isoAgo(14) },
      { campaignId: "demo-thr-03", title: "Database discovery behavior", severity: "Medium", summary: "Unusual enumeration against a demo database was correlated with application telemetry and edge signals.", involvedHosts: ["API-GOV-01", "DB-CORE-01"], hops: ["API-GOV-01", "DB-CORE-01"], lastSeenUtc: isoAgo(27) },
      { campaignId: "demo-thr-04", title: "Outbound anomaly cluster", severity: "Low", summary: "A rare outbound destination was observed from a web node and retained for analyst review.", involvedHosts: ["WEB-GOV-02"], hops: ["WEB-GOV-02", "Internet"], lastSeenUtc: isoAgo(52) }
    ];

    const assets = agents.map((agent, index) => ({
      assetId: `asset-${String(index + 1).padStart(2, "0")}`,
      name: agent.computerName,
      hostName: agent.computerName,
      ipAddress: agent.hostIp,
      platform: agent.platform,
      status: agent.online ? "online" : "offline"
    }));

    const kinds = [
      ["internet", "Internet", "edge", "◎"], ["waf", "WAF / AI-WAF", "security", "W"],
      ["load-balancer", "Load Balancer", "network", "⇄"], ["web-server", "Web Server", "application", "WEB"],
      ["application", "Application / API", "application", "APP"], ["database", "Database", "data", "DB"],
      ["firewall", "Firewall", "security", "FW"], ["vpn", "VPN", "security", "VPN"],
      ["identity", "AD / LDAP / IdP", "identity", "ID"], ["sensor", "Suricata / Zeek / EDR", "security", "S"],
      ["cloud", "Cloud / SaaS", "cloud", "☁"], ["backup", "Backup / Storage", "data", "B"]
    ].map(([kind, label, category, icon]) => ({ kind, label, category, icon }));

    const topologyNodes = [
      ["n1", "Internet", "internet", "edge", 50, 170], ["n2", "AI-WAF", "waf", "security", 235, 170],
      ["n3", "Load Balancer", "load-balancer", "network", 420, 170], ["n4", "WEB-GOV-01", "web-server", "application", 605, 85],
      ["n5", "WEB-GOV-02", "web-server", "application", 605, 255], ["n6", "API-GOV-01", "application", "application", 790, 170],
      ["n7", "DB-CORE-01", "database", "data", 975, 170], ["n8", "FW-EDGE-01", "firewall", "security", 420, 360],
      ["n9", "AD-PRIMARY-01", "identity", "identity", 605, 360], ["n10", "SOC Sensor", "sensor", "security", 790, 360]
    ].map(([nodeId, label, kind, category, x, y], index) => ({ nodeId, label, kind, category, x, y, status: index === 8 ? "watching" : "healthy", telemetrySourceIds: [], metadata: {} }));
    const topologyEdges = [["n1","n2","HTTPS"],["n2","n3","HTTPS"],["n3","n4","HTTPS"],["n3","n5","HTTPS"],["n4","n6","API"],["n5","n6","API"],["n6","n7","SQL"],["n8","n9","LDAP"],["n9","n10","Events"],["n6","n10","Telemetry"]]
      .map(([sourceNodeId, targetNodeId, protocol], index) => ({ edgeId: `e${index + 1}`, sourceNodeId, targetNodeId, label: protocol, protocol, bidirectional: false }));

    return {
      health: { version: "1.1.0-demo", status: "Healthy", mode: "Demo", timestampUtc: new Date(now).toISOString() },
      agents,
      assets,
      incidents,
      threats,
      signatures: Array.from({ length: 164 }, (_, index) => ({ signatureId: `demo-sig-${index + 1}`, name: `Demo detection ${index + 1}` })),
      llmStatus: { enabled: true, upstreamReachable: true, activeTokenCount: 2, proxyBaseUrl: "/api/v1/llm/v1", upstreamBaseUrl: "http://qwen-demo.local:8000/v1", model: "Qwen3.5-9B", upstreamError: null },
      llmTokens: [
        { tokenId: "demo-token-soc", name: "SOC Analyst Demo", tokenPrefix: "nts_demo_soc…", createdUtc: isoAgo(1440), expiresUtc: new Date(now + 89 * 86400000).toISOString(), requestCount: 1842, revokedUtc: null },
        { tokenId: "demo-token-agent", name: "Linux Agent Demo", tokenPrefix: "nts_demo_lin…", createdUtc: isoAgo(2880), expiresUtc: new Date(now + 88 * 86400000).toISOString(), requestCount: 932, revokedUtc: null }
      ],
      kinds,
      topologies: [{
        topologyId: "demo-topology-main", tenantId: "default", name: "Government Service Demo", description: "Synthetic infrastructure topology for NT Shield demonstration.", version: 1,
        nodes: topologyNodes, edges: topologyEdges, createdAtUtc: isoAgo(43200), updatedAtUtc: isoAgo(5)
      }],
      workflows: [{
        workflowId: "demo-workflow-zero-day", tenantId: "default", name: "Behavioral Zero-Day Correlation", description: "Demo workflow using only synthetic telemetry.", topologyId: "demo-topology-main", enabled: true, version: 1,
        nodes: [
          { nodeId: "w1", type: "trigger", label: "Endpoint + WAF telemetry", x: 60, y: 160, config: {} },
          { nodeId: "w2", type: "filter", label: "Rare behavior", x: 260, y: 160, config: {} },
          { nodeId: "w3", type: "correlate", label: "Cross-host correlation", x: 460, y: 160, config: {} },
          { nodeId: "w4", type: "ai", label: "AI Analyst", x: 660, y: 160, config: {} },
          { nodeId: "w5", type: "approval", label: "Human approval", x: 860, y: 160, config: {} },
          { nodeId: "w6", type: "notify", label: "Thai incident alert", x: 1060, y: 160, config: {} }
        ],
        edges: [["w1","w2"],["w2","w3"],["w3","w4"],["w4","w5"],["w5","w6"]].map(([sourceNodeId,targetNodeId], index) => ({ edgeId: `we${index + 1}`, sourceNodeId, targetNodeId, label: "" })),
        createdAtUtc: isoAgo(43200), updatedAtUtc: isoAgo(6)
      }]
    };
  }

  function hostForIp(ip, agents) { return agents.find(agent => agent.hostIp === ip)?.computerName || null; }

  function init() {
    if (mapState.initialized) return;
    mapState.canvas = document.querySelector("#defenseGlobeCanvas");
    if (!mapState.canvas) return;
    mapState.ctx = mapState.canvas.getContext("2d", { alpha: true });
    mapState.reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    mapState.initialized = true;
    const observer = new ResizeObserver(() => { resize(); draw(performance.now()); });
    observer.observe(mapState.canvas.parentElement);
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) stop(); else if (mapState.active) start();
    });
    resize();
    draw(performance.now());
  }

  function update(payload = {}) {
    const incidents = Array.isArray(payload.incidents) ? payload.incidents : [];
    const threats = Array.isArray(payload.threats) ? payload.threats : [];
    const onlineAgents = Number(payload.onlineAgents) || 0;
    mapState.attackCount = Math.min(attackRoutes.length, Math.max(2, incidents.length + threats.length));
    mapState.defenseCount = Math.min(defenseRoutes.length, Math.max(1, onlineAgents));
    draw(performance.now());
  }

  function setActive(active) {
    mapState.active = Boolean(active);
    if (!mapState.initialized) init();
    if (mapState.active && !mapState.reduceMotion) start(); else stop();
    if (mapState.active) draw(performance.now());
  }

  function start() {
    if (mapState.frame || document.hidden || !mapState.active) return;
    mapState.lastTime = performance.now();
    mapState.frame = requestAnimationFrame(animate);
  }

  function stop() {
    if (mapState.frame) cancelAnimationFrame(mapState.frame);
    mapState.frame = 0;
  }

  function animate(time) {
    mapState.frame = 0;
    const delta = Math.min(40, time - mapState.lastTime);
    mapState.lastTime = time;
    mapState.rotation += delta * 0.000035;
    draw(time);
    if (mapState.active && !mapState.reduceMotion && !document.hidden) mapState.frame = requestAnimationFrame(animate);
  }

  function resize() {
    const rect = mapState.canvas.getBoundingClientRect();
    const width = Math.max(1, Math.round(rect.width));
    const height = Math.max(1, Math.round(rect.height));
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    if (width === mapState.width && height === mapState.height && dpr === mapState.dpr) return;
    mapState.width = width;
    mapState.height = height;
    mapState.dpr = dpr;
    mapState.canvas.width = Math.round(width * dpr);
    mapState.canvas.height = Math.round(height * dpr);
    mapState.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function draw(time) {
    if (!mapState.ctx || !mapState.width || !mapState.height) return;
    const ctx = mapState.ctx;
    const width = mapState.width;
    const height = mapState.height;
    ctx.setTransform(mapState.dpr, 0, 0, mapState.dpr, 0, 0);
    ctx.clearRect(0, 0, width, height);

    const radius = Math.min(width * 0.245, height * 0.36);
    const center = { x: width * 0.49, y: height * 0.52 };
    drawFloor(ctx, center, radius, width, height, time);
    drawSphere(ctx, center, radius, time);
    drawAttackArcs(ctx, center, radius, width, height, time);
    drawDefenseArcs(ctx, center, radius, width, height, time);
    drawOrbitParticles(ctx, center, radius, time);
  }

  function drawFloor(ctx, center, radius, width, height, time) {
    ctx.save();
    const floorY = center.y + radius * 0.84;
    for (let ring = 0; ring < 5; ring++) {
      ctx.beginPath();
      ctx.ellipse(center.x, floorY, radius * (0.70 + ring * 0.23), radius * (0.13 + ring * 0.04), 0, 0, Math.PI * 2);
      ctx.strokeStyle = `rgba(230,174,0,${0.22 - ring * 0.032})`;
      ctx.lineWidth = 1;
      ctx.setLineDash(ring % 2 ? [4, 7] : []);
      ctx.stroke();
    }
    ctx.setLineDash([]);
    const glow = ctx.createRadialGradient(center.x, floorY, 0, center.x, floorY, radius * 1.4);
    glow.addColorStop(0, "rgba(255,202,24,.12)");
    glow.addColorStop(1, "rgba(255,202,24,0)");
    ctx.fillStyle = glow;
    ctx.fillRect(0, floorY - radius * 0.3, width, height - floorY + radius * 0.3);
    ctx.restore();
  }

  function drawSphere(ctx, center, radius, time) {
    ctx.save();
    const halo = ctx.createRadialGradient(center.x, center.y, radius * 0.25, center.x, center.y, radius * 1.36);
    halo.addColorStop(0, "rgba(255,208,42,.13)");
    halo.addColorStop(0.48, "rgba(255,208,42,.045)");
    halo.addColorStop(1, "rgba(255,208,42,0)");
    ctx.fillStyle = halo;
    ctx.beginPath(); ctx.arc(center.x, center.y, radius * 1.36, 0, Math.PI * 2); ctx.fill();

    const sphere = ctx.createRadialGradient(center.x - radius * 0.34, center.y - radius * 0.38, radius * 0.03, center.x, center.y, radius);
    sphere.addColorStop(0, "rgba(255,255,255,.99)");
    sphere.addColorStop(0.55, "rgba(245,247,249,.9)");
    sphere.addColorStop(1, "rgba(207,214,223,.46)");
    ctx.fillStyle = sphere;
    ctx.beginPath(); ctx.arc(center.x, center.y, radius, 0, Math.PI * 2); ctx.fill();
    ctx.strokeStyle = "rgba(177,187,199,.44)";
    ctx.lineWidth = 1.2;
    ctx.stroke();

    ctx.save();
    ctx.beginPath(); ctx.arc(center.x, center.y, radius - 0.5, 0, Math.PI * 2); ctx.clip();
    drawGrid(ctx, center, radius);
    drawLandPoints(ctx, center, radius);
    const scanX = center.x - radius + ((time * 0.028) % (radius * 2));
    const scan = ctx.createLinearGradient(scanX - 18, 0, scanX + 18, 0);
    scan.addColorStop(0, "rgba(255,205,35,0)");
    scan.addColorStop(0.5, "rgba(255,205,35,.16)");
    scan.addColorStop(1, "rgba(255,205,35,0)");
    ctx.fillStyle = scan;
    ctx.fillRect(scanX - 18, center.y - radius, 36, radius * 2);
    ctx.restore();

    ctx.beginPath();
    ctx.arc(center.x, center.y, radius * 1.055, -0.4, Math.PI * 1.62);
    ctx.strokeStyle = "rgba(243,183,0,.28)";
    ctx.lineWidth = 1;
    ctx.setLineDash([3, 7]);
    ctx.stroke();
    ctx.restore();
  }

  function drawGrid(ctx, center, radius) {
    for (let lat = -60; lat <= 60; lat += 15) {
      drawProjectedPath(ctx, center, radius, Array.from({ length: 121 }, (_, index) => [lat, -180 + index * 3]), "rgba(151,163,178,.19)", 0.7);
    }
    for (let lon = -180; lon < 180; lon += 20) {
      drawProjectedPath(ctx, center, radius, Array.from({ length: 81 }, (_, index) => [-80 + index * 2, lon]), "rgba(151,163,178,.16)", 0.65);
    }
  }

  function drawProjectedPath(ctx, center, radius, coordinates, color, lineWidth) {
    let drawing = false;
    ctx.beginPath();
    coordinates.forEach(([lat, lon]) => {
      const point = project(lat, lon, center, radius);
      if (point.z <= 0) { drawing = false; return; }
      if (!drawing) { ctx.moveTo(point.x, point.y); drawing = true; }
      else ctx.lineTo(point.x, point.y);
    });
    ctx.strokeStyle = color;
    ctx.lineWidth = lineWidth;
    ctx.stroke();
  }

  function drawLandPoints(ctx, center, radius) {
    for (const point of mapState.landPoints) {
      const projected = project(point.lat, point.lon, center, radius);
      if (projected.z <= 0) continue;
      const alpha = 0.18 + projected.z * 0.48;
      const size = point.size * (0.74 + projected.z * 0.46);
      ctx.fillStyle = `rgba(103,116,133,${alpha})`;
      ctx.beginPath();
      ctx.arc(projected.x, projected.y, size, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  function drawAttackArcs(ctx, center, radius, width, height, time) {
    for (let index = 0; index < mapState.attackCount; index++) {
      const attack = attackRoutes[index];
      const start = { x: width * attack.origin[0], y: height * attack.origin[1] };
      const target = project(attack.target[0], attack.target[1], center, radius);
      const control = { x: (start.x + target.x) / 2, y: Math.min(start.y, target.y) + height * attack.bend };
      drawCurve(ctx, start, control, target, "rgba(255,84,54,.66)", [5, 5]);
      const progress = mapState.reduceMotion ? 0.66 : ((time * 0.00016 + attack.phase) % 1);
      const particle = quadratic(start, control, target, progress);
      drawPulse(ctx, particle.x, particle.y, "#ff5a3d", 3.1, time + index * 300);
      drawThreatMarker(ctx, start.x + 8, start.y, index);
      if (index < 4) drawRouteLabel(ctx, quadratic(start, control, target, 0.58), attack.label);
    }
  }

  function drawDefenseArcs(ctx, center, radius, width, height, time) {
    for (let index = 0; index < mapState.defenseCount; index++) {
      const defense = defenseRoutes[index];
      const start = project(defense.target[0], defense.target[1], center, radius);
      const end = { x: width * defense.end[0], y: height * defense.end[1] };
      const control = { x: (start.x + end.x) / 2, y: Math.min(start.y, end.y) + height * defense.bend };
      drawCurve(ctx, start, control, end, "rgba(238,180,0,.56)", []);
      const progress = mapState.reduceMotion ? 0.58 : ((time * 0.00013 + defense.phase) % 1);
      const particle = quadratic(start, control, end, progress);
      drawPulse(ctx, particle.x, particle.y, "#ffc400", 2.7, time + index * 440);
    }
  }

  function drawCurve(ctx, start, control, end, color, dash) {
    ctx.save();
    ctx.beginPath();
    ctx.moveTo(start.x, start.y);
    ctx.quadraticCurveTo(control.x, control.y, end.x, end.y);
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.25;
    ctx.setLineDash(dash);
    ctx.stroke();
    ctx.restore();
  }

  function drawThreatMarker(ctx, x, y, index) {
    ctx.save();
    ctx.translate(x, y);
    ctx.beginPath();
    for (let side = 0; side < 6; side++) {
      const angle = Math.PI / 3 * side - Math.PI / 2;
      const px = Math.cos(angle) * 10;
      const py = Math.sin(angle) * 10;
      if (side === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py);
    }
    ctx.closePath();
    ctx.fillStyle = "rgba(255,255,255,.94)";
    ctx.fill();
    ctx.strokeStyle = "rgba(255,84,54,.78)";
    ctx.stroke();
    ctx.fillStyle = "#ff5a3d";
    ctx.font = "900 9px system-ui";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText("!", 0, 1);
    ctx.fillStyle = "rgba(66,73,84,.78)";
    ctx.font = "700 7px system-ui";
    ctx.textAlign = "left";
    ctx.fillText(index % 2 ? "THREAT" : "AI THREAT", 14, 0);
    ctx.restore();
  }

  function drawRouteLabel(ctx, point, text) {
    ctx.save();
    ctx.font = "700 7px ui-monospace, SFMono-Regular, Consolas, monospace";
    const paddingX = 8;
    const width = Math.min(205, ctx.measureText(text).width + paddingX * 2 + 8);
    const height = 22;
    const x = Math.max(5, Math.min(mapState.width - width - 5, point.x - width / 2));
    const y = Math.max(5, Math.min(mapState.height - height - 5, point.y - height / 2));
    roundedRect(ctx, x, y, width, height, 11);
    ctx.fillStyle = "rgba(255,255,255,.92)";
    ctx.fill();
    ctx.strokeStyle = "rgba(235,177,0,.62)";
    ctx.lineWidth = 1;
    ctx.stroke();
    ctx.fillStyle = "#f0ad00";
    ctx.beginPath(); ctx.arc(x + 9, y + height / 2, 3.2, 0, Math.PI * 2); ctx.fill();
    ctx.fillStyle = "#735a16";
    ctx.textBaseline = "middle";
    ctx.textAlign = "left";
    const maxTextWidth = width - 25;
    let visible = text;
    while (visible.length > 8 && ctx.measureText(visible).width > maxTextWidth) visible = `${visible.slice(0, -2)}…`;
    ctx.fillText(visible, x + 17, y + height / 2 + 0.5);
    ctx.restore();
  }

  function roundedRect(ctx, x, y, width, height, radius) {
    const r = Math.min(radius, width / 2, height / 2);
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.arcTo(x + width, y, x + width, y + height, r);
    ctx.arcTo(x + width, y + height, x, y + height, r);
    ctx.arcTo(x, y + height, x, y, r);
    ctx.arcTo(x, y, x + width, y, r);
    ctx.closePath();
  }

  function drawPulse(ctx, x, y, color, radius, time) {
    const pulse = 0.5 + Math.sin(time * 0.006) * 0.5;
    ctx.save();
    ctx.globalAlpha = 0.28 * (1 - pulse);
    ctx.fillStyle = color;
    ctx.beginPath(); ctx.arc(x, y, radius + pulse * 8, 0, Math.PI * 2); ctx.fill();
    ctx.globalAlpha = 1;
    ctx.fillStyle = color;
    ctx.strokeStyle = "#fff";
    ctx.lineWidth = 1.2;
    ctx.beginPath(); ctx.arc(x, y, radius, 0, Math.PI * 2); ctx.fill(); ctx.stroke();
    ctx.restore();
  }

  function drawOrbitParticles(ctx, center, radius, time) {
    for (let index = 0; index < 16; index++) {
      const angle = index / 16 * Math.PI * 2 + time * 0.00008;
      const orbit = radius * (1.05 + (index % 3) * 0.12);
      const x = center.x + Math.cos(angle) * orbit;
      const y = center.y + Math.sin(angle) * orbit * 0.35;
      ctx.fillStyle = index % 4 === 0 ? "rgba(255,196,0,.75)" : "rgba(181,190,201,.48)";
      ctx.beginPath();
      ctx.arc(x, y, index % 4 === 0 ? 1.8 : 1.1, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  function project(latDegrees, lonDegrees, center, radius) {
    const lat = latDegrees * Math.PI / 180;
    const lon = lonDegrees * Math.PI / 180 + mapState.rotation;
    const cosLat = Math.cos(lat);
    const x = cosLat * Math.sin(lon);
    const y = -Math.sin(lat);
    const z = cosLat * Math.cos(lon);
    return { x: center.x + x * radius, y: center.y + y * radius, z };
  }

  function quadratic(start, control, end, progress) {
    const inverse = 1 - progress;
    return {
      x: inverse * inverse * start.x + 2 * inverse * progress * control.x + progress * progress * end.x,
      y: inverse * inverse * start.y + 2 * inverse * progress * control.y + progress * progress * end.y
    };
  }

  function createLandPoints() {
    const regions = [
      [42, -103, 25, 48, 240], [-14, -61, 31, 20, 130], [53, 14, 14, 27, 95],
      [7, 21, 33, 23, 155], [38, 86, 29, 62, 300], [-25, 135, 14, 23, 80], [70, -42, 9, 17, 35]
    ];
    let seed = 90210;
    const random = () => {
      seed = (seed * 1664525 + 1013904223) >>> 0;
      return seed / 4294967296;
    };
    const points = [];
    regions.forEach(([centerLat, centerLon, latRadius, lonRadius, count]) => {
      for (let index = 0; index < count; index++) {
        const angle = random() * Math.PI * 2;
        const distance = Math.sqrt(random());
        const lat = Math.max(-82, Math.min(82, centerLat + Math.sin(angle) * latRadius * distance));
        const lon = centerLon + Math.cos(angle) * lonRadius * distance;
        points.push({ lat, lon, size: random() > 0.78 ? 1.15 : 0.7 });
      }
    });
    return points;
  }

  globalThis.NTShieldDefenseMap = { init, update, setActive };
})();
