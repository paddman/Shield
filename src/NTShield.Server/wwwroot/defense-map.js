"use strict";

/* Real country geometry + GeoIP-positioned attack sources for the overview globe. */
(function () {
  const WORLD_DATA_URL = "assets/maps/countries-110m.json?v=2.0.2";
  const MAX_GEO_ATTACKS = 8;
  const MAX_DEFENSE_AGENTS = 3;
  const mapState = {
    canvas: null,
    ctx: null,
    pinHost: null,
    geoCaption: null,
    requestJson: null,
    getTenant: null,
    width: 0,
    height: 0,
    dpr: 1,
    active: false,
    onscreen: true,
    initialized: false,
    frame: 0,
    lastTime: 0,
    rotation: -100,
    reduceMotion: false,
    defenseCount: 1,
    countries: null,
    graticule: null,
    geoAttacks: [],
    geoRequestId: 0,
    geoController: null,
    lastLookupKey: "",
    centeredOnFirstAttack: false
  };

  function init(options = {}) {
    if (mapState.initialized) return;
    mapState.canvas = document.querySelector("#defenseGlobeCanvas");
    if (!mapState.canvas) return;
    mapState.ctx = mapState.canvas.getContext("2d", { alpha: true });
    mapState.pinHost = document.querySelector("#defenseIncidentPins");
    mapState.geoCaption = document.querySelector(".defense-map-heading small");
    mapState.requestJson = options.requestJson || null;
    mapState.getTenant = options.getTenant || null;
    mapState.reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    mapState.initialized = true;

    const observer = new ResizeObserver(() => {
      resize();
      draw(performance.now());
    });
    observer.observe(mapState.canvas.parentElement);
    if ("IntersectionObserver" in globalThis) {
      const visibilityObserver = new IntersectionObserver(entries => {
        mapState.onscreen = Boolean(entries[0]?.isIntersecting);
        if (mapState.active && mapState.onscreen && !document.hidden) start();
        else stop();
      }, { rootMargin: "120px", threshold: .01 });
      visibilityObserver.observe(mapState.canvas.parentElement);
    }
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) stop();
      else if (mapState.active) start();
    });

    resize();
    loadWorldGeometry();
    draw(performance.now());
  }

  async function loadWorldGeometry() {
    if (!globalThis.d3 || !globalThis.topojson) {
      setGeoCaption("World geometry library unavailable");
      return;
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    try {
      const response = await fetch(WORLD_DATA_URL, { cache: "force-cache", signal: controller.signal });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const world = await response.json();
      mapState.countries = globalThis.topojson.feature(world, world.objects.countries);
      mapState.graticule = globalThis.d3.geoGraticule10();
      draw(performance.now());
    } catch (error) {
      console.warn("NT Shield world geometry unavailable", error);
      setGeoCaption("World map unavailable • telemetry remains active");
    } finally {
      clearTimeout(timer);
    }
  }

  function update({ incidents = [], onlineAgents = 0 } = {}) {
    mapState.defenseCount = Math.min(MAX_DEFENSE_AGENTS, Math.max(1, Number(onlineAgents) || 0));
    if (mapState.active) resolveGeoAttacks(incidents);
    draw(performance.now());
  }

  async function resolveGeoAttacks(incidents) {
    const candidates = collectAttackSources(incidents).slice(0, MAX_GEO_ATTACKS);
    const lookupKey = `${String(mapState.getTenant?.() || "default")}|${candidates.map(item => item.ip.toLowerCase()).sort().join(",")}`;
    if (lookupKey === mapState.lastLookupKey) return;
    mapState.lastLookupKey = lookupKey;
    const requestId = ++mapState.geoRequestId;
    mapState.geoController?.abort();
    const controller = new AbortController();
    mapState.geoController = controller;
    mapState.geoAttacks = [];
    syncGeoPins();

    if (!candidates.length) {
      setGeoCaption("No source IP available for geolocation");
      return;
    }
    if (!mapState.requestJson) {
      setGeoCaption("GeoIP service unavailable");
      return;
    }

    setGeoCaption("Resolving attack-source countries…");
    try {
      const locations = await mapState.requestJson("/api/v1/geoip/lookup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: { ips: candidates.map(item => item.ip) },
        signal: controller.signal,
        timeoutMs: 8000
      });
      if (requestId !== mapState.geoRequestId) return;

      const byIp = new Map((Array.isArray(locations) ? locations : [])
        .map(location => [String(location.ip || "").toLowerCase(), location]));
      mapState.geoAttacks = candidates.flatMap(candidate => {
        const location = byIp.get(candidate.ip.toLowerCase());
        const latitude = Number(location?.latitude);
        const longitude = Number(location?.longitude);
        if (!location?.success || location.isPrivate || !Number.isFinite(latitude) || !Number.isFinite(longitude)) return [];
        return [{
          ...candidate,
          latitude,
          longitude,
          country: location.country || "Unknown country",
          countryCode: location.countryCode || "",
          region: location.region || "",
          city: location.city || ""
        }];
      });

      if (mapState.geoAttacks.length && !mapState.centeredOnFirstAttack) {
        mapState.rotation = normalizeLongitude(-mapState.geoAttacks[0].longitude);
        mapState.centeredOnFirstAttack = true;
      }
      syncGeoPins();

      const privateCount = (Array.isArray(locations) ? locations : []).filter(item => item.isPrivate).length;
      if (mapState.geoAttacks.length) {
        setGeoCaption(`${mapState.geoAttacks.length} public source IP${mapState.geoAttacks.length === 1 ? "" : "s"} located • GeoIP approximate`);
      } else if (privateCount) {
        setGeoCaption("Private source IPs • Local Network (no country assigned)");
      } else {
        setGeoCaption("Public source country could not be resolved");
      }
      draw(performance.now());
    } catch (error) {
      if (requestId !== mapState.geoRequestId) return;
      mapState.lastLookupKey = "";
      if (error?.name === "AbortError") return;
      console.warn("NT Shield GeoIP lookup failed", error);
      setGeoCaption("GeoIP lookup unavailable • no synthetic location shown");
    } finally {
      if (mapState.geoController === controller) mapState.geoController = null;
    }
  }

  function collectAttackSources(incidents) {
    const seen = new Set();
    const sources = [];
    for (const item of Array.isArray(incidents) ? incidents : []) {
      const ip = normalizeIp(readIncidentIp(item, "source"));
      if (!ip || seen.has(ip.toLowerCase())) continue;
      seen.add(ip.toLowerCase());
      const eventId = pick(item, "eventId");
      const computerName = pick(item, "computerName");
      sources.push({
        ip,
        title: String(pick(item, "title") || [eventId ? `Detection ${eventId}` : "Confirmed incident", computerName].filter(Boolean).join(" • ")),
        severity: severityClass(pick(item, "severity")),
        eventId: String(eventId || ""),
        eventRecordId: String(pick(item, "eventRecordId") || "")
      });
    }
    return sources;
  }

  function readIncidentIp(item, side) {
    const direct = pick(item, `${side}Ip`);
    if (direct) return String(direct).split(",")[0].trim();
    if (side !== "source") return "";
    const description = String(pick(item, "description") || "");
    return /(?:^|\s)SourceIp=([^\s,]+)/i.exec(description)?.[1] || "";
  }

  function normalizeIp(value) {
    let candidate = String(value || "").trim();
    if (!candidate) return "";
    const bracketed = /^\[([^\]]+)](?::\d+)?$/.exec(candidate);
    if (bracketed) return bracketed[1];
    const ipv4WithPort = /^(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?$/.exec(candidate);
    if (ipv4WithPort) return ipv4WithPort[1];
    return candidate;
  }

  function pick(item, key) {
    if (!item) return undefined;
    if (item[key] !== undefined && item[key] !== null) return item[key];
    const pascal = key.charAt(0).toUpperCase() + key.slice(1);
    return item[pascal];
  }

  function severityClass(value) {
    if (typeof value === "number") {
      if (value >= 4) return "critical";
      if (value >= 3) return "high";
      if (value >= 2) return "medium";
      return "low";
    }
    const text = String(value || "").toLowerCase();
    return ["critical", "high", "medium", "low"].includes(text) ? text : "medium";
  }

  function setGeoCaption(text) {
    if (mapState.geoCaption) mapState.geoCaption.textContent = text;
  }

  function syncGeoPins() {
    if (!mapState.pinHost) return;
    mapState.pinHost.replaceChildren();
    const summary = mapState.geoAttacks.slice(0, 5).map(attack => `${attack.ip}, ${attack.country}`).join("; ");
    mapState.canvas?.setAttribute("aria-label", summary ? `Live incident map: ${summary}` : "Live incident map");
  }

  function setActive(active) {
    mapState.active = Boolean(active);
    if (!mapState.initialized) init();
    if (mapState.active) start();
    else {
      stop();
      mapState.geoRequestId++;
      mapState.geoController?.abort();
      mapState.geoController = null;
      mapState.lastLookupKey = "";
    }
  }

  function start() {
    if (!mapState.initialized || mapState.frame || mapState.reduceMotion || document.hidden || !mapState.onscreen) return;
    mapState.lastTime = performance.now();
    mapState.frame = requestAnimationFrame(animate);
  }

  function stop() {
    if (mapState.frame) cancelAnimationFrame(mapState.frame);
    mapState.frame = 0;
  }

  function animate(time) {
    mapState.frame = 0;
    if (time - mapState.lastTime < 50) {
      if (mapState.active && mapState.onscreen && !document.hidden) mapState.frame = requestAnimationFrame(animate);
      return;
    }
    const delta = Math.min(40, time - mapState.lastTime);
    mapState.lastTime = time;
    mapState.rotation = normalizeLongitude(mapState.rotation + delta * .0018);
    draw(time);
    if (mapState.active && mapState.onscreen && !mapState.reduceMotion && !document.hidden) {
      mapState.frame = requestAnimationFrame(animate);
    }
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

    const radius = Math.min(width * .225, height * .34);
    if (radius <= .5) return;
    const center = { x: width * .49, y: height * .58 };
    drawFloor(ctx, center, radius, width, height);

    const projection = createProjection(center, radius);
    if (projection) drawRealGlobe(ctx, projection, center, radius, time);
    else drawFallbackGlobe(ctx, center, radius);

    const agentTargets = getAgentTargets().slice(0, mapState.defenseCount);
    const attackRoutes = buildAttackRoutes(projection, radius, time, agentTargets);
    drawGeoAttacks(ctx, attackRoutes, time);
    drawGeoLabels(ctx, attackRoutes);
  }

  function createProjection(center, radius) {
    if (!globalThis.d3) return null;
    return globalThis.d3.geoOrthographic()
      .translate([center.x, center.y])
      .scale(radius)
      .clipAngle(90)
      .precision(.45)
      .rotate([mapState.rotation, -8, 0]);
  }

  function drawRealGlobe(ctx, projection, center, radius, time) {
    const path = globalThis.d3.geoPath(projection, ctx);
    const sphere = { type: "Sphere" };
    ctx.save();

    const halo = ctx.createRadialGradient(center.x, center.y, radius * .45, center.x, center.y, radius * 1.35);
    halo.addColorStop(0, "rgba(255,208,42,.12)");
    halo.addColorStop(.52, "rgba(255,208,42,.035)");
    halo.addColorStop(1, "rgba(255,208,42,0)");
    ctx.fillStyle = halo;
    ctx.beginPath();
    ctx.arc(center.x, center.y, radius * 1.35, 0, Math.PI * 2);
    ctx.fill();

    const ocean = ctx.createRadialGradient(center.x - radius * .34, center.y - radius * .4, radius * .04, center.x, center.y, radius);
    ocean.addColorStop(0, "rgba(255,255,255,.99)");
    ocean.addColorStop(.55, "rgba(244,247,250,.94)");
    ocean.addColorStop(1, "rgba(208,216,225,.62)");
    ctx.beginPath();
    path(sphere);
    ctx.fillStyle = ocean;
    ctx.fill();

    if (mapState.graticule) {
      ctx.beginPath();
      path(mapState.graticule);
      ctx.strokeStyle = "rgba(130,145,162,.19)";
      ctx.lineWidth = .7;
      ctx.stroke();
    }

    if (mapState.countries) {
      ctx.beginPath();
      path(mapState.countries);
      ctx.fillStyle = "rgba(171,183,196,.42)";
      ctx.fill();
      ctx.strokeStyle = "rgba(101,117,136,.48)";
      ctx.lineWidth = .65;
      ctx.stroke();
    }

    ctx.save();
    ctx.beginPath();
    ctx.arc(center.x, center.y, radius, 0, Math.PI * 2);
    ctx.clip();
    const scanX = center.x - radius + ((time * .025) % (radius * 2));
    const scan = ctx.createLinearGradient(scanX - 20, 0, scanX + 20, 0);
    scan.addColorStop(0, "rgba(255,205,35,0)");
    scan.addColorStop(.5, "rgba(255,205,35,.14)");
    scan.addColorStop(1, "rgba(255,205,35,0)");
    ctx.fillStyle = scan;
    ctx.fillRect(scanX - 20, center.y - radius, 40, radius * 2);
    ctx.restore();

    ctx.beginPath();
    path(sphere);
    ctx.strokeStyle = "rgba(154,167,183,.52)";
    ctx.lineWidth = 1.15;
    ctx.stroke();
    ctx.restore();
  }

  function drawFallbackGlobe(ctx, center, radius) {
    ctx.save();
    ctx.fillStyle = "rgba(244,247,250,.94)";
    ctx.strokeStyle = "rgba(154,167,183,.5)";
    ctx.lineWidth = 1.1;
    ctx.beginPath();
    ctx.arc(center.x, center.y, radius, 0, Math.PI * 2);
    ctx.fill();
    ctx.stroke();
    ctx.strokeStyle = "rgba(130,145,162,.18)";
    for (let index = -2; index <= 2; index++) {
      ctx.beginPath();
      ctx.ellipse(center.x, center.y, radius * Math.cos(index * .27), radius, 0, 0, Math.PI * 2);
      ctx.stroke();
      ctx.beginPath();
      ctx.ellipse(center.x, center.y, radius, radius * Math.cos(index * .27), 0, 0, Math.PI * 2);
      ctx.stroke();
    }
    ctx.restore();
  }

  function getAgentTargets() {
    const container = mapState.canvas?.parentElement;
    if (!container) return [];
    const containerRect = container.getBoundingClientRect();
    return [...container.querySelectorAll(".defense-agent > i")].map(agent => {
      const rect = agent.getBoundingClientRect();
      return {
        x: rect.left - containerRect.left + rect.width / 2,
        y: rect.top - containerRect.top + rect.height / 2
      };
    });
  }

  function buildAttackRoutes(projection, radius, time, agentTargets) {
    if (!projection || !globalThis.d3 || !agentTargets.length) return [];
    const routes = [];
    mapState.geoAttacks.forEach((attack, index) => {
      if (!isGeoVisible(attack)) return;
      const point = projection([attack.longitude, attack.latitude]);
      if (!point) return;
      const start = { x: point[0], y: point[1] };
      const target = agentTargets[index % agentTargets.length];
      const deltaX = target.x - start.x;
      const deltaY = target.y - start.y;
      const distance = Math.max(1, Math.hypot(deltaX, deltaY));
      const curve = Math.min(radius * .28, distance * .18) * (index % 2 ? 1 : -1);
      const control = {
        x: (start.x + target.x) / 2 - deltaY / distance * curve,
        y: (start.y + target.y) / 2 + deltaX / distance * curve
      };
      const motion = routeMotion(time, index);
      routes.push({ index, attack, start, control, target, motion });
    });
    return routes;
  }

  function routeMotion(time, index) {
    if (mapState.reduceMotion) return { progress: 0, opacity: 1 };
    const cycle = (time * .00014 + index * .43) % 1;
    if (cycle < .14) return { progress: 0, opacity: Math.min(1, cycle / .045) };
    if (cycle > .93) return { progress: 1, opacity: Math.max(0, (1 - cycle) / .07) };
    const linear = (cycle - .14) / .79;
    return {
      progress: linear * linear * (3 - 2 * linear),
      opacity: 1
    };
  }

  function drawGeoAttacks(ctx, routes, time) {
    routes.forEach(({ index, start, control, target, motion }) => {
      drawCurve(ctx, start, control, target, "rgba(255,84,54,.72)", [5, 5]);
      drawPulse(ctx, start.x, start.y, "#ff5a3d", 3.5, time + index * 330);
      const packet = quadratic(start, control, target, motion.progress);
      drawPulse(ctx, packet.x, packet.y, "#ff5a3d", 3, time + index * 410);
    });
  }

  function drawGeoLabels(ctx, routes) {
    ctx.save();
    ctx.font = "800 9px ui-monospace, SFMono-Regular, Consolas, monospace";
    routes.slice(0, 3).forEach(({ attack, start, control, target, motion }) => {
      const packet = quadratic(start, control, target, motion.progress);
      const label = `${attack.ip} • ${attack.country}`.slice(0, 46);
      const width = Math.min(210, Math.ceil(ctx.measureText(label).width) + 16);
      const x = Math.max(4, Math.min(mapState.width - width - 4, packet.x - width / 2));
      const y = Math.max(17, packet.y - 18);
      ctx.globalAlpha = motion.opacity;
      ctx.fillStyle = "rgba(255,255,255,.94)";
      ctx.strokeStyle = attack.severity === "critical" || attack.severity === "high" ? "rgba(255,90,61,.58)" : "rgba(224,168,15,.58)";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.rect(x, y - 13, width, 19);
      ctx.fill();
      ctx.stroke();
      ctx.fillStyle = "#6b4b00";
      ctx.fillText(label, x + 8, y);
    });
    ctx.restore();
  }

  function isGeoVisible(attack) {
    const globeCenter = [normalizeLongitude(-mapState.rotation), 8];
    return globalThis.d3.geoDistance(
      [attack.longitude, attack.latitude],
      globeCenter) < Math.PI / 2 - .025;
  }

  function drawFloor(ctx, center, radius, width, height) {
    ctx.save();
    const floorY = center.y + radius * .83;
    for (let ring = 0; ring < 5; ring++) {
      ctx.beginPath();
      ctx.ellipse(center.x, floorY, radius * (.68 + ring * .24), radius * (.13 + ring * .042), 0, 0, Math.PI * 2);
      ctx.strokeStyle = `rgba(230,174,0,${.22 - ring * .032})`;
      ctx.lineWidth = 1;
      ctx.setLineDash(ring % 2 ? [4, 7] : []);
      ctx.stroke();
    }
    ctx.setLineDash([]);
    const glow = ctx.createRadialGradient(center.x, floorY, 0, center.x, floorY, radius * 1.4);
    glow.addColorStop(0, "rgba(255,202,24,.11)");
    glow.addColorStop(1, "rgba(255,202,24,0)");
    ctx.fillStyle = glow;
    ctx.fillRect(0, floorY - radius * .3, width, height - floorY + radius * .3);
    ctx.restore();
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

  function drawPulse(ctx, x, y, color, radius, time) {
    const pulse = .5 + Math.sin(time * .006) * .5;
    ctx.save();
    ctx.globalAlpha = .3 * (1 - pulse);
    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.arc(x, y, radius + pulse * 9, 0, Math.PI * 2);
    ctx.fill();
    ctx.globalAlpha = 1;
    ctx.fillStyle = color;
    ctx.strokeStyle = "#fff";
    ctx.lineWidth = 1.3;
    ctx.beginPath();
    ctx.arc(x, y, radius, 0, Math.PI * 2);
    ctx.fill();
    ctx.stroke();
    ctx.restore();
  }

  function quadratic(start, control, end, progress) {
    const inverse = 1 - progress;
    return {
      x: inverse * inverse * start.x + 2 * inverse * progress * control.x + progress * progress * end.x,
      y: inverse * inverse * start.y + 2 * inverse * progress * control.y + progress * progress * end.y
    };
  }

  function normalizeLongitude(value) {
    return ((value + 180) % 360 + 360) % 360 - 180;
  }

  globalThis.NTShieldDefenseMap = { init, update, setActive };
})();
