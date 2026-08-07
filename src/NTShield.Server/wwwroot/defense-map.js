"use strict";

/* Dependency-free animated globe for the Global Defense overview. */
(function () {
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
    rotation: -.45,
    reduceMotion: false,
    attackCount: 0,
    defenseCount: 1,
    landPoints: []
  };

  const regions = [
    [42, -103, 28, 52, 230], [-15, -61, 34, 22, 125], [53, 15, 17, 28, 105],
    [4, 20, 35, 24, 155], [37, 87, 31, 65, 280], [-25, 135, 16, 25, 80], [71, -42, 11, 18, 38]
  ];

  const attacks = [
    { origin: [.03, .23], target: [40, 84], bend: -.23, phase: .08 },
    { origin: [.01, .38], target: [20, 54], bend: -.12, phase: .39 },
    { origin: [.05, .55], target: [7, 30], bend: .02, phase: .66 },
    { origin: [.12, .73], target: [-12, 16], bend: .17, phase: .86 },
    { origin: [.20, .88], target: [-29, 35], bend: .28, phase: .21 }
  ];

  const defenses = [
    { target: [45, 105], end: [.92, .25], bend: -.18, phase: .12 },
    { target: [18, 120], end: [.96, .51], bend: -.04, phase: .48 },
    { target: [-17, 112], end: [.87, .76], bend: .18, phase: .78 }
  ];

  function init() {
    if (mapState.initialized) return;
    mapState.canvas = document.querySelector("#defenseGlobeCanvas");
    if (!mapState.canvas) return;
    mapState.ctx = mapState.canvas.getContext("2d", { alpha: true });
    mapState.reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    mapState.landPoints = createLandPoints();
    mapState.initialized = true;
    const observer = new ResizeObserver(() => { resize(); draw(performance.now()); });
    observer.observe(mapState.canvas.parentElement);
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) stop(); else if (mapState.active) start();
    });
    resize();
    draw(performance.now());
  }

  function setActive(active) {
    mapState.active = Boolean(active);
    if (!mapState.initialized) init();
    if (mapState.active && !mapState.reduceMotion) start(); else stop();
    if (mapState.active) draw(performance.now());
  }

  function update(payload = {}) {
    const incidents = Array.isArray(payload.incidents) ? payload.incidents : [];
    const threats = Array.isArray(payload.threats) ? payload.threats : [];
    const onlineAgents = Number(payload.onlineAgents) || 0;
    mapState.attackCount = Math.min(attacks.length, incidents.length + threats.length);
    mapState.defenseCount = Math.min(defenses.length, Math.max(1, onlineAgents));
    draw(performance.now());
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
    mapState.rotation += delta * .000035;
    draw(time);
    if (mapState.active && !mapState.reduceMotion && !document.hidden) mapState.frame = requestAnimationFrame(animate);
  }

  function resize() {
    const rect = mapState.canvas.getBoundingClientRect();
    const width = Math.max(1, Math.round(rect.width));
    const height = Math.max(1, Math.round(rect.height));
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    if (width === mapState.width && height === mapState.height && dpr === mapState.dpr) return;
    mapState.width = width; mapState.height = height; mapState.dpr = dpr;
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

    const radius = Math.min(width * .255, height * .37);
    const center = { x: width * .49, y: height * .52 };
    drawFloor(ctx, center, radius, width, height, time);
    drawGlobe(ctx, center, radius, time);
    drawAttackArcs(ctx, center, radius, width, height, time);
    drawDefenseArcs(ctx, center, radius, width, height, time);
    drawOrbitParticles(ctx, center, radius, time);
  }

  function drawFloor(ctx, center, radius, width, height, time) {
    ctx.save();
    const floorY = center.y + radius * .83;
    for (let ring = 0; ring < 5; ring++) {
      ctx.beginPath();
      ctx.ellipse(center.x, floorY, radius * (.68 + ring * .24), radius * (.13 + ring * .042), 0, 0, Math.PI * 2);
      ctx.strokeStyle = `rgba(230,174,0,${.23 - ring * .032})`;
      ctx.lineWidth = 1;
      ctx.setLineDash(ring % 2 ? [4, 7] : []);
      ctx.stroke();
    }
    ctx.setLineDash([]);
    const glow = ctx.createRadialGradient(center.x, floorY, 0, center.x, floorY, radius * 1.4);
    glow.addColorStop(0, "rgba(255,202,24,.12)"); glow.addColorStop(1, "rgba(255,202,24,0)");
    ctx.fillStyle = glow; ctx.fillRect(0, floorY - radius * .3, width, height - floorY + radius * .3);
    const sweep = (time * .035) % 360;
    ctx.translate(center.x, floorY); ctx.rotate(sweep * Math.PI / 180);
    ctx.beginPath(); ctx.moveTo(0, 0); ctx.lineTo(radius * 1.35, 0);
    ctx.strokeStyle = "rgba(246,187,0,.2)"; ctx.stroke();
    ctx.restore();
  }

  function drawGlobe(ctx, center, radius, time) {
    ctx.save();
    const halo = ctx.createRadialGradient(center.x, center.y, radius * .35, center.x, center.y, radius * 1.36);
    halo.addColorStop(0, "rgba(255,208,42,.13)"); halo.addColorStop(.48, "rgba(255,208,42,.045)"); halo.addColorStop(1, "rgba(255,208,42,0)");
    ctx.fillStyle = halo; ctx.beginPath(); ctx.arc(center.x, center.y, radius * 1.36, 0, Math.PI * 2); ctx.fill();

    const sphere = ctx.createRadialGradient(center.x - radius * .3, center.y - radius * .38, radius * .04, center.x, center.y, radius);
    sphere.addColorStop(0, "rgba(255,255,255,.98)"); sphere.addColorStop(.48, "rgba(245,247,249,.87)"); sphere.addColorStop(1, "rgba(207,214,223,.42)");
    ctx.fillStyle = sphere; ctx.beginPath(); ctx.arc(center.x, center.y, radius, 0, Math.PI * 2); ctx.fill();
    ctx.strokeStyle = "rgba(177,187,199,.42)"; ctx.lineWidth = 1.2; ctx.stroke();

    ctx.save();
    ctx.beginPath(); ctx.arc(center.x, center.y, radius - .5, 0, Math.PI * 2); ctx.clip();
    drawLatitudeLines(ctx, center, radius);
    drawLongitudeLines(ctx, center, radius);
    drawLand(ctx, center, radius);
    const scanX = center.x - radius + ((time * .028) % (radius * 2));
    const scan = ctx.createLinearGradient(scanX - 18, 0, scanX + 18, 0);
    scan.addColorStop(0, "rgba(255,205,35,0)"); scan.addColorStop(.5, "rgba(255,205,35,.16)"); scan.addColorStop(1, "rgba(255,205,35,0)");
    ctx.fillStyle = scan; ctx.fillRect(scanX - 18, center.y - radius, 36, radius * 2);
    ctx.restore();

    ctx.beginPath(); ctx.arc(center.x, center.y, radius * 1.055, -.4, Math.PI * 1.62);
    ctx.strokeStyle = "rgba(243,183,0,.28)"; ctx.lineWidth = 1; ctx.setLineDash([3,7]); ctx.stroke(); ctx.setLineDash([]);
    ctx.restore();
  }

  function drawLatitudeLines(ctx, center, radius) {
    for (let lat = -60; lat <= 60; lat += 15) {
      drawProjectedPath(ctx, center, radius, Array.from({ length: 121 }, (_, index) => [lat, -180 + index * 3]), "rgba(151,163,178,.2)", .7);
    }
  }

  function drawLongitudeLines(ctx, center, radius) {
    for (let lon = -180; lon < 180; lon += 20) {
      drawProjectedPath(ctx, center, radius, Array.from({ length: 81 }, (_, index) => [-80 + index * 2, lon]), "rgba(151,163,178,.17)", .65);
    }
  }

  function drawProjectedPath(ctx, center, radius, coordinates, color, lineWidth) {
    ctx.beginPath();
    let drawing = false;
    coordinates.forEach(([lat, lon]) => {
      const point = project(lat, lon, center, radius);
      if (point.z < -.02) { drawing = false; return; }
      if (!drawing) { ctx.moveTo(point.x, point.y); drawing = true; } else ctx.lineTo(point.x, point.y);
    });
    ctx.strokeStyle = color; ctx.lineWidth = lineWidth; ctx.stroke();
  }

  function drawLand(ctx, center, radius) {
    mapState.landPoints.forEach(point => {
      const projected = project(point.lat, point.lon, center, radius);
      if (projected.z <= 0) return;
      const alpha = .2 + projected.z * .42;
      ctx.fillStyle = `rgba(111,124,141,${alpha})`;
      ctx.fillRect(projected.x, projected.y, point.size, point.size);
    });
  }

  function drawAttackArcs(ctx, center, radius, width, height, time) {
    for (let index = 0; index < mapState.attackCount; index++) {
      const attack = attacks[index];
      const start = { x: width * attack.origin[0], y: height * attack.origin[1] };
      const target = project(attack.target[0], attack.target[1], center, radius);
      const control = { x: (start.x + target.x) / 2, y: Math.min(start.y, target.y) + height * attack.bend };
      drawCurve(ctx, start, control, target, "rgba(255,84,54,.7)", [5,5]);
      const progress = mapState.reduceMotion ? .66 : ((time * .00016 + attack.phase) % 1);
      const particle = quadratic(start, control, target, progress);
      drawPulse(ctx, particle.x, particle.y, "#ff5a3d", 3.2, time + index * 300);
      drawThreatMarker(ctx, start.x, start.y, index);
    }
  }

  function drawDefenseArcs(ctx, center, radius, width, height, time) {
    for (let index = 0; index < mapState.defenseCount; index++) {
      const defense = defenses[index];
      const start = project(defense.target[0], defense.target[1], center, radius);
      const end = { x: width * defense.end[0], y: height * defense.end[1] };
      const control = { x: (start.x + end.x) / 2, y: Math.min(start.y, end.y) + height * defense.bend };
      drawCurve(ctx, start, control, end, "rgba(238,180,0,.56)", []);
      const progress = mapState.reduceMotion ? .58 : ((time * .00013 + defense.phase) % 1);
      const particle = quadratic(start, control, end, progress);
      drawPulse(ctx, particle.x, particle.y, "#ffc400", 2.7, time + index * 440);
    }
  }

  function drawCurve(ctx, start, control, end, color, dash) {
    ctx.save(); ctx.beginPath(); ctx.moveTo(start.x, start.y); ctx.quadraticCurveTo(control.x, control.y, end.x, end.y);
    ctx.strokeStyle = color; ctx.lineWidth = 1.25; ctx.setLineDash(dash); ctx.stroke(); ctx.restore();
  }

  function drawThreatMarker(ctx, x, y, index) {
    ctx.save(); ctx.translate(x, y);
    ctx.beginPath();
    for (let side = 0; side < 6; side++) {
      const angle = Math.PI / 3 * side - Math.PI / 2;
      const px = Math.cos(angle) * 13; const py = Math.sin(angle) * 13;
      if (side === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py);
    }
    ctx.closePath(); ctx.fillStyle = "rgba(255,255,255,.9)"; ctx.fill(); ctx.strokeStyle = "rgba(255,84,54,.78)"; ctx.stroke();
    ctx.fillStyle = "#ff5a3d"; ctx.font = "900 10px system-ui"; ctx.textAlign = "center"; ctx.textBaseline = "middle"; ctx.fillText("!", 0, 1);
    ctx.fillStyle = "rgba(66,73,84,.8)"; ctx.font = "700 7px system-ui"; ctx.textAlign = "left"; ctx.fillText(index % 2 ? "THREAT" : "AI THREAT", 18, -1);
    ctx.restore();
  }

  function drawPulse(ctx, x, y, color, radius, time) {
    const pulse = .5 + Math.sin(time * .006) * .5;
    ctx.save(); ctx.globalAlpha = .28 * (1 - pulse); ctx.fillStyle = color; ctx.beginPath(); ctx.arc(x, y, radius + pulse * 8, 0, Math.PI * 2); ctx.fill();
    ctx.globalAlpha = 1; ctx.fillStyle = color; ctx.strokeStyle = "#fff"; ctx.lineWidth = 1.2; ctx.beginPath(); ctx.arc(x, y, radius, 0, Math.PI * 2); ctx.fill(); ctx.stroke(); ctx.restore();
  }

  function drawOrbitParticles(ctx, center, radius, time) {
    for (let index = 0; index < 16; index++) {
      const angle = index / 16 * Math.PI * 2 + time * .00008;
      const orbit = radius * (1.05 + (index % 3) * .12);
      const x = center.x + Math.cos(angle) * orbit;
      const y = center.y + Math.sin(angle) * orbit * .35;
      ctx.fillStyle = index % 4 === 0 ? "rgba(255,196,0,.75)" : "rgba(181,190,201,.48)";
      ctx.beginPath(); ctx.arc(x, y, index % 4 === 0 ? 1.8 : 1.1, 0, Math.PI * 2); ctx.fill();
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
        points.push({ lat, lon, size: random() > .78 ? 1.5 : .8 });
      }
    });
    return points;
  }

  globalThis.NTShieldDefenseMap = { init, update, setActive };
})();
