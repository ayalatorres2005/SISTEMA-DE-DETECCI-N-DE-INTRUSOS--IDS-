<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IDS FIEE — Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@700;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:#0d0f14; --surface:#141720; --border:#1e2535;
    --accent:#00d4ff; --text:#e2e8f0; --muted:#64748b;
    --green:#10b981; --yellow:#f59e0b; --orange:#f97316; --red:#ef4444;
  }
  *{margin:0;padding:0;box-sizing:border-box}
  body{background:var(--bg);color:var(--text);font-family:'JetBrains Mono',monospace;font-size:13px}
  header{padding:1.2rem 2rem;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:1rem}
  header h1{font-family:'Syne',sans-serif;font-size:1.3rem;font-weight:800;color:var(--accent);text-shadow:0 0 20px rgba(0,212,255,.3)}
  header .sub{color:var(--muted);font-size:.72rem;letter-spacing:.1em}
  .badge{background:rgba(0,212,255,.12);border:1px solid rgba(0,212,255,.3);color:var(--accent);padding:.2rem .6rem;border-radius:99px;font-size:.65rem;margin-left:auto}

  .grid{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;padding:1.5rem 2rem 0}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:1.1rem 1.3rem}
  .card .label{color:var(--muted);font-size:.65rem;letter-spacing:.12em;text-transform:uppercase;margin-bottom:.4rem}
  .card .val{font-family:'Syne',sans-serif;font-size:2rem;font-weight:800;line-height:1}
  .card .sub{font-size:.65rem;color:var(--muted);margin-top:.3rem}
  .c-green{color:var(--green)} .c-yellow{color:var(--yellow)}
  .c-orange{color:var(--orange)} .c-red{color:var(--red)}

  .section{padding:1.5rem 2rem}
  .section h2{font-family:'Syne',sans-serif;font-size:.9rem;font-weight:700;color:var(--accent);letter-spacing:.08em;margin-bottom:1rem}

  table{width:100%;border-collapse:collapse}
  thead tr{background:#1a1f2e}
  th{padding:.6rem .8rem;text-align:left;font-size:.62rem;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);font-weight:600}
  td{padding:.55rem .8rem;border-bottom:1px solid var(--border);font-size:.72rem}
  tbody tr:hover{background:#181d2a}

  .badge-nivel{padding:.15rem .5rem;border-radius:4px;font-size:.62rem;font-weight:600}
  .CRÍTICO,.CRITICO{background:rgba(239,68,68,.15);color:#f87171}
  .ALTO{background:rgba(249,115,22,.15);color:#fb923c}
  .MEDIO{background:rgba(245,158,11,.15);color:#fbbf24}
  .BAJO{background:rgba(16,185,129,.15);color:#34d399}

  .refresh-bar{display:flex;align-items:center;gap:.6rem;padding:0 2rem 1rem;color:var(--muted);font-size:.65rem}
  .dot-live{width:7px;height:7px;border-radius:50%;background:var(--green);animation:pulse 1.5s infinite}
  @keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.7)}}

  .empty{text-align:center;padding:3rem;color:var(--muted)}
</style>
</head>
<body>

<header>
  <div>
    <h1>⚡ IDS FIEE — Dashboard</h1>
    <div class="sub">Sistema de Detección de Intrusos · Gestión de Ciberseguridad</div>
  </div>
  <div class="badge" id="ts">Cargando...</div>
</header>

<div class="grid">
  <div class="card">
    <div class="label">Total Alertas</div>
    <div class="val c-yellow" id="stat-total">—</div>
    <div class="sub">desde inicio del monitoreo</div>
  </div>
  <div class="card">
    <div class="label">Alertas Críticas</div>
    <div class="val c-red" id="stat-criticas">—</div>
    <div class="sub">requieren acción inmediata</div>
  </div>
  <div class="card">
    <div class="label">Tipos de Ataque</div>
    <div class="val c-orange" id="stat-tipos">—</div>
    <div class="sub">distintos detectados</div>
  </div>
  <div class="card">
    <div class="label">Estado</div>
    <div class="val c-green" style="font-size:1.3rem;margin-top:.3rem">🟢 ACTIVO</div>
    <div class="sub">monitoreo en curso</div>
  </div>
</div>

<div class="refresh-bar">
  <div class="dot-live"></div>
  Actualizando cada 5 segundos
</div>

<div class="section">
  <h2>ALERTAS RECIENTES</h2>
  <table>
    <thead>
      <tr>
        <th>Hora</th><th>Nivel</th><th>Tipo Ataque</th>
        <th>IP Origen</th><th>IP Destino</th><th>Puerto</th>
        <th>Score</th><th>Modelo</th><th>Acción</th>
      </tr>
    </thead>
    <tbody id="tabla-alertas">
      <tr><td colspan="9" class="empty">Cargando alertas...</td></tr>
    </tbody>
  </table>
</div>

<script>
function fmt(ts) {
  if (!ts) return "—";
  return ts.replace("T"," ").substring(0,19);
}

async function cargar() {
  try {
    const [resAlertas, resStats] = await Promise.all([
      fetch("/api/alertas").then(r => r.json()),
      fetch("/api/estadisticas").then(r => r.json()),
    ]);

    document.getElementById("stat-total").textContent    = resStats.total ?? 0;
    document.getElementById("stat-criticas").textContent = resStats.criticas ?? 0;
    document.getElementById("stat-tipos").textContent    =
      Object.keys(resStats.por_tipo || {}).length;
    document.getElementById("ts").textContent =
      "Actualizado: " + new Date().toLocaleTimeString("es-PE");

    const tbody = document.getElementById("tabla-alertas");
    if (!resAlertas.length) {
      tbody.innerHTML = '<tr><td colspan="9" class="empty">Sin alertas registradas aún.</td></tr>';
      return;
    }
    tbody.innerHTML = resAlertas.map(a => `
      <tr>
        <td>${fmt(a.timestamp).slice(-8)}</td>
        <td><span class="badge-nivel ${(a.nivel||"").replace("Í","I")}">${a.nivel||"—"}</span></td>
        <td>${(a.tipo_ataque||"").toUpperCase()}</td>
        <td>${a.ip_origen||"—"}</td>
        <td>${a.ip_destino||"—"}</td>
        <td>${a.puerto_dst||"—"}</td>
        <td><strong>${a.score??""}</strong></td>
        <td>${a.modelo||"—"}</td>
        <td>${(a.accion||"").replace(/[🚨⚠️📋📝]/g,"").trim()}</td>
      </tr>
    `).join("");
  } catch(e) {
    console.error("Error cargando datos:", e);
  }
}

cargar();
setInterval(cargar, 5000);
</script>
</body>
</html>
