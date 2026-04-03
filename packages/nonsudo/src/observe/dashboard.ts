export const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>nonsudo observe</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: #070B11; color: #CDD9E5; font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 13px; }
  header { padding: 16px 20px; border-bottom: 1px solid #1c2333; display: flex; justify-content: space-between; align-items: center; }
  header h1 { font-size: 16px; font-weight: 600; color: #00C2FF; }
  .stats { display: flex; gap: 24px; font-size: 12px; color: #8b949e; }
  .stats span { color: #CDD9E5; }
  #log { overflow-y: auto; height: calc(100vh - 80px); padding: 8px 0; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 6px 20px; color: #8b949e; font-weight: 500; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; position: sticky; top: 0; background: #070B11; }
  td { padding: 5px 20px; border-top: 1px solid #161b22; white-space: nowrap; }
  .blast-CRITICAL { color: #ef4444; font-weight: 600; }
  .blast-HIGH { color: #f59e0b; font-weight: 600; }
  .blast-MED { color: #3b82f6; }
  .blast-LOW { color: #6b7280; }
  .blast-UNKNOWN { color: #6b7280; }
  .latency { color: #8b949e; }
  .tool { color: #CDD9E5; }
  .time { color: #8b949e; }
</style>
</head>
<body>
<header>
  <h1>nonsudo observe</h1>
  <div class="stats">
    Calls: <span id="calls">0</span>
    &nbsp;&middot;&nbsp;
    Uptime: <span id="uptime">0s</span>
    &nbsp;&middot;&nbsp;
    Workflow: <span id="wfid">-</span>
  </div>
</header>
<div id="log">
<table>
  <thead><tr><th>Time</th><th>Tool</th><th>Blast Radius</th><th>Latency</th></tr></thead>
  <tbody id="rows"></tbody>
</table>
</div>
<script>
const MAX_ROWS = 500;
const rows = document.getElementById('rows');
const callsEl = document.getElementById('calls');
const uptimeEl = document.getElementById('uptime');
const wfidEl = document.getElementById('wfid');
let callCount = 0;
const startTime = Date.now();

function updateUptime() {
  const s = Math.floor((Date.now() - startTime) / 1000);
  const m = Math.floor(s / 60);
  const h = Math.floor(m / 60);
  if (h > 0) uptimeEl.textContent = h + 'h ' + (m % 60) + 'm';
  else if (m > 0) uptimeEl.textContent = m + 'm ' + (s % 60) + 's';
  else uptimeEl.textContent = s + 's';
}
setInterval(updateUptime, 1000);

const es = new EventSource('/events');
es.onmessage = function(e) {
  const d = JSON.parse(e.data);
  if (wfidEl.textContent === '-') wfidEl.textContent = d.workflow_id ? d.workflow_id.slice(0, 12) + '...' : '-';
  callCount++;
  callsEl.textContent = callCount;
  const tr = document.createElement('tr');
  const t = new Date(d.issued_at);
  const ts = t.toLocaleTimeString('en-US', {hour12: false});
  tr.innerHTML =
    '<td class="time">' + ts + '</td>' +
    '<td class="tool">' + (d.tool_name || '-') + '</td>' +
    '<td class="blast-' + d.blast_radius + '">' + d.blast_radius + '</td>' +
    '<td class="latency">' + d.latency_ms + 'ms</td>';
  rows.appendChild(tr);
  if (rows.children.length > MAX_ROWS) rows.removeChild(rows.firstChild);
  tr.scrollIntoView({behavior: 'smooth', block: 'end'});
};
</script>
</body>
</html>`;
