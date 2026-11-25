/* Frontend controller for Web & URL Security Analyzer (SIEM-Ready Edition) */

const SEVERITY_STYLES = {
  LOW: {
    pill: "bg-emerald-500/15 text-emerald-300 border-emerald-500/35",
    bar: "bg-emerald-500",
    bannerBorder: "border-emerald-500/35",
  },
  MEDIUM: {
    pill: "bg-amber-500/15 text-amber-300 border-amber-500/35",
    bar: "bg-amber-500",
    bannerBorder: "border-amber-500/35",
  },
  HIGH: {
    pill: "bg-orange-500/15 text-orange-300 border-orange-500/35",
    bar: "bg-orange-500",
    bannerBorder: "border-orange-500/35",
  },
  CRITICAL: {
    pill: "bg-rose-500/15 text-rose-300 border-rose-500/40",
    bar: "bg-rose-500",
    bannerBorder: "border-rose-500/40",
  },
};

let currentScan = null;
let severityChartInstance = null;
let headersChartInstance = null;

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function getSeverityStyle(severity) {
  return SEVERITY_STYLES[severity] || SEVERITY_STYLES.LOW;
}

function showScanError(message) {
  const el = document.getElementById("scan-error");
  if (!message) {
    el.classList.add("hidden");
    el.textContent = "";
    return;
  }
  el.textContent = message;
  el.classList.remove("hidden");
}

function buildSummaryLine(scan) {
  const intel = scan.modules.threat_intelligence;
  const phish = scan.modules.phishing_analysis;
  const httpTls = scan.modules.http_tls_audit;

  if (intel.listed) {
    return `Critical threat intelligence match: ${intel.source_reason}. Immediate isolation recommended.`;
  }
  if (scan.severity === "HIGH" || scan.severity === "CRITICAL") {
    return `High-risk indicators detected (${phish.triggered_rules.length} heuristic rules triggered). Inspect before trusting.`;
  }
  if (scan.severity === "MEDIUM") {
    return `Moderate risk posture: ${httpTls.missing_headers.length} security headers missing or transport weaknesses detected.`;
  }
  return "Low risk posture: no threat intelligence or phishing indicators found.";
}

function renderScanDetails(scan) {
  currentScan = scan;
  const resultView = document.getElementById("result-view");
  resultView.classList.remove("hidden");

  const style = getSeverityStyle(scan.severity);
  const banner = document.getElementById("verdict-banner");
  banner.className = `bg-slate-900 border ${style.bannerBorder} rounded-2xl p-5 sm:p-6 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-5`;

  document.getElementById("res-timestamp").textContent = new Date(scan.timestamp).toLocaleString();
  document.getElementById("res-url").textContent = scan.target_url;
  document.getElementById("res-summary").textContent = buildSummaryLine(scan);
  document.getElementById("res-score-text").textContent = `${scan.overall_risk_score} / 100`;

  const scoreBar = document.getElementById("res-score-bar");
  scoreBar.style.width = `${scan.overall_risk_score}%`;
  scoreBar.className = `h-full rounded-full transition-all duration-300 ${style.bar}`;

  const sevPill = document.getElementById("res-severity-pill");
  sevPill.textContent = scan.severity;
  sevPill.className = `px-4 py-2 rounded-xl text-sm font-extrabold tracking-wide border ${style.pill}`;

  // Card 1: HTTP Headers & TLS Audit
  const httpTls = scan.modules.http_tls_audit;
  const httpsBadge = document.getElementById("card-https-badge");
  httpsBadge.textContent = httpTls.https_enabled ? "HTTPS Enabled" : "Unencrypted / Non-HTTPS";
  httpsBadge.className = `px-2.5 py-0.5 text-xs font-semibold rounded-full border ${
    httpTls.https_enabled ? SEVERITY_STYLES.LOW.pill : SEVERITY_STYLES.CRITICAL.pill
  }`;

  document.getElementById("card-http-status").textContent =
    httpTls.status_code !== null ? `HTTP ${httpTls.status_code}` : "Unreachable";
  document.getElementById("card-latency").textContent =
    httpTls.response_time_ms !== null ? `${httpTls.response_time_ms} ms` : "-";

  const ssl = httpTls.ssl_certificate || {};
  const sslBox = document.getElementById("card-ssl-box");
  if (!httpTls.https_enabled) {
    sslBox.innerHTML = `<span class="text-slate-400">TLS Certificate:</span> <span class="text-amber-300 font-medium">Not applicable (HTTP / non-HTTPS)</span>`;
  } else if (ssl.valid) {
    sslBox.innerHTML = `
      <div class="flex justify-between"><span class="text-slate-400">TLS Cert Status:</span><span class="text-emerald-300 font-semibold">&#x2713; Valid</span></div>
      <div class="flex justify-between"><span class="text-slate-400">Expires In:</span><span class="text-slate-200 font-medium">${escapeHtml(ssl.days_until_expiration ?? "N/A")} days</span></div>
      ${ssl.issuer ? `<div class="flex justify-between"><span class="text-slate-400">Issuer:</span><span class="text-slate-200">${escapeHtml(ssl.issuer)}</span></div>` : ""}
    `;
  } else {
    sslBox.innerHTML = `
      <div class="flex justify-between"><span class="text-slate-400">TLS Cert Status:</span><span class="text-rose-300 font-semibold">&#x2715; Invalid / Unverified</span></div>
      ${ssl.error ? `<p class="text-rose-300/90 mt-1">${escapeHtml(ssl.error)}</p>` : ""}
    `;
  }

  const serverWarn = document.getElementById("card-server-warning");
  if (httpTls.server_header_exposed) {
    serverWarn.textContent = `Exposed Server Header: "${httpTls.server_header}" (fingerprinting risk)`;
    serverWarn.classList.remove("hidden");
  } else {
    serverWarn.classList.add("hidden");
  }

  const httpErr = document.getElementById("card-http-error");
  if (httpTls.error) {
    httpErr.textContent = `Connection note: ${httpTls.error}`;
    httpErr.classList.remove("hidden");
  } else {
    httpErr.classList.add("hidden");
  }

  const headersList = document.getElementById("card-headers-list");
  let headersHtml = "";
  if (httpTls.present_headers.length > 0) {
    headersHtml += `<div class="flex flex-wrap gap-1.5">`;
    httpTls.present_headers.forEach((h) => {
      headersHtml += `<span class="px-2 py-1 rounded-md bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">&#x2713; ${escapeHtml(h)}</span>`;
    });
    headersHtml += `</div>`;
  }
  if (httpTls.missing_headers.length > 0) {
    headersHtml += `<div class="flex flex-wrap gap-1.5">`;
    httpTls.missing_headers.forEach((h) => {
      headersHtml += `<span class="px-2 py-1 rounded-md bg-rose-500/10 text-rose-300 border border-rose-500/30">&#x2715; ${escapeHtml(h)}</span>`;
    });
    headersHtml += `</div>`;
  }
  headersList.innerHTML = headersHtml;

  const remEl = document.getElementById("card-remediations");
  remEl.innerHTML = scan.remediation_tips.map((tip) => `<li>${escapeHtml(tip)}</li>`).join("");

  // Card 2: Phishing Heuristics
  const phish = scan.modules.phishing_analysis;
  const phishPct = Math.round((phish.phishing_probability || 0) * 100);
  document.getElementById("card-phish-pct").textContent = `${phishPct}%`;
  const phishBar = document.getElementById("card-phish-bar");
  phishBar.style.width = `${phishPct}%`;

  const phishBadge = document.getElementById("card-phish-badge");
  if (phishPct >= 60) {
    phishBadge.textContent = "High Suspicion";
    phishBadge.className = `px-2.5 py-0.5 text-xs font-semibold rounded-full border ${SEVERITY_STYLES.CRITICAL.pill}`;
    phishBar.className = "h-full rounded-full transition-all duration-300 bg-rose-500";
  } else if (phishPct >= 25) {
    phishBadge.textContent = "Suspicious";
    phishBadge.className = `px-2.5 py-0.5 text-xs font-semibold rounded-full border ${SEVERITY_STYLES.MEDIUM.pill}`;
    phishBar.className = "h-full rounded-full transition-all duration-300 bg-amber-500";
  } else {
    phishBadge.textContent = "Clean";
    phishBadge.className = `px-2.5 py-0.5 text-xs font-semibold rounded-full border ${SEVERITY_STYLES.LOW.pill}`;
    phishBar.className = "h-full rounded-full transition-all duration-300 bg-emerald-500";
  }

  const rulesEl = document.getElementById("card-phish-rules");
  if (phish.triggered_rules && phish.triggered_rules.length > 0) {
    rulesEl.innerHTML = phish.triggered_rules
      .map(
        (rule) => `
          <div class="bg-slate-950/70 border border-slate-800 border-l-2 border-l-amber-400 rounded-lg p-2.5">
            <div class="flex justify-between font-semibold text-slate-200 mb-0.5">
              <span>${escapeHtml(rule.rule_id)}</span>
              <span class="text-amber-300">+${Math.round(rule.weight * 100)}%</span>
            </div>
            <p class="text-slate-400">${escapeHtml(rule.description)}</p>
          </div>`
      )
      .join("");
  } else {
    rulesEl.innerHTML = `<div class="bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 rounded-xl p-3">No phishing rules triggered.</div>`;
  }

  // Card 3: Threat Intelligence
  const intel = scan.modules.threat_intelligence;
  const intelBadge = document.getElementById("card-intel-badge");
  intelBadge.textContent = intel.listed ? "Threat Listed" : "Clean";
  intelBadge.className = `px-2.5 py-0.5 text-xs font-semibold rounded-full border ${
    intel.listed ? SEVERITY_STYLES.CRITICAL.pill : SEVERITY_STYLES.LOW.pill
  }`;

  document.getElementById("card-intel-domain").textContent = scan.domain;
  document.getElementById("card-intel-hits").textContent = intel.hits;
  document.getElementById("card-intel-ext").textContent = intel.external_lookup_used
    ? "Enabled (Env Key)"
    : "Offline Curated Feed";

  const intelReason = document.getElementById("card-intel-reason");
  intelReason.textContent = intel.source_reason;
  intelReason.className = `rounded-xl p-3.5 text-xs border ${
    intel.listed
      ? "bg-rose-500/10 border-rose-500/30 text-rose-200"
      : "bg-emerald-500/10 border-emerald-500/30 text-emerald-200"
  }`;

  // SIEM JSON Block
  const siemPre = document.getElementById("siem-json-pre");
  siemPre.textContent = JSON.stringify(scan.siem_event, null, 2);
}

async function refreshStatsAndCharts() {
  try {
    const res = await fetch("/api/stats");
    if (!res.ok) return;
    const stats = await res.json();

    document.getElementById("kpi-total").textContent = stats.total_scans;
    document.getElementById("kpi-high").textContent = stats.critical_high_count;
    document.getElementById("kpi-clean").textContent = stats.clean_count;
    document.getElementById("kpi-avg").textContent = stats.avg_risk_score;

    renderCharts(stats);
  } catch (err) {
    console.error("Failed to fetch stats:", err);
  }
}

function renderCharts(stats) {
  if (typeof Chart === "undefined") return;

  const dist = stats.severity_distribution || { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
  const sevCtx = document.getElementById("severity-chart").getContext("2d");
  if (severityChartInstance) severityChartInstance.destroy();
  severityChartInstance = new Chart(sevCtx, {
    type: "doughnut",
    data: {
      labels: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
      datasets: [
        {
          data: [dist.LOW || 0, dist.MEDIUM || 0, dist.HIGH || 0, dist.CRITICAL || 0],
          backgroundColor: ["#10b981", "#f59e0b", "#f97316", "#f43f5e"],
          borderColor: "#0f172a",
          borderWidth: 2,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "right",
          labels: { color: "#cbd5e1", font: { size: 12 } },
        },
      },
    },
  });

  const topHeaders = stats.top_missing_headers || [];
  const hdrCtx = document.getElementById("headers-chart").getContext("2d");
  if (headersChartInstance) headersChartInstance.destroy();
  headersChartInstance = new Chart(hdrCtx, {
    type: "bar",
    data: {
      labels: topHeaders.length > 0 ? topHeaders.map((h) => h.header) : ["No data yet"],
      datasets: [
        {
          label: "Missing Count",
          data: topHeaders.length > 0 ? topHeaders.map((h) => h.count) : [0],
          backgroundColor: "rgba(56, 189, 248, 0.7)",
          borderColor: "#38bdf8",
          borderWidth: 1,
          borderRadius: 6,
        },
      ],
    },
    options: {
      indexAxis: "y",
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
      },
      scales: {
        x: {
          beginAtZero: true,
          ticks: { color: "#94a3b8", precision: 0 },
          grid: { color: "rgba(148, 163, 184, 0.1)" },
        },
        y: {
          ticks: { color: "#cbd5e1", font: { size: 11 } },
          grid: { display: false },
        },
      },
    },
  });
}

async function refreshHistory() {
  const severity = document.getElementById("history-severity-filter").value;
  const search = document.getElementById("history-search").value.trim();

  const params = new URLSearchParams();
  if (severity && severity !== "ALL") params.set("severity", severity);
  if (search) params.set("search", search);

  try {
    const res = await fetch(`/api/history?${params.toString()}`);
    if (!res.ok) return;
    const rows = await res.json();
    const tbody = document.getElementById("history-tbody");

    if (rows.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="5" class="py-6 text-center text-slate-500 text-sm">
            No matching scan records found.
          </td>
        </tr>`;
      return;
    }

    tbody.innerHTML = rows
      .map((row) => {
        const style = getSeverityStyle(row.severity);
        return `
          <tr class="hover:bg-slate-800/40 transition">
            <td class="py-3 px-3 text-slate-400 whitespace-nowrap">${escapeHtml(new Date(row.timestamp).toLocaleString())}</td>
            <td class="py-3 px-3 text-slate-200 font-medium break-all">${escapeHtml(row.target_url)}</td>
            <td class="py-3 px-3 font-bold text-slate-100">${row.overall_risk_score} / 100</td>
            <td class="py-3 px-3">
              <span class="px-2.5 py-0.5 text-xs font-bold rounded-full border ${style.pill}">${escapeHtml(row.severity)}</span>
            </td>
            <td class="py-3 px-3 text-right whitespace-nowrap space-x-2">
              <button
                type="button"
                class="view-scan-btn px-2.5 py-1 rounded-md text-xs font-medium bg-sky-500/15 text-sky-300 border border-sky-500/30 hover:bg-sky-500/25 cursor-pointer"
                data-id="${row.id}"
              >View Details</button>
              <button
                type="button"
                class="delete-scan-btn px-2.5 py-1 rounded-md text-xs font-medium bg-rose-500/10 text-rose-300 border border-rose-500/30 hover:bg-rose-500/20 cursor-pointer"
                data-id="${row.id}"
              >Delete</button>
            </td>
          </tr>`;
      })
      .join("");
  } catch (err) {
    console.error("Failed to fetch history:", err);
  }
}

async function runSingleScan(url) {
  const rawUrl = url.trim();
  if (!rawUrl) return;

  const btn = document.getElementById("single-scan-btn");
  const spinner = document.getElementById("single-spinner");
  const btnText = document.getElementById("single-btn-text");

  showScanError("");
  btn.disabled = true;
  spinner.classList.remove("hidden");
  btnText.textContent = "Analyzing...";

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: rawUrl }),
    });
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.detail || `Server returned HTTP ${res.status}`);
    }
    const data = await res.json();
    renderScanDetails(data);
    await Promise.all([refreshStatsAndCharts(), refreshHistory()]);
  } catch (err) {
    showScanError(`Scan failed: ${err.message}`);
  } finally {
    btn.disabled = false;
    spinner.classList.add("hidden");
    btnText.textContent = "Analyze URL";
  }
}

async function runBatchScan(rawText) {
  const urls = rawText
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  if (urls.length === 0) {
    showScanError("Please enter at least one URL for batch scanning.");
    return;
  }
  if (urls.length > 10) {
    showScanError("Maximum 10 URLs allowed per batch.");
    return;
  }

  const btn = document.getElementById("batch-scan-btn");
  const spinner = document.getElementById("batch-spinner");
  const btnText = document.getElementById("batch-btn-text");
  const batchBox = document.getElementById("batch-results-box");

  showScanError("");
  btn.disabled = true;
  spinner.classList.remove("hidden");
  btnText.textContent = "Scanning Batch...";

  try {
    const res = await fetch("/api/scan/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ urls }),
    });
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.detail || `Server returned HTTP ${res.status}`);
    }
    const batch = await res.json();

    batchBox.classList.remove("hidden");
    batchBox.innerHTML = batch.results
      .map((item) => {
        const style = getSeverityStyle(item.severity);
        return `
          <div class="flex items-center justify-between gap-3 bg-slate-950/70 border border-slate-800 rounded-xl p-3 text-xs">
            <span class="text-slate-200 font-medium break-all">${escapeHtml(item.target_url)}</span>
            <div class="flex items-center gap-2.5 shrink-0">
              <span class="font-bold text-slate-100">${item.overall_risk_score}/100</span>
              <span class="px-2 py-0.5 rounded-full border font-bold ${style.pill}">${escapeHtml(item.severity)}</span>
              <button type="button" class="view-scan-btn px-2 py-1 rounded bg-sky-500/15 text-sky-300 border border-sky-500/30 cursor-pointer" data-id="${item.id}">Inspect</button>
            </div>
          </div>`;
      })
      .join("");

    if (batch.results.length > 0) {
      renderScanDetails(batch.results[0]);
    }
    await Promise.all([refreshStatsAndCharts(), refreshHistory()]);
  } catch (err) {
    showScanError(`Batch scan failed: ${err.message}`);
  } finally {
    btn.disabled = false;
    spinner.classList.add("hidden");
    btnText.textContent = "Scan Batch";
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const tabSingle = document.getElementById("tab-single");
  const tabBatch = document.getElementById("tab-batch");
  const panelSingle = document.getElementById("panel-single");
  const panelBatch = document.getElementById("panel-batch");

  tabSingle.addEventListener("click", () => {
    tabSingle.className = "px-4 py-2 rounded-lg text-sm font-semibold bg-sky-500/15 text-sky-300 border border-sky-500/40 transition";
    tabBatch.className = "px-4 py-2 rounded-lg text-sm font-semibold bg-slate-950/60 text-slate-400 border border-slate-800 hover:text-slate-200 transition";
    panelSingle.classList.remove("hidden");
    panelBatch.classList.add("hidden");
  });

  tabBatch.addEventListener("click", () => {
    tabBatch.className = "px-4 py-2 rounded-lg text-sm font-semibold bg-sky-500/15 text-sky-300 border border-sky-500/40 transition";
    tabSingle.className = "px-4 py-2 rounded-lg text-sm font-semibold bg-slate-950/60 text-slate-400 border border-slate-800 hover:text-slate-200 transition";
    panelBatch.classList.remove("hidden");
    panelSingle.classList.add("hidden");
  });

  document.getElementById("single-scan-form").addEventListener("submit", (e) => {
    e.preventDefault();
    runSingleScan(document.getElementById("single-url-input").value);
  });

  document.getElementById("batch-scan-form").addEventListener("submit", (e) => {
    e.preventDefault();
    runBatchScan(document.getElementById("batch-urls-input").value);
  });

  document.querySelectorAll(".demo-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetUrl = btn.getAttribute("data-url");
      document.getElementById("single-url-input").value = targetUrl;
      runSingleScan(targetUrl);
    });
  });

  document.getElementById("history-search").addEventListener("input", refreshHistory);
  document.getElementById("history-severity-filter").addEventListener("change", refreshHistory);

  document.body.addEventListener("click", async (e) => {
    const viewBtn = e.target.closest(".view-scan-btn");
    if (viewBtn) {
      const id = viewBtn.getAttribute("data-id");
      const res = await fetch(`/api/history/${id}`);
      if (res.ok) {
        const data = await res.json();
        renderScanDetails(data);
        document.getElementById("result-view").scrollIntoView({ behavior: "smooth" });
      }
      return;
    }

    const delBtn = e.target.closest(".delete-scan-btn");
    if (delBtn) {
      const id = delBtn.getAttribute("data-id");
      const res = await fetch(`/api/history/${id}`, { method: "DELETE" });
      if (res.ok) {
        if (currentScan && String(currentScan.id) === String(id)) {
          document.getElementById("result-view").classList.add("hidden");
          currentScan = null;
        }
        await Promise.all([refreshStatsAndCharts(), refreshHistory()]);
      }
    }
  });

  const siemPre = document.getElementById("siem-json-pre");
  const toggleBtn = document.getElementById("toggle-json-btn");
  toggleBtn.addEventListener("click", () => {
    const hidden = siemPre.classList.toggle("hidden");
    toggleBtn.textContent = hidden ? "Show JSON" : "Hide JSON";
  });

  document.getElementById("copy-json-btn").addEventListener("click", async () => {
    if (!currentScan) return;
    await navigator.clipboard.writeText(JSON.stringify(currentScan.siem_event, null, 2));
    const btn = document.getElementById("copy-json-btn");
    btn.textContent = "Copied!";
    setTimeout(() => { btn.textContent = "Copy JSON"; }, 1500);
  });

  document.getElementById("download-json-btn").addEventListener("click", () => {
    if (!currentScan) return;
    const blob = new Blob([JSON.stringify(currentScan.siem_event, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `siem-event-${currentScan.id || "scan"}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });

  refreshStatsAndCharts();
  refreshHistory();
});

