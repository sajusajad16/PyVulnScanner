/**
 * PhishGuard AI – Frontend JavaScript
 * Handles scanning, result rendering, history, and UI interactions.
 */

"use strict";

// ── State ──────────────────────────────────
let currentTab    = "url";
let lastResult    = null;
let featuresOpen  = false;

const LOADING_MESSAGES = [
  "Extracting URL features…",
  "Running ML model…",
  "Checking domain similarity…",
  "Analysing keywords…",
  "Calculating risk score…",
];

// ══════════════════════════════════════════════
//  TAB SWITCHING
// ══════════════════════════════════════════════

function switchTab(tab) {
  currentTab = tab;

  // Update tab buttons
  document.querySelectorAll(".tab").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.tab === tab);
  });

  // Update panels
  document.querySelectorAll(".panel").forEach(panel => {
    panel.classList.toggle("active", panel.id === `panel-${tab}`);
  });

  // Clear result on tab switch
  clearResult();
}

// ══════════════════════════════════════════════
//  QUICK TESTS
// ══════════════════════════════════════════════

function quickTest(url) {
  const input = document.getElementById("url-input");
  if (input) {
    input.value = url;
    input.focus();
    scan();
  }
}

// ══════════════════════════════════════════════
//  MAIN SCAN FUNCTION
// ══════════════════════════════════════════════

async function scan() {
  let endpoint, payload;

  if (currentTab === "url") {
    const url = document.getElementById("url-input").value.trim();
    if (!url) return showInputError("url-input", "Please enter a URL");
    endpoint = "/api/scan-url";
    payload  = { url };

  } else if (currentTab === "email") {
    const email = document.getElementById("email-input").value.trim();
    if (!email) return showInputError("email-input", "Please paste email content");
    endpoint = "/api/scan-email";
    payload  = { email };

  } else {
    const html = document.getElementById("html-input").value.trim();
    if (!html) return showInputError("html-input", "Please paste HTML content");
    endpoint = "/api/scan-html";
    payload  = { html };
  }

  showLoading();

  try {
    const res = await fetch(endpoint, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(payload),
    });

    const data = await res.json();

    if (!res.ok || data.error) {
      throw new Error(data.error || `Server error ${res.status}`);
    }

    lastResult = data;
    renderResult(data);

  } catch (err) {
    showError(err.message || "Scan failed. Is the backend running?");
  }
}

// ══════════════════════════════════════════════
//  LOADING STATE
// ══════════════════════════════════════════════

function showLoading() {
  const panel   = document.getElementById("result-panel");
  const loading = document.getElementById("loading-state");
  const content = document.getElementById("result-content");
  const msgEl   = document.getElementById("loading-msg");

  panel.classList.remove("hidden");
  loading.classList.remove("hidden");
  content.classList.add("hidden");

  // Cycle through loading messages
  let i = 0;
  msgEl.textContent = LOADING_MESSAGES[0];
  const interval = setInterval(() => {
    i = (i + 1) % LOADING_MESSAGES.length;
    msgEl.textContent = LOADING_MESSAGES[i];
  }, 600);

  // Attach interval ID so we can clear it
  panel._loadingInterval = interval;
}

function hideLoading() {
  const panel   = document.getElementById("result-panel");
  const loading = document.getElementById("loading-state");
  const content = document.getElementById("result-content");

  if (panel._loadingInterval) {
    clearInterval(panel._loadingInterval);
    panel._loadingInterval = null;
  }

  loading.classList.add("hidden");
  content.classList.remove("hidden");
}

// ══════════════════════════════════════════════
//  RESULT RENDERING
// ══════════════════════════════════════════════

function renderResult(data) {
  hideLoading();

  const score   = data.risk_score || 0;
  const verdict = data.verdict    || "Unknown";
  const issues  = data.issues     || [];

  // ── Verdict banner ──────────────────────
  const banner    = document.getElementById("verdict-banner");
  const labelEl   = document.getElementById("verdict-label");
  const subEl     = document.getElementById("verdict-sub");
  const iconEl    = document.getElementById("verdict-icon");
  const scoreNum  = document.getElementById("score-number");
  const ringFill  = document.getElementById("ring-fill");

  banner.className = "verdict-banner " + verdict.toLowerCase();
  labelEl.textContent = verdict;
  labelEl.className   = "verdict-label " + verdict.toLowerCase();
  subEl.textContent   = `Risk Score: ${score.toFixed(1)} / 100`;

  iconEl.textContent = verdict === "Safe" ? "✅"
                     : verdict === "Suspicious" ? "⚠️"
                     : "🚨";

  // Animate score number
  animateNumber(scoreNum, 0, Math.round(score), 1000);

  // Animate ring
  const circumference = 314;
  const offset        = circumference - (score / 100) * circumference;
  ringFill.style.strokeDashoffset = offset;

  const ringColor = verdict === "Safe"       ? "#22c55e"
                  : verdict === "Suspicious" ? "#f97316"
                  : "#ef4444";
  ringFill.style.stroke   = ringColor;
  scoreNum.style.color    = ringColor;

  // ── Score breakdown ─────────────────────
  const mlScore   = data.ml_score   || 0;
  const ruleScore = data.rule_score || 0;

  animateBar("ml-bar",   mlScore);
  animateBar("rule-bar", ruleScore);
  document.getElementById("ml-score-val").textContent   = `${mlScore.toFixed(1)}%`;
  document.getElementById("rule-score-val").textContent = `${ruleScore.toFixed(1)}%`;

  // ── Issues ──────────────────────────────
  const issuesList = document.getElementById("issues-list");
  issuesList.innerHTML = "";

  if (issues.length === 0) {
    issuesList.innerHTML = `<p class="no-issues">✅ No phishing indicators detected.</p>`;
  } else {
    issues.forEach(iss => {
      const li = document.createElement("li");
      li.textContent = iss;
      if (iss.includes("🔴"))      li.className = "issue-high";
      else if (iss.includes("⚠️")) li.className = "issue-medium";
      else                          li.className = "issue-info";
      issuesList.appendChild(li);
    });
  }
  document.getElementById("issue-count").textContent = issues.length;

  // ── Features table ──────────────────────
  const tbody   = document.getElementById("features-body");
  tbody.innerHTML = "";
  const feats   = data.features || {};

  Object.entries(feats).forEach(([k, v]) => {
    if (typeof v === "object") return; // skip nested
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${k}</td><td>${formatValue(v)}</td>`;
    tbody.appendChild(tr);
  });

  // ── Raw JSON ─────────────────────────────
  document.getElementById("raw-json").textContent = JSON.stringify(data, null, 2);

  // Scroll to result
  document.getElementById("result-panel").scrollIntoView({ behavior: "smooth", block: "start" });
}

function showError(msg) {
  hideLoading();
  const panel   = document.getElementById("result-panel");
  const content = document.getElementById("result-content");
  panel.classList.remove("hidden");
  content.classList.remove("hidden");

  document.getElementById("verdict-banner").className = "verdict-banner";
  document.getElementById("verdict-label").textContent = "Error";
  document.getElementById("verdict-label").className   = "verdict-label";
  document.getElementById("verdict-icon").textContent  = "❌";
  document.getElementById("verdict-sub").textContent   = msg;
  document.getElementById("score-number").textContent  = "—";
  document.getElementById("issues-list").innerHTML =
    `<li class="issue-high">❌ ${msg}</li>`;
  document.getElementById("issue-count").textContent = "!";
}

// ══════════════════════════════════════════════
//  FEATURE PANEL TOGGLE
// ══════════════════════════════════════════════

function toggleFeatures() {
  featuresOpen = !featuresOpen;
  document.getElementById("features-section").classList.toggle("hidden", !featuresOpen);
  document.getElementById("features-arrow").textContent = featuresOpen ? "▲" : "▼";
}

// ══════════════════════════════════════════════
//  REPORT GENERATION
// ══════════════════════════════════════════════

async function downloadReport(format) {
  if (!lastResult) return;

  try {
    const res = await fetch("/api/report", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ result: lastResult, format }),
    });
    const data = await res.json();
    if (data.report_path) {
      showToast(`✅ Report saved: ${data.report_path}`);
    }
  } catch (e) {
    showToast("❌ Report generation failed (check if server is running)");
  }
}

async function copyJSON() {
  if (!lastResult) return;
  try {
    await navigator.clipboard.writeText(JSON.stringify(lastResult, null, 2));
    showToast("✅ JSON copied to clipboard!");
  } catch {
    showToast("❌ Could not copy (clipboard not available)");
  }
}

// ══════════════════════════════════════════════
//  SCAN HISTORY
// ══════════════════════════════════════════════

async function loadHistory() {
  const wrap = document.getElementById("history-table-wrap");
  wrap.innerHTML = `<p class="history-empty">Loading…</p>`;

  try {
    const res  = await fetch("/api/history?limit=20");
    const rows = await res.json();

    if (!Array.isArray(rows) || rows.length === 0) {
      wrap.innerHTML = `<p class="history-empty">No scans recorded yet.</p>`;
      return;
    }

    const table = document.createElement("table");
    table.className = "history-table";
    table.innerHTML = `
      <thead>
        <tr>
          <th>#</th>
          <th>Type</th>
          <th>Verdict</th>
          <th>Score</th>
          <th>Scanned At</th>
          <th>Target</th>
        </tr>
      </thead>
      <tbody></tbody>`;

    const tbody = table.querySelector("tbody");
    rows.forEach(r => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${r.id}</td>
        <td>${r.scan_type || "—"}</td>
        <td><span class="badge-verdict badge-${r.verdict || 'Unknown'}">${r.verdict || "—"}</span></td>
        <td>${r.risk_score != null ? r.risk_score.toFixed(1) : "—"}</td>
        <td>${(r.scanned_at || "").slice(0, 19)}</td>
        <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${r.target || "—"}</td>`;
      tbody.appendChild(tr);
    });

    wrap.innerHTML = "";
    wrap.appendChild(table);

  } catch (e) {
    wrap.innerHTML = `<p class="history-empty">Could not load history: ${e.message}</p>`;
  }
}

// ══════════════════════════════════════════════
//  CLEAR / RESET
// ══════════════════════════════════════════════

function clearResult() {
  const panel = document.getElementById("result-panel");
  panel.classList.add("hidden");
  lastResult   = null;
  featuresOpen = false;
  document.getElementById("features-section").classList.add("hidden");
  document.getElementById("features-arrow").textContent = "▼";
}

// ══════════════════════════════════════════════
//  HELPER UTILITIES
// ══════════════════════════════════════════════

function animateNumber(el, from, to, duration) {
  const startTime = performance.now();
  function step(now) {
    const progress = Math.min((now - startTime) / duration, 1);
    const eased    = 1 - Math.pow(1 - progress, 3); // ease-out cubic
    el.textContent = Math.round(from + (to - from) * eased);
    if (progress < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

function animateBar(id, pct) {
  const el = document.getElementById(id);
  if (!el) return;
  el.style.width = "0%";
  requestAnimationFrame(() => {
    setTimeout(() => { el.style.width = `${Math.min(pct, 100)}%`; }, 50);
  });
}

function formatValue(v) {
  if (typeof v === "boolean") return v ? "✓ true" : "✗ false";
  if (typeof v === "number")  return v % 1 === 0 ? v : v.toFixed(4);
  return String(v);
}

function showInputError(id, msg) {
  const el = document.getElementById(id);
  if (el) {
    el.style.borderColor = "var(--phishing)";
    el.style.boxShadow   = "0 0 0 3px rgba(239,68,68,0.2)";
    setTimeout(() => {
      el.style.borderColor = "";
      el.style.boxShadow   = "";
    }, 2000);
  }
}

// ── Toast notification ────────────────────
let _toastTimeout;
function showToast(msg) {
  let toast = document.getElementById("_toast");
  if (!toast) {
    toast = document.createElement("div");
    toast.id = "_toast";
    toast.style.cssText = `
      position:fixed;bottom:2rem;right:2rem;z-index:9999;
      background:#1e293b;border:1px solid rgba(0,200,255,0.3);
      color:#e2eaf4;padding:.75rem 1.25rem;border-radius:10px;
      font-family:'Space Mono',monospace;font-size:.82rem;
      box-shadow:0 8px 32px rgba(0,0,0,.5);
      transform:translateY(20px);opacity:0;transition:all .25s;
    `;
    document.body.appendChild(toast);
  }
  toast.textContent = msg;
  toast.style.transform = "translateY(0)";
  toast.style.opacity   = "1";
  clearTimeout(_toastTimeout);
  _toastTimeout = setTimeout(() => {
    toast.style.transform = "translateY(20px)";
    toast.style.opacity   = "0";
  }, 3500);
}

// ══════════════════════════════════════════════
//  KEYBOARD SHORTCUT
// ══════════════════════════════════════════════

document.addEventListener("keydown", e => {
  if (e.key === "Escape") clearResult();
});

// ── Ping health on load ───────────────────
window.addEventListener("DOMContentLoaded", () => {
  fetch("/api/health")
    .then(r => r.json())
    .then(d => console.log("PhishGuard API:", d.status))
    .catch(() => console.warn("Backend not reachable. Start app.py first."));
});
