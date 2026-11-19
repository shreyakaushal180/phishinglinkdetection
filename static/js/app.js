/**
 * app.js  —  PhishGuard AI frontend logic
 */

(function () {
  "use strict";

  // ── DOM refs ───────────────────────────────────────────────────────────
  const urlInput      = document.getElementById("urlInput");
  const scanBtn       = document.getElementById("scanBtn");
  const clearBtn      = document.getElementById("clearBtn");
  const resultArea    = document.getElementById("resultArea");
  const loadingState  = document.getElementById("loadingState");
  const resultCard    = document.getElementById("resultCard");
  const errorCard     = document.getElementById("errorCard");
  const errorMsg      = document.getElementById("errorMsg");
  const modelBadge    = document.getElementById("modelBadge");
  const badgeDot      = modelBadge.querySelector(".badge-dot");
  const badgeText     = modelBadge.querySelector(".badge-text");

  const resultVerdict  = document.getElementById("resultVerdict");
  const verdictIcon    = document.getElementById("verdictIcon");
  const verdictLabel   = document.getElementById("verdictLabel");
  const verdictUrl     = document.getElementById("verdictUrl");
  const confidencePill = document.getElementById("confidencePill");
  const confBar        = document.getElementById("confBar");
  const confPct        = document.getElementById("confPct");
  const featuresGrid   = document.getElementById("featuresGrid");

  const batchInput     = document.getElementById("batchInput");
  const batchScanBtn   = document.getElementById("batchScanBtn");
  const batchResults   = document.getElementById("batchResults");

  // ── Model status ───────────────────────────────────────────────────────
  async function checkModelStatus() {
    try {
      const res  = await fetch("/api/status");
      const data = await res.json();
      if (data.ready) {
        badgeDot.classList.add("ready");
        badgeText.textContent = `Model ready · ${data.features} features`;
      } else {
        badgeDot.classList.add("error");
        badgeText.textContent = "Model not loaded — run train_model.py";
      }
    } catch {
      badgeDot.classList.add("error");
      badgeText.textContent = "Server offline";
    }
  }
  checkModelStatus();

  // ── Clear button visibility ────────────────────────────────────────────
  urlInput.addEventListener("input", () => {
    clearBtn.classList.toggle("visible", urlInput.value.length > 0);
  });
  clearBtn.addEventListener("click", () => {
    urlInput.value = "";
    clearBtn.classList.remove("visible");
    urlInput.focus();
    hideResult();
  });

  // ── Example pills ──────────────────────────────────────────────────────
  document.querySelectorAll(".pill").forEach(pill => {
    pill.addEventListener("click", () => {
      urlInput.value = pill.dataset.url;
      clearBtn.classList.add("visible");
      urlInput.focus();
      runScan();
    });
  });

  // ── Scan on button / enter ─────────────────────────────────────────────
  scanBtn.addEventListener("click", runScan);
  urlInput.addEventListener("keydown", e => {
    if (e.key === "Enter") runScan();
  });

  // ── Single URL scan ────────────────────────────────────────────────────
  async function runScan() {
    const url = urlInput.value.trim();
    if (!url) {
      urlInput.focus();
      urlInput.classList.add("shake");
      setTimeout(() => urlInput.classList.remove("shake"), 500);
      return;
    }

    showLoading();
    scanBtn.disabled = true;

    try {
      const res  = await fetch("/api/predict", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ url }),
      });
      const data = await res.json();

      if (!data.success) throw new Error(data.error || "Unknown error");
      showResult(data);
    } catch (err) {
      showError(err.message);
    } finally {
      scanBtn.disabled = false;
    }
  }

  // ── UI helpers ─────────────────────────────────────────────────────────
  function hideResult() {
    resultArea.classList.add("hidden");
    loadingState.classList.add("hidden");
    resultCard.classList.add("hidden");
    errorCard.classList.add("hidden");
  }

  function showLoading() {
    resultArea.classList.remove("hidden");
    loadingState.classList.remove("hidden");
    resultCard.classList.add("hidden");
    errorCard.classList.add("hidden");
  }

  function showResult(data) {
    const isPhish = data.prediction === 1;
    const cls     = isPhish ? "danger" : "safe";
    const icon    = isPhish ? "🚨" : "✅";
    const label   = isPhish ? "Phishing URL Detected" : "Safe — Legitimate URL";

    // Verdict strip
    resultVerdict.className = `result-verdict ${cls}`;
    verdictIcon.textContent = icon;
    verdictLabel.textContent = label;
    verdictLabel.className  = `verdict-label ${cls}`;
    verdictUrl.textContent   = data.url;

    // Confidence pill
    confidencePill.textContent = `${data.confidence}%`;
    confidencePill.className   = `confidence-pill ${cls}`;

    // Confidence bar
    confPct.textContent = `${data.confidence}%`;
    confBar.className   = `confidence-bar-fill ${cls}`;
    // Animate after short delay so CSS transition triggers
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        confBar.style.width = `${data.confidence}%`;
      });
    });

    // Feature chips
    featuresGrid.innerHTML = "";
    if (data.top_features && data.top_features.length) {
      data.top_features.forEach(f => {
        const chip = document.createElement("div");
        chip.className = "feature-chip";
        chip.innerHTML = `<span class="chip-name">${formatFeatureName(f.name)}</span>
                          <span class="chip-val">${formatValue(f.value)}</span>`;
        featuresGrid.appendChild(chip);
      });
    }

    // Show
    loadingState.classList.add("hidden");
    errorCard.classList.add("hidden");
    resultCard.classList.remove("hidden");
  }

  function showError(msg) {
    loadingState.classList.add("hidden");
    resultCard.classList.add("hidden");
    errorMsg.textContent = msg;
    errorCard.classList.remove("hidden");
  }

  // ── Format helpers ─────────────────────────────────────────────────────
  function formatFeatureName(name) {
    // CamelCase → readable
    return name.replace(/([A-Z])/g, " $1").trim();
  }
  function formatValue(v) {
    if (typeof v === "number") return Number.isInteger(v) ? v : v.toFixed(3);
    return String(v);
  }

  // ── Batch scan ─────────────────────────────────────────────────────────
  batchScanBtn.addEventListener("click", runBatchScan);

  async function runBatchScan() {
    const raw  = batchInput.value.trim();
    if (!raw) return;
    const urls = raw.split("\n").map(u => u.trim()).filter(Boolean);
    if (!urls.length) return;

    batchScanBtn.disabled = true;
    batchScanBtn.innerHTML = `<span class="spinner-ring" style="width:18px;height:18px;border-width:2px;"></span> Scanning…`;

    batchResults.classList.remove("hidden");
    batchResults.innerHTML = `<div class="loading-state" style="padding:20px;justify-content:center;">
      <div class="spinner-ring"></div> <span>Analyzing ${urls.length} URL${urls.length>1?"s",""}…</span>
    </div>`;

    try {
      const res  = await fetch("/api/batch", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ urls }),
      });
      const data = await res.json();
      if (!data.success) throw new Error(data.error);
      renderBatchResults(data.results);
    } catch (err) {
      batchResults.innerHTML = `<div class="error-card"><span class="error-icon">⚠️</span>${err.message}</div>`;
    } finally {
      batchScanBtn.disabled = false;
      batchScanBtn.innerHTML = `<span>⚡</span> Scan All`;
    }
  }

  function renderBatchResults(results) {
    batchResults.innerHTML = "";

    const summary = document.createElement("div");
    const phishCount = results.filter(r => r.prediction === 1).length;
    const safeCount  = results.filter(r => r.prediction === 0).length;
    summary.style.cssText = "font-size:.8rem;color:var(--text-muted);margin-bottom:10px;padding:0 4px;";
    summary.innerHTML = `Scanned <strong>${results.length}</strong> URLs &nbsp;·&nbsp; ` +
      `<span style="color:var(--safe)">✅ ${safeCount} Safe</span> &nbsp;·&nbsp; ` +
      `<span style="color:var(--danger)">🚨 ${phishCount} Phishing</span>`;
    batchResults.appendChild(summary);

    results.forEach(r => {
      if (r.error) {
        const row = document.createElement("div");
        row.className = "batch-row";
        row.innerHTML = `<span class="batch-verdict-icon">⚠️</span>
                         <span class="batch-url" title="${r.url}">${r.url}</span>
                         <span class="batch-label" style="color:var(--warn)">Error</span>`;
        batchResults.appendChild(row);
        return;
      }
      const isPhish = r.prediction === 1;
      const row = document.createElement("div");
      row.className = `batch-row ${isPhish ? "danger-row" : "safe-row"}`;
      row.innerHTML = `
        <span class="batch-verdict-icon">${isPhish ? "🚨" : "✅"}</span>
        <span class="batch-url" title="${r.url}">${r.url}</span>
        <span class="batch-label ${isPhish ? "danger" : "safe"}">${r.label}</span>
        <span class="batch-conf">${r.confidence}%</span>`;
      batchResults.appendChild(row);
    });
  }

  // ── Shake animation for empty input ───────────────────────────────────
  const style = document.createElement("style");
  style.textContent = `
    @keyframes shake {
      0%,100% { transform: translateX(0); }
      20%,60%  { transform: translateX(-6px); }
      40%,80%  { transform: translateX(6px); }
    }
    .shake { animation: shake .4s ease; }
  `;
  document.head.appendChild(style);

})();
