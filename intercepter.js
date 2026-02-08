/**
 * intercepter.js (fullscreen UI controller)
 *
 * WHAT IT DOES:
 * 1) Gets the pending URL that background.js stored in chrome.storage.session
 *    - preferred: pendingUrl:<tabId>
 *    - fallback: pendingUrl
 * 2) Runs placeholder analysis using analyzer.js (window.analyzeUrl)
 * 3) Renders results into your Basic/Advanced tab UI
 * 4) "Continue to site" works by sending ALLOW_NAV to background.js
 *    so you DON'T get stuck in an infinite redirect loop.
 *
 * REQUIRED SCRIPT ORDER IN index.html:
 *   <script src="Tab_functions.js"></script>
 *   <script src="analyzer.js"></script>
 *   <script src="intercepter.js"></script>
 */

const STATE = {
  tabId: null,
  site: null,
  result: null
};

const PENDING_PREFIX = "pendingUrl:";
const PENDING_FALLBACK = "pendingUrl";

// ------------------------------
// DOM helpers
// ------------------------------
function $(id) {
  return document.getElementById(id);
}

function setText(id, text) {
  const el = $(id);
  if (el) el.textContent = text ?? "";
}

// Adds a CSS class for the color (expects .black/.red/.orange/.yellow/.green in CSS)
function setColorText(id, colorName) {
  const el = $(id);
  if (!el) return;
  el.textContent = colorName ?? "";
  el.className = "";
  if (colorName) el.classList.add(String(colorName).toLowerCase());
}

// ------------------------------
// Determine tabId for this extension page tab
// ------------------------------
function getCurrentTabId(cb) {
  chrome.tabs.getCurrent((tab) => {
    if (tab && typeof tab.id === "number") return cb(tab.id);

    // fallback
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const t = tabs && tabs[0];
      cb(t && typeof t.id === "number" ? t.id : null);
    });
  });
}

// ------------------------------
// Read the pending URL stored by background.js
// ------------------------------
function loadPendingUrl(tabId, cb) {
  const perTabKey = tabId != null ? `${PENDING_PREFIX}${tabId}` : null;

  if (perTabKey) {
    chrome.storage.session.get(perTabKey, (data) => {
      const url = data && data[perTabKey];
      if (url) return cb(url, perTabKey);

      // fallback to old key
      chrome.storage.session.get(PENDING_FALLBACK, (data2) => {
        const url2 = data2 && data2[PENDING_FALLBACK];
        cb(url2 || null, PENDING_FALLBACK);
      });
    });
    return;
  }

  chrome.storage.session.get(PENDING_FALLBACK, (data) => {
    const url = data && data[PENDING_FALLBACK];
    cb(url || null, PENDING_FALLBACK);
  });
}

function clearPendingUrl(key) {
  try {
    chrome.storage.session.remove(key);
  } catch {}
}

// ------------------------------
// Render analysis result into UI
// ------------------------------
function renderResult(result) {
  const displayUrl = (result && result.http && result.http.finalUrl) || result.url || "";
  const scoreText = typeof result.score === "number" ? `${result.score}%` : "";
  const colorText = result.color ? String(result.color) : "";

  // Basic tab
  setText("urlBasic", displayUrl);
  setText("ratingBasic", scoreText);
  setColorText("colorBasic", colorText);
  if (Array.isArray(result.reasons)) {
    setText("reasonsBasic", result.reasons.join(" • "));
  }

  // Advanced tab
  setText("urlAdvanced", displayUrl);
  setText("ratingAdvanced", scoreText);
  setColorText("colorAdvanced", colorText);
  setText("advancedDump", JSON.stringify(result, null, 2));
}

// ------------------------------
// Analysis pipeline (placeholder)
// ------------------------------
async function runAnalysis(url) {
  if (!window.analyzeUrl) {
    setText("statusText", "Error: analyzer.js not loaded (window.analyzeUrl missing).");
    console.error("window.analyzeUrl missing. Ensure analyzer.js loads before intercepter.js");
    return;
  }

  setText("statusText", "Analyzing...");
  setText("advancedDump", "(analyzing...)");

  try {
    const result = await window.analyzeUrl(url);
    STATE.result = result;

    renderResult(result);
    setText("statusText", "Done");
  } catch (err) {
    console.error("Analysis failed:", err);
    setText("statusText", "Analysis failed (check console).");
    setText("advancedDump", String(err));
  }
}

// ------------------------------
// Proceed / Back
// ------------------------------
function proceed() {
  if (!STATE.site) return;

  /**
   * IMPORTANT:
   * We tell background.js "ALLOW_NAV" first so it temporarily stops intercepting.
   * Then we navigate the tab to the real site.
   */
  chrome.runtime.sendMessage({ type: "ALLOW_NAV" }, () => {
    if (STATE.tabId != null) chrome.tabs.update(STATE.tabId, { url: STATE.site });
    else chrome.tabs.update({ url: STATE.site });
  });
}

function goBack() {
  if (STATE.tabId != null) chrome.tabs.goBack(STATE.tabId);
}

// ------------------------------
// Boot
// ------------------------------
document.addEventListener("DOMContentLoaded", () => {
  // default tab open (from Tab_functions.js)
  const def = $("defaultOpen");
  if (def) def.click();

  // Buttons
  const proceedBtn = $("proceedBtn");
  if (proceedBtn) proceedBtn.addEventListener("click", proceed);

  const backBtn = $("backBtn");
  if (backBtn) backBtn.addEventListener("click", goBack);

  setText("statusText", "Loading pending URL...");

  getCurrentTabId((tabId) => {
    STATE.tabId = tabId;

    loadPendingUrl(tabId, (url, usedKey) => {
      if (!url) {
        setText("statusText", "No pending URL found. Try clicking a result/link again.");
        setText("advancedDump", "(no pending URL)");
        return;
      }

      // Clear stored pending URL so refresh doesn't reuse it
      clearPendingUrl(usedKey);

      STATE.site = url;

      // Show URL immediately
      setText("urlBasic", url);
      setText("urlAdvanced", url);

      // Run placeholder analysis
      runAnalysis(url);
    });
  });
});
