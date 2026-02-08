// background.js (MV3 service worker)

// ------------------------------
// Helpers
// ------------------------------
function safeParse(url) {
  try { return new URL(url); } catch { return null; }
}

function isInternalUrl(url) {
  return (
    url.startsWith("chrome://") ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("about:") ||
    url.startsWith("edge://")
  );
}

/**
 * Allow the search results pages so users can browse results.
 * (But we will still intercept the "outbound click redirect" pages separately.)
 */
function isSearchResultsPage(urlObj) {
  const host = urlObj.hostname.toLowerCase();
  const path = urlObj.pathname.toLowerCase();

  // Google results page
  if (host.includes("google.") && path === "/search") return true;

  // Bing results page
  if (host === "www.bing.com" && path === "/search") return true;

  // DuckDuckGo results page (usually "/")
  if (host === "duckduckgo.com" && path === "/") return true;

  return false;
}

/**
 * Search engines often redirect clicks through an intermediate URL.
 * We catch that and extract the real destination so we can prompt on the real site.
 */
function extractSearchRedirectTarget(urlObj) {
  const host = urlObj.hostname.toLowerCase();
  const path = urlObj.pathname.toLowerCase();

  // Google click redirect: https://www.google.com/url?url=DEST or ?q=DEST
  if (host.includes("google.") && path === "/url") {
    return urlObj.searchParams.get("url") || urlObj.searchParams.get("q");
  }

  // DuckDuckGo click redirect: https://duckduckgo.com/l/?uddg=DEST
  if (host === "duckduckgo.com" && path.startsWith("/l/")) {
    return urlObj.searchParams.get("uddg");
  }

  return null;
}

// ------------------------------
// Proceed bypass: store allowUntil in session storage (survives SW sleep)
// ------------------------------
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.type === "ALLOW_NAV") {
    const tabId = sender.tab && sender.tab.id;
    if (typeof tabId === "number") {
      const allowKey = `allowUntil:${tabId}`;
      const allowUntil = Date.now() + 15000; // 15 seconds
      chrome.storage.session.set({ [allowKey]: allowUntil }, () => {
        sendResponse({ ok: true, allowUntil });
      });
      return true; // async response
    }
  }
});

// ------------------------------
// Intercept navigations
// ------------------------------
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;

  const url = details.url;
  if (!url || isInternalUrl(url)) return;

  const urlObj = safeParse(url);
  if (!urlObj) return;

  const uiUrl = chrome.runtime.getURL("index.html");
  if (url === uiUrl) return;

  // 1) If this is a search-engine click redirect, intercept and prompt on the REAL destination
  const redirectedTarget = extractSearchRedirectTarget(urlObj);
  if (redirectedTarget) {
    const pendingKey = `pendingUrl:${details.tabId}`;
    chrome.storage.session.set({ [pendingKey]: redirectedTarget }, () => {
      chrome.tabs.update(details.tabId, { url: uiUrl });
    });
    return;
  }

  // 2) Let search result pages show normally (no prompt)
  if (isSearchResultsPage(urlObj)) return;

  const allowKey = `allowUntil:${details.tabId}`;

  // 3) Check allow window (so "Continue" actually goes through)
  chrome.storage.session.get(allowKey, (data) => {
    const allowUntil = data && data[allowKey];

    if (allowUntil && Date.now() < allowUntil) {
      return; // allowed, do not redirect
    }

    // cleanup old allow window
    if (allowUntil) chrome.storage.session.remove(allowKey);

    // 4) Store pending URL and redirect to fullscreen UI
    const pendingKey = `pendingUrl:${details.tabId}`;
    chrome.storage.session.set({ [pendingKey]: url }, () => {
      chrome.tabs.update(details.tabId, { url: uiUrl });
    });
  });
});
