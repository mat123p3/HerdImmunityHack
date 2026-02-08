chrome.webNavigation.onBeforeNavigate.addListener(details => {
  if (details.frameId !== 0) return;

  const url = details.url;

  // Ignore chrome / extension pages to avoid loops
  if (
    url.startsWith("chrome://") ||
    url.startsWith("chrome-extension://")
  ) return;

  chrome.storage.session.set({ pendingUrl: url });

  chrome.tabs.update(details.tabId, {
    url: chrome.runtime.getURL("index.html")
  });
});
