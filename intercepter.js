chrome.storage.session.get("pendingUrl", data => {
  if (!data.pendingUrl) return;

  STATE.site = data.pendingUrl;
  crunchData(STATE.site); // your analysis pipeline
});

function proceed() {
  chrome.tabs.update({ url: STATE.site });
}
/* this is where scraper logic may take place ^^^^^ to be reviewed or replaced with existing funcitons*/