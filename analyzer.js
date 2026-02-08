// analyzer.js
// Placeholder “integrity” analyzer (browser-safe).
// Later you can replace internals with: fetch("http://localhost:5050/scan?url=...")

function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

function scoreToColor(score) {
  if (score < 20) return "Black";
  if (score < 40) return "Red";
  if (score < 60) return "Orange";
  if (score < 80) return "Yellow";
  return "Green";
}

async function analyzeUrl(url) {
  let score = 50;
  const reasons = [];

  let u;
  try {
    u = new URL(url);
  } catch {
    return {
      url,
      score: 0,
      color: "Black",
      reasons: ["Invalid URL"],
      http: null,
      stats: null
    };
  }

  const https = u.protocol === "https:";
  score += https ? 15 : -15;
  reasons.push(https ? "Uses HTTPS" : "Not HTTPS");

  // quick domain heuristics
  const host = u.hostname.toLowerCase();
  const suspiciousTlds = ["zip", "mov", "top", "xyz", "click"];
  const tld = host.split(".").pop();
  if (suspiciousTlds.includes(tld)) {
    score -= 12;
    reasons.push(`Suspicious TLD (.${tld})`);
  }

  // Try a simple HEAD/GET timing signal (often blocked; that’s ok)
  let http = null;
  try {
    const start = performance.now();
    let res = await fetch(url, { method: "HEAD", redirect: "follow" });
    if (res.status === 405 || res.status === 403) {
      res = await fetch(url, { method: "GET", redirect: "follow" });
    }
    const timeMs = Math.round(performance.now() - start);

    http = { status: res.status, timeMs, finalUrl: res.url };

    if (res.status >= 200 && res.status < 400) score += 10;
    else score -= 10;

    if (timeMs < 800) score += 5;
    if (timeMs > 3000) score -= 5;

    const ct = (res.headers.get("content-type") || "").toLowerCase();
    if (!ct.includes("text/html")) {
      score -= 5;
      reasons.push("Not HTML content");
    }
  } catch {
    score -= 8;
    reasons.push("Fetch blocked/failed (common)");
  }

  score = clamp(Math.round(score), 0, 100);

  return {
    url,
    score,
    color: scoreToColor(score),
    reasons,
    http,
    stats: null
  };
}

// expose globally
window.analyzeUrl = analyzeUrl;
