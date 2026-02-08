import readline from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import dns from "node:dns/promises";
import tls from "node:tls";
import whois from "whois-json";
import fs from "node:fs/promises";
import path from "node:path";
import { exec as execCb } from "node:child_process";
import { promisify } from "node:util";

const exec = promisify(execCb);
const IPINFO_TOKEN = process.env.IPINFO_TOKEN ?? "";

// -------------------------------
// Types
// -------------------------------
type Geo = { city?: string; region?: string; country?: string; isp?: string; source?: string };
type HttpInfo = { status: number; timeSec: number; finalUrl: string; headers: Record<string, string> };
type TlsInfo = { subject?: any; issuer?: any; valid_from?: string; valid_to?: string; fingerprint256?: string };

type RawData = {
  targetUrl: string;
  host: string;
  whoisDomain: string;
  ips: string[];
  geo?: Geo;
  http?: HttpInfo;
  tls?: TlsInfo;
  whois?: Record<string, any>;
  errors: string[];
  savedFilePath: string;
};

type Verdict = {
  stars: 1 | 2 | 3 | 4 | 5;
  label: "SAFE" | "CAUTION" | "RISKY";
  reasons: string[];
};

// -------------------------------
// Helpers
// -------------------------------
function normalizeUrl(raw: string): string {
  const s = raw.trim();
  if (!/^https?:\/\//i.test(s)) return "https://" + s;
  return s;
}

function getHost(url: string): string {
  return new URL(url).hostname;
}

function stripWww(host: string): string {
  return host.startsWith("www.") ? host.slice(4) : host;
}

function safeFilename(s: string) {
  return s.replace(/[^a-zA-Z0-9._-]+/g, "_");
}

function nowStamp() {
  const d = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
}

function starsText(n: number) {
  return "★".repeat(n) + "☆".repeat(5 - n);
}

// -------------------------------
// Share (simple copy-paste token)
// -------------------------------
function makeShareToken(url: string, label: string, stars: number) {
  const ts = new Date().toISOString();
  // Keep it very simple and copy-paste friendly
  return `SAFE-LINK|${url}|${label}|${stars}|${ts}`;
}

function parseShareToken(token: string) {
  const trimmed = token.trim();
  if (!trimmed.startsWith("SAFE-LINK|")) return null;

  const parts = trimmed.split("|");
  if (parts.length < 2) return null;

  const url = parts[1];
  if (!/^https?:\/\//i.test(url)) return null;

  return { url };
}

// -------------------------------
// GEO lookups
// -------------------------------
async function ipInfoLookup(ip: string) {
  if (!IPINFO_TOKEN) throw new Error("Missing IPINFO_TOKEN");

  const url = `https://ipinfo.io/${encodeURIComponent(ip)}?token=${encodeURIComponent(IPINFO_TOKEN)}`;
  const res = await fetch(url, { headers: { Accept: "application/json" } });

  const text = await res.text();
  if (!res.ok) throw new Error(`IPinfo HTTP ${res.status}: ${text}`);

  const data = JSON.parse(text);
  if (data?.error) {
    throw new Error(`IPinfo error: ${data.error.title ?? ""} ${data.error.message ?? ""}`.trim());
  }
  return data;
}

async function ipGeoFallback(ip: string) {
  const res = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, {
    headers: { Accept: "application/json" }
  });

  const data = await res.json();
  if (data?.success === false) throw new Error(`ipwho.is error: ${data?.message ?? "unknown"}`);
  return data;
}

// -------------------------------
// HTTP request
// -------------------------------
async function httpRequest(url: string): Promise<HttpInfo> {
  const controller = new AbortController();
  const start = Date.now();
  const timeout = setTimeout(() => controller.abort(), 10_000);

  try {
    let res = await fetch(url, { method: "HEAD", redirect: "follow", signal: controller.signal });

    if (res.status === 405 || res.status === 403) {
      res = await fetch(url, { method: "GET", redirect: "follow", signal: controller.signal });
    }

    const end = Date.now();
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => (headers[k] = v));

    return { status: res.status, timeSec: (end - start) / 1000, headers, finalUrl: res.url };
  } finally {
    clearTimeout(timeout);
  }
}

// -------------------------------
// TLS cert
// -------------------------------
function getTlsCert(domain: string, port = 443): Promise<any> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: domain,
      port,
      servername: domain,
      rejectUnauthorized: false
    });

    socket.setTimeout(10_000);

    socket.once("secureConnect", () => {
      const cert = socket.getPeerCertificate(true);
      socket.end();
      resolve(cert);
    });

    socket.once("timeout", () => {
      socket.destroy();
      reject(new Error("TLS timeout"));
    });

    socket.once("error", (err) => reject(err));
  });
}

// -------------------------------
// TXT formatting
// -------------------------------
function formatRawTxt(d: Omit<RawData, "savedFilePath">) {
  const lines: string[] = [];
  lines.push("=".repeat(70));
  lines.push(`TARGET URL : ${d.targetUrl}`);
  lines.push(`DOMAIN     : ${d.host}`);
  lines.push("=".repeat(70));
  lines.push("");

  lines.push(`IP ADDRESS : ${d.ips.length ? d.ips.join(", ") : "(none)"}`);
  lines.push("-".repeat(70));

  if (d.geo) {
    lines.push(`GEO LOCATION (${d.geo.source ?? "unknown"})`);
    lines.push(`  City    : ${d.geo.city ?? "(unknown)"}`);
    lines.push(`  Region  : ${d.geo.region ?? "(unknown)"}`);
    lines.push(`  Country : ${d.geo.country ?? "(unknown)"}`);
    lines.push(`  ISP     : ${d.geo.isp ?? "(unknown)"}`);
  } else {
    lines.push("GEO LOCATION : (not available)");
  }

  lines.push("-".repeat(70));

  if (d.http) {
    lines.push(`STATUS CODE   : ${d.http.status}`);
    lines.push(`RESPONSE TIME : ${d.http.timeSec.toFixed(4)} seconds`);
    lines.push(`FINAL URL     : ${d.http.finalUrl}`);
    lines.push("HEADERS:");
    for (const [k, v] of Object.entries(d.http.headers)) lines.push(`  ${k}: ${v}`);
  } else {
    lines.push("HTTP : (not available)");
  }

  lines.push("-".repeat(70));

  if (d.tls) {
    lines.push("SSL CERTIFICATE (selected fields):");
    lines.push(`  subject        : ${JSON.stringify(d.tls.subject ?? {})}`);
    lines.push(`  issuer         : ${JSON.stringify(d.tls.issuer ?? {})}`);
    lines.push(`  valid_from     : ${d.tls.valid_from ?? ""}`);
    lines.push(`  valid_to       : ${d.tls.valid_to ?? ""}`);
    lines.push(`  fingerprint256 : ${d.tls.fingerprint256 ?? ""}`);
  } else {
    lines.push("SSL CERTIFICATE : (not available)");
  }

  lines.push("-".repeat(70));

  if (d.whois) {
    lines.push(`WHOIS DATA (query: ${d.whoisDomain}):`);
    for (const [k, v] of Object.entries(d.whois ?? {})) {
      lines.push(`  ${k}: ${Array.isArray(v) ? v.join(", ") : String(v)}`);
    }
  } else {
    lines.push("WHOIS : (not available)");
  }

  if (d.errors.length) {
    lines.push("");
    lines.push("ERRORS:");
    for (const e of d.errors) lines.push(`  - ${e}`);
  }

  lines.push("");
  lines.push("✔ Scan complete");
  return lines.join("\n");
}

// ===============================
// F_DATA(URL_CLICK)
// ===============================
async function F_Data(urlClick: string): Promise<RawData> {
  const errors: string[] = [];

  const targetUrl = normalizeUrl(urlClick);
  const host = getHost(targetUrl);
  const whoisDomain = stripWww(host);

  // DNS/IP
  let ips: string[] = [];
  try {
    const results = await dns.lookup(host, { all: true });
    ips = results.map((r) => r.address);
  } catch (e: any) {
    errors.push(`IP ERROR: ${e?.message ?? String(e)}`);
  }

  // GEO
  let geo: Geo | undefined;
  if (ips.length) {
    const ip = ips[0];

    if (IPINFO_TOKEN) {
      try {
        const d = await ipInfoLookup(ip);
        geo = { city: d.city, region: d.region, country: d.country, isp: d.org, source: "ipinfo" };
      } catch (e: any) {
        errors.push(`GEO ERROR (ipinfo): ${e?.message ?? String(e)}`);
      }
    }

    if (!geo) {
      try {
        const g = await ipGeoFallback(ip);
        geo = { city: g.city, region: g.region, country: g.country, isp: g.connection?.isp, source: "ipwho.is" };
      } catch (e: any) {
        errors.push(`GEO ERROR (fallback): ${e?.message ?? String(e)}`);
      }
    }
  } else {
    errors.push("No IP addresses resolved from DNS");
  }

  // HTTP
  let http: HttpInfo | undefined;
  try {
    http = await httpRequest(targetUrl);
  } catch (e: any) {
    errors.push(`HTTP ERROR: ${e?.message ?? String(e)}`);
  }

  // TLS
  let tlsInfo: TlsInfo | undefined;
  try {
    const cert = await getTlsCert(host);
    tlsInfo = {
      subject: cert.subject,
      issuer: cert.issuer,
      valid_from: cert.valid_from,
      valid_to: cert.valid_to,
      fingerprint256: cert.fingerprint256
    };
  } catch (e: any) {
    errors.push(`SSL ERROR: ${e?.message ?? String(e)}`);
  }

  // WHOIS
  let whoisData: Record<string, any> | undefined;
  try {
    whoisData = await whois(whoisDomain);
  } catch (e: any) {
    errors.push(`WHOIS ERROR: ${e?.message ?? String(e)}`);
  }

  // Save .txt
  const outDir = path.resolve(process.cwd(), "output");
  await fs.mkdir(outDir, { recursive: true });

  const fileName = `rawdata-${safeFilename(whoisDomain)}-${nowStamp()}.txt`;
  const savedFilePath = path.join(outDir, fileName);

  const txt = formatRawTxt({
    targetUrl,
    host,
    whoisDomain,
    ips,
    geo,
    http,
    tls: tlsInfo,
    whois: whoisData,
    errors
  });

  await fs.writeFile(savedFilePath, txt, "utf8");

  return {
    targetUrl,
    host,
    whoisDomain,
    ips,
    geo,
    http,
    tls: tlsInfo,
    whois: whoisData,
    errors,
    savedFilePath
  };
}

// ===============================
// F_VF (interpret/grade)
// ===============================
function F_VF(d: RawData): Verdict {
  let score = 0; // higher = riskier
  const reasons: string[] = [];

  // HTTPS?
  const isHttps = d.targetUrl.toLowerCase().startsWith("https://");
  if (!isHttps) {
    score += 3;
    reasons.push("Not using HTTPS");
  } else {
    reasons.push("Uses HTTPS");
  }

  // HTTP status
  if (d.http) {
    if (d.http.status >= 400) {
      score += 2;
      reasons.push(`HTTP error status: ${d.http.status}`);
    } else {
      reasons.push(`HTTP status OK: ${d.http.status}`);
    }
  } else {
    score += 2;
    reasons.push("HTTP request failed");
  }

  // Redirect mismatch
  if (d.http?.finalUrl) {
    try {
      const finalHost = getHost(d.http.finalUrl);
      if (stripWww(finalHost) !== stripWww(d.host)) {
        score += 2;
        reasons.push(`Redirected to different host: ${finalHost}`);
      }
    } catch {
      score += 1;
      reasons.push("Could not parse final redirect URL");
    }
  }

  // Missing TLS
  if (!d.tls) {
    score += 3;
    reasons.push("No TLS certificate info");
  } else {
    reasons.push("TLS certificate present");
  }

  // Missing WHOIS
  if (!d.whois) {
    score += 1;
    reasons.push("WHOIS lookup missing or failed");
  } else {
    reasons.push("WHOIS data found");
  }

  // Errors
  if (d.errors.length) {
    score += 1;
    reasons.push(`Errors encountered: ${d.errors.length}`);
  }

  // Score → Stars/Label
  let stars: Verdict["stars"];
  let label: Verdict["label"];

  if (score <= 1) {
    stars = 5; label = "SAFE";
  } else if (score <= 3) {
    stars = 4; label = "SAFE";
  } else if (score <= 5) {
    stars = 3; label = "CAUTION";
  } else if (score <= 7) {
    stars = 2; label = "RISKY";
  } else {
    stars = 1; label = "RISKY";
  }

  return { stars, label, reasons: reasons.slice(0, 8) };
}

// -------------------------------
// Open URL in browser (macOS)
// -------------------------------
async function openInBrowser(url: string) {
  await exec(`open "${url.replace(/"/g, '\\"')}"`);
}

// ===============================
// F_UI
// ===============================
async function F_UI() {
  const rl = readline.createInterface({ input, output });

  console.log("\n=== SAFE-LINK ===");
  console.log("1) Scan a URL");
  console.log("2) Paste a share code (from a friend)");
  const mode = (await rl.question("Choose (1/2): ")).trim();

  let urlClick = "";

  if (mode === "2") {
    const token = await rl.question("Paste share code: ");
    const parsed = parseShareToken(token);
    if (!parsed) {
      console.log("Invalid share code.");
      await rl.question("\nPress ENTER to close...");
      rl.close();
      return;
    }
    urlClick = parsed.url;
    console.log(`Loaded URL: ${urlClick}`);
  } else {
    urlClick = (await rl.question("Enter website URL: ")).trim();
  }

  // F_DATA
  const data = await F_Data(urlClick);
  console.log(`\nSaved raw data to: ${data.savedFilePath}`);

  // F_VF
  const verdict = F_VF(data);
  console.log("\n" + "-".repeat(70));
  console.log(`VERDICT: ${verdict.label}  ${starsText(verdict.stars)}`);
  console.log("Reasons:");
  for (const r of verdict.reasons) console.log(`  - ${r}`);
  console.log("-".repeat(70));

  // Share token (simple copy/paste)
  const share = makeShareToken(data.targetUrl, verdict.label, verdict.stars);
  console.log("\nSHARE THIS (copy/paste to friend):");
  console.log(share);

  // Go / No
  const ans = (await rl.question("\nGo to this website? (y/n): ")).trim().toLowerCase();
  if (ans === "y" || ans === "yes") {
    console.log("Opening in browser...");
    await openInBrowser(data.targetUrl);
  } else {
    console.log("Canceled.");
  }

  await rl.question("\nPress ENTER to close...");
  rl.close();
}

// RUN
F_UI().catch((err) => {
  console.error(err);
  process.exit(1);
});
