import readline from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import dns from "node:dns/promises";
import tls from "node:tls";
import whois from "whois-json";

const IPINFO_TOKEN = process.env.IPINFO_TOKEN ?? "";

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

/**
 * IPinfo lookup (requires token).
 * Throws helpful errors instead of returning null so you can see what went wrong.
 */
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

/**
 * No-token fallback geo lookup (ipwho.is).
 * Helpful when you don’t want to configure IPINFO_TOKEN yet.
 */
async function ipGeoFallback(ip: string) {
  const res = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, {
    headers: { Accept: "application/json" }
  });

  const data = await res.json();

  if (data?.success === false) {
    throw new Error(`ipwho.is error: ${data?.message ?? "unknown"}`);
  }

  return data;
}

async function httpRequest(url: string) {
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

    return {
      status: res.status,
      timeSec: (end - start) / 1000,
      headers,
      finalUrl: res.url
    };
  } finally {
    clearTimeout(timeout);
  }
}

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

async function scanWebsite(url: string) {
  const host = getHost(url);
  const domainForWhois = stripWww(host);

  console.log("\n" + "=".repeat(70));
  console.log(`TARGET URL : ${url}`);
  console.log(`DOMAIN     : ${host}`);
  console.log("=".repeat(70));

  // -------------------------------
  // DNS / IP
  // -------------------------------
  let ips: string[] = [];
  try {
    const results = await dns.lookup(host, { all: true });
    ips = results.map((r) => r.address);
    console.log(`IP ADDRESS : ${ips.join(", ") || "(none)"}`);
  } catch (e: any) {
    console.log(`IP ERROR   : ${e?.message ?? String(e)}`);
  }

  console.log("-".repeat(70));

  // -------------------------------
  // GEO LOCATION
  // -------------------------------
  if (ips.length) {
    const ip = ips[0];

    // Try IPinfo first (if token provided); otherwise fallback
    if (IPINFO_TOKEN) {
      try {
        const d = await ipInfoLookup(ip);
        console.log("GEO LOCATION (ipinfo)");
        console.log(`  City    : ${d.city ?? "(unknown)"}`);
        console.log(`  Region  : ${d.region ?? "(unknown)"}`);
        console.log(`  Country : ${d.country ?? "(unknown)"}`);
        console.log(`  ISP     : ${d.org ?? "(unknown)"}`);
      } catch (e: any) {
        console.log(`GEO ERROR (ipinfo): ${e?.message ?? String(e)}`);

        // Fallback if IPinfo fails
        try {
          const g = await ipGeoFallback(ip);
          console.log("GEO LOCATION (fallback)");
          console.log(`  City    : ${g.city ?? "(unknown)"}`);
          console.log(`  Region  : ${g.region ?? "(unknown)"}`);
          console.log(`  Country : ${g.country ?? "(unknown)"}`);
          console.log(`  ISP     : ${g.connection?.isp ?? "(unknown)"}`);
        } catch (e2: any) {
          console.log(`GEO ERROR (fallback): ${e2?.message ?? String(e2)}`);
        }
      }
    } else {
      // No token, use fallback directly
      try {
        const g = await ipGeoFallback(ip);
        console.log("GEO LOCATION (fallback)");
        console.log(`  City    : ${g.city ?? "(unknown)"}`);
        console.log(`  Region  : ${g.region ?? "(unknown)"}`);
        console.log(`  Country : ${g.country ?? "(unknown)"}`);
        console.log(`  ISP     : ${g.connection?.isp ?? "(unknown)"}`);
      } catch (e2: any) {
        console.log(`GEO ERROR (fallback): ${e2?.message ?? String(e2)}`);
      }
    }
  } else {
    console.log("GEO LOCATION : (skipped — no IP found)");
  }

  console.log("-".repeat(70));

  // -------------------------------
  // HTTP REQUEST
  // -------------------------------
  try {
    const info = await httpRequest(url);
    console.log(`STATUS CODE   : ${info.status}`);
    console.log(`RESPONSE TIME : ${info.timeSec.toFixed(4)} seconds`);
    console.log(`FINAL URL     : ${info.finalUrl}`);
    console.log("HEADERS:");
    for (const [k, v] of Object.entries(info.headers)) {
      console.log(`  ${k}: ${v}`);
    }
  } catch (e: any) {
    console.log(`HTTP ERROR    : ${e?.message ?? String(e)}`);
  }

  console.log("-".repeat(70));

  // -------------------------------
  // SSL CERTIFICATE
  // -------------------------------
  try {
    const cert = await getTlsCert(host);

    console.log("SSL CERTIFICATE (selected fields):");
    console.log(`  subject        : ${JSON.stringify(cert.subject ?? {})}`);
    console.log(`  issuer         : ${JSON.stringify(cert.issuer ?? {})}`);
    console.log(`  valid_from     : ${cert.valid_from ?? ""}`);
    console.log(`  valid_to       : ${cert.valid_to ?? ""}`);
    console.log(`  fingerprint256 : ${cert.fingerprint256 ?? ""}`);
  } catch (e: any) {
    console.log(`SSL ERROR     : ${e?.message ?? String(e)}`);
  }

  console.log("-".repeat(70));

  // -------------------------------
  // WHOIS
  // -------------------------------
  try {
    const w = await whois(domainForWhois);
    console.log("WHOIS DATA:");
    for (const [k, v] of Object.entries(w ?? {})) {
      console.log(`  ${k}: ${Array.isArray(v) ? v.join(", ") : String(v)}`);
    }
  } catch (e: any) {
    console.log(`WHOIS ERROR   : ${e?.message ?? String(e)}`);
  }

  console.log("\n✔ Scan complete");
}

async function main() {
  const rl = readline.createInterface({ input, output });

  let target = (await rl.question("Enter website URL: ")).trim();
  target = normalizeUrl(target);

  await scanWebsite(target);

  await rl.question("\nPress ENTER to close...");
  rl.close();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
