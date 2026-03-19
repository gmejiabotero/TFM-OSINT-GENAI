// ============================================================================
// SCRIPT FINAL — CURADO TWITTER (N8N READY)
// Alineado con el schema unificado para RAG y el script CISA
// ============================================================================

// Helpers
function normalizeTimestamp(ts) {
  if (!ts) return new Date().toISOString();
  const parsed = new Date(ts);
  return isNaN(parsed.getTime()) ? new Date().toISOString() : parsed.toISOString();
}

// Extract CVEs
function extractCVEs(text) {
  const regex = /\bCVE-\d{4}-\d{4,7}\b/gi;
  return text.match(regex) || [];
}

// Extract IOC (IPs, domains, urls, hashes, emails)
function extractIndicators(text) {
  const indicators = [];

  const urlRegex = /\bhttps?:\/\/[^\s)]+/gi;
  const ipRegex = /\b\d{1,3}(\.\d{1,3}){3}\b/g;
  const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
  const hashRegex = /\b[A-Fa-f0-9]{32,64}\b/g;

  const urls = text.match(urlRegex) || [];
  const ips = text.match(ipRegex) || [];
  const emails = text.match(emailRegex) || [];
  const hashes = text.match(hashRegex) || [];

  // Filtering noisy URLs: remove twitter internal tracking, t.co, media, and CISA if present
  const blacklistPatterns = [
    "https://t.co/",
    "https://x.com/",
    "twitter.com",
    "pbs.twimg.com",
    "cisa.gov",            // internal to CISA, not an IOC
  ];

  urls.forEach(u => {
    if (!blacklistPatterns.some(b => u.includes(b))) {
      indicators.push({ type: "url", value: u });
    }
  });

  ips.forEach(ip => indicators.push({ type: "ip", value: ip }));
  emails.forEach(e => {
    // Filter CISA internal emails
    if (!e.endsWith("@cisa.gov")) {
      indicators.push({ type: "email", value: e });
    }
  });
  hashes.forEach(h => indicators.push({ type: "hash", value: h }));

  return indicators;
}

// Confidence scoring
function assignConfidence(indType, cves, isCTI) {
  if (isCTI) return 100; // Highest
  if (indType === "cve" && cves.length > 0) return 90;
  if (["ip", "domain", "hash", "url", "email"].includes(indType)) return 70;
  return 30; // informational
}

// MITRE ATT&CK TTP generator
function generateTTP(text, isCTI) {
  if (!isCTI) return [];

  const ttp = [];

  const map = [
    { pattern: /ransomware/i, t: "TA0040" },
    { pattern: /apt/i, t: "TA0010" },
    { pattern: /lateral/i, t: "T1021" },
    { pattern: /persistence/i, t: "T1053" },
    { pattern: /credential/i, t: "T1555" },
    { pattern: /c2|command and control/i, t: "T1071" },
    { pattern: /exfiltration/i, t: "T1041" }
  ];

  for (const entry of map) {
    if (entry.pattern.test(text)) ttp.push(entry.t);
  }

  if (ttp.length === 0) ttp.push("TA0001"); // default CTI baseline

  return ttp;
}

// ============================================================================
// PROCESS INPUT
// ============================================================================

const input = items[0].json.tweets;    // Using your real structure
const outputs = [];

for (const tw of input) {

  const text = tw.text || "";
  const created = tw.createdAt || null;
  const author = tw.author || {};

  // Extract CVEs
  const cves = extractCVEs(text);

  // Determine CTI classification
  const isCTI = /ransomware|apt|threat/i.test(tw.text);

  // Extract IOC
  const rawIndicators = extractIndicators(text);

  // Add CVE indicators
  cves.forEach(cve => rawIndicators.push({ type: "cve", value: cve }));

  // If nothing extracted, add informational indicator
  if (rawIndicators.length === 0) {
    rawIndicators.push({
      type: "informational",
      value: "no_ioc_detected"
    });
  }

  // Build final indicators array with confidence
  const indicators = rawIndicators.map(ind => ({
    type: ind.type,
    value: ind.value,
    confidence: assignConfidence(ind.type, cves, isCTI)
  }));

  // Generate TTPs
  const ttps = generateTTP(text, isCTI);

  // Build unified record
  const unified = {
    id: tw.id,
    source: "twitter",
    source_url: tw.url || tw.twitterUrl || null,

    ingest_timestamp: new Date().toISOString(),
    published_timestamp: normalizeTimestamp(created),

    title: null,
    text: text,
    summary: null,

    cves: cves,
    indicators: indicators,
    ttps: ttps,
    tags: ["osint", "threat", "twitter"],

    author: {
      name: author.name || null,
      id: author.id || null,
      type: author.type || "user",
      profile_url: author.url || null
    },

    references: (tw.entities?.urls || []).map(u => u.expanded_url).filter(Boolean),

    raw: {
      content: text
    },

    provenance: {
      ingested_from_file: "TWITTER_Extract.json",
      original_record_id: tw.id
    }
  };

  outputs.push({ json: unified });
}

return outputs;
