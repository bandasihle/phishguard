export const API_BASE = "http://localhost:5000";
const USE_MOCK = false;

export type FeatureRow = {
  name: string;
  label: string;
  value: -1 | 0 | 1;
  importance: number;
};

export type AnalysisResult = {
  url: string;
  verdict: "PHISHING" | "LEGITIMATE";
  risk_level: "HIGH" | "MEDIUM" | "LOW" | "SAFE";
  confidence: number;
  phishing_probability: number;
  legit_probability: number;
  red_flags: string[];
  feature_breakdown: FeatureRow[];
};

// --- Mock data (used when USE_MOCK = true) ---

const mockPhishing: AnalysisResult = {
  url: "http://paypal-secure.ru/login",
  verdict: "PHISHING",
  risk_level: "HIGH",
  confidence: 91.3,
  phishing_probability: 91.3,
  legit_probability: 8.7,
  red_flags: [
    "Hyphen in domain — common fake-domain pattern (e.g. paypal-secure.com)",
    "No HTTPS",
    "@ symbol present — browser ignores everything before it",
  ],
  feature_breakdown: [
    { name: "SSLfinal_State", label: "HTTPS / SSL", value: -1, importance: 0.34 },
    { name: "URL_of_Anchor", label: "Anchor Tag URLs", value: 0, importance: 0.27 },
    { name: "web_traffic", label: "Site Traffic Rank", value: 0, importance: 0.07 },
    { name: "having_Sub_Domain", label: "Subdomain Count", value: 1, importance: 0.06 },
    { name: "Prefix_Suffix", label: "Hyphen in Domain", value: -1, importance: 0.04 },
  ],
};

const mockLegit: AnalysisResult = {
  url: "https://www.github.com",
  verdict: "LEGITIMATE",
  risk_level: "SAFE",
  confidence: 96.4,
  phishing_probability: 3.6,
  legit_probability: 96.4,
  red_flags: [],
  feature_breakdown: [
    { name: "SSLfinal_State", label: "HTTPS / SSL", value: 1, importance: 0.34 },
    { name: "URL_of_Anchor", label: "Anchor Tag URLs", value: 1, importance: 0.27 },
    { name: "web_traffic", label: "Site Traffic Rank", value: 1, importance: 0.07 },
    { name: "having_Sub_Domain", label: "Subdomain Count", value: 1, importance: 0.06 },
    { name: "Prefix_Suffix", label: "Hyphen in Domain", value: 1, importance: 0.04 },
  ],
};

function pickMock(url: string): AnalysisResult {
  const u = url.toLowerCase();
  const looksPhishy =
    u.includes("-") ||
    u.includes("@") ||
    !u.startsWith("https") ||
    /\.(ru|tk|ml|ga|cf)(\/|$)/.test(u) ||
    /(paypal|bank|secure|login|verify|account|update)/.test(u.replace(/^https?:\/\//, ""));
  return { ...(looksPhishy ? mockPhishing : mockLegit), url };
}

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

// --- API calls ---

export async function analyzeUrl(url: string): Promise<AnalysisResult> {
  if (USE_MOCK) {
    await wait(700);
    return pickMock(url);
  }
  const res = await fetch(`${API_BASE}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  if (!res.ok) throw new Error("Analyze failed");
  return res.json();
}

export async function bulkAnalyze(urls: string[]): Promise<AnalysisResult[]> {
  if (USE_MOCK) {
    await wait(900);
    return urls.map((u) => pickMock(u));
  }
  const res = await fetch(`${API_BASE}/bulk`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ urls }),
  });
  if (!res.ok) throw new Error("Bulk analyze failed");
  const data = await res.json();
  return data.results;
}
