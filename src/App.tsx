import { useState } from "react";
import {
  Shield,
  ShieldCheck,
  ShieldX,
  ShieldAlert,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Loader2,
} from "lucide-react";
import { analyzeUrl, bulkAnalyze, type AnalysisResult } from "@/services/api";

export default function App() {
  const [url, setUrl] = useState("");
  const [bulkOpen, setBulkOpen] = useState(false);
  const [bulkText, setBulkText] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [bulkResults, setBulkResults] = useState<AnalysisResult[] | null>(null);

  async function handleAnalyze() {
    setError(null);

    if (bulkOpen) {
      const urls = bulkText
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean)
        .slice(0, 10);
      if (urls.length === 0) {
        setError("Enter at least one URL.");
        return;
      }
      setLoading(true);
      setBulkResults(null);
      try {
        const res = await bulkAnalyze(urls);
        setBulkResults(res);
      } catch {
        setError("Could not reach analysis server — is the backend running?");
      } finally {
        setLoading(false);
      }
      return;
    }

    if (!url.trim()) {
      setError("Please paste a URL to analyze.");
      return;
    }
    setLoading(true);
    setResult(null);
    try {
      const res = await analyzeUrl(url.trim());
      setResult(res);
    } catch {
      setError("Could not reach analysis server — is the backend running?");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Navbar */}
      <header className="border-b border-gray-100 bg-white">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand text-brand-foreground">
              <Shield className="h-5 w-5" strokeWidth={2.5} />
            </div>
            <span className="text-lg font-semibold tracking-tight">PhishGuard</span>
          </div>
          <span className="inline-flex items-center gap-1.5 rounded-full border border-gray-200 bg-gray-50 px-3 py-1 text-xs font-medium text-gray-600">
            <span className="h-1.5 w-1.5 rounded-full bg-success" />
            97.1% accuracy
          </span>
        </div>
      </header>

      <main className="mx-auto max-w-[800px] px-6 py-12">
        <div className="mb-8 text-center">
          <h1 className="text-3xl font-semibold tracking-tight text-gray-900">
            Is that link safe?
          </h1>
          <p className="mt-2 text-sm text-gray-500">
            Paste any URL and PhishGuard will analyze it for phishing signals.
          </p>
        </div>

        {/* Analyzer */}
        <section className="rounded-xl border border-gray-100 bg-white p-5 shadow-sm">
          {!bulkOpen ? (
            <div className="flex flex-col gap-3 sm:flex-row">
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleAnalyze()}
                placeholder="Paste a URL to analyze..."
                className="flex-1 rounded-lg border border-gray-200 bg-white px-4 py-3 text-sm text-gray-900 placeholder:text-gray-400 outline-none transition focus:border-brand focus:ring-2 focus:ring-brand/20"
              />
              <button
                onClick={handleAnalyze}
                disabled={loading}
                className="inline-flex items-center justify-center gap-2 rounded-lg bg-brand px-5 py-3 text-sm font-medium text-brand-foreground transition hover:opacity-90 disabled:opacity-60"
              >
                {loading && <Loader2 className="h-4 w-4 animate-spin" />}
                Analyze
              </button>
            </div>
          ) : (
            <div className="flex flex-col gap-3">
              <textarea
                value={bulkText}
                onChange={(e) => setBulkText(e.target.value)}
                placeholder={"https://example.com\nhttp://paypal-secure.ru/login\n..."}
                rows={6}
                className="w-full rounded-lg border border-gray-200 bg-white px-4 py-3 font-mono text-sm text-gray-900 placeholder:text-gray-400 outline-none transition focus:border-brand focus:ring-2 focus:ring-brand/20"
              />
              <div className="flex items-center justify-between">
                <span className="text-xs text-gray-500">One URL per line · max 10</span>
                <button
                  onClick={handleAnalyze}
                  disabled={loading}
                  className="inline-flex items-center justify-center gap-2 rounded-lg bg-brand px-5 py-2.5 text-sm font-medium text-brand-foreground transition hover:opacity-90 disabled:opacity-60"
                >
                  {loading && <Loader2 className="h-4 w-4 animate-spin" />}
                  Analyze all
                </button>
              </div>
            </div>
          )}

          <button
            onClick={() => {
              setBulkOpen((v) => !v);
              setError(null);
            }}
            className="mt-3 text-xs font-medium text-brand hover:underline"
          >
            {bulkOpen ? "← Single URL mode" : "Or try bulk analysis →"}
          </button>

          {error && (
            <p className="mt-3 rounded-md bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>
          )}
        </section>

        {/* Results */}
        <div className="mt-6">
          {loading && <SkeletonCard />}
          {!loading && !result && !bulkResults && !bulkOpen && <EmptyCard />}
          {!loading && !bulkOpen && result && <ResultCard result={result} />}
          {!loading && bulkOpen && bulkResults && <BulkResultsTable results={bulkResults} />}
        </div>
      </main>
    </div>
  );
}

function EmptyCard() {
  return (
    <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-gray-200 bg-white py-12 text-center">
      <Shield className="h-10 w-10 text-gray-300" strokeWidth={1.5} />
      <p className="mt-3 text-sm text-gray-500">Enter a URL above to check it</p>
    </div>
  );
}

function SkeletonCard() {
  return (
    <div className="overflow-hidden rounded-xl border border-gray-100 bg-white shadow-sm">
      <div className="h-12 animate-pulse bg-gray-100" />
      <div className="grid grid-cols-3 gap-4 p-6">
        {[0, 1, 2].map((i) => (
          <div key={i} className="space-y-2">
            <div className="h-3 w-24 animate-pulse rounded bg-gray-100" />
            <div className="h-8 w-16 animate-pulse rounded bg-gray-100" />
          </div>
        ))}
      </div>
    </div>
  );
}

function ResultCard({ result }: { result: AnalysisResult }) {
  const [open, setOpen] = useState(false);
  const isPhish = result.verdict === "PHISHING";

  return (
    <div className="overflow-hidden rounded-xl border border-gray-100 bg-white shadow-sm">
      {/* Verdict banner */}
      <div
        className={`flex items-center justify-between px-5 py-3 text-white ${
          isPhish ? "bg-red-600" : "bg-green-600"
        }`}
      >
        <div className="flex items-center gap-2.5">
          {isPhish ? (
            <ShieldX className="h-5 w-5" strokeWidth={2.5} />
          ) : (
            <ShieldCheck className="h-5 w-5" strokeWidth={2.5} />
          )}
          <span className="text-sm font-bold tracking-wide">
            {isPhish ? "PHISHING DETECTED" : "LEGITIMATE"}
          </span>
        </div>
        <span className="rounded-full bg-white/20 px-2.5 py-0.5 text-xs font-semibold tracking-wide">
          {result.risk_level}
        </span>
      </div>

      <div className="p-5">
        <p className="mb-5 truncate text-sm text-gray-500" title={result.url}>
          <span className="text-gray-400">URL: </span>
          <span className="font-mono text-gray-700">{result.url}</span>
        </p>

        {/* Stats */}
        <div className="grid grid-cols-3 gap-4">
          <Stat
            label="Phishing Probability"
            value={`${result.phishing_probability.toFixed(1)}%`}
            tone={result.phishing_probability > 50 ? "danger" : "default"}
          />
          <Stat label="Confidence" value={`${result.confidence.toFixed(1)}%`} tone="default" />
          <Stat
            label="Red Flags"
            value={String(result.red_flags.length)}
            tone={result.red_flags.length > 0 ? "warning" : "default"}
          />
        </div>

        {/* Red flags */}
        {result.red_flags.length > 0 && (
          <div className="mt-6 rounded-lg border border-red-100 bg-red-50/60 p-4">
            <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold text-red-900">
              <ShieldAlert className="h-4 w-4" /> Red Flags Detected
            </h3>
            <ul className="space-y-2">
              {result.red_flags.map((flag, i) => (
                <li key={i} className="flex items-start gap-2 text-sm text-red-800">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-red-500" />
                  <span>{flag}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Feature breakdown */}
        <div className="mt-6 rounded-lg border border-gray-100">
          <button
            onClick={() => setOpen((v) => !v)}
            className="flex w-full items-center justify-between px-4 py-3 text-sm font-medium text-gray-700 hover:bg-gray-50"
          >
            <span>Feature Analysis (top {result.feature_breakdown.length})</span>
            {open ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
          </button>
          {open && (
            <div className="border-t border-gray-100">
              <table className="w-full text-sm">
                <thead className="bg-gray-50 text-xs uppercase tracking-wide text-gray-500">
                  <tr>
                    <th className="px-4 py-2 text-left font-medium">Feature</th>
                    <th className="px-4 py-2 text-left font-medium">Signal</th>
                    <th className="px-4 py-2 text-left font-medium">Importance</th>
                  </tr>
                </thead>
                <tbody>
                  {result.feature_breakdown.map((f) => (
                    <tr key={f.name} className="border-t border-gray-100">
                      <td className="px-4 py-2.5 text-gray-700">{f.label}</td>
                      <td className="px-4 py-2.5">
                        <SignalBadge value={f.value} />
                      </td>
                      <td className="px-4 py-2.5">
                        <div className="flex items-center gap-2">
                          <div className="h-1.5 w-32 overflow-hidden rounded-full bg-gray-100">
                            <div
                              className="h-full rounded-full bg-brand"
                              style={{ width: `${Math.min(100, f.importance * 100)}%` }}
                            />
                          </div>
                          <span className="text-xs text-gray-500">
                            {(f.importance * 100).toFixed(0)}%
                          </span>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function Stat({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone: "default" | "danger" | "warning";
}) {
  const color =
    tone === "danger" ? "text-red-600" : tone === "warning" ? "text-amber-600" : "text-gray-900";
  return (
    <div className="rounded-lg border border-gray-100 bg-gray-50/60 p-4">
      <div className="text-xs font-medium uppercase tracking-wide text-gray-500">{label}</div>
      <div className={`mt-1 text-2xl font-semibold tabular-nums ${color}`}>{value}</div>
    </div>
  );
}

function SignalBadge({ value }: { value: -1 | 0 | 1 }) {
  if (value === 1)
    return (
      <span className="inline-flex rounded-md bg-green-50 px-2 py-0.5 text-xs font-medium text-green-700">
        Safe
      </span>
    );
  if (value === -1)
    return (
      <span className="inline-flex rounded-md bg-red-50 px-2 py-0.5 text-xs font-medium text-red-700">
        Phishing
      </span>
    );
  return (
    <span className="inline-flex rounded-md bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-600">
      Neutral
    </span>
  );
}

function BulkResultsTable({ results }: { results: AnalysisResult[] }) {
  return (
    <div className="overflow-hidden rounded-xl border border-gray-100 bg-white shadow-sm">
      <div className="border-b border-gray-100 px-5 py-3 text-sm font-semibold text-gray-700">
        Bulk results ({results.length})
      </div>
      <table className="w-full text-sm">
        <thead className="bg-gray-50 text-xs uppercase tracking-wide text-gray-500">
          <tr>
            <th className="px-5 py-2.5 text-left font-medium">URL</th>
            <th className="px-5 py-2.5 text-left font-medium">Verdict</th>
            <th className="px-5 py-2.5 text-right font-medium">Phishing %</th>
          </tr>
        </thead>
        <tbody>
          {results.map((r, i) => {
            const isPhish = r.verdict === "PHISHING";
            return (
              <tr key={i} className="border-t border-gray-100">
                <td className="max-w-[380px] px-5 py-3">
                  <div title={r.url} className="truncate font-mono text-xs text-gray-700">
                    {r.url}
                  </div>
                </td>
                <td className="px-5 py-3">
                  <span
                    className={`inline-flex rounded-md px-2 py-0.5 text-xs font-semibold ${
                      isPhish ? "bg-red-50 text-red-700" : "bg-green-50 text-green-700"
                    }`}
                  >
                    {r.verdict}
                  </span>
                </td>
                <td
                  className={`px-5 py-3 text-right tabular-nums ${
                    isPhish ? "text-red-600" : "text-gray-700"
                  }`}
                >
                  {r.phishing_probability.toFixed(1)}%
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
