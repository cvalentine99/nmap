/**
 * CVE Lookup — Search and browse Common Vulnerabilities and Exposures.
 * Integrates with NVD NIST API 2.0 via backend cve-service.
 * Supports search by CVE ID, keyword, CPE, and service+version.
 */
import { useState, useMemo, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Search,
  Shield,
  AlertTriangle,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Loader2,
  Database,
  Globe,
  Bug,
  Clock,
  ArrowLeft,
  Copy,
  CheckCircle,
  XCircle,
  Info,
  Server,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";

// ─── Severity Helpers ────────────────────────────────────────────

function getSeverityColor(severity: string | null | undefined): string {
  switch (severity?.toUpperCase()) {
    case "CRITICAL": return "text-red-400 bg-red-500/15 border-red-500/30";
    case "HIGH": return "text-orange-400 bg-orange-500/15 border-orange-500/30";
    case "MEDIUM": return "text-yellow-400 bg-yellow-500/15 border-yellow-500/30";
    case "LOW": return "text-green-400 bg-green-500/15 border-green-500/30";
    default: return "text-muted-foreground bg-muted/50 border-border/30";
  }
}

function getSeverityDotColor(severity: string | null | undefined): string {
  switch (severity?.toUpperCase()) {
    case "CRITICAL": return "bg-red-400";
    case "HIGH": return "bg-orange-400";
    case "MEDIUM": return "bg-yellow-400";
    case "LOW": return "bg-green-400";
    default: return "bg-muted-foreground";
  }
}

function getCvssBarColor(score: number | null | undefined): string {
  if (!score) return "bg-muted";
  if (score >= 9.0) return "bg-red-500";
  if (score >= 7.0) return "bg-orange-500";
  if (score >= 4.0) return "bg-yellow-500";
  return "bg-green-500";
}

function formatDate(date: string | Date | null | undefined): string {
  if (!date) return "N/A";
  return new Date(date).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

// ─── CVE Detail Panel ────────────────────────────────────────────

function CveDetailPanel({ cve, onBack }: { cve: any; onBack: () => void }) {
  const [copied, setCopied] = useState(false);

  const copyId = () => {
    navigator.clipboard.writeText(cve.cveId);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
    toast.success("CVE ID copied to clipboard");
  };

  const references = (cve.references || cve.rawJson?.cve?.references || []) as Array<{
    url: string;
    source?: string;
    tags?: string[];
  }>;

  const affectedProducts = (cve.affectedProducts || []) as Array<{
    criteria: string;
    versionStart?: string;
    versionEnd?: string;
  }>;

  const cweIds = (cve.cweIds || []) as string[];

  return (
    <motion.div
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: -20 }}
      className="space-y-4"
    >
      {/* Header */}
      <div className="flex items-start gap-3">
        <Button
          variant="ghost"
          size="sm"
          onClick={onBack}
          className="text-muted-foreground hover:text-foreground shrink-0 mt-0.5"
        >
          <ArrowLeft className="w-4 h-4 mr-1" />
          Back
        </Button>
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1">
            <h2 className="text-xl font-bold text-foreground font-[Outfit]">{cve.cveId}</h2>
            <Button variant="ghost" size="sm" onClick={copyId} className="h-6 w-6 p-0">
              {copied ? <CheckCircle className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5 text-muted-foreground" />}
            </Button>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            {cve.cvssV3Severity && (
              <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold border ${getSeverityColor(cve.cvssV3Severity)}`}>
                {cve.cvssV3Severity}
              </span>
            )}
            {cve.cvssV3Score != null && (
              <span className="text-sm text-muted-foreground">
                CVSS v3.1: <span className="text-foreground font-semibold">{cve.cvssV3Score.toFixed(1)}</span>
              </span>
            )}
            {cve.isKev && (
              <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold bg-red-500/20 text-red-300 border border-red-500/30">
                <AlertTriangle className="w-3 h-3 mr-1" />
                CISA KEV
              </span>
            )}
          </div>
        </div>
      </div>

      {/* CVSS Score Bar */}
      {cve.cvssV3Score != null && (
        <Card className="border-border/50 bg-card/80">
          <CardContent className="p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-muted-foreground">CVSS v3.1 Base Score</span>
              <span className="text-lg font-bold text-foreground">{cve.cvssV3Score.toFixed(1)} / 10.0</span>
            </div>
            <div className="w-full h-3 bg-background rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-500 ${getCvssBarColor(cve.cvssV3Score)}`}
                style={{ width: `${(cve.cvssV3Score / 10) * 100}%` }}
              />
            </div>
            {cve.cvssV3Vector && (
              <code className="block mt-2 text-[10px] text-muted-foreground font-mono break-all">
                {cve.cvssV3Vector}
              </code>
            )}
          </CardContent>
        </Card>
      )}

      {/* Description */}
      <Card className="border-border/50 bg-card/80">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Info className="w-4 h-4 text-cyan-400" />
            Description
          </CardTitle>
        </CardHeader>
        <CardContent className="pt-0">
          <p className="text-sm text-muted-foreground leading-relaxed">
            {cve.description || "No description available."}
          </p>
        </CardContent>
      </Card>

      {/* Dates & CWE */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <Card className="border-border/50 bg-card/80">
          <CardContent className="p-4">
            <div className="flex items-center gap-2 mb-2">
              <Clock className="w-4 h-4 text-purple-400" />
              <span className="text-xs font-semibold text-foreground">Timeline</span>
            </div>
            <div className="space-y-1.5 text-xs text-muted-foreground">
              <div className="flex justify-between">
                <span>Published</span>
                <span className="text-foreground">{formatDate(cve.publishedDate)}</span>
              </div>
              <div className="flex justify-between">
                <span>Last Modified</span>
                <span className="text-foreground">{formatDate(cve.lastModifiedDate)}</span>
              </div>
              {cve.fetchedAt && (
                <div className="flex justify-between">
                  <span>Cached</span>
                  <span className="text-foreground">{formatDate(cve.fetchedAt)}</span>
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        {cweIds.length > 0 && (
          <Card className="border-border/50 bg-card/80">
            <CardContent className="p-4">
              <div className="flex items-center gap-2 mb-2">
                <Bug className="w-4 h-4 text-orange-400" />
                <span className="text-xs font-semibold text-foreground">Weakness Types (CWE)</span>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {cweIds.map((cwe: string) => (
                  <a
                    key={cwe}
                    href={`https://cwe.mitre.org/data/definitions/${cwe.replace("CWE-", "")}.html`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono bg-orange-500/10 text-orange-400 border border-orange-500/20 hover:bg-orange-500/20 transition-colors"
                  >
                    {cwe}
                    <ExternalLink className="w-2.5 h-2.5 ml-1" />
                  </a>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </div>

      {/* Affected Products */}
      {affectedProducts.length > 0 && (
        <Card className="border-border/50 bg-card/80">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Server className="w-4 h-4 text-green-400" />
              Affected Products ({affectedProducts.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="space-y-1.5 max-h-[200px] overflow-y-auto">
              {affectedProducts.map((product: any, i: number) => (
                <div key={i} className="flex items-center gap-2 p-2 rounded bg-background/50 border border-border/20">
                  <code className="text-[10px] font-mono text-muted-foreground break-all flex-1">
                    {product.criteria}
                  </code>
                  {product.versionEnd && (
                    <span className="text-[10px] text-red-400 shrink-0">
                      &lt; {product.versionEnd}
                    </span>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* References */}
      {references.length > 0 && (
        <Card className="border-border/50 bg-card/80">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-400" />
              References ({references.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="space-y-1.5 max-h-[250px] overflow-y-auto">
              {references.map((ref: any, i: number) => (
                <a
                  key={i}
                  href={ref.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-start gap-2 p-2 rounded bg-background/50 border border-border/20 hover:border-cyan-500/30 hover:bg-cyan-500/5 transition-colors group"
                >
                  <ExternalLink className="w-3.5 h-3.5 text-muted-foreground group-hover:text-cyan-400 shrink-0 mt-0.5" />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-foreground truncate group-hover:text-cyan-400 transition-colors">
                      {ref.url}
                    </p>
                    {ref.tags && ref.tags.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-1">
                        {ref.tags.map((tag: string, j: number) => (
                          <span key={j} className="text-[9px] px-1.5 py-0.5 rounded bg-muted/50 text-muted-foreground">
                            {tag}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </a>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </motion.div>
  );
}

// ─── CVE Result Card ─────────────────────────────────────────────

function CveResultCard({ cve, onClick }: { cve: any; onClick: () => void }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 5 }}
      animate={{ opacity: 1, y: 0 }}
      className="cursor-pointer"
      onClick={onClick}
    >
      <Card className="border-border/50 bg-card/80 hover:border-purple-500/30 hover:bg-card/90 transition-all duration-200">
        <CardContent className="p-4">
          <div className="flex items-start justify-between gap-3">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1.5">
                <code className="text-sm font-mono font-semibold text-foreground">{cve.cveId}</code>
                {cve.cvssV3Severity && (
                  <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold border ${getSeverityColor(cve.cvssV3Severity)}`}>
                    {cve.cvssV3Severity}
                  </span>
                )}
                {cve.isKev && (
                  <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold bg-red-500/20 text-red-300 border border-red-500/30">
                    KEV
                  </span>
                )}
              </div>
              <p className="text-xs text-muted-foreground line-clamp-2 leading-relaxed">
                {cve.description || "No description available."}
              </p>
              <div className="flex items-center gap-3 mt-2 text-[10px] text-muted-foreground">
                {cve.cvssV3Score != null && (
                  <span className="flex items-center gap-1">
                    <span className={`w-1.5 h-1.5 rounded-full ${getSeverityDotColor(cve.cvssV3Severity)}`} />
                    CVSS {cve.cvssV3Score.toFixed(1)}
                  </span>
                )}
                {cve.publishedDate && (
                  <span>{formatDate(cve.publishedDate)}</span>
                )}
                {cve.cweIds && (cve.cweIds as string[]).length > 0 && (
                  <span>{(cve.cweIds as string[])[0]}</span>
                )}
              </div>
            </div>
            <div className="flex items-center gap-1 shrink-0">
              {cve.cvssV3Score != null && (
                <div className="flex flex-col items-center">
                  <span className={`text-lg font-bold ${
                    cve.cvssV3Score >= 9 ? "text-red-400" :
                    cve.cvssV3Score >= 7 ? "text-orange-400" :
                    cve.cvssV3Score >= 4 ? "text-yellow-400" :
                    "text-green-400"
                  }`}>
                    {cve.cvssV3Score.toFixed(1)}
                  </span>
                  <span className="text-[9px] text-muted-foreground">CVSS</span>
                </div>
              )}
            </div>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}

// ─── Service Lookup Tab ──────────────────────────────────────────

function ServiceLookupTab({ onSelectCve }: { onSelectCve: (cve: any) => void }) {
  // Read URL params for pre-populated service lookup
  const urlParams = typeof window !== "undefined" ? new URLSearchParams(window.location.search) : null;
  const [service, setService] = useState(urlParams?.get("service") || "");
  const [product, setProduct] = useState("");
  const [version, setVersion] = useState(urlParams?.get("version") || "");
  const [searchTriggered, setSearchTriggered] = useState(!!(urlParams?.get("service")));

  const serviceQuery = trpc.cve.forService.useQuery(
    { service, product: product || undefined, version: version || undefined },
    { enabled: searchTriggered && !!service }
  );

  const handleSearch = () => {
    if (!service.trim()) {
      toast.error("Please enter a service name");
      return;
    }
    setSearchTriggered(true);
  };

  return (
    <div className="space-y-4">
      <Card className="border-border/50 bg-card/80">
        <CardContent className="p-4">
          <p className="text-xs text-muted-foreground mb-3">
            Enter a service name and optional version to find known CVEs. Maps Nmap service names to CPE identifiers for NVD lookup.
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
            <Input
              placeholder="Service (e.g., openssh, nginx)"
              value={service}
              onChange={e => { setService(e.target.value); setSearchTriggered(false); }}
              className="bg-background/50 border-border/50 text-sm"
            />
            <Input
              placeholder="Product (optional)"
              value={product}
              onChange={e => { setProduct(e.target.value); setSearchTriggered(false); }}
              className="bg-background/50 border-border/50 text-sm"
            />
            <div className="flex gap-2">
              <Input
                placeholder="Version (e.g., 8.9)"
                value={version}
                onChange={e => { setVersion(e.target.value); setSearchTriggered(false); }}
                className="bg-background/50 border-border/50 text-sm"
                onKeyDown={e => e.key === "Enter" && handleSearch()}
              />
              <Button
                onClick={handleSearch}
                className="bg-purple-600 hover:bg-purple-700 text-white shrink-0"
                disabled={serviceQuery.isLoading}
              >
                {serviceQuery.isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
              </Button>
            </div>
          </div>
          {serviceQuery.data?.cpeName && (
            <div className="mt-2 flex items-center gap-2">
              <span className="text-[10px] text-muted-foreground">CPE:</span>
              <code className="text-[10px] font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded">
                {serviceQuery.data.cpeName}
              </code>
              {serviceQuery.data.fromCache && (
                <span className="text-[10px] text-green-400 flex items-center gap-1">
                  <Database className="w-3 h-3" /> Cached
                </span>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {serviceQuery.isLoading && (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 animate-spin text-purple-400 mr-2" />
          <span className="text-sm text-muted-foreground">Querying NVD API...</span>
        </div>
      )}

      {serviceQuery.data && !serviceQuery.isLoading && (
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs text-muted-foreground">
              {serviceQuery.data.cves.length} CVE{serviceQuery.data.cves.length !== 1 ? "s" : ""} found
            </span>
          </div>
          {serviceQuery.data.cves.length === 0 ? (
            <Card className="border-border/50 bg-card/80">
              <CardContent className="p-8 text-center">
                <CheckCircle className="w-8 h-8 text-green-400 mx-auto mb-2" />
                <p className="text-sm text-muted-foreground">No known CVEs found for this service/version.</p>
              </CardContent>
            </Card>
          ) : (
            serviceQuery.data.cves.map((cve: any) => (
              <CveResultCard
                key={cve.cveId}
                cve={cve}
                onClick={() => onSelectCve(cve)}
              />
            ))
          )}
        </div>
      )}
    </div>
  );
}

// ─── Main CVE Lookup Page ────────────────────────────────────────

export default function CveLookup() {
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [activeTab, setActiveTab] = useState("search");
  const [selectedCve, setSelectedCve] = useState<any>(null);
  const [searchTriggered, setSearchTriggered] = useState(false);
  const [urlParamsApplied, setUrlParamsApplied] = useState(false);

  // Read URL query params for pre-populated searches from ScanResults/HostDetail
  useEffect(() => {
    if (urlParamsApplied) return;
    const params = new URLSearchParams(window.location.search);
    const q = params.get("q");
    const service = params.get("service");
    const version = params.get("version");

    if (q) {
      // Direct CVE ID or keyword search
      setSearchQuery(q);
      setActiveTab("search");
      setSearchTriggered(true);
    } else if (service) {
      // Service lookup from scan results
      setActiveTab("service");
      // The ServiceLookupTab will read these from URL
    }
    setUrlParamsApplied(true);
  }, [urlParamsApplied]);

  // Search query
  const searchResults = trpc.cve.search.useQuery(
    {
      query: searchQuery,
      severity: severityFilter !== "all" ? severityFilter as any : undefined,
      resultsPerPage: 20,
    },
    { enabled: searchTriggered && !!searchQuery }
  );

  // Cached CVEs for browse tab
  const cachedCves = trpc.cve.cached.useQuery(
    { limit: 50, severity: severityFilter !== "all" ? severityFilter : undefined },
    { enabled: activeTab === "browse" }
  );

  const handleSearch = () => {
    if (!searchQuery.trim()) {
      toast.error("Please enter a search query");
      return;
    }
    setSearchTriggered(true);
  };

  const handleSelectCve = async (cve: any) => {
    // If we only have partial data (from service lookup), fetch full details
    if (!cve.description && cve.cveId) {
      setSelectedCve({ cveId: cve.cveId, loading: true });
      // The detail panel will show loading state
    }
    setSelectedCve(cve);
  };

  // If a CVE is selected, show detail panel
  if (selectedCve) {
    return (
      <CveDetailView
        cveId={selectedCve.cveId}
        initialData={selectedCve}
        onBack={() => setSelectedCve(null)}
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
      >
        <div className="flex items-center gap-3 mb-1">
          <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-red-500/10">
            <Shield className="w-5 h-5 text-red-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-foreground font-[Outfit]">CVE Lookup</h1>
            <p className="text-sm text-muted-foreground">
              Search the National Vulnerability Database for known vulnerabilities
            </p>
          </div>
        </div>
      </motion.div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-background/50 border border-border/50">
          <TabsTrigger value="search" className="data-[state=active]:bg-purple-500/20 data-[state=active]:text-purple-400">
            <Search className="w-3.5 h-3.5 mr-1.5" />
            Search
          </TabsTrigger>
          <TabsTrigger value="service" className="data-[state=active]:bg-green-500/20 data-[state=active]:text-green-400">
            <Server className="w-3.5 h-3.5 mr-1.5" />
            Service Lookup
          </TabsTrigger>
          <TabsTrigger value="browse" className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400">
            <Database className="w-3.5 h-3.5 mr-1.5" />
            Browse Cached
          </TabsTrigger>
        </TabsList>

        {/* Search Tab */}
        <TabsContent value="search" className="mt-4 space-y-4">
          <Card className="border-border/50 bg-card/80">
            <CardContent className="p-4">
              <div className="flex gap-2">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                  <Input
                    placeholder="Search by CVE ID (CVE-2021-44228), keyword (log4j), or CPE (cpe:2.3:a:apache:...)"
                    value={searchQuery}
                    onChange={e => { setSearchQuery(e.target.value); setSearchTriggered(false); }}
                    onKeyDown={e => e.key === "Enter" && handleSearch()}
                    className="pl-9 bg-background/50 border-border/50 text-sm"
                  />
                </div>
                <Select value={severityFilter} onValueChange={v => { setSeverityFilter(v); setSearchTriggered(false); }}>
                  <SelectTrigger className="w-[140px] bg-background/50 border-border/50 text-sm">
                    <SelectValue placeholder="Severity" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Severity</SelectItem>
                    <SelectItem value="CRITICAL">Critical</SelectItem>
                    <SelectItem value="HIGH">High</SelectItem>
                    <SelectItem value="MEDIUM">Medium</SelectItem>
                    <SelectItem value="LOW">Low</SelectItem>
                  </SelectContent>
                </Select>
                <Button
                  onClick={handleSearch}
                  className="bg-purple-600 hover:bg-purple-700 text-white"
                  disabled={searchResults.isLoading}
                >
                  {searchResults.isLoading ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    "Search"
                  )}
                </Button>
              </div>
              <div className="flex flex-wrap gap-2 mt-3">
                <span className="text-[10px] text-muted-foreground">Quick:</span>
                {["CVE-2021-44228", "CVE-2024-3094", "openssh", "apache http_server", "nginx"].map(q => (
                  <button
                    key={q}
                    onClick={() => { setSearchQuery(q); setSearchTriggered(false); }}
                    className="text-[10px] px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20 hover:bg-purple-500/20 transition-colors"
                  >
                    {q}
                  </button>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Results */}
          {searchResults.isLoading && (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-6 h-6 animate-spin text-purple-400 mr-2" />
              <span className="text-sm text-muted-foreground">Querying NVD API (may take a few seconds)...</span>
            </div>
          )}

          {searchResults.data && !searchResults.isLoading && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">
                  {searchResults.data.totalResults} result{searchResults.data.totalResults !== 1 ? "s" : ""} found
                </span>
              </div>
              {searchResults.data.results.length === 0 ? (
                <Card className="border-border/50 bg-card/80">
                  <CardContent className="p-8 text-center">
                    <XCircle className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
                    <p className="text-sm text-muted-foreground">No CVEs found matching your query.</p>
                  </CardContent>
                </Card>
              ) : (
                searchResults.data.results.map((cve: any) => (
                  <CveResultCard
                    key={cve.cveId}
                    cve={cve}
                    onClick={() => handleSelectCve(cve)}
                  />
                ))
              )}
            </div>
          )}

          {!searchTriggered && !searchResults.data && (
            <Card className="border-border/50 bg-card/80">
              <CardContent className="p-12 text-center">
                <Shield className="w-12 h-12 text-purple-400/30 mx-auto mb-3" />
                <h3 className="text-lg font-semibold text-foreground font-[Outfit] mb-1">Search the NVD</h3>
                <p className="text-sm text-muted-foreground max-w-md mx-auto">
                  Enter a CVE ID, keyword, or CPE string to search the National Vulnerability Database.
                  Results are cached locally for faster subsequent lookups.
                </p>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Service Lookup Tab */}
        <TabsContent value="service" className="mt-4">
          <ServiceLookupTab onSelectCve={handleSelectCve} />
        </TabsContent>

        {/* Browse Cached Tab */}
        <TabsContent value="browse" className="mt-4 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs text-muted-foreground">
              {cachedCves.data?.total || 0} cached CVE{(cachedCves.data?.total || 0) !== 1 ? "s" : ""}
            </span>
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="w-[140px] bg-background/50 border-border/50 text-sm">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severity</SelectItem>
                <SelectItem value="CRITICAL">Critical</SelectItem>
                <SelectItem value="HIGH">High</SelectItem>
                <SelectItem value="MEDIUM">Medium</SelectItem>
                <SelectItem value="LOW">Low</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {cachedCves.isLoading && (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-6 h-6 animate-spin text-cyan-400 mr-2" />
              <span className="text-sm text-muted-foreground">Loading cached CVEs...</span>
            </div>
          )}

          {cachedCves.data?.results.length === 0 && !cachedCves.isLoading && (
            <Card className="border-border/50 bg-card/80">
              <CardContent className="p-8 text-center">
                <Database className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
                <p className="text-sm text-muted-foreground">
                  No cached CVEs yet. Search for CVEs to populate the local cache.
                </p>
              </CardContent>
            </Card>
          )}

          {cachedCves.data?.results.map((cve: any) => (
            <CveResultCard
              key={cve.cveId}
              cve={cve}
              onClick={() => handleSelectCve(cve)}
            />
          ))}
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ─── CVE Detail View (fetches full data if needed) ───────────────

function CveDetailView({ cveId, initialData, onBack }: {
  cveId: string;
  initialData: any;
  onBack: () => void;
}) {
  const fullCve = trpc.cve.getById.useQuery(
    { cveId },
    { enabled: !initialData?.description }
  );

  const cve = initialData?.description ? initialData : fullCve.data || initialData;

  if (fullCve.isLoading && !initialData?.description) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="w-6 h-6 animate-spin text-purple-400 mr-2" />
        <span className="text-sm text-muted-foreground">Loading CVE details...</span>
      </div>
    );
  }

  return <CveDetailPanel cve={cve} onBack={onBack} />;
}
