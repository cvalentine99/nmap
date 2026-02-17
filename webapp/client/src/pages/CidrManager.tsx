/*
 * CidrManager — CIDR Scope Manager
 * Spectra Command Dark Theme
 * Allowlist/denylist manager for scan scope enforcement with CIDR validation
 */
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import {
  Shield,
  Plus,
  Trash2,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Network,
  Lock,
  Unlock,
  Search,
  Download,
  Upload,
  RefreshCw,
  Info,
  Globe,
} from "lucide-react";
import { toast } from "sonner";
import { motion, AnimatePresence } from "framer-motion";

interface CidrEntry {
  id: string;
  cidr: string;
  label: string;
  type: "allow" | "deny";
  hosts: number;
  addedBy: string;
  addedAt: string;
  enabled: boolean;
}

const initialEntries: CidrEntry[] = [
  { id: "1", cidr: "192.168.1.0/24", label: "Corporate LAN", type: "allow", hosts: 254, addedBy: "admin", addedAt: "2026-02-10", enabled: true },
  { id: "2", cidr: "10.0.0.0/16", label: "Internal Network", type: "allow", hosts: 65534, addedBy: "admin", addedAt: "2026-02-10", enabled: true },
  { id: "3", cidr: "172.16.0.0/12", label: "Private Range", type: "allow", hosts: 1048574, addedBy: "admin", addedAt: "2026-02-10", enabled: false },
  { id: "4", cidr: "192.168.1.1/32", label: "Gateway (Protected)", type: "deny", hosts: 1, addedBy: "admin", addedAt: "2026-02-11", enabled: true },
  { id: "5", cidr: "10.0.0.0/8", label: "Production Servers", type: "deny", hosts: 16777214, addedBy: "security", addedAt: "2026-02-12", enabled: true },
  { id: "6", cidr: "192.168.100.0/24", label: "Guest WiFi", type: "deny", hosts: 254, addedBy: "admin", addedAt: "2026-02-14", enabled: true },
];

function validateCidr(input: string): { valid: boolean; error?: string } {
  const cidrRegex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/;
  const match = input.match(cidrRegex);
  if (!match) return { valid: false, error: "Invalid CIDR format. Use x.x.x.x/y" };

  const octets = [parseInt(match[1]), parseInt(match[2]), parseInt(match[3]), parseInt(match[4])];
  const prefix = parseInt(match[5]);

  for (const octet of octets) {
    if (octet > 255) return { valid: false, error: "Octet value must be 0-255" };
  }
  if (prefix > 32) return { valid: false, error: "Prefix length must be 0-32" };

  return { valid: true };
}

function calculateHosts(cidr: string): number {
  const prefix = parseInt(cidr.split("/")[1]);
  if (prefix === 32) return 1;
  if (prefix === 31) return 2;
  return Math.pow(2, 32 - prefix) - 2;
}

function checkConflicts(newCidr: string, entries: CidrEntry[]): CidrEntry[] {
  // Simple overlap check - in production this would be proper CIDR math
  const newBase = newCidr.split("/")[0].split(".").slice(0, 3).join(".");
  return entries.filter((e) => {
    const existingBase = e.cidr.split("/")[0].split(".").slice(0, 3).join(".");
    return existingBase === newBase && e.cidr !== newCidr;
  });
}

export default function CidrManager() {
  const [entries, setEntries] = useState<CidrEntry[]>(initialEntries);
  const utils = trpc.useUtils();
  const { data: cidrRules } = trpc.cidr.list.useQuery();
  const createRule = trpc.cidr.create.useMutation({ onSuccess: () => utils.cidr.list.invalidate() });
  const updateRule = trpc.cidr.update.useMutation({ onSuccess: () => utils.cidr.list.invalidate() });
  const deleteRule = trpc.cidr.delete.useMutation({ onSuccess: () => utils.cidr.list.invalidate() });

  // Merge real data with local state
  const effectiveEntries = useMemo(() => {
    if (cidrRules && cidrRules.length > 0) {
      return cidrRules.map((r: any) => ({
        id: String(r.id),
        cidr: r.cidr,
        label: r.label || "",
        type: r.type as "allow" | "deny",
        hosts: calculateHosts(r.cidr),
        addedBy: "user",
        addedAt: new Date(r.createdAt).toLocaleDateString(),
        enabled: r.enabled,
      }));
    }
    return entries;
  }, [cidrRules, entries]);
  const [newCidr, setNewCidr] = useState("");
  const [newLabel, setNewLabel] = useState("");
  const [newType, setNewType] = useState<"allow" | "deny">("allow");
  const [searchQuery, setSearchQuery] = useState("");
  const [filterType, setFilterType] = useState<"all" | "allow" | "deny">("all");
  const [validationResult, setValidationResult] = useState<{ valid: boolean; error?: string } | null>(null);

  const filteredEntries = useMemo(() => {
    return effectiveEntries.filter((e) => {
      const matchesSearch =
        !searchQuery ||
        e.cidr.includes(searchQuery) ||
        e.label.toLowerCase().includes(searchQuery.toLowerCase());
      const matchesType = filterType === "all" || e.type === filterType;
      return matchesSearch && matchesType;
    });
  }, [effectiveEntries, searchQuery, filterType]);

  const allowCount = effectiveEntries.filter((e) => e.type === "allow").length;
  const denyCount = effectiveEntries.filter((e) => e.type === "deny").length;
  const totalHosts = effectiveEntries.filter((e) => e.type === "allow" && e.enabled).reduce((s, e) => s + e.hosts, 0);

  const handleCidrChange = (value: string) => {
    setNewCidr(value);
    if (value.length > 3) {
      setValidationResult(validateCidr(value));
    } else {
      setValidationResult(null);
    }
  };

  const addEntry = () => {
    const validation = validateCidr(newCidr);
    if (!validation.valid) {
      toast.error(validation.error || "Invalid CIDR");
      return;
    }

    const conflicts = checkConflicts(newCidr, entries);
    if (conflicts.length > 0) {
      toast.warning(`Potential overlap with: ${conflicts.map((c) => c.cidr).join(", ")}`);
    }

    const newEntry: CidrEntry = {
      id: Date.now().toString(),
      cidr: newCidr,
      label: newLabel || "Unnamed Range",
      type: newType,
      hosts: calculateHosts(newCidr),
      addedBy: "admin",
      addedAt: new Date().toISOString().split("T")[0],
      enabled: true,
    };

    setEntries((prev) => [...prev, newEntry]);
    // Persist to database
    createRule.mutate({ cidr: newCidr, label: newLabel || "Unnamed Range", type: newType, enabled: true });
    setNewCidr("");
    setNewLabel("");
    setValidationResult(null);
    toast.success(`${newType === "allow" ? "Allowlist" : "Denylist"} entry added`);
  };

  const removeEntry = (id: string) => {
    setEntries((prev) => prev.filter((e) => e.id !== id));
    const numId = parseInt(id);
    if (!isNaN(numId)) deleteRule.mutate({ id: numId });
    toast.success("Entry removed");
  };

  const toggleEntry = (id: string) => {
    const entry = effectiveEntries.find(e => e.id === id);
    setEntries((prev) =>
      prev.map((e) => (e.id === id ? { ...e, enabled: !e.enabled } : e))
    );
    const numId = parseInt(id);
    if (!isNaN(numId) && entry) updateRule.mutate({ id: numId, enabled: !entry.enabled });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}>
        <div className="flex items-center gap-2 mb-1">
          <Shield className="w-4 h-4 text-green-400" />
          <span className="text-[11px] font-semibold tracking-[0.2em] uppercase text-green-400">
            Scope Control
          </span>
        </div>
        <h2 className="text-2xl font-bold text-foreground font-[Outfit]">CIDR Scope Manager</h2>
        <p className="text-sm text-muted-foreground mt-1">
          Manage scan scope enforcement with allowlist and denylist rules. All scans are validated against these rules before execution.
        </p>
      </motion.div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: "Allowlist Rules", value: allowCount, icon: Unlock, color: "text-green-400" },
          { label: "Denylist Rules", value: denyCount, icon: Lock, color: "text-red-400" },
          { label: "Total Entries", value: entries.length, icon: Network, color: "text-cyan-400" },
          { label: "Scannable Hosts", value: totalHosts.toLocaleString(), icon: Globe, color: "text-purple-400" },
        ].map((stat, i) => {
          const Icon = stat.icon;
          return (
            <motion.div
              key={stat.label}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3, delay: i * 0.05 }}
            >
              <Card className="border-border/30 bg-card/60">
                <CardContent className="p-3">
                  <div className="flex items-center gap-1.5 mb-1">
                    <Icon className={`w-3 h-3 ${stat.color}`} />
                    <span className="text-[10px] text-muted-foreground uppercase">{stat.label}</span>
                  </div>
                  <p className="text-lg font-bold font-mono text-foreground">{stat.value}</p>
                </CardContent>
              </Card>
            </motion.div>
          );
        })}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Add New Entry */}
        <div className="xl:col-span-1">
          <Card className="border-border/50 bg-card/80">
            <CardHeader className="pb-3">
              <div className="flex items-center gap-2">
                <Plus className="w-4 h-4 text-cyan-400" />
                <CardTitle className="text-sm font-semibold font-[Outfit]">Add CIDR Rule</CardTitle>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* CIDR Input */}
              <div className="space-y-1.5">
                <Label className="text-xs text-muted-foreground">CIDR Range</Label>
                <div className="relative">
                  <Input
                    placeholder="192.168.1.0/24"
                    value={newCidr}
                    onChange={(e) => handleCidrChange(e.target.value)}
                    className={`font-mono text-sm bg-input/50 border-border/50 pr-8 ${
                      validationResult
                        ? validationResult.valid
                          ? "border-green-500/50"
                          : "border-red-500/50"
                        : ""
                    }`}
                  />
                  {validationResult && (
                    <div className="absolute right-2.5 top-1/2 -translate-y-1/2">
                      {validationResult.valid ? (
                        <CheckCircle2 className="w-4 h-4 text-green-400" />
                      ) : (
                        <XCircle className="w-4 h-4 text-red-400" />
                      )}
                    </div>
                  )}
                </div>
                {validationResult && !validationResult.valid && (
                  <p className="text-[10px] text-red-400">{validationResult.error}</p>
                )}
                {validationResult?.valid && newCidr && (
                  <p className="text-[10px] text-green-400">
                    {calculateHosts(newCidr).toLocaleString()} hosts in range
                  </p>
                )}
              </div>

              {/* Label */}
              <div className="space-y-1.5">
                <Label className="text-xs text-muted-foreground">Label</Label>
                <Input
                  placeholder="e.g., Corporate LAN"
                  value={newLabel}
                  onChange={(e) => setNewLabel(e.target.value)}
                  className="text-sm bg-input/50 border-border/50"
                />
              </div>

              {/* Type toggle */}
              <div className="space-y-1.5">
                <Label className="text-xs text-muted-foreground">Rule Type</Label>
                <div className="flex gap-2">
                  <Button
                    variant={newType === "allow" ? "default" : "outline"}
                    size="sm"
                    className={`flex-1 gap-1.5 text-xs ${
                      newType === "allow"
                        ? "bg-green-600 hover:bg-green-700 text-white"
                        : "border-border/50"
                    }`}
                    onClick={() => setNewType("allow")}
                  >
                    <Unlock className="w-3 h-3" />
                    Allowlist
                  </Button>
                  <Button
                    variant={newType === "deny" ? "default" : "outline"}
                    size="sm"
                    className={`flex-1 gap-1.5 text-xs ${
                      newType === "deny"
                        ? "bg-red-600 hover:bg-red-700 text-white"
                        : "border-border/50"
                    }`}
                    onClick={() => setNewType("deny")}
                  >
                    <Lock className="w-3 h-3" />
                    Denylist
                  </Button>
                </div>
              </div>

              <Button
                className="w-full bg-cyan-600 hover:bg-cyan-700 text-white gap-1.5 text-xs"
                onClick={addEntry}
                disabled={!newCidr || (validationResult !== null && !validationResult.valid)}
              >
                <Plus className="w-3 h-3" />
                Add Rule
              </Button>

              <Separator className="bg-border/30" />

              {/* Quick actions */}
              <div className="space-y-2">
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Quick Actions</p>
                <Button
                  variant="outline"
                  size="sm"
                  className="w-full justify-start gap-2 text-xs border-border/40"
                  onClick={() => toast("Feature coming soon", { description: "Import CIDR list from file" })}
                >
                  <Upload className="w-3 h-3" />
                  Import from File
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="w-full justify-start gap-2 text-xs border-border/40"
                  onClick={() => toast("Feature coming soon", { description: "Export CIDR rules" })}
                >
                  <Download className="w-3 h-3" />
                  Export Rules
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="w-full justify-start gap-2 text-xs border-border/40"
                  onClick={() => toast("Feature coming soon", { description: "Validate all rules for conflicts" })}
                >
                  <RefreshCw className="w-3 h-3" />
                  Check Conflicts
                </Button>
              </div>

              {/* Info box */}
              <div className="p-3 rounded-md bg-cyan-500/5 border border-cyan-500/20">
                <div className="flex gap-2">
                  <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                  <div>
                    <p className="text-xs text-cyan-400 font-medium">Scope Enforcement</p>
                    <p className="text-[10px] text-muted-foreground mt-0.5">
                      Denylist rules take priority over allowlist. A target must match at least one allowlist rule and no denylist rules to be scanned.
                    </p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Entry List */}
        <div className="xl:col-span-2">
          {/* Search & Filter */}
          <div className="flex items-center gap-3 mb-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Search CIDR or label..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9 bg-input/50 border-border/50 text-sm"
              />
            </div>
            <div className="flex gap-1">
              {(["all", "allow", "deny"] as const).map((type) => (
                <Button
                  key={type}
                  variant={filterType === type ? "default" : "outline"}
                  size="sm"
                  className={`text-xs capitalize ${
                    filterType === type
                      ? type === "allow"
                        ? "bg-green-600 hover:bg-green-700"
                        : type === "deny"
                        ? "bg-red-600 hover:bg-red-700"
                        : ""
                      : "border-border/50"
                  }`}
                  onClick={() => setFilterType(type)}
                >
                  {type}
                </Button>
              ))}
            </div>
          </div>

          {/* Entries */}
          <div className="space-y-2">
            <AnimatePresence mode="popLayout">
              {filteredEntries.map((entry, i) => (
                <motion.div
                  key={entry.id}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -8 }}
                  transition={{ duration: 0.2, delay: i * 0.02 }}
                >
                  <Card className={`border-border/30 bg-card/60 ${!entry.enabled ? "opacity-50" : ""} transition-opacity`}>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-4">
                        {/* Type badge */}
                        <div className={`shrink-0 p-2 rounded-md ${
                          entry.type === "allow"
                            ? "bg-green-500/10 border border-green-500/20"
                            : "bg-red-500/10 border border-red-500/20"
                        }`}>
                          {entry.type === "allow" ? (
                            <Unlock className="w-4 h-4 text-green-400" />
                          ) : (
                            <Lock className="w-4 h-4 text-red-400" />
                          )}
                        </div>

                        {/* Info */}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-0.5">
                            <code className="text-sm font-mono text-foreground font-medium">{entry.cidr}</code>
                            <Badge
                              className={`text-[9px] capitalize ${
                                entry.type === "allow"
                                  ? "bg-green-500/10 text-green-400 border-green-500/30"
                                  : "bg-red-500/10 text-red-400 border-red-500/30"
                              } border`}
                            >
                              {entry.type}
                            </Badge>
                          </div>
                          <p className="text-xs text-muted-foreground">{entry.label}</p>
                          <div className="flex items-center gap-3 mt-1 text-[10px] text-muted-foreground">
                            <span>{entry.hosts.toLocaleString()} hosts</span>
                            <span>by {entry.addedBy}</span>
                            <span>{entry.addedAt}</span>
                          </div>
                        </div>

                        {/* Actions */}
                        <div className="flex items-center gap-3 shrink-0">
                          <Switch
                            checked={entry.enabled}
                            onCheckedChange={() => toggleEntry(entry.id)}
                          />
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-8 w-8 p-0 text-muted-foreground hover:text-red-400"
                            onClick={() => removeEntry(entry.id)}
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </Button>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </motion.div>
              ))}
            </AnimatePresence>

            {filteredEntries.length === 0 && (
              <div className="text-center py-12 text-muted-foreground">
                <Shield className="w-8 h-8 mx-auto mb-2 opacity-30" />
                <p className="text-sm">No matching rules found</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
