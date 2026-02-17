/**
 * Alerts — CVE Alert Center
 * Notification center with alert history, rule management, and severity filtering.
 */
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Bell,
  BellRing,
  Shield,
  AlertTriangle,
  AlertOctagon,
  CheckCircle,
  XCircle,
  Eye,
  Search,
  Plus,
  Trash2,
  Filter,
  Clock,
  Target,
  Server,
  Bug,
  ChevronRight,
  Info,
} from "lucide-react";
import { toast } from "sonner";
import { motion } from "framer-motion";
import { Link } from "wouter";

// Severity config
const SEVERITY_CONFIG: Record<string, { color: string; bg: string; border: string; icon: typeof AlertOctagon }> = {
  critical: { color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/30", icon: AlertOctagon },
  high: { color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30", icon: AlertTriangle },
  medium: { color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30", icon: Info },
  low: { color: "text-green-400", bg: "bg-green-500/10", border: "border-green-500/30", icon: Shield },
  info: { color: "text-cyan-400", bg: "bg-cyan-500/10", border: "border-cyan-500/30", icon: Info },
};

const STATUS_CONFIG: Record<string, { color: string; bg: string; label: string }> = {
  new: { color: "text-red-400", bg: "bg-red-500/20", label: "New" },
  acknowledged: { color: "text-yellow-400", bg: "bg-yellow-500/20", label: "Acknowledged" },
  investigating: { color: "text-purple-400", bg: "bg-purple-500/20", label: "Investigating" },
  resolved: { color: "text-green-400", bg: "bg-green-500/20", label: "Resolved" },
  dismissed: { color: "text-muted-foreground", bg: "bg-muted/50", label: "Dismissed" },
};

function SeverityBadge({ severity }: { severity: string }) {
  const config = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.info;
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold border ${config.bg} ${config.color} ${config.border}`}>
      {severity.toUpperCase()}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const config = STATUS_CONFIG[status] || STATUS_CONFIG.new;
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium ${config.bg} ${config.color}`}>
      {config.label}
    </span>
  );
}

function AlertStatsCards() {
  const { data: stats } = trpc.alert.stats.useQuery();

  const cards = [
    { label: "Total Alerts", value: stats?.total || 0, color: "text-purple-400", bg: "bg-purple-500/10", icon: Bell },
    { label: "New", value: stats?.newCount || 0, color: "text-red-400", bg: "bg-red-500/10", icon: BellRing },
    { label: "Critical", value: stats?.criticalCount || 0, color: "text-red-400", bg: "bg-red-500/10", icon: AlertOctagon },
    { label: "High", value: stats?.highCount || 0, color: "text-orange-400", bg: "bg-orange-500/10", icon: AlertTriangle },
    { label: "Acknowledged", value: stats?.acknowledgedCount || 0, color: "text-yellow-400", bg: "bg-yellow-500/10", icon: Eye },
    { label: "Resolved", value: stats?.resolvedCount || 0, color: "text-green-400", bg: "bg-green-500/10", icon: CheckCircle },
  ];

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
      {cards.map((card, i) => {
        const Icon = card.icon;
        return (
          <motion.div
            key={card.label}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3, delay: i * 0.05 }}
          >
            <Card className="border-border/50 bg-card/80 backdrop-blur-sm">
              <CardContent className="p-3">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[11px] text-muted-foreground">{card.label}</span>
                  <div className={`w-6 h-6 rounded-md flex items-center justify-center ${card.bg}`}>
                    <Icon className={`w-3.5 h-3.5 ${card.color}`} />
                  </div>
                </div>
                <div className="text-xl font-bold text-foreground font-[Outfit]">{card.value}</div>
              </CardContent>
            </Card>
          </motion.div>
        );
      })}
    </div>
  );
}

function AlertHistory() {
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedAlerts, setSelectedAlerts] = useState<Set<number>>(new Set());

  const { data: alertList, refetch } = trpc.alert.list.useQuery({
    limit: 100,
    ...(severityFilter !== "all" ? { severity: severityFilter as any } : {}),
    ...(statusFilter !== "all" ? { status: statusFilter as any } : {}),
  });

  const updateStatus = trpc.alert.updateStatus.useMutation({
    onSuccess: () => {
      refetch();
      toast.success("Alert status updated");
    },
  });

  const bulkDismiss = trpc.alert.bulkDismiss.useMutation({
    onSuccess: (data) => {
      refetch();
      setSelectedAlerts(new Set());
      toast.success(`${data.dismissed} alerts dismissed`);
    },
  });

  const filteredAlerts = useMemo(() => {
    if (!alertList) return [];
    if (!searchQuery) return alertList;
    const q = searchQuery.toLowerCase();
    return alertList.filter(
      (a: any) =>
        a.title?.toLowerCase().includes(q) ||
        a.cveId?.toLowerCase().includes(q) ||
        a.targetIp?.toLowerCase().includes(q) ||
        a.service?.toLowerCase().includes(q)
    );
  }, [alertList, searchQuery]);

  const toggleSelect = (id: number) => {
    const next = new Set(selectedAlerts);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setSelectedAlerts(next);
  };

  const selectAll = () => {
    if (selectedAlerts.size === filteredAlerts.length) {
      setSelectedAlerts(new Set());
    } else {
      setSelectedAlerts(new Set(filteredAlerts.map((a: any) => a.id)));
    }
  };

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            placeholder="Search alerts by CVE, IP, service..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-9 bg-background/50 border-border/50"
          />
        </div>

        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-[140px] bg-background/50 border-border/50">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severity</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>

        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-[160px] bg-background/50 border-border/50">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Status</SelectItem>
            <SelectItem value="new">New</SelectItem>
            <SelectItem value="acknowledged">Acknowledged</SelectItem>
            <SelectItem value="investigating">Investigating</SelectItem>
            <SelectItem value="resolved">Resolved</SelectItem>
            <SelectItem value="dismissed">Dismissed</SelectItem>
          </SelectContent>
        </Select>

        {selectedAlerts.size > 0 && (
          <Button
            variant="outline"
            size="sm"
            className="border-red-500/30 text-red-400 hover:bg-red-500/10"
            onClick={() => bulkDismiss.mutate({ ids: Array.from(selectedAlerts) })}
          >
            <XCircle className="w-3.5 h-3.5 mr-1" />
            Dismiss ({selectedAlerts.size})
          </Button>
        )}
      </div>

      {/* Alert List */}
      <div className="space-y-2">
        {filteredAlerts.length === 0 ? (
          <Card className="border-border/50 bg-card/80">
            <CardContent className="py-12 text-center">
              <Bell className="w-10 h-10 text-muted-foreground mx-auto mb-3 opacity-40" />
              <p className="text-sm text-muted-foreground">No alerts found</p>
              <p className="text-xs text-muted-foreground mt-1">
                Alerts will appear here when scans discover vulnerabilities matching your rules.
              </p>
            </CardContent>
          </Card>
        ) : (
          <>
            {/* Select all header */}
            <div className="flex items-center gap-2 px-2 text-xs text-muted-foreground">
              <input
                type="checkbox"
                checked={selectedAlerts.size === filteredAlerts.length && filteredAlerts.length > 0}
                onChange={selectAll}
                className="rounded border-border/50"
              />
              <span>{filteredAlerts.length} alert{filteredAlerts.length !== 1 ? "s" : ""}</span>
            </div>

            {filteredAlerts.map((alert: any) => {
              const sevConfig = SEVERITY_CONFIG[alert.severity] || SEVERITY_CONFIG.info;
              const SevIcon = sevConfig.icon;

              return (
                <motion.div
                  key={alert.id}
                  initial={{ opacity: 0, x: -5 }}
                  animate={{ opacity: 1, x: 0 }}
                  className={`rounded-lg border transition-all ${
                    alert.status === "new"
                      ? `${sevConfig.border} ${sevConfig.bg}`
                      : "border-border/30 bg-card/60"
                  }`}
                >
                  <div className="flex items-start gap-3 p-4">
                    <input
                      type="checkbox"
                      checked={selectedAlerts.has(alert.id)}
                      onChange={() => toggleSelect(alert.id)}
                      className="mt-1 rounded border-border/50"
                    />
                    <div className={`mt-0.5 p-1.5 rounded-md ${sevConfig.bg}`}>
                      <SevIcon className={`w-4 h-4 ${sevConfig.color}`} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <span className="text-sm font-medium text-foreground">{alert.title}</span>
                        <SeverityBadge severity={alert.severity} />
                        <StatusBadge status={alert.status} />
                      </div>

                      {alert.message && (
                        <p className="text-xs text-muted-foreground mb-2 line-clamp-2 font-mono">
                          {alert.message.replace(/\*\*/g, "").slice(0, 200)}
                        </p>
                      )}

                      <div className="flex items-center gap-4 text-[11px] text-muted-foreground flex-wrap">
                        {alert.cveId && (
                          <Link href={`/tools/cve?cveId=${alert.cveId}`}>
                            <span className="flex items-center gap-1 text-cyan-400 hover:underline cursor-pointer">
                              <Bug className="w-3 h-3" /> {alert.cveId}
                            </span>
                          </Link>
                        )}
                        {alert.targetIp && (
                          <span className="flex items-center gap-1">
                            <Server className="w-3 h-3" /> {alert.targetIp}
                            {alert.portNumber ? `:${alert.portNumber}` : ""}
                          </span>
                        )}
                        {alert.service && (
                          <span className="flex items-center gap-1">
                            <Target className="w-3 h-3" /> {alert.service}
                            {alert.serviceVersion ? ` ${alert.serviceVersion}` : ""}
                          </span>
                        )}
                        {alert.cvssScore && (
                          <span className={`font-semibold ${
                            alert.cvssScore >= 9 ? "text-red-400" :
                            alert.cvssScore >= 7 ? "text-orange-400" :
                            alert.cvssScore >= 4 ? "text-yellow-400" : "text-green-400"
                          }`}>
                            CVSS {alert.cvssScore}
                          </span>
                        )}
                        <span className="flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          {alert.createdAt ? new Date(alert.createdAt).toLocaleString() : "Unknown"}
                        </span>
                      </div>
                    </div>

                    {/* Action buttons */}
                    <div className="flex items-center gap-1 shrink-0">
                      {alert.status === "new" && (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 text-xs text-yellow-400 hover:bg-yellow-500/10"
                          onClick={() => updateStatus.mutate({ id: alert.id, status: "acknowledged" })}
                        >
                          <Eye className="w-3 h-3 mr-1" /> Ack
                        </Button>
                      )}
                      {(alert.status === "new" || alert.status === "acknowledged") && (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 text-xs text-purple-400 hover:bg-purple-500/10"
                          onClick={() => updateStatus.mutate({ id: alert.id, status: "investigating" })}
                        >
                          <Search className="w-3 h-3 mr-1" /> Investigate
                        </Button>
                      )}
                      {alert.status !== "resolved" && alert.status !== "dismissed" && (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 text-xs text-green-400 hover:bg-green-500/10"
                          onClick={() => updateStatus.mutate({ id: alert.id, status: "resolved" })}
                        >
                          <CheckCircle className="w-3 h-3 mr-1" /> Resolve
                        </Button>
                      )}
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </>
        )}
      </div>
    </div>
  );
}

function AlertRulesManager() {
  const { data: rules, refetch } = trpc.alertRule.list.useQuery();
  const [showCreate, setShowCreate] = useState(false);
  const [newRule, setNewRule] = useState({
    name: "",
    description: "",
    severityThreshold: "high" as "critical" | "high" | "medium" | "low",
    cvssThreshold: 7.0,
    watchedServices: "",
    watchedTargets: "",
    watchedCveIds: "",
    alertOnKev: true,
    cooldownMinutes: 60,
  });

  const toggleRule = trpc.alertRule.toggle.useMutation({
    onSuccess: () => {
      refetch();
      toast.success("Rule updated");
    },
  });

  const deleteRule = trpc.alertRule.delete.useMutation({
    onSuccess: () => {
      refetch();
      toast.success("Rule deleted");
    },
  });

  const createRule = trpc.alertRule.create.useMutation({
    onSuccess: () => {
      refetch();
      setShowCreate(false);
      setNewRule({
        name: "",
        description: "",
        severityThreshold: "high",
        cvssThreshold: 7.0,
        watchedServices: "",
        watchedTargets: "",
        watchedCveIds: "",
        alertOnKev: true,
        cooldownMinutes: 60,
      });
      toast.success("Alert rule created");
    },
  });

  const handleCreate = () => {
    if (!newRule.name.trim()) {
      toast.error("Rule name is required");
      return;
    }
    createRule.mutate({
      name: newRule.name,
      description: newRule.description || undefined,
      severityThreshold: newRule.severityThreshold,
      cvssThreshold: newRule.cvssThreshold,
      watchedServices: newRule.watchedServices
        ? newRule.watchedServices.split(",").map((s) => s.trim()).filter(Boolean)
        : undefined,
      watchedTargets: newRule.watchedTargets
        ? newRule.watchedTargets.split(",").map((s) => s.trim()).filter(Boolean)
        : undefined,
      watchedCveIds: newRule.watchedCveIds
        ? newRule.watchedCveIds.split(",").map((s) => s.trim()).filter(Boolean)
        : undefined,
      alertOnKev: newRule.alertOnKev,
      cooldownMinutes: newRule.cooldownMinutes,
    });
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          Alert rules determine which vulnerabilities trigger notifications.
        </p>
        <Dialog open={showCreate} onOpenChange={setShowCreate}>
          <DialogTrigger asChild>
            <Button size="sm" className="bg-purple-600 hover:bg-purple-700 text-white gap-1">
              <Plus className="w-3.5 h-3.5" /> New Rule
            </Button>
          </DialogTrigger>
          <DialogContent className="bg-card border-border/50 max-w-lg">
            <DialogHeader>
              <DialogTitle className="font-[Outfit]">Create Alert Rule</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 py-2">
              <div>
                <Label className="text-xs text-muted-foreground">Rule Name</Label>
                <Input
                  value={newRule.name}
                  onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
                  placeholder="e.g., Critical CVE Alert"
                  className="bg-background/50 border-border/50 mt-1"
                />
              </div>
              <div>
                <Label className="text-xs text-muted-foreground">Description</Label>
                <Input
                  value={newRule.description}
                  onChange={(e) => setNewRule({ ...newRule, description: e.target.value })}
                  placeholder="When to trigger this alert..."
                  className="bg-background/50 border-border/50 mt-1"
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label className="text-xs text-muted-foreground">Severity Threshold</Label>
                  <Select
                    value={newRule.severityThreshold}
                    onValueChange={(v) => setNewRule({ ...newRule, severityThreshold: v as any })}
                  >
                    <SelectTrigger className="bg-background/50 border-border/50 mt-1">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="critical">Critical</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="low">Low</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label className="text-xs text-muted-foreground">CVSS Threshold</Label>
                  <Input
                    type="number"
                    min={0}
                    max={10}
                    step={0.1}
                    value={newRule.cvssThreshold}
                    onChange={(e) => setNewRule({ ...newRule, cvssThreshold: parseFloat(e.target.value) || 0 })}
                    className="bg-background/50 border-border/50 mt-1"
                  />
                </div>
              </div>
              <div>
                <Label className="text-xs text-muted-foreground">Watched Services (comma-separated)</Label>
                <Input
                  value={newRule.watchedServices}
                  onChange={(e) => setNewRule({ ...newRule, watchedServices: e.target.value })}
                  placeholder="e.g., ssh, http, smb, rdp"
                  className="bg-background/50 border-border/50 mt-1"
                />
              </div>
              <div>
                <Label className="text-xs text-muted-foreground">Watched Targets (CIDR, comma-separated)</Label>
                <Input
                  value={newRule.watchedTargets}
                  onChange={(e) => setNewRule({ ...newRule, watchedTargets: e.target.value })}
                  placeholder="e.g., 192.168.1.0/24, 10.0.0.0/8"
                  className="bg-background/50 border-border/50 mt-1"
                />
              </div>
              <div>
                <Label className="text-xs text-muted-foreground">Watched CVE IDs (comma-separated)</Label>
                <Input
                  value={newRule.watchedCveIds}
                  onChange={(e) => setNewRule({ ...newRule, watchedCveIds: e.target.value })}
                  placeholder="e.g., CVE-2024-1234, CVE-2023-5678"
                  className="bg-background/50 border-border/50 mt-1"
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="flex items-center gap-2">
                  <Switch
                    checked={newRule.alertOnKev}
                    onCheckedChange={(v) => setNewRule({ ...newRule, alertOnKev: v })}
                  />
                  <Label className="text-xs text-muted-foreground">Alert on KEV entries</Label>
                </div>
                <div>
                  <Label className="text-xs text-muted-foreground">Cooldown (minutes)</Label>
                  <Input
                    type="number"
                    min={1}
                    value={newRule.cooldownMinutes}
                    onChange={(e) => setNewRule({ ...newRule, cooldownMinutes: parseInt(e.target.value) || 60 })}
                    className="bg-background/50 border-border/50 mt-1"
                  />
                </div>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowCreate(false)}>Cancel</Button>
              <Button
                className="bg-purple-600 hover:bg-purple-700 text-white"
                onClick={handleCreate}
                disabled={createRule.isPending}
              >
                {createRule.isPending ? "Creating..." : "Create Rule"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Rules List */}
      <div className="space-y-3">
        {(!rules || rules.length === 0) ? (
          <Card className="border-border/50 bg-card/80">
            <CardContent className="py-8 text-center">
              <Shield className="w-8 h-8 text-muted-foreground mx-auto mb-2 opacity-40" />
              <p className="text-sm text-muted-foreground">No alert rules configured</p>
              <p className="text-xs text-muted-foreground mt-1">
                Default rules will be created automatically on the first scan.
              </p>
            </CardContent>
          </Card>
        ) : (
          rules.map((rule: any) => (
            <Card key={rule.id} className={`border-border/50 ${rule.enabled ? "bg-card/80" : "bg-card/40 opacity-60"}`}>
              <CardContent className="p-4">
                <div className="flex items-start gap-3">
                  <Switch
                    checked={rule.enabled}
                    onCheckedChange={(enabled) => toggleRule.mutate({ id: rule.id, enabled })}
                    className="mt-1"
                  />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-sm font-medium text-foreground">{rule.name}</span>
                      <SeverityBadge severity={rule.severityThreshold} />
                      {rule.cvssThreshold && (
                        <span className="text-[11px] text-muted-foreground">
                          CVSS ≥ {rule.cvssThreshold}
                        </span>
                      )}
                    </div>
                    {rule.description && (
                      <p className="text-xs text-muted-foreground mb-2">{rule.description}</p>
                    )}
                    <div className="flex items-center gap-3 text-[11px] text-muted-foreground flex-wrap">
                      {rule.watchedServices && (
                        <span className="flex items-center gap-1">
                          <Server className="w-3 h-3" />
                          Services: {Array.isArray(rule.watchedServices) ? rule.watchedServices.join(", ") : rule.watchedServices}
                        </span>
                      )}
                      {rule.watchedTargets && (
                        <span className="flex items-center gap-1">
                          <Target className="w-3 h-3" />
                          Targets: {Array.isArray(rule.watchedTargets) ? rule.watchedTargets.join(", ") : rule.watchedTargets}
                        </span>
                      )}
                      <span className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        Cooldown: {rule.cooldownMinutes || 60}m
                      </span>
                      {rule.alertOnKev && (
                        <span className="text-orange-400">KEV alerts enabled</span>
                      )}
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-red-400 hover:bg-red-500/10 h-7"
                    onClick={() => {
                      if (confirm("Delete this alert rule?")) {
                        deleteRule.mutate({ id: rule.id });
                      }
                    }}
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))
        )}
      </div>
    </div>
  );
}

export default function Alerts() {
  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
      >
        <div className="flex items-center gap-3 mb-1">
          <div className="p-2 rounded-lg bg-red-500/10">
            <BellRing className="w-5 h-5 text-red-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-foreground font-[Outfit]">CVE Alert Center</h1>
            <p className="text-xs text-muted-foreground">
              Automated vulnerability alerting for discovered services
            </p>
          </div>
        </div>
      </motion.div>

      {/* Stats */}
      <AlertStatsCards />

      {/* Tabs */}
      <Tabs defaultValue="alerts" className="space-y-4">
        <TabsList className="bg-card/80 border border-border/50">
          <TabsTrigger value="alerts" className="data-[state=active]:bg-purple-500/20 data-[state=active]:text-purple-400 gap-1.5">
            <Bell className="w-3.5 h-3.5" /> Alert History
          </TabsTrigger>
          <TabsTrigger value="rules" className="data-[state=active]:bg-purple-500/20 data-[state=active]:text-purple-400 gap-1.5">
            <Shield className="w-3.5 h-3.5" /> Alert Rules
          </TabsTrigger>
        </TabsList>

        <TabsContent value="alerts">
          <AlertHistory />
        </TabsContent>

        <TabsContent value="rules">
          <AlertRulesManager />
        </TabsContent>
      </Tabs>
    </div>
  );
}
