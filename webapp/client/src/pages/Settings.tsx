/*
 * Settings — Platform Configuration
 * Spectra Command Dark Theme
 */
import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import {
  Settings as SettingsIcon,
  Shield,
  Globe,
  Bell,
  Users,
  Key,
  Database,
  Save,
  Plus,
  Trash2,
  AlertTriangle,
  Cpu,
} from "lucide-react";
import { motion } from "framer-motion";
import { toast } from "sonner";

const TOPO_IMAGE = "https://private-us-east-1.manuscdn.com/sessionFile/lPjfb29pgYeS2MTiIzmJY7/sandbox/nzEOAhVoSOSinYNAfaFTry-img-4_1771331592000_na1fn_bmV0d29yay10b3BvLXYy.png?x-oss-process=image/resize,w_1920,h_1920/format,webp/quality,q_80&Expires=1798761600&Policy=eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiaHR0cHM6Ly9wcml2YXRlLXVzLWVhc3QtMS5tYW51c2Nkbi5jb20vc2Vzc2lvbkZpbGUvbFBqZmIyOXBnWWVTMk1UaUl6bUpZNy9zYW5kYm94L256RU9BaFZvU09TaW5ZTkFmYUZUcnktaW1nLTRfMTc3MTMzMTU5MjAwMF9uYTFmbl9ibVYwZDI5eWF5MTBiM0J2TFhZeS5wbmc~eC1vc3MtcHJvY2Vzcz1pbWFnZS9yZXNpemUsd18xOTIwLGhfMTkyMC9mb3JtYXQsd2VicC9xdWFsaXR5LHFfODAiLCJDb25kaXRpb24iOnsiRGF0ZUxlc3NUaGFuIjp7IkFXUzpFcG9jaFRpbWUiOjE3OTg3NjE2MDB9fX1dfQ__&Key-Pair-Id=K2HSFNDJXOU9YS&Signature=kgSB8YTl17Dh7na8~qZKEc-e--5zmvyMVsGWdB5-7Cw0j5F2ZkUdN-sZSU6AogH~BpRK2NIO-BbB5KJh2ASUeO3mXdVXc~o4fEiIGl38e1j-qanWTXqN9zycdz-BpJGFQsfANDg8kOPyQPo-jX7Mt83h~IKdXVnz7bT222GgoG0HycdCvcEWz74iNvex66PwssT-KhIJ1~LQIRdSVqLTICx9pRpRIT-WM3e2QXXHOZUkQKhG71LOGQRcWi5HHLEJSyB-LNel2jN9AyHnfkmN6O6~QwSu2AEhdiXIfMMtcVGpi5M5HntA-mZhr~7y8N9zgCAvbermTlNG~0DyTYME1w__";

export default function Settings() {
  const { data: cudaStatus } = trpc.cuda.status.useQuery();
  const { data: nmapInfo } = trpc.info.nmapVersion.useQuery();
  const [allowedCidrs, setAllowedCidrs] = useState("192.168.0.0/16\n10.0.0.0/8\n172.16.0.0/12");
  const [deniedCidrs, setDeniedCidrs] = useState("127.0.0.0/8\n169.254.0.0/16");
  const [maxConcurrent, setMaxConcurrent] = useState("5");
  const [rateLimit, setRateLimit] = useState("10");
  const [notifications, setNotifications] = useState(true);
  const [auditRetention, setAuditRetention] = useState("90");

  const handleSave = () => {
    toast.success("Settings saved", { description: "Configuration updated successfully" });
  };

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
      >
        <div className="flex items-center gap-2 mb-1">
          <SettingsIcon className="w-4 h-4 text-muted-foreground" />
          <span className="text-[11px] font-semibold tracking-[0.2em] uppercase text-muted-foreground">
            Configuration
          </span>
        </div>
        <h2 className="text-2xl font-bold text-foreground font-[Outfit]">Settings</h2>
        <p className="text-sm text-muted-foreground mt-1">
          Configure scan policies, security controls, and platform behavior.
        </p>
      </motion.div>

      <Tabs defaultValue="security" className="space-y-4">
        <TabsList className="bg-secondary/50">
          <TabsTrigger value="security" className="gap-1.5">
            <Shield className="w-3.5 h-3.5" /> Security
          </TabsTrigger>
          <TabsTrigger value="scanning" className="gap-1.5">
            <Globe className="w-3.5 h-3.5" /> Scanning
          </TabsTrigger>
          <TabsTrigger value="notifications" className="gap-1.5">
            <Bell className="w-3.5 h-3.5" /> Notifications
          </TabsTrigger>
          <TabsTrigger value="system" className="gap-1.5">
            <Database className="w-3.5 h-3.5" /> System
          </TabsTrigger>
          <TabsTrigger value="cuda" className="gap-1.5">
            <Cpu className="w-3.5 h-3.5" /> CUDA/GPU
          </TabsTrigger>
        </TabsList>

        {/* Security Tab */}
        <TabsContent value="security" className="space-y-4">
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
            <Card className="border-border/50 bg-card/80">
              <CardHeader className="pb-3">
                <CardTitle className="text-base font-semibold font-[Outfit]">CIDR Allowlist</CardTitle>
                <p className="text-xs text-muted-foreground">Only targets within these ranges can be scanned</p>
              </CardHeader>
              <CardContent className="pt-0">
                <Textarea
                  value={allowedCidrs}
                  onChange={(e) => setAllowedCidrs(e.target.value)}
                  className="bg-input/50 border-border/50 font-mono text-sm h-24"
                  placeholder="One CIDR per line"
                />
              </CardContent>
            </Card>
          </motion.div>

          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3, delay: 0.1 }}>
            <Card className="border-border/50 bg-card/80">
              <CardHeader className="pb-3">
                <CardTitle className="text-base font-semibold font-[Outfit] flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-red-400" />
                  CIDR Denylist
                </CardTitle>
                <p className="text-xs text-muted-foreground">These ranges are always blocked from scanning</p>
              </CardHeader>
              <CardContent className="pt-0">
                <Textarea
                  value={deniedCidrs}
                  onChange={(e) => setDeniedCidrs(e.target.value)}
                  className="bg-input/50 border-border/50 font-mono text-sm h-24"
                  placeholder="One CIDR per line"
                />
              </CardContent>
            </Card>
          </motion.div>

          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3, delay: 0.2 }}>
            <Card className="border-border/50 bg-card/80">
              <CardHeader className="pb-3">
                <CardTitle className="text-base font-semibold font-[Outfit]">Rate Limiting</CardTitle>
              </CardHeader>
              <CardContent className="pt-0 space-y-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <Label className="text-sm mb-2 block">Max Concurrent Scans</Label>
                    <Input
                      type="number"
                      value={maxConcurrent}
                      onChange={(e) => setMaxConcurrent(e.target.value)}
                      className="bg-input/50 border-border/50 text-sm"
                    />
                  </div>
                  <div>
                    <Label className="text-sm mb-2 block">Scans per Hour (per user)</Label>
                    <Input
                      type="number"
                      value={rateLimit}
                      onChange={(e) => setRateLimit(e.target.value)}
                      className="bg-input/50 border-border/50 text-sm"
                    />
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        </TabsContent>

        {/* Scanning Tab */}
        <TabsContent value="scanning" className="space-y-4">
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
            <Card className="border-border/50 bg-card/80">
              <CardHeader className="pb-3">
                <CardTitle className="text-base font-semibold font-[Outfit]">Nmap Configuration</CardTitle>
              </CardHeader>
              <CardContent className="pt-0 space-y-4">
                <div>
                  <Label className="text-sm mb-2 block">Nmap Binary Path</Label>
                  <Input
                    defaultValue="/usr/bin/nmap"
                    className="bg-input/50 border-border/50 font-mono text-sm"
                    readOnly
                  />
                  <p className="text-[11px] text-muted-foreground mt-1">Read-only. Configured at deployment.</p>
                </div>
                <Separator className="bg-border/30" />
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <Label className="text-sm">Allow OS Detection (-O)</Label>
                      <p className="text-[11px] text-muted-foreground">Requires root/sudo privileges</p>
                    </div>
                    <Switch defaultChecked />
                  </div>
                  <div className="flex items-center justify-between">
                    <div>
                      <Label className="text-sm">Allow Script Scanning (--script)</Label>
                      <p className="text-[11px] text-muted-foreground">NSE script execution</p>
                    </div>
                    <Switch defaultChecked />
                  </div>
                  <div className="flex items-center justify-between">
                    <div>
                      <Label className="text-sm">Allow UDP Scanning (-sU)</Label>
                      <p className="text-[11px] text-muted-foreground">Slower but more comprehensive</p>
                    </div>
                    <Switch />
                  </div>
                  <div className="flex items-center justify-between">
                    <div>
                      <Label className="text-sm">Allow Aggressive Timing (-T5)</Label>
                      <p className="text-[11px] text-muted-foreground">May trigger IDS alerts</p>
                    </div>
                    <Switch />
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        </TabsContent>

        {/* Notifications Tab */}
        <TabsContent value="notifications" className="space-y-4">
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
            <Card className="border-border/50 bg-card/80">
              <CardHeader className="pb-3">
                <CardTitle className="text-base font-semibold font-[Outfit]">Alert Preferences</CardTitle>
              </CardHeader>
              <CardContent className="pt-0 space-y-3">
                <div className="flex items-center justify-between">
                  <div>
                    <Label className="text-sm">Enable Notifications</Label>
                    <p className="text-[11px] text-muted-foreground">Receive alerts for scan events</p>
                  </div>
                  <Switch checked={notifications} onCheckedChange={setNotifications} />
                </div>
                <Separator className="bg-border/30" />
                <div className="flex items-center justify-between">
                  <div>
                    <Label className="text-sm">Critical Vulnerability Alerts</Label>
                    <p className="text-[11px] text-muted-foreground">Immediate notification for critical findings</p>
                  </div>
                  <Switch defaultChecked />
                </div>
                <div className="flex items-center justify-between">
                  <div>
                    <Label className="text-sm">Scan Completion Alerts</Label>
                    <p className="text-[11px] text-muted-foreground">Notify when scans finish</p>
                  </div>
                  <Switch defaultChecked />
                </div>
                <div className="flex items-center justify-between">
                  <div>
                    <Label className="text-sm">New Host Discovery</Label>
                    <p className="text-[11px] text-muted-foreground">Alert when new hosts appear on the network</p>
                  </div>
                  <Switch />
                </div>
              </CardContent>
            </Card>
          </motion.div>
        </TabsContent>

        {/* System Tab */}
        <TabsContent value="system" className="space-y-4">
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
            <Card className="border-border/50 bg-card/80">
              <CardHeader className="pb-3">
                <CardTitle className="text-base font-semibold font-[Outfit]">Data Retention</CardTitle>
              </CardHeader>
              <CardContent className="pt-0 space-y-4">
                <div>
                  <Label className="text-sm mb-2 block">Audit Log Retention (days)</Label>
                  <Input
                    type="number"
                    value={auditRetention}
                    onChange={(e) => setAuditRetention(e.target.value)}
                    className="bg-input/50 border-border/50 text-sm w-32"
                  />
                </div>
                <div className="flex items-center justify-between">
                  <div>
                    <Label className="text-sm">Auto-purge Old Scan Results</Label>
                    <p className="text-[11px] text-muted-foreground">Remove results older than retention period</p>
                  </div>
                  <Switch />
                </div>
              </CardContent>
            </Card>
          </motion.div>

          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3, delay: 0.1 }}>
            <Card className="border-border/50 bg-card/80">
              <CardHeader className="pb-3">
                <CardTitle className="text-base font-semibold font-[Outfit]">Platform Info</CardTitle>
              </CardHeader>
              <CardContent className="pt-0">
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <p className="text-[11px] text-muted-foreground mb-0.5">Version</p>
                    <p className="font-mono text-foreground">1.0.0-beta</p>
                  </div>
                  <div>
                    <p className="text-[11px] text-muted-foreground mb-0.5">Nmap Version</p>
                    <p className="font-mono text-foreground">{nmapInfo?.version || "Not detected"}</p>
                  </div>
                  <div>
                    <p className="text-[11px] text-muted-foreground mb-0.5">Source</p>
                    <a href="https://github.com/nmap/nmap" target="_blank" rel="noopener noreferrer" className="font-mono text-purple-400 hover:underline">
                      github.com/nmap/nmap
                    </a>
                  </div>
                  <div>
                    <p className="text-[11px] text-muted-foreground mb-0.5">License</p>
                    <p className="font-mono text-foreground">NPSL</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        </TabsContent>

        {/* CUDA/GPU Tab */}
        <TabsContent value="cuda" className="space-y-4">
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
            <Card className="border-border/50 bg-card/80">
              <CardHeader className="pb-3">
                <div className="flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-purple-400" />
                  <div>
                    <CardTitle className="text-base font-semibold font-[Outfit]">CUDA GPU Status</CardTitle>
                    <p className="text-xs text-muted-foreground">GPU acceleration for high-speed packet processing</p>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="pt-0 space-y-4">
                <div className={`p-4 rounded-lg border ${
                  cudaStatus?.available
                    ? "border-green-500/30 bg-green-500/5"
                    : "border-yellow-500/30 bg-yellow-500/5"
                }`}>
                  <div className="flex items-center gap-2 mb-2">
                    <span className={`w-2 h-2 rounded-full ${cudaStatus?.available ? "bg-green-400 animate-pulse" : "bg-yellow-400"}`} />
                    <span className={`text-sm font-medium ${cudaStatus?.available ? "text-green-400" : "text-yellow-400"}`}>
                      {cudaStatus?.available ? "CUDA Available" : "CUDA Not Available"}
                    </span>
                  </div>
                  {(cudaStatus as any)?.driverVersion && (
                    <p className="text-xs text-muted-foreground">Driver: {(cudaStatus as any).driverVersion}</p>
                  )}
                </div>

                {cudaStatus?.devices && cudaStatus.devices.length > 0 ? (
                  <div className="space-y-3">
                    <h4 className="text-sm font-medium text-foreground">Detected GPUs</h4>
                    {cudaStatus.devices.map((dev: any, i: number) => (
                      <div key={i} className="p-3 rounded-lg border border-border/30 bg-background/50">
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-sm font-medium text-foreground">{dev.name}</span>
                          <span className="text-[11px] text-purple-400 font-mono">GPU {i}</span>
                        </div>
                        {dev.memory && (
                          <p className="text-xs text-muted-foreground">Memory: {dev.memory}</p>
                        )}
                        {dev.utilization !== undefined && (
                          <p className="text-xs text-muted-foreground">Utilization: {dev.utilization}%</p>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-6">
                    <Cpu className="w-8 h-8 text-muted-foreground mx-auto mb-2 opacity-50" />
                    <p className="text-sm text-muted-foreground">No CUDA-capable GPUs detected</p>
                    <p className="text-xs text-muted-foreground mt-1">Install NVIDIA drivers and CUDA toolkit to enable GPU acceleration</p>
                  </div>
                )}

                <Separator className="bg-border/30" />

                <div>
                  <h4 className="text-sm font-medium text-foreground mb-2">CUDA Acceleration Features</h4>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {[
                      { label: "Parallel Port Scanning", desc: "GPU-accelerated SYN/ACK packet generation" },
                      { label: "Hash Cracking", desc: "CUDA-powered password hash analysis" },
                      { label: "Packet Processing", desc: "High-throughput network packet inspection" },
                      { label: "Pattern Matching", desc: "GPU regex for service fingerprinting" },
                    ].map((feat) => (
                      <div key={feat.label} className="p-2.5 rounded-lg border border-border/30 bg-background/30">
                        <p className="text-xs font-medium text-foreground">{feat.label}</p>
                        <p className="text-[10px] text-muted-foreground mt-0.5">{feat.desc}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        </TabsContent>
      </Tabs>

      {/* Save button */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.3 }}
        className="flex justify-end"
      >
        <Button onClick={handleSave} className="bg-purple-600 hover:bg-purple-700 text-white gap-2">
          <Save className="w-4 h-4" />
          Save Changes
        </Button>
      </motion.div>
    </div>
  );
}
