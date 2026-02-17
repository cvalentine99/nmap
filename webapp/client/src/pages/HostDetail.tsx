/*
 * HostDetail — Deep Host Drilldown Page
 * Spectra Command Dark Theme
 * Shows ports, services, OS fingerprint, vulnerabilities, scripts output, and timeline
 */
import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";
import { Progress } from "@/components/ui/progress";
import {
  Server,
  Wifi,
  Shield,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Globe,
  Cpu,
  HardDrive,
  ArrowLeft,
  Copy,
  ExternalLink,
  FileCode,
  Activity,
  Lock,
  Unlock,
  ChevronRight,
} from "lucide-react";
import { toast } from "sonner";
import { motion } from "framer-motion";
import { Link } from "wouter";

// Mock host data
const hostData = {
  ip: "192.168.1.25",
  hostname: "web-server.local",
  mac: "AA:BB:CC:DD:EE:FF",
  vendor: "Dell Inc.",
  os: {
    name: "Debian 11 (Bullseye)",
    family: "Linux",
    accuracy: 96,
    cpe: "cpe:/o:debian:debian_linux:11",
  },
  status: "up",
  latency: "0.0056s",
  distance: 1,
  lastScan: "2026-02-17 08:15:22",
  uptime: { seconds: 2592000, lastBoot: "2026-01-18 08:15:00" },
  ports: [
    {
      port: 21,
      protocol: "tcp",
      state: "open",
      service: "ftp",
      version: "vsftpd 3.0.3",
      cpe: "cpe:/a:vsftpd:vsftpd:3.0.3",
      scripts: [
        { name: "ftp-anon", output: "Anonymous FTP login allowed (FTP code 230)\ndrwxr-xr-x  2 ftp ftp  4096 Jan 15 pub" },
      ],
      risk: "medium",
    },
    {
      port: 22,
      protocol: "tcp",
      state: "open",
      service: "ssh",
      version: "OpenSSH 8.9p1 Ubuntu",
      cpe: "cpe:/a:openbsd:openssh:8.9p1",
      scripts: [
        { name: "ssh-hostkey", output: "3072 SHA256:abc123... (RSA)\n256  SHA256:def456... (ECDSA)\n256  SHA256:ghi789... (ED25519)" },
      ],
      risk: "low",
    },
    {
      port: 80,
      protocol: "tcp",
      state: "open",
      service: "http",
      version: "Apache httpd 2.4.54",
      cpe: "cpe:/a:apache:http_server:2.4.54",
      scripts: [
        { name: "http-title", output: "Site: Company Intranet Portal" },
        { name: "http-headers", output: "Server: Apache/2.4.54\nX-Frame-Options: SAMEORIGIN\nContent-Type: text/html" },
        { name: "http-enum", output: "/admin/: Possible admin folder\n/robots.txt: Robots file\n/.git/HEAD: Git folder" },
      ],
      risk: "high",
    },
    {
      port: 443,
      protocol: "tcp",
      state: "open",
      service: "https",
      version: "Apache httpd 2.4.54",
      cpe: "cpe:/a:apache:http_server:2.4.54",
      scripts: [
        { name: "ssl-cert", output: "Subject: commonName=web-server.local\nIssuer: commonName=Internal CA\nNot valid before: 2025-06-01\nNot valid after: 2026-06-01" },
        { name: "ssl-heartbleed", output: "VULNERABLE: The Heartbleed Bug\nState: VULNERABLE\nRisk factor: High\nCVE: CVE-2014-0160" },
      ],
      risk: "critical",
    },
    {
      port: 3306,
      protocol: "tcp",
      state: "filtered",
      service: "mysql",
      version: "",
      scripts: [],
      risk: "info",
    },
    {
      port: 8443,
      protocol: "tcp",
      state: "open",
      service: "https-alt",
      version: "Tomcat 9.0.65",
      cpe: "cpe:/a:apache:tomcat:9.0.65",
      scripts: [],
      risk: "low",
    },
  ],
  vulnerabilities: [
    {
      id: "CVE-2014-0160",
      title: "OpenSSL Heartbleed",
      severity: "critical",
      port: 443,
      description: "The TLS and DTLS implementations in OpenSSL allow remote attackers to obtain sensitive information from process memory.",
      cvss: 7.5,
    },
    {
      id: "CVE-2023-25690",
      title: "Apache HTTP Request Smuggling",
      severity: "high",
      port: 80,
      description: "Some mod_proxy configurations allow HTTP Request Smuggling attacks.",
      cvss: 9.8,
    },
    {
      id: "FINDING-001",
      title: "Anonymous FTP Access",
      severity: "medium",
      port: 21,
      description: "FTP server allows anonymous login which could expose sensitive files.",
      cvss: 5.3,
    },
    {
      id: "FINDING-002",
      title: "Git Repository Exposed",
      severity: "high",
      port: 80,
      description: "The .git directory is accessible via HTTP, potentially exposing source code and credentials.",
      cvss: 7.5,
    },
  ],
  scanTimeline: [
    { time: "08:15:22", event: "Host discovered via ARP ping", type: "discovery" },
    { time: "08:15:23", event: "SYN scan initiated on 1000 ports", type: "scan" },
    { time: "08:15:24", event: "Port 21/tcp open (ftp)", type: "port" },
    { time: "08:15:24", event: "Port 22/tcp open (ssh)", type: "port" },
    { time: "08:15:25", event: "Port 80/tcp open (http)", type: "port" },
    { time: "08:15:25", event: "Port 443/tcp open (https)", type: "port" },
    { time: "08:15:26", event: "Port 8443/tcp open (https-alt)", type: "port" },
    { time: "08:15:27", event: "Service version detection started", type: "scan" },
    { time: "08:15:35", event: "OS detection: Debian 11 (96%)", type: "os" },
    { time: "08:15:40", event: "NSE scripts started (12 scripts)", type: "script" },
    { time: "08:15:45", event: "VULN: Heartbleed detected on port 443", type: "vuln" },
    { time: "08:15:48", event: "FINDING: Anonymous FTP on port 21", type: "vuln" },
    { time: "08:15:50", event: "FINDING: .git exposed on port 80", type: "vuln" },
    { time: "08:15:55", event: "Scan complete for 192.168.1.25", type: "complete" },
  ],
};

const riskColors: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: "bg-red-500/10", text: "text-red-400", border: "border-red-500/30" },
  high: { bg: "bg-orange-500/10", text: "text-orange-400", border: "border-orange-500/30" },
  medium: { bg: "bg-yellow-500/10", text: "text-yellow-400", border: "border-yellow-500/30" },
  low: { bg: "bg-green-500/10", text: "text-green-400", border: "border-green-500/30" },
  info: { bg: "bg-blue-500/10", text: "text-blue-400", border: "border-blue-500/30" },
};

const severityOrder = ["critical", "high", "medium", "low", "info"];

const timelineTypeColors: Record<string, string> = {
  discovery: "bg-green-400",
  scan: "bg-blue-400",
  port: "bg-cyan-400",
  os: "bg-purple-400",
  script: "bg-yellow-400",
  vuln: "bg-red-400",
  complete: "bg-green-400",
};

export default function HostDetail() {
  const [selectedPort, setSelectedPort] = useState<number | null>(null);

  const sortedPorts = [...hostData.ports].sort((a, b) => {
    const aIdx = severityOrder.indexOf(a.risk);
    const bIdx = severityOrder.indexOf(b.risk);
    return aIdx - bIdx;
  });

  return (
    <div className="space-y-6">
      {/* Back + Header */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}>
        <Link href="/scan/results" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground mb-3 transition-colors">
          <ArrowLeft className="w-3.5 h-3.5" />
          Back to Results
        </Link>
        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <Server className="w-4 h-4 text-cyan-400" />
              <span className="text-[11px] font-semibold tracking-[0.2em] uppercase text-cyan-400">
                Host Detail
              </span>
            </div>
            <h2 className="text-2xl font-bold text-foreground font-[Outfit] font-mono">{hostData.ip}</h2>
            <p className="text-sm text-muted-foreground mt-0.5">{hostData.hostname}</p>
          </div>
          <Badge className={`${hostData.status === "up" ? "bg-green-500/10 text-green-400 border-green-500/30" : "bg-red-500/10 text-red-400 border-red-500/30"} border text-xs`}>
            {hostData.status === "up" ? "Online" : "Down"}
          </Badge>
        </div>
      </motion.div>

      {/* Quick Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
        {[
          { label: "Open Ports", value: hostData.ports.filter((p) => p.state === "open").length.toString(), icon: Wifi, color: "text-cyan-400" },
          { label: "Filtered", value: hostData.ports.filter((p) => p.state === "filtered").length.toString(), icon: Shield, color: "text-yellow-400" },
          { label: "Vulns", value: hostData.vulnerabilities.length.toString(), icon: AlertTriangle, color: "text-red-400" },
          { label: "OS Confidence", value: `${hostData.os.accuracy}%`, icon: Cpu, color: "text-purple-400" },
          { label: "Latency", value: hostData.latency, icon: Activity, color: "text-green-400" },
          { label: "Hops", value: hostData.distance.toString(), icon: Globe, color: "text-orange-400" },
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

      {/* Main tabs */}
      <Tabs defaultValue="ports" className="space-y-4">
        <TabsList className="bg-secondary/50">
          <TabsTrigger value="ports">Ports & Services</TabsTrigger>
          <TabsTrigger value="vulns">Vulnerabilities</TabsTrigger>
          <TabsTrigger value="os">OS & System</TabsTrigger>
          <TabsTrigger value="timeline">Scan Timeline</TabsTrigger>
        </TabsList>

        {/* Ports & Services */}
        <TabsContent value="ports" className="space-y-4">
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
            {/* Port list */}
            <div className="xl:col-span-2">
              <Card className="border-border/50 bg-card/80">
                <CardContent className="p-0">
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-border/30">
                          <th className="text-left py-3 px-4 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Port</th>
                          <th className="text-left py-3 px-4 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">State</th>
                          <th className="text-left py-3 px-4 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Service</th>
                          <th className="text-left py-3 px-4 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Version</th>
                          <th className="text-left py-3 px-4 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Risk</th>
                          <th className="text-left py-3 px-4 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Scripts</th>
                        </tr>
                      </thead>
                      <tbody>
                        {sortedPorts.map((port) => {
                          const risk = riskColors[port.risk];
                          const isSelected = selectedPort === port.port;
                          return (
                            <tr
                              key={port.port}
                              onClick={() => setSelectedPort(isSelected ? null : port.port)}
                              className={`border-b border-border/10 cursor-pointer transition-colors ${isSelected ? "bg-cyan-500/5" : "hover:bg-accent/20"}`}
                            >
                              <td className="py-3 px-4 font-mono text-cyan-400">{port.port}/{port.protocol}</td>
                              <td className="py-3 px-4">
                                <div className="flex items-center gap-1.5">
                                  {port.state === "open" ? (
                                    <Unlock className="w-3 h-3 text-green-400" />
                                  ) : (
                                    <Lock className="w-3 h-3 text-yellow-400" />
                                  )}
                                  <span className={port.state === "open" ? "text-green-400" : "text-yellow-400"}>
                                    {port.state}
                                  </span>
                                </div>
                              </td>
                              <td className="py-3 px-4 text-foreground/80">{port.service}</td>
                              <td className="py-3 px-4 text-muted-foreground font-mono text-xs">{port.version || "—"}</td>
                              <td className="py-3 px-4">
                                <Badge className={`${risk.bg} ${risk.text} ${risk.border} border text-[10px] capitalize`}>
                                  {port.risk}
                                </Badge>
                              </td>
                              <td className="py-3 px-4">
                                {port.scripts.length > 0 && (
                                  <Badge variant="outline" className="text-[10px] border-border/40 text-muted-foreground gap-1">
                                    <FileCode className="w-3 h-3" />
                                    {port.scripts.length}
                                  </Badge>
                                )}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Script output panel */}
            <div className="xl:col-span-1">
              <Card className="border-border/50 bg-card/80 sticky top-4">
                <CardHeader className="pb-2">
                  <div className="flex items-center gap-2">
                    <FileCode className="w-4 h-4 text-green-400" />
                    <CardTitle className="text-sm font-semibold font-[Outfit]">Script Output</CardTitle>
                  </div>
                </CardHeader>
                <CardContent>
                  {selectedPort ? (
                    (() => {
                      const port = hostData.ports.find((p) => p.port === selectedPort);
                      if (!port || port.scripts.length === 0) {
                        return <p className="text-sm text-muted-foreground">No script output for this port.</p>;
                      }
                      return (
                        <div className="space-y-3">
                          {port.scripts.map((script, i) => (
                            <div key={i}>
                              <div className="flex items-center justify-between mb-1">
                                <span className="text-xs font-mono text-cyan-400">{script.name}</span>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  className="h-5 px-1.5 text-[10px]"
                                  onClick={() => {
                                    navigator.clipboard.writeText(script.output);
                                    toast.success("Output copied");
                                  }}
                                >
                                  <Copy className="w-3 h-3" />
                                </Button>
                              </div>
                              <div className="bg-background/80 rounded-md p-2.5 border border-border/30 font-mono text-[11px] text-foreground/70 whitespace-pre overflow-x-auto">
                                {script.output}
                              </div>
                            </div>
                          ))}
                        </div>
                      );
                    })()
                  ) : (
                    <div className="text-center py-8 text-muted-foreground">
                      <FileCode className="w-8 h-8 mx-auto mb-2 opacity-30" />
                      <p className="text-sm">Select a port to view script output</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </div>
        </TabsContent>

        {/* Vulnerabilities */}
        <TabsContent value="vulns" className="space-y-3">
          {hostData.vulnerabilities.map((vuln, i) => {
            const risk = riskColors[vuln.severity];
            return (
              <motion.div
                key={vuln.id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3, delay: i * 0.05 }}
              >
                <Card className={`${risk.border} border bg-card/80`}>
                  <CardContent className="p-4">
                    <div className="flex items-start justify-between gap-4">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <Badge className={`${risk.bg} ${risk.text} ${risk.border} border text-[10px] capitalize`}>
                            {vuln.severity}
                          </Badge>
                          <span className="text-xs font-mono text-muted-foreground">{vuln.id}</span>
                        </div>
                        <h4 className="text-sm font-semibold text-foreground">{vuln.title}</h4>
                        <p className="text-xs text-muted-foreground mt-1">{vuln.description}</p>
                        <div className="flex items-center gap-3 mt-2">
                          <span className="text-[10px] text-muted-foreground">Port: <span className="text-cyan-400 font-mono">{vuln.port}</span></span>
                          <span className="text-[10px] text-muted-foreground">CVSS: <span className="text-foreground font-mono">{vuln.cvss}</span></span>
                        </div>
                      </div>
                      <div className="shrink-0">
                        <div className="w-14 h-14 rounded-full border-2 flex items-center justify-center" style={{ borderColor: vuln.cvss >= 9 ? "#ef4444" : vuln.cvss >= 7 ? "#f97316" : vuln.cvss >= 4 ? "#eab308" : "#22c55e" }}>
                          <span className="text-sm font-bold font-mono" style={{ color: vuln.cvss >= 9 ? "#ef4444" : vuln.cvss >= 7 ? "#f97316" : vuln.cvss >= 4 ? "#eab308" : "#22c55e" }}>
                            {vuln.cvss}
                          </span>
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </motion.div>
            );
          })}
        </TabsContent>

        {/* OS & System */}
        <TabsContent value="os" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card className="border-border/50 bg-card/80">
              <CardHeader className="pb-3">
                <div className="flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-purple-400" />
                  <CardTitle className="text-sm font-semibold font-[Outfit]">Operating System</CardTitle>
                </div>
              </CardHeader>
              <CardContent className="space-y-3">
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Detected OS</p>
                  <p className="text-sm text-foreground font-medium">{hostData.os.name}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">OS Family</p>
                  <p className="text-sm text-foreground">{hostData.os.family}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1">Confidence</p>
                  <div className="flex items-center gap-2">
                    <Progress value={hostData.os.accuracy} className="h-1.5 flex-1" />
                    <span className="text-xs font-mono text-foreground">{hostData.os.accuracy}%</span>
                  </div>
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">CPE</p>
                  <code className="text-xs font-mono text-cyan-400">{hostData.os.cpe}</code>
                </div>
              </CardContent>
            </Card>

            <Card className="border-border/50 bg-card/80">
              <CardHeader className="pb-3">
                <div className="flex items-center gap-2">
                  <HardDrive className="w-4 h-4 text-orange-400" />
                  <CardTitle className="text-sm font-semibold font-[Outfit]">System Info</CardTitle>
                </div>
              </CardHeader>
              <CardContent className="space-y-3">
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">MAC Address</p>
                  <p className="text-sm font-mono text-foreground">{hostData.mac}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Vendor</p>
                  <p className="text-sm text-foreground">{hostData.vendor}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Uptime</p>
                  <p className="text-sm text-foreground">{Math.floor(hostData.uptime.seconds / 86400)} days</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Last Boot</p>
                  <p className="text-sm font-mono text-foreground">{hostData.uptime.lastBoot}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Network Distance</p>
                  <p className="text-sm text-foreground">{hostData.distance} hop(s)</p>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Scan Timeline */}
        <TabsContent value="timeline">
          <Card className="border-border/50 bg-card/80">
            <CardContent className="p-5">
              <div className="relative pl-6">
                {/* Timeline line */}
                <div className="absolute left-[7px] top-2 bottom-2 w-px bg-border/30" />

                <div className="space-y-4">
                  {hostData.scanTimeline.map((event, i) => (
                    <motion.div
                      key={i}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ duration: 0.3, delay: i * 0.04 }}
                      className="relative"
                    >
                      {/* Dot */}
                      <div className={`absolute -left-6 top-1.5 w-3 h-3 rounded-full ${timelineTypeColors[event.type]} border-2 border-background`} />

                      <div className="flex items-start gap-3">
                        <span className="text-[10px] font-mono text-muted-foreground shrink-0 w-16 pt-0.5">
                          {event.time}
                        </span>
                        <p className={`text-sm ${event.type === "vuln" ? "text-red-400" : event.type === "complete" ? "text-green-400" : "text-foreground/80"}`}>
                          {event.event}
                        </p>
                      </div>
                    </motion.div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
