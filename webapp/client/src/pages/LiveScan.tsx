/*
 * LiveScan — Real-Time Scan Progress View
 * Spectra Command Dark Theme
 * Terminal output streaming, host discovery feed, port discovery animation
 */
import { useState, useEffect, useRef, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Play,
  Pause,
  Square,
  Terminal,
  Activity,
  Server,
  Wifi,
  Clock,
  ChevronRight,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  Crosshair,
  Zap,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

interface TerminalLine {
  timestamp: string;
  text: string;
  type: "info" | "discovery" | "port" | "warning" | "complete" | "system";
}

interface DiscoveredHost {
  ip: string;
  hostname?: string;
  os?: string;
  status: "up" | "filtered";
  ports: { port: number; service: string; state: string; version?: string }[];
  discoveredAt: number;
}

const typeColors: Record<string, string> = {
  info: "text-foreground/70",
  discovery: "text-green-400",
  port: "text-cyan-400",
  warning: "text-yellow-400",
  complete: "text-purple-400",
  system: "text-muted-foreground",
};

// Simulated scan data
const simulatedTerminalLines: Omit<TerminalLine, "timestamp">[] = [
  { text: "Starting Nmap 7.94SVN ( https://nmap.org )", type: "system" },
  { text: "Initiating Ping Scan at 08:15", type: "system" },
  { text: "Scanning 256 hosts [4 ports/host]", type: "info" },
  { text: "Completed Ping Scan at 08:15, 2.34s elapsed (256 total hosts)", type: "system" },
  { text: "Nmap scan report for 192.168.1.1", type: "discovery" },
  { text: "Host is up (0.0012s latency).", type: "discovery" },
  { text: "Initiating SYN Stealth Scan at 08:15", type: "system" },
  { text: "Discovered open port 22/tcp on 192.168.1.1", type: "port" },
  { text: "Discovered open port 80/tcp on 192.168.1.1", type: "port" },
  { text: "Discovered open port 443/tcp on 192.168.1.1", type: "port" },
  { text: "Nmap scan report for 192.168.1.5", type: "discovery" },
  { text: "Host is up (0.0034s latency).", type: "discovery" },
  { text: "Discovered open port 22/tcp on 192.168.1.5", type: "port" },
  { text: "Discovered open port 3306/tcp on 192.168.1.5", type: "port" },
  { text: "Discovered open port 8080/tcp on 192.168.1.5", type: "port" },
  { text: "WARNING: RST from 192.168.1.10 — host may be behind firewall", type: "warning" },
  { text: "Nmap scan report for 192.168.1.10", type: "discovery" },
  { text: "Host is up (0.0089s latency).", type: "discovery" },
  { text: "Discovered open port 445/tcp on 192.168.1.10", type: "port" },
  { text: "Discovered open port 139/tcp on 192.168.1.10", type: "port" },
  { text: "Initiating Service scan at 08:16", type: "system" },
  { text: "Scanning 8 services on 3 hosts", type: "info" },
  { text: "Completed Service scan at 08:16, 11.05s elapsed (8 services)", type: "system" },
  { text: "Nmap scan report for 192.168.1.25", type: "discovery" },
  { text: "Host is up (0.0056s latency).", type: "discovery" },
  { text: "Discovered open port 21/tcp on 192.168.1.25", type: "port" },
  { text: "Discovered open port 80/tcp on 192.168.1.25", type: "port" },
  { text: "Discovered open port 443/tcp on 192.168.1.25", type: "port" },
  { text: "Discovered open port 8443/tcp on 192.168.1.25", type: "port" },
  { text: "WARNING: Weak cipher suites detected on 192.168.1.25:443", type: "warning" },
  { text: "Initiating OS detection at 08:17", type: "system" },
  { text: "Nmap scan report for 192.168.1.50", type: "discovery" },
  { text: "Host is up (0.0023s latency).", type: "discovery" },
  { text: "Discovered open port 53/tcp on 192.168.1.50", type: "port" },
  { text: "Discovered open port 53/udp on 192.168.1.50", type: "port" },
  { text: "Discovered open port 953/tcp on 192.168.1.50", type: "port" },
  { text: "OS detection: Linux 5.4 - 5.15 (96% confidence)", type: "info" },
  { text: "Completed OS detection at 08:17, 3.22s elapsed", type: "system" },
  { text: "NSE: Script scanning 5 hosts.", type: "system" },
  { text: "Completed NSE at 08:18, 15.34s elapsed", type: "system" },
  { text: "Nmap done: 256 IP addresses (5 hosts up) scanned in 32.95 seconds", type: "complete" },
];

const simulatedHosts: DiscoveredHost[] = [
  {
    ip: "192.168.1.1",
    hostname: "gateway.local",
    os: "Linux 5.15 (OpenWrt)",
    status: "up",
    ports: [
      { port: 22, service: "ssh", state: "open", version: "OpenSSH 8.9" },
      { port: 80, service: "http", state: "open", version: "nginx 1.24" },
      { port: 443, service: "https", state: "open", version: "nginx 1.24" },
    ],
    discoveredAt: 3,
  },
  {
    ip: "192.168.1.5",
    hostname: "db-server.local",
    os: "Ubuntu 22.04",
    status: "up",
    ports: [
      { port: 22, service: "ssh", state: "open", version: "OpenSSH 8.9" },
      { port: 3306, service: "mysql", state: "open", version: "MySQL 8.0.32" },
      { port: 8080, service: "http-proxy", state: "open", version: "Apache Tomcat 9.0" },
    ],
    discoveredAt: 8,
  },
  {
    ip: "192.168.1.10",
    hostname: "workstation-01",
    os: "Windows 10 Pro",
    status: "up",
    ports: [
      { port: 445, service: "microsoft-ds", state: "open" },
      { port: 139, service: "netbios-ssn", state: "open" },
    ],
    discoveredAt: 14,
  },
  {
    ip: "192.168.1.25",
    hostname: "web-server.local",
    os: "Debian 11",
    status: "up",
    ports: [
      { port: 21, service: "ftp", state: "open", version: "vsftpd 3.0.3" },
      { port: 80, service: "http", state: "open", version: "Apache 2.4.54" },
      { port: 443, service: "https", state: "open", version: "Apache 2.4.54" },
      { port: 8443, service: "https-alt", state: "open" },
    ],
    discoveredAt: 20,
  },
  {
    ip: "192.168.1.50",
    hostname: "dns-server.local",
    os: "Linux 5.4",
    status: "up",
    ports: [
      { port: 53, service: "domain", state: "open", version: "BIND 9.18" },
      { port: 953, service: "rndc", state: "open" },
    ],
    discoveredAt: 26,
  },
];

export default function LiveScan() {
  const [isRunning, setIsRunning] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const [progress, setProgress] = useState(0);
  const [terminalLines, setTerminalLines] = useState<TerminalLine[]>([]);
  const [discoveredHosts, setDiscoveredHosts] = useState<DiscoveredHost[]>([]);
  const [lineIndex, setLineIndex] = useState(0);
  const [elapsedTime, setElapsedTime] = useState(0);
  const [selectedHost, setSelectedHost] = useState<DiscoveredHost | null>(null);
  const terminalRef = useRef<HTMLDivElement>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const getTimestamp = useCallback(() => {
    const now = new Date();
    return now.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }, []);

  const startScan = useCallback(() => {
    setIsRunning(true);
    setIsPaused(false);
    setTerminalLines([]);
    setDiscoveredHosts([]);
    setLineIndex(0);
    setProgress(0);
    setElapsedTime(0);
    setSelectedHost(null);
  }, []);

  const stopScan = useCallback(() => {
    setIsRunning(false);
    setIsPaused(false);
    if (intervalRef.current) clearInterval(intervalRef.current);
    if (timerRef.current) clearInterval(timerRef.current);
  }, []);

  const togglePause = useCallback(() => {
    setIsPaused((prev) => !prev);
  }, []);

  // Terminal line feeder
  useEffect(() => {
    if (!isRunning || isPaused) {
      if (intervalRef.current) clearInterval(intervalRef.current);
      return;
    }

    intervalRef.current = setInterval(() => {
      setLineIndex((prev) => {
        if (prev >= simulatedTerminalLines.length) {
          setIsRunning(false);
          return prev;
        }
        const line = simulatedTerminalLines[prev];
        setTerminalLines((lines) => [
          ...lines,
          { ...line, timestamp: new Date().toLocaleTimeString("en-US", { hour12: false }) },
        ]);
        setProgress(Math.round(((prev + 1) / simulatedTerminalLines.length) * 100));

        // Check if we should add a discovered host
        const hostToAdd = simulatedHosts.find((h) => h.discoveredAt === prev);
        if (hostToAdd) {
          setDiscoveredHosts((hosts) => [...hosts, hostToAdd]);
        }

        return prev + 1;
      });
    }, 400 + Math.random() * 300);

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [isRunning, isPaused]);

  // Elapsed time counter
  useEffect(() => {
    if (!isRunning || isPaused) {
      if (timerRef.current) clearInterval(timerRef.current);
      return;
    }

    timerRef.current = setInterval(() => {
      setElapsedTime((prev) => prev + 1);
    }, 1000);

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [isRunning, isPaused]);

  // Auto-scroll terminal
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [terminalLines]);

  const formatTime = (seconds: number) => {
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return `${m.toString().padStart(2, "0")}:${s.toString().padStart(2, "0")}`;
  };

  const totalPorts = discoveredHosts.reduce((sum, h) => sum + h.ports.length, 0);

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}>
        <div className="flex items-center gap-2 mb-1">
          <Activity className="w-4 h-4 text-green-400" />
          <span className="text-[11px] font-semibold tracking-[0.2em] uppercase text-green-400">
            Live Monitor
          </span>
        </div>
        <h2 className="text-2xl font-bold text-foreground font-[Outfit]">Scan Progress</h2>
        <p className="text-sm text-muted-foreground mt-1">
          Real-time scan execution monitor with terminal output and host discovery feed.
        </p>
      </motion.div>

      {/* Controls & Status Bar */}
      <Card className="border-border/50 bg-card/80">
        <CardContent className="p-4">
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
            {/* Controls */}
            <div className="flex items-center gap-2">
              {!isRunning ? (
                <Button onClick={startScan} className="bg-green-600 hover:bg-green-700 text-white gap-2">
                  <Play className="w-4 h-4" />
                  {terminalLines.length > 0 ? "Restart Demo" : "Start Demo Scan"}
                </Button>
              ) : (
                <>
                  <Button onClick={togglePause} variant="outline" className="gap-2 border-border/50">
                    {isPaused ? <Play className="w-4 h-4" /> : <Pause className="w-4 h-4" />}
                    {isPaused ? "Resume" : "Pause"}
                  </Button>
                  <Button onClick={stopScan} variant="outline" className="gap-2 border-red-500/30 text-red-400 hover:bg-red-500/10">
                    <Square className="w-4 h-4" />
                    Stop
                  </Button>
                </>
              )}
            </div>

            <Separator orientation="vertical" className="h-8 hidden sm:block bg-border/30" />

            {/* Stats */}
            <div className="flex items-center gap-6 text-sm">
              <div className="flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-muted-foreground" />
                <span className="text-muted-foreground">Elapsed:</span>
                <span className="font-mono text-foreground">{formatTime(elapsedTime)}</span>
              </div>
              <div className="flex items-center gap-1.5">
                <Server className="w-3.5 h-3.5 text-green-400" />
                <span className="text-muted-foreground">Hosts:</span>
                <span className="font-mono text-green-400">{discoveredHosts.length}</span>
              </div>
              <div className="flex items-center gap-1.5">
                <Wifi className="w-3.5 h-3.5 text-cyan-400" />
                <span className="text-muted-foreground">Ports:</span>
                <span className="font-mono text-cyan-400">{totalPorts}</span>
              </div>
              <div className="flex items-center gap-1.5">
                {isRunning ? (
                  isPaused ? (
                    <Badge className="bg-yellow-500/10 text-yellow-400 border border-yellow-500/30 text-[10px]">Paused</Badge>
                  ) : (
                    <Badge className="bg-green-500/10 text-green-400 border border-green-500/30 text-[10px] gap-1">
                      <Loader2 className="w-3 h-3 animate-spin" />
                      Scanning
                    </Badge>
                  )
                ) : progress >= 100 ? (
                  <Badge className="bg-purple-500/10 text-purple-400 border border-purple-500/30 text-[10px] gap-1">
                    <CheckCircle2 className="w-3 h-3" />
                    Complete
                  </Badge>
                ) : (
                  <Badge className="bg-secondary text-muted-foreground text-[10px]">Idle</Badge>
                )}
              </div>
            </div>
          </div>

          {/* Progress bar */}
          {(isRunning || progress > 0) && (
            <div className="mt-4">
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-xs text-muted-foreground">Scan progress</span>
                <span className="text-xs font-mono text-foreground">{progress}%</span>
              </div>
              <Progress value={progress} className="h-1.5" />
            </div>
          )}
        </CardContent>
      </Card>

      {/* Main content: Terminal + Host Discovery */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        {/* Terminal Output */}
        <div className="xl:col-span-2">
          <Card className="border-border/50 bg-card/80 h-[500px] flex flex-col">
            <CardHeader className="pb-2 shrink-0">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-green-400" />
                <CardTitle className="text-sm font-semibold font-[Outfit]">Terminal Output</CardTitle>
                <span className="text-[10px] text-muted-foreground ml-auto">{terminalLines.length} lines</span>
              </div>
            </CardHeader>
            <CardContent className="flex-1 overflow-hidden pt-0 pb-3 px-3">
              <div
                ref={terminalRef}
                className="h-full overflow-y-auto bg-background/80 rounded-lg border border-border/30 p-3 font-mono text-xs space-y-0.5"
              >
                {terminalLines.length === 0 && (
                  <div className="flex items-center justify-center h-full text-muted-foreground text-sm">
                    <div className="text-center">
                      <Terminal className="w-8 h-8 mx-auto mb-2 opacity-30" />
                      <p>Click "Start Demo Scan" to begin</p>
                      <p className="text-[10px] mt-1">Simulates scanning 192.168.1.0/24</p>
                    </div>
                  </div>
                )}
                <AnimatePresence>
                  {terminalLines.map((line, i) => (
                    <motion.div
                      key={i}
                      initial={{ opacity: 0, x: -5 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ duration: 0.15 }}
                      className={`${typeColors[line.type]} leading-relaxed`}
                    >
                      <span className="text-muted-foreground/50">[{line.timestamp}] </span>
                      {line.text}
                    </motion.div>
                  ))}
                </AnimatePresence>
                {isRunning && !isPaused && (
                  <motion.span
                    animate={{ opacity: [1, 0] }}
                    transition={{ duration: 0.8, repeat: Infinity }}
                    className="text-green-400"
                  >
                    █
                  </motion.span>
                )}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Host Discovery Feed */}
        <div className="xl:col-span-1">
          <Card className="border-border/50 bg-card/80 h-[500px] flex flex-col">
            <CardHeader className="pb-2 shrink-0">
              <div className="flex items-center gap-2">
                <Server className="w-4 h-4 text-cyan-400" />
                <CardTitle className="text-sm font-semibold font-[Outfit]">Discovered Hosts</CardTitle>
                <Badge variant="outline" className="ml-auto text-[10px] border-cyan-500/30 text-cyan-400">
                  {discoveredHosts.length}
                </Badge>
              </div>
            </CardHeader>
            <CardContent className="flex-1 overflow-hidden pt-0 pb-3 px-3">
              <ScrollArea className="h-full">
                <div className="space-y-2">
                  {discoveredHosts.length === 0 && (
                    <div className="flex items-center justify-center h-64 text-muted-foreground text-sm">
                      <div className="text-center">
                        <Crosshair className="w-8 h-8 mx-auto mb-2 opacity-30" />
                        <p>Waiting for host discovery...</p>
                      </div>
                    </div>
                  )}
                  <AnimatePresence>
                    {discoveredHosts.map((host) => (
                      <motion.div
                        key={host.ip}
                        initial={{ opacity: 0, y: 10, scale: 0.95 }}
                        animate={{ opacity: 1, y: 0, scale: 1 }}
                        transition={{ duration: 0.3, type: "spring" }}
                      >
                        <button
                          onClick={() => setSelectedHost(selectedHost?.ip === host.ip ? null : host)}
                          className={`
                            w-full text-left p-3 rounded-lg border transition-all duration-200
                            ${selectedHost?.ip === host.ip
                              ? "border-cyan-500/30 bg-cyan-500/5"
                              : "border-border/30 bg-background/50 hover:border-border/50 hover:bg-background/80"
                            }
                          `}
                        >
                          <div className="flex items-center justify-between mb-1.5">
                            <div className="flex items-center gap-2">
                              <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                              <span className="text-sm font-mono font-medium text-foreground">{host.ip}</span>
                            </div>
                            <Badge className="bg-green-500/10 text-green-400 border border-green-500/30 text-[9px]">
                              {host.ports.length} ports
                            </Badge>
                          </div>
                          {host.hostname && (
                            <p className="text-[11px] text-muted-foreground mb-1">{host.hostname}</p>
                          )}
                          {host.os && (
                            <p className="text-[10px] text-purple-400/70">{host.os}</p>
                          )}

                          {/* Expanded port list */}
                          <AnimatePresence>
                            {selectedHost?.ip === host.ip && (
                              <motion.div
                                initial={{ height: 0, opacity: 0 }}
                                animate={{ height: "auto", opacity: 1 }}
                                exit={{ height: 0, opacity: 0 }}
                                transition={{ duration: 0.2 }}
                                className="overflow-hidden"
                              >
                                <Separator className="my-2 bg-border/20" />
                                <div className="space-y-1">
                                  {host.ports.map((port) => (
                                    <div key={`${port.port}-${port.service}`} className="flex items-center gap-2 text-[11px]">
                                      <span className="text-cyan-400 font-mono w-12">{port.port}</span>
                                      <span className="text-foreground/70">{port.service}</span>
                                      {port.version && (
                                        <span className="text-muted-foreground ml-auto text-[10px] truncate max-w-[120px]">
                                          {port.version}
                                        </span>
                                      )}
                                    </div>
                                  ))}
                                </div>
                              </motion.div>
                            )}
                          </AnimatePresence>
                        </button>
                      </motion.div>
                    ))}
                  </AnimatePresence>
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Scan Summary (shown when complete) */}
      <AnimatePresence>
        {progress >= 100 && !isRunning && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 20 }}
            transition={{ duration: 0.5 }}
          >
            <Card className="border-purple-500/30 bg-purple-500/5">
              <CardContent className="p-5">
                <div className="flex items-center gap-2 mb-3">
                  <CheckCircle2 className="w-5 h-5 text-purple-400" />
                  <h3 className="text-lg font-semibold font-[Outfit] text-foreground">Scan Complete</h3>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                  <div>
                    <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Duration</p>
                    <p className="text-lg font-mono text-foreground">{formatTime(elapsedTime)}</p>
                  </div>
                  <div>
                    <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Hosts Up</p>
                    <p className="text-lg font-mono text-green-400">{discoveredHosts.length}/256</p>
                  </div>
                  <div>
                    <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Open Ports</p>
                    <p className="text-lg font-mono text-cyan-400">{totalPorts}</p>
                  </div>
                  <div>
                    <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Warnings</p>
                    <p className="text-lg font-mono text-yellow-400">
                      {terminalLines.filter((l) => l.type === "warning").length}
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
