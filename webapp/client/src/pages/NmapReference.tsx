/*
 * NmapReference — Complete Nmap Flag & Option Cheatsheet
 * Spectra Command Dark Theme
 * Organized by category with copy-to-clipboard and search
 */
import { useState, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Search,
  BookOpen,
  Copy,
  Crosshair,
  Network,
  Shield,
  Zap,
  Clock,
  FileOutput,
  Code2,
  Radar,
  Eye,
  Fingerprint,
  Server,
} from "lucide-react";
import { toast } from "sonner";
import { motion } from "framer-motion";

interface NmapFlag {
  flag: string;
  description: string;
  example?: string;
  notes?: string;
}

interface FlagCategory {
  id: string;
  label: string;
  icon: React.ElementType;
  color: string;
  flags: NmapFlag[];
}

const flagCategories: FlagCategory[] = [
  {
    id: "target",
    label: "Target Specification",
    icon: Crosshair,
    color: "text-green-400",
    flags: [
      { flag: "-iL <inputfile>", description: "Input from list of hosts/networks", example: "nmap -iL targets.txt" },
      { flag: "-iR <num hosts>", description: "Choose random targets", example: "nmap -iR 100" },
      { flag: "--exclude <host1[,host2]>", description: "Exclude hosts/networks", example: "nmap --exclude 192.168.1.1" },
      { flag: "--excludefile <file>", description: "Exclude list from file", example: "nmap --excludefile excluded.txt" },
      { flag: "CIDR notation", description: "Scan a subnet", example: "nmap 192.168.1.0/24" },
      { flag: "Range notation", description: "Scan an IP range", example: "nmap 192.168.1.1-254" },
      { flag: "Hostname", description: "Scan by hostname", example: "nmap scanme.nmap.org" },
    ],
  },
  {
    id: "discovery",
    label: "Host Discovery",
    icon: Radar,
    color: "text-cyan-400",
    flags: [
      { flag: "-sL", description: "List scan — simply list targets to scan", notes: "No packets sent" },
      { flag: "-sn", description: "Ping scan — disable port scan", example: "nmap -sn 192.168.1.0/24" },
      { flag: "-Pn", description: "Treat all hosts as online — skip host discovery", example: "nmap -Pn 192.168.1.1" },
      { flag: "-PS <portlist>", description: "TCP SYN discovery to given ports", example: "nmap -PS22,80,443 192.168.1.0/24" },
      { flag: "-PA <portlist>", description: "TCP ACK discovery to given ports", example: "nmap -PA80 192.168.1.0/24" },
      { flag: "-PU <portlist>", description: "UDP discovery to given ports", example: "nmap -PU53 192.168.1.0/24" },
      { flag: "-PE", description: "ICMP echo request discovery", notes: "Default for unprivileged users" },
      { flag: "-PP", description: "ICMP timestamp request discovery" },
      { flag: "-PM", description: "ICMP address mask request discovery" },
      { flag: "-PO <protocol list>", description: "IP Protocol ping" },
      { flag: "-n", description: "Never do DNS resolution", notes: "Speeds up scan" },
      { flag: "-R", description: "Always resolve DNS (default: sometimes)" },
      { flag: "--traceroute", description: "Trace hop path to each host", example: "nmap --traceroute 8.8.8.8" },
    ],
  },
  {
    id: "scan-techniques",
    label: "Scan Techniques",
    icon: Eye,
    color: "text-purple-400",
    flags: [
      { flag: "-sS", description: "TCP SYN scan (stealth)", example: "nmap -sS 192.168.1.1", notes: "Default privileged scan, fast & stealthy" },
      { flag: "-sT", description: "TCP connect scan", example: "nmap -sT 192.168.1.1", notes: "Default unprivileged scan, full TCP handshake" },
      { flag: "-sU", description: "UDP scan", example: "nmap -sU 192.168.1.1", notes: "Slow but important for DNS, SNMP, DHCP" },
      { flag: "-sA", description: "TCP ACK scan", notes: "Map firewall rulesets" },
      { flag: "-sW", description: "TCP Window scan", notes: "Like ACK but detects open ports" },
      { flag: "-sM", description: "TCP Maimon scan", notes: "FIN/ACK probe" },
      { flag: "-sN", description: "TCP Null scan", notes: "No flags set" },
      { flag: "-sF", description: "TCP FIN scan", notes: "Only FIN flag" },
      { flag: "-sX", description: "TCP Xmas scan", notes: "FIN, PSH, URG flags" },
      { flag: "--scanflags <flags>", description: "Customize TCP scan flags", example: "nmap --scanflags URGACKPSH 192.168.1.1" },
      { flag: "-sI <zombie host>", description: "Idle scan (zombie)", notes: "Extremely stealthy, uses third-party host" },
      { flag: "-sO", description: "IP protocol scan", notes: "Determine supported IP protocols" },
      { flag: "-b <FTP relay host>", description: "FTP bounce scan" },
    ],
  },
  {
    id: "port",
    label: "Port Specification",
    icon: Network,
    color: "text-orange-400",
    flags: [
      { flag: "-p <port ranges>", description: "Scan specified ports", example: "nmap -p 22,80,443 192.168.1.1" },
      { flag: "-p-", description: "Scan all 65535 ports", example: "nmap -p- 192.168.1.1", notes: "Thorough but slow" },
      { flag: "-p U:53,T:21-25,80", description: "Scan specific UDP and TCP ports", example: "nmap -p U:53,111,T:21-25,80,443" },
      { flag: "-F", description: "Fast scan — fewer ports than default (100)", example: "nmap -F 192.168.1.0/24" },
      { flag: "--top-ports <n>", description: "Scan <n> most common ports", example: "nmap --top-ports 1000 192.168.1.1" },
      { flag: "-r", description: "Scan ports sequentially — don't randomize" },
    ],
  },
  {
    id: "service",
    label: "Service / Version Detection",
    icon: Fingerprint,
    color: "text-yellow-400",
    flags: [
      { flag: "-sV", description: "Probe open ports to determine service/version", example: "nmap -sV 192.168.1.1" },
      { flag: "--version-intensity <0-9>", description: "Set version scan intensity", example: "nmap -sV --version-intensity 5" },
      { flag: "--version-light", description: "Limit to most likely probes (intensity 2)" },
      { flag: "--version-all", description: "Try every single probe (intensity 9)" },
      { flag: "--version-trace", description: "Show detailed version scan activity" },
    ],
  },
  {
    id: "os",
    label: "OS Detection",
    icon: Server,
    color: "text-red-400",
    flags: [
      { flag: "-O", description: "Enable OS detection", example: "nmap -O 192.168.1.1" },
      { flag: "--osscan-limit", description: "Limit OS detection to promising targets" },
      { flag: "--osscan-guess", description: "Guess OS more aggressively", example: "nmap -O --osscan-guess 192.168.1.1" },
      { flag: "--max-os-tries <n>", description: "Set max number of OS detection tries" },
    ],
  },
  {
    id: "timing",
    label: "Timing & Performance",
    icon: Clock,
    color: "text-cyan-400",
    flags: [
      { flag: "-T0", description: "Paranoid — IDS evasion, very slow", notes: "5 min between probes" },
      { flag: "-T1", description: "Sneaky — IDS evasion, slow", notes: "15 sec between probes" },
      { flag: "-T2", description: "Polite — slows scan to use less bandwidth" },
      { flag: "-T3", description: "Normal — default speed" },
      { flag: "-T4", description: "Aggressive — speeds up, assumes fast network", example: "nmap -T4 192.168.1.0/24" },
      { flag: "-T5", description: "Insane — fastest, may miss ports", notes: "Can overwhelm targets" },
      { flag: "--min-hostgroup <size>", description: "Minimum parallel host scan group" },
      { flag: "--max-hostgroup <size>", description: "Maximum parallel host scan group" },
      { flag: "--min-parallelism <n>", description: "Minimum outstanding probes" },
      { flag: "--max-parallelism <n>", description: "Maximum outstanding probes" },
      { flag: "--min-rtt-timeout <time>", description: "Minimum probe round-trip time" },
      { flag: "--max-rtt-timeout <time>", description: "Maximum probe round-trip time" },
      { flag: "--max-retries <tries>", description: "Caps number of port scan probe retransmissions" },
      { flag: "--host-timeout <time>", description: "Give up on target after this long", example: "nmap --host-timeout 30m" },
      { flag: "--scan-delay <time>", description: "Adjust delay between probes" },
    ],
  },
  {
    id: "scripts",
    label: "NSE Scripts",
    icon: Code2,
    color: "text-green-400",
    flags: [
      { flag: "-sC", description: "Equivalent to --script=default", example: "nmap -sC 192.168.1.1" },
      { flag: "--script <scripts>", description: "Run specified scripts", example: "nmap --script vuln 192.168.1.1" },
      { flag: "--script-args <args>", description: "Provide arguments to scripts", example: "nmap --script http-brute --script-args userdb=users.txt" },
      { flag: "--script-args-file <file>", description: "Provide NSE script args from file" },
      { flag: "--script-trace", description: "Show all data sent and received by scripts" },
      { flag: "--script-updatedb", description: "Update the script database" },
      { flag: "--script-help <scripts>", description: "Show help about scripts", example: "nmap --script-help ssl-heartbleed" },
    ],
  },
  {
    id: "evasion",
    label: "Firewall / IDS Evasion",
    icon: Shield,
    color: "text-red-400",
    flags: [
      { flag: "-f", description: "Fragment packets (8 bytes after IP header)" },
      { flag: "--mtu <val>", description: "Specify custom MTU (must be multiple of 8)" },
      { flag: "-D <decoy1,decoy2,...>", description: "Cloak scan with decoys", example: "nmap -D RND:10 192.168.1.1" },
      { flag: "-S <IP>", description: "Spoof source address" },
      { flag: "-e <iface>", description: "Use specified interface" },
      { flag: "-g / --source-port <port>", description: "Use given source port number", example: "nmap -g 53 192.168.1.1" },
      { flag: "--proxies <url1,...>", description: "Relay connections through HTTP/SOCKS4 proxies" },
      { flag: "--data-length <num>", description: "Append random data to sent packets" },
      { flag: "--ttl <val>", description: "Set IP time-to-live field" },
      { flag: "--spoof-mac <mac>", description: "Spoof MAC address", example: "nmap --spoof-mac 0 192.168.1.1" },
      { flag: "--badsum", description: "Send packets with bogus TCP/UDP checksums" },
    ],
  },
  {
    id: "output",
    label: "Output",
    icon: FileOutput,
    color: "text-purple-400",
    flags: [
      { flag: "-oN <file>", description: "Normal output to file", example: "nmap -oN scan.txt 192.168.1.1" },
      { flag: "-oX <file>", description: "XML output to file", example: "nmap -oX scan.xml 192.168.1.1" },
      { flag: "-oG <file>", description: "Grepable output to file" },
      { flag: "-oA <basename>", description: "Output in all three major formats at once", example: "nmap -oA scan_results 192.168.1.1" },
      { flag: "-v", description: "Increase verbosity level (use -vv for more)" },
      { flag: "-d", description: "Increase debugging level (use -dd for more)" },
      { flag: "--reason", description: "Display the reason a port is in a state" },
      { flag: "--open", description: "Only show open (or possibly open) ports", example: "nmap --open 192.168.1.1" },
      { flag: "--packet-trace", description: "Show all packets sent and received" },
      { flag: "--resume <file>", description: "Resume an aborted scan" },
      { flag: "--stylesheet <url>", description: "XSL stylesheet for XML output" },
      { flag: "--webxml", description: "Reference stylesheet from Nmap.Org for XML" },
    ],
  },
  {
    id: "misc",
    label: "Miscellaneous",
    icon: Zap,
    color: "text-orange-400",
    flags: [
      { flag: "-6", description: "Enable IPv6 scanning" },
      { flag: "-A", description: "Enable OS detection, version detection, script scanning, and traceroute", example: "nmap -A 192.168.1.1" },
      { flag: "--datadir <dirname>", description: "Specify custom Nmap data file location" },
      { flag: "--send-eth", description: "Send using raw ethernet frames" },
      { flag: "--send-ip", description: "Send at raw IP level" },
      { flag: "--privileged", description: "Assume user is fully privileged" },
      { flag: "--unprivileged", description: "Assume user lacks raw socket privileges" },
      { flag: "-V", description: "Print version number" },
      { flag: "-h", description: "Print help summary page" },
    ],
  },
];

export default function NmapReference() {
  const [searchQuery, setSearchQuery] = useState("");

  const filteredCategories = useMemo(() => {
    if (!searchQuery) return flagCategories;
    const q = searchQuery.toLowerCase();
    return flagCategories
      .map((cat) => ({
        ...cat,
        flags: cat.flags.filter(
          (f) =>
            f.flag.toLowerCase().includes(q) ||
            f.description.toLowerCase().includes(q) ||
            (f.notes && f.notes.toLowerCase().includes(q))
        ),
      }))
      .filter((cat) => cat.flags.length > 0);
  }, [searchQuery]);

  const totalFlags = flagCategories.reduce((sum, cat) => sum + cat.flags.length, 0);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success("Copied to clipboard");
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}>
        <div className="flex items-center gap-2 mb-1">
          <BookOpen className="w-4 h-4 text-orange-400" />
          <span className="text-[11px] font-semibold tracking-[0.2em] uppercase text-orange-400">
            Reference
          </span>
        </div>
        <h2 className="text-2xl font-bold text-foreground font-[Outfit]">Nmap Cheatsheet</h2>
        <p className="text-sm text-muted-foreground mt-1">
          Complete reference for {totalFlags} Nmap flags and options across {flagCategories.length} categories.
        </p>
      </motion.div>

      {/* Search */}
      <div className="relative max-w-md">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
        <Input
          placeholder="Search flags, options, descriptions..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="pl-9 bg-input/50 border-border/50 text-sm"
        />
      </div>

      {/* Categories */}
      <div className="space-y-6">
        {filteredCategories.map((category, catIdx) => {
          const Icon = category.icon;
          return (
            <motion.div
              key={category.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3, delay: catIdx * 0.05 }}
            >
              <Card className="border-border/50 bg-card/80 overflow-hidden">
                <CardHeader className="pb-3">
                  <div className="flex items-center gap-2.5">
                    <div className={`p-1.5 rounded-md bg-secondary/80 ${category.color}`}>
                      <Icon className="w-4 h-4" />
                    </div>
                    <CardTitle className="text-base font-semibold font-[Outfit]">{category.label}</CardTitle>
                    <Badge variant="outline" className="ml-auto text-[10px] border-border/40 text-muted-foreground">
                      {category.flags.length} flags
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent className="pt-0">
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-border/30">
                          <th className="text-left py-2 pr-4 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground w-[220px]">
                            Flag
                          </th>
                          <th className="text-left py-2 pr-4 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                            Description
                          </th>
                          <th className="text-left py-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground w-[280px]">
                            Example
                          </th>
                          <th className="w-10" />
                        </tr>
                      </thead>
                      <tbody>
                        {category.flags.map((f, i) => (
                          <tr
                            key={i}
                            className="border-b border-border/10 hover:bg-accent/20 transition-colors group"
                          >
                            <td className="py-2.5 pr-4">
                              <code className="text-xs font-mono text-cyan-400 bg-cyan-500/5 px-1.5 py-0.5 rounded">
                                {f.flag}
                              </code>
                            </td>
                            <td className="py-2.5 pr-4 text-foreground/80">
                              {f.description}
                              {f.notes && (
                                <span className="text-muted-foreground text-xs ml-1">— {f.notes}</span>
                              )}
                            </td>
                            <td className="py-2.5">
                              {f.example && (
                                <code className="text-[11px] font-mono text-green-400/80">{f.example}</code>
                              )}
                            </td>
                            <td className="py-2.5">
                              {f.example && (
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  className="h-6 w-6 p-0 opacity-0 group-hover:opacity-100 transition-opacity text-muted-foreground hover:text-foreground"
                                  onClick={() => copyToClipboard(f.example!)}
                                >
                                  <Copy className="w-3 h-3" />
                                </Button>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          );
        })}
      </div>

      {/* Quick Reference Cards */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.3 }}
      >
        <h3 className="text-lg font-semibold font-[Outfit] text-foreground mb-4">Common Scan Recipes</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {[
            { title: "Quick Network Sweep", cmd: "nmap -sn -T4 192.168.1.0/24", desc: "Discover live hosts without port scanning" },
            { title: "Full Port + Service", cmd: "nmap -p- -sV -T4 192.168.1.1", desc: "Scan all 65535 ports with version detection" },
            { title: "Aggressive Audit", cmd: "nmap -A -T4 -p- 192.168.1.1", desc: "OS, version, scripts, and traceroute" },
            { title: "Stealth SYN Scan", cmd: "nmap -sS -T2 -f 192.168.1.1", desc: "Low-profile fragmented SYN scan" },
            { title: "Vulnerability Check", cmd: "nmap -sV --script vuln 192.168.1.1", desc: "Run all vulnerability detection scripts" },
            { title: "Top 100 UDP", cmd: "nmap -sU --top-ports 100 192.168.1.1", desc: "Scan top 100 UDP ports" },
          ].map((recipe, i) => (
            <Card key={i} className="border-border/30 bg-card/60 hover:bg-card/80 transition-colors group">
              <CardContent className="p-4">
                <div className="flex items-start justify-between">
                  <div>
                    <p className="text-sm font-medium text-foreground">{recipe.title}</p>
                    <p className="text-xs text-muted-foreground mt-0.5">{recipe.desc}</p>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 px-2 text-[10px] opacity-0 group-hover:opacity-100 transition-opacity text-muted-foreground hover:text-foreground shrink-0"
                    onClick={() => copyToClipboard(recipe.cmd)}
                  >
                    <Copy className="w-3 h-3 mr-1" />
                    Copy
                  </Button>
                </div>
                <div className="mt-2 bg-background/80 rounded-md px-3 py-2 border border-border/20 font-mono text-xs text-green-400 overflow-x-auto">
                  <span className="text-muted-foreground">$ </span>{recipe.cmd}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </motion.div>
    </div>
  );
}
