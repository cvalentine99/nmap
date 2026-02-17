/*
 * NseScripts — NSE Script Browser
 * Spectra Command Dark Theme
 * Browse, search, and explore all Nmap Scripting Engine scripts by category
 */
import { useState, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Search,
  Code2,
  Shield,
  AlertTriangle,
  Info,
  Copy,
  ChevronRight,
  Filter,
  BookOpen,
  Zap,
  Lock,
  Globe,
  Database,
  Wifi,
  Bug,
  FileCode,
  Network,
} from "lucide-react";
import { toast } from "sonner";
import { motion, AnimatePresence } from "framer-motion";

interface NseScript {
  name: string;
  category: string[];
  risk: "safe" | "intrusive" | "exploit" | "dos";
  description: string;
  usage: string;
  output: string;
  ports?: string;
}

const nseCategories = [
  { id: "all", label: "All Scripts", icon: Code2, count: 42 },
  { id: "auth", label: "Auth", icon: Lock, count: 6 },
  { id: "broadcast", label: "Broadcast", icon: Wifi, count: 4 },
  { id: "brute", label: "Brute Force", icon: Zap, count: 5 },
  { id: "default", label: "Default", icon: Shield, count: 8 },
  { id: "discovery", label: "Discovery", icon: Search, count: 7 },
  { id: "exploit", label: "Exploit", icon: Bug, count: 4 },
  { id: "external", label: "External", icon: Globe, count: 2 },
  { id: "fuzzer", label: "Fuzzer", icon: AlertTriangle, count: 2 },
  { id: "malware", label: "Malware", icon: AlertTriangle, count: 2 },
  { id: "safe", label: "Safe", icon: Shield, count: 12 },
  { id: "version", label: "Version", icon: Database, count: 5 },
  { id: "vuln", label: "Vuln", icon: Bug, count: 8 },
];

const riskColors: Record<string, { bg: string; text: string; border: string }> = {
  safe: { bg: "bg-green-500/10", text: "text-green-400", border: "border-green-500/30" },
  intrusive: { bg: "bg-yellow-500/10", text: "text-yellow-400", border: "border-yellow-500/30" },
  exploit: { bg: "bg-red-500/10", text: "text-red-400", border: "border-red-500/30" },
  dos: { bg: "bg-red-600/10", text: "text-red-500", border: "border-red-600/30" },
};

const scripts: NseScript[] = [
  {
    name: "ssh-brute",
    category: ["brute", "intrusive"],
    risk: "intrusive",
    description: "Performs brute-force password auditing against SSH servers. Uses a dictionary of common usernames and passwords to attempt authentication.",
    usage: "nmap -p 22 --script ssh-brute <target>",
    output: "22/tcp open  ssh\n| ssh-brute:\n|   Accounts:\n|     admin:password - Valid credentials\n|_  Statistics: Performed 1024 guesses in 45 seconds",
    ports: "22",
  },
  {
    name: "http-title",
    category: ["default", "discovery", "safe"],
    risk: "safe",
    description: "Shows the title of the default page of a web server. The script also follows redirects and reports the final destination URL.",
    usage: "nmap -p 80 --script http-title <target>",
    output: "80/tcp open  http\n|_http-title: Welcome to nginx!",
    ports: "80,443,8080,8443",
  },
  {
    name: "ssl-heartbleed",
    category: ["vuln", "safe"],
    risk: "safe",
    description: "Detects whether a server is vulnerable to the OpenSSL Heartbleed bug (CVE-2014-0160). Does not exploit the vulnerability.",
    usage: "nmap -p 443 --script ssl-heartbleed <target>",
    output: "443/tcp open  https\n| ssl-heartbleed:\n|   VULNERABLE:\n|   The Heartbleed Bug is a serious vulnerability in OpenSSL\n|     State: VULNERABLE\n|     Risk factor: High\n|       CVE: CVE-2014-0160",
    ports: "443",
  },
  {
    name: "smb-vuln-ms17-010",
    category: ["vuln", "safe"],
    risk: "safe",
    description: "Detects Microsoft Windows systems vulnerable to the remote code execution vulnerability MS17-010 (EternalBlue). Does not attempt exploitation.",
    usage: "nmap -p 445 --script smb-vuln-ms17-010 <target>",
    output: "445/tcp open  microsoft-ds\n| smb-vuln-ms17-010:\n|   VULNERABLE:\n|   Remote Code Execution vulnerability in Microsoft SMBv1\n|     State: VULNERABLE\n|     Risk factor: HIGH\n|       CVE: CVE-2017-0143",
    ports: "445",
  },
  {
    name: "dns-brute",
    category: ["discovery", "intrusive"],
    risk: "intrusive",
    description: "Attempts to enumerate DNS hostnames by brute force guessing of common subdomains. Useful for discovering hidden services and subdomains.",
    usage: "nmap --script dns-brute <target>",
    output: "Host script results:\n| dns-brute:\n|   DNS Brute-force hostnames:\n|     www.example.com - 93.184.216.34\n|     mail.example.com - 93.184.216.35\n|     ftp.example.com - 93.184.216.36",
  },
  {
    name: "vuln",
    category: ["vuln"],
    risk: "safe",
    description: "Runs all scripts in the vuln category. Checks for known vulnerabilities across all detected services. Comprehensive but time-consuming.",
    usage: "nmap --script vuln <target>",
    output: "Multiple vulnerability check results...\nSee individual vuln scripts for output format.",
  },
  {
    name: "http-enum",
    category: ["discovery", "intrusive"],
    risk: "intrusive",
    description: "Enumerates directories used by popular web applications and servers. Checks for the existence of common web paths and files.",
    usage: "nmap -p 80 --script http-enum <target>",
    output: "80/tcp open  http\n| http-enum:\n|   /admin/: Possible admin folder\n|   /robots.txt: Robots file\n|   /phpmyadmin/: phpMyAdmin\n|_  /.git/HEAD: Git folder",
    ports: "80,443,8080",
  },
  {
    name: "banner",
    category: ["discovery", "safe"],
    risk: "safe",
    description: "Connects to open ports and prints out anything sent by the listening service. Useful for identifying unknown or custom services.",
    usage: "nmap --script banner -p 1-10000 <target>",
    output: "22/tcp open  ssh\n|_banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\n80/tcp open  http\n|_banner: HTTP/1.1 200 OK",
    ports: "1-65535",
  },
  {
    name: "ssl-cert",
    category: ["default", "discovery", "safe"],
    risk: "safe",
    description: "Retrieves a server's SSL certificate. Displays the subject, issuer, validity dates, and public key information.",
    usage: "nmap -p 443 --script ssl-cert <target>",
    output: "443/tcp open  https\n| ssl-cert: Subject: commonName=example.com\n| Issuer: commonName=R3/organizationName=Let's Encrypt\n| Not valid before: 2024-01-15\n| Not valid after:  2024-04-15",
    ports: "443,8443",
  },
  {
    name: "ftp-anon",
    category: ["auth", "default", "safe"],
    risk: "safe",
    description: "Checks if an FTP server allows anonymous login. Reports whether anonymous access is permitted and what files are accessible.",
    usage: "nmap -p 21 --script ftp-anon <target>",
    output: "21/tcp open  ftp\n| ftp-anon: Anonymous FTP login allowed (FTP code 230)\n| drwxr-xr-x  2 ftp ftp  4096 Jan 15 pub\n|_-rw-r--r--  1 ftp ftp   187 Jan 15 welcome.msg",
    ports: "21",
  },
  {
    name: "smb-enum-shares",
    category: ["discovery", "intrusive"],
    risk: "intrusive",
    description: "Enumerates shared folders on SMB/CIFS servers. Shows share names, types, comments, and access permissions.",
    usage: "nmap -p 445 --script smb-enum-shares <target>",
    output: "445/tcp open  microsoft-ds\n| smb-enum-shares:\n|   ADMIN$ - Remote Admin (access: denied)\n|   C$ - Default share (access: denied)\n|   IPC$ - Remote IPC (access: read)\n|_  Public - (access: read/write)",
    ports: "445",
  },
  {
    name: "http-sql-injection",
    category: ["vuln", "intrusive"],
    risk: "intrusive",
    description: "Spiders a web server looking for URLs containing queries vulnerable to SQL injection. Tests common injection patterns.",
    usage: "nmap -p 80 --script http-sql-injection <target>",
    output: "80/tcp open  http\n| http-sql-injection:\n|   Possible sqli for queries:\n|     http://example.com/page.php?id=1' OR '1'='1\n|_    http://example.com/search.php?q=test' UNION SELECT",
    ports: "80,443",
  },
  {
    name: "snmp-brute",
    category: ["brute", "intrusive"],
    risk: "intrusive",
    description: "Attempts to find SNMP community strings by brute force guessing. Tests common community string names against SNMP services.",
    usage: "nmap -sU -p 161 --script snmp-brute <target>",
    output: "161/udp open  snmp\n| snmp-brute:\n|   public - Valid credentials\n|_  private - Valid credentials",
    ports: "161",
  },
  {
    name: "mysql-info",
    category: ["default", "discovery", "safe"],
    risk: "safe",
    description: "Connects to a MySQL server and prints information such as the protocol, version, thread ID, status, capabilities, and the password salt.",
    usage: "nmap -p 3306 --script mysql-info <target>",
    output: "3306/tcp open  mysql\n| mysql-info:\n|   Protocol: 10\n|   Version: 8.0.32-0ubuntu0.22.04.2\n|   Thread ID: 15\n|   Capabilities: 65535\n|_  Salt: aBcDeFgHiJkLmNoPqRsT",
    ports: "3306",
  },
  {
    name: "broadcast-dhcp-discover",
    category: ["broadcast", "safe"],
    risk: "safe",
    description: "Sends a DHCP request to the broadcast address and reports the results. Useful for discovering DHCP servers on the local network.",
    usage: "nmap --script broadcast-dhcp-discover",
    output: "Pre-scan script results:\n| broadcast-dhcp-discover:\n|   Response 1 of 1:\n|     IP Offered: 192.168.1.100\n|     DHCP Message Type: DHCPOFFER\n|     Server Identifier: 192.168.1.1\n|     Subnet Mask: 255.255.255.0\n|_    Router: 192.168.1.1",
  },
  {
    name: "traceroute-geolocation",
    category: ["discovery", "safe", "external"],
    risk: "safe",
    description: "Lists the geographic locations of each hop in a traceroute and optionally saves the results to a KML file for Google Earth.",
    usage: "nmap --traceroute --script traceroute-geolocation <target>",
    output: "TRACEROUTE (using port 80/tcp)\nHOP RTT     ADDRESS          GEOLOCATION\n1   1.00ms  192.168.1.1      - ,-\n2   5.00ms  10.0.0.1         40.7128,-74.0060 US\n3   15.0ms  93.184.216.34    51.5074,-0.1278 GB",
  },
  {
    name: "ssh-hostkey",
    category: ["default", "safe"],
    risk: "safe",
    description: "Shows the target SSH server's key fingerprint and (with high enough verbosity level) the public key itself.",
    usage: "nmap -p 22 --script ssh-hostkey <target>",
    output: "22/tcp open  ssh\n| ssh-hostkey:\n|   3072 SHA256:abc123... (RSA)\n|   256  SHA256:def456... (ECDSA)\n|_  256  SHA256:ghi789... (ED25519)",
    ports: "22",
  },
  {
    name: "http-headers",
    category: ["discovery", "safe"],
    risk: "safe",
    description: "Performs a HEAD request for the root folder of a web server and displays the HTTP headers returned.",
    usage: "nmap -p 80 --script http-headers <target>",
    output: "80/tcp open  http\n| http-headers:\n|   Server: nginx/1.24.0\n|   Content-Type: text/html\n|   X-Frame-Options: SAMEORIGIN\n|   Strict-Transport-Security: max-age=31536000\n|_  X-Content-Type-Options: nosniff",
    ports: "80,443",
  },
  {
    name: "whois-ip",
    category: ["discovery", "external", "safe"],
    risk: "safe",
    description: "Queries the WHOIS services for the target IP address and provides information about the IP address allocation.",
    usage: "nmap --script whois-ip <target>",
    output: "Host script results:\n| whois-ip:\n|   NetRange: 93.184.216.0 - 93.184.216.255\n|   OrgName: Edgecast Inc.\n|   Country: US\n|_  RegDate: 2014-03-28",
  },
  {
    name: "firewall-bypass",
    category: ["vuln", "intrusive"],
    risk: "intrusive",
    description: "Detects a vulnerability in netfilter and other firewalls that use helpers to dynamically open ports for protocols such as FTP and SIP.",
    usage: "nmap --script firewall-bypass <target>",
    output: "Host script results:\n| firewall-bypass:\n|   VULNERABLE:\n|   Firewall helper module vulnerability\n|     State: VULNERABLE\n|_    Description: Conntrack helpers can be abused to bypass firewall rules",
  },
  {
    name: "smtp-enum-users",
    category: ["auth", "intrusive"],
    risk: "intrusive",
    description: "Attempts to enumerate the users on an SMTP server by issuing VRFY, EXPN, or RCPT TO commands.",
    usage: "nmap -p 25 --script smtp-enum-users <target>",
    output: "25/tcp open  smtp\n| smtp-enum-users:\n|   root\n|   admin\n|   postmaster\n|_  webmaster",
    ports: "25",
  },
];

export default function NseScripts() {
  const [searchQuery, setSearchQuery] = useState("");
  const [activeCategory, setActiveCategory] = useState("all");
  const [selectedScript, setSelectedScript] = useState<NseScript | null>(null);

  const filteredScripts = useMemo(() => {
    return scripts.filter((s) => {
      const matchesSearch =
        !searchQuery ||
        s.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        s.description.toLowerCase().includes(searchQuery.toLowerCase());
      const matchesCategory =
        activeCategory === "all" || s.category.includes(activeCategory);
      return matchesSearch && matchesCategory;
    });
  }, [searchQuery, activeCategory]);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success("Copied to clipboard");
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}>
        <div className="flex items-center gap-2 mb-1">
          <Code2 className="w-4 h-4 text-cyan-400" />
          <span className="text-[11px] font-semibold tracking-[0.2em] uppercase text-cyan-400">
            Scripting Engine
          </span>
        </div>
        <h2 className="text-2xl font-bold text-foreground font-[Outfit]">NSE Script Browser</h2>
        <p className="text-sm text-muted-foreground mt-1">
          Browse, search, and explore {scripts.length} Nmap Scripting Engine scripts across {nseCategories.length - 1} categories.
        </p>
      </motion.div>

      <div className="flex flex-col lg:flex-row gap-6">
        {/* Left: Categories + Search */}
        <div className="lg:w-72 shrink-0 space-y-4">
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              placeholder="Search scripts..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-9 bg-input/50 border-border/50 text-sm"
            />
          </div>

          {/* Category list */}
          <Card className="border-border/50 bg-card/80">
            <CardHeader className="pb-2 pt-4 px-4">
              <div className="flex items-center gap-2">
                <Filter className="w-3.5 h-3.5 text-muted-foreground" />
                <CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Categories
                </CardTitle>
              </div>
            </CardHeader>
            <CardContent className="px-2 pb-3">
              <div className="space-y-0.5">
                {nseCategories.map((cat) => {
                  const Icon = cat.icon;
                  const isActive = activeCategory === cat.id;
                  return (
                    <button
                      key={cat.id}
                      onClick={() => setActiveCategory(cat.id)}
                      className={`
                        w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-sm transition-all duration-200
                        ${isActive
                          ? "bg-cyan-500/10 text-cyan-400 shadow-[inset_0_0_0_1px_rgba(34,211,238,0.15)]"
                          : "text-muted-foreground hover:text-foreground hover:bg-accent/30"
                        }
                      `}
                    >
                      <Icon className="w-3.5 h-3.5 shrink-0" />
                      <span className="truncate">{cat.label}</span>
                      <span className={`ml-auto text-[10px] px-1.5 py-0.5 rounded-full ${isActive ? "bg-cyan-500/20 text-cyan-300" : "bg-secondary text-muted-foreground"}`}>
                        {cat.count}
                      </span>
                    </button>
                  );
                })}
              </div>
            </CardContent>
          </Card>

          {/* Risk Legend */}
          <Card className="border-border/50 bg-card/80">
            <CardContent className="p-4 space-y-2">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-2">Risk Levels</p>
              {Object.entries(riskColors).map(([risk, colors]) => (
                <div key={risk} className="flex items-center gap-2">
                  <div className={`w-2 h-2 rounded-full ${colors.bg} ${colors.border} border`} />
                  <span className={`text-xs capitalize ${colors.text}`}>{risk}</span>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>

        {/* Right: Script list + Detail */}
        <div className="flex-1 min-w-0 space-y-4">
          {/* Results count */}
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              <span className="text-foreground font-medium">{filteredScripts.length}</span> scripts found
            </p>
          </div>

          <div className="flex flex-col xl:flex-row gap-4">
            {/* Script list */}
            <ScrollArea className="flex-1 min-w-0">
              <div className="space-y-2 max-h-[calc(100vh-320px)]">
                <AnimatePresence mode="popLayout">
                  {filteredScripts.map((script, i) => {
                    const risk = riskColors[script.risk];
                    const isSelected = selectedScript?.name === script.name;
                    return (
                      <motion.div
                        key={script.name}
                        initial={{ opacity: 0, y: 8 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -8 }}
                        transition={{ duration: 0.2, delay: i * 0.02 }}
                      >
                        <button
                          onClick={() => setSelectedScript(script)}
                          className={`
                            w-full text-left p-3.5 rounded-lg border transition-all duration-200
                            ${isSelected
                              ? "border-cyan-500/30 bg-cyan-500/5 shadow-[inset_0_0_0_1px_rgba(34,211,238,0.1)]"
                              : "border-border/30 bg-card/60 hover:border-border/60 hover:bg-card/80"
                            }
                          `}
                        >
                          <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0">
                              <div className="flex items-center gap-2 mb-1">
                                <FileCode className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                                <span className="text-sm font-mono font-medium text-foreground truncate">
                                  {script.name}
                                </span>
                              </div>
                              <p className="text-xs text-muted-foreground line-clamp-2">
                                {script.description}
                              </p>
                              <div className="flex items-center gap-1.5 mt-2 flex-wrap">
                                {script.category.map((cat) => (
                                  <Badge
                                    key={cat}
                                    variant="outline"
                                    className="text-[10px] px-1.5 py-0 border-border/40 text-muted-foreground"
                                  >
                                    {cat}
                                  </Badge>
                                ))}
                              </div>
                            </div>
                            <div className="flex items-center gap-2 shrink-0">
                              <Badge className={`${risk.bg} ${risk.text} ${risk.border} border text-[10px] capitalize`}>
                                {script.risk}
                              </Badge>
                              <ChevronRight className="w-3.5 h-3.5 text-muted-foreground" />
                            </div>
                          </div>
                        </button>
                      </motion.div>
                    );
                  })}
                </AnimatePresence>
              </div>
            </ScrollArea>

            {/* Detail panel */}
            <AnimatePresence mode="wait">
              {selectedScript && (
                <motion.div
                  key={selectedScript.name}
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 20 }}
                  transition={{ duration: 0.3 }}
                  className="xl:w-[420px] shrink-0"
                >
                  <Card className="border-border/50 bg-card/80 sticky top-4">
                    <CardHeader className="pb-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <FileCode className="w-4 h-4 text-cyan-400" />
                          <CardTitle className="text-base font-mono">{selectedScript.name}</CardTitle>
                        </div>
                        <Badge className={`${riskColors[selectedScript.risk].bg} ${riskColors[selectedScript.risk].text} ${riskColors[selectedScript.risk].border} border text-[10px] capitalize`}>
                          {selectedScript.risk}
                        </Badge>
                      </div>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      {/* Description */}
                      <div>
                        <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-1.5">
                          Description
                        </p>
                        <p className="text-sm text-foreground/80 leading-relaxed">
                          {selectedScript.description}
                        </p>
                      </div>

                      <Separator className="bg-border/30" />

                      {/* Categories */}
                      <div>
                        <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-1.5">
                          Categories
                        </p>
                        <div className="flex flex-wrap gap-1.5">
                          {selectedScript.category.map((cat) => (
                            <Badge key={cat} variant="outline" className="text-xs border-cyan-500/30 text-cyan-400">
                              {cat}
                            </Badge>
                          ))}
                        </div>
                      </div>

                      {selectedScript.ports && (
                        <>
                          <Separator className="bg-border/30" />
                          <div>
                            <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-1.5">
                              Common Ports
                            </p>
                            <p className="text-sm font-mono text-foreground/80">{selectedScript.ports}</p>
                          </div>
                        </>
                      )}

                      <Separator className="bg-border/30" />

                      {/* Usage */}
                      <div>
                        <div className="flex items-center justify-between mb-1.5">
                          <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                            Usage
                          </p>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-6 px-2 text-[10px] text-muted-foreground hover:text-foreground"
                            onClick={() => copyToClipboard(selectedScript.usage)}
                          >
                            <Copy className="w-3 h-3 mr-1" />
                            Copy
                          </Button>
                        </div>
                        <div className="bg-background/80 rounded-md p-3 border border-border/30 font-mono text-xs text-green-400 overflow-x-auto">
                          <span className="text-muted-foreground">$ </span>
                          {selectedScript.usage}
                        </div>
                      </div>

                      <Separator className="bg-border/30" />

                      {/* Example Output */}
                      <div>
                        <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-1.5">
                          Example Output
                        </p>
                        <div className="bg-background/80 rounded-md p-3 border border-border/30 font-mono text-[11px] text-foreground/70 overflow-x-auto whitespace-pre">
                          {selectedScript.output}
                        </div>
                      </div>

                      {/* Action buttons */}
                      <div className="flex gap-2 pt-1">
                        <Button
                          size="sm"
                          className="bg-cyan-600 hover:bg-cyan-700 text-white gap-1.5 text-xs"
                          onClick={() => {
                            copyToClipboard(selectedScript.usage);
                            toast.success("Command copied — paste into New Scan");
                          }}
                        >
                          <Copy className="w-3 h-3" />
                          Copy Command
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          className="gap-1.5 text-xs border-border/50"
                          onClick={() => toast("Feature coming soon", { description: "View full NSE documentation" })}
                        >
                          <BookOpen className="w-3 h-3" />
                          Docs
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </div>
  );
}
