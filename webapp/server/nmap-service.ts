/**
 * Nmap Execution Service
 * Handles spawning nmap processes, parsing XML output, and persisting results.
 * Supports CUDA GPU acceleration flags when available.
 */
import { spawn, type ChildProcess } from "child_process";
import {
  createScan, updateScan, createHost, createPorts,
  createVulnerabilities, createAuditEntry, getScanById,
} from "./db";
import type { InsertHost, InsertPort, InsertVulnerability } from "../drizzle/schema";
import { evaluateScanAlerts } from "./alert-service";

// Active scan processes tracked by scan ID
const activeScans = new Map<number, ChildProcess>();

/**
 * Build the nmap command from scan parameters.
 */
export function buildNmapCommand(params: {
  target: string;
  flags?: string;
  profile?: string;
  cudaEnabled?: boolean;
  cudaDevice?: string;
}): { command: string; args: string[] } {
  const args: string[] = [];

  // Always output XML for parsing
  args.push("-oX", "-");

  // Profile-based presets
  if (params.profile) {
    switch (params.profile) {
      case "quick":
        args.push("-T4", "-F");
        break;
      case "intense":
        args.push("-T4", "-A", "-v");
        break;
      case "intense_udp":
        args.push("-sS", "-sU", "-T4", "-A", "-v");
        break;
      case "intense_all_tcp":
        args.push("-p", "1-65535", "-T4", "-A", "-v");
        break;
      case "intense_no_ping":
        args.push("-T4", "-A", "-v", "-Pn");
        break;
      case "ping_scan":
        args.push("-sn");
        break;
      case "quick_plus":
        args.push("-sV", "-T4", "-O", "-F", "--version-light");
        break;
      case "quick_traceroute":
        args.push("-sn", "--traceroute");
        break;
      case "slow_comprehensive":
        args.push("-sS", "-sU", "-T4", "-A", "-v", "-PE", "-PS80,443",
          "-PA3389", "-PP", "-PU40125", "-PY", "--source-port", "53",
          "--script", "default,safe,vuln");
        break;
      case "stealth_syn":
        args.push("-sS", "-T2", "-f", "--data-length", "24");
        break;
      case "vuln_assessment":
        args.push("-sV", "--script", "vuln", "-T4");
        break;
      case "os_detection":
        args.push("-O", "--osscan-guess", "-T4");
        break;
      case "service_version":
        args.push("-sV", "--version-all", "-T4");
        break;
      default:
        break;
    }
  }

  // Custom flags override/append
  if (params.flags) {
    const customArgs = params.flags.split(/\s+/).filter(Boolean);
    args.push(...customArgs);
  }

  // CUDA acceleration flags (for custom nmap builds with GPU support)
  if (params.cudaEnabled) {
    args.push("--cuda");
    if (params.cudaDevice) {
      args.push("--cuda-device", params.cudaDevice);
    }
  }

  // Target must be last
  args.push(params.target);

  return { command: "nmap", args };
}

/**
 * Parse Nmap XML output into structured data.
 */
export function parseNmapXml(xml: string): {
  hosts: Omit<InsertHost, "scanId">[];
  ports: { hostIp: string; port: Omit<InsertPort, "hostId" | "scanId"> }[];
  vulns: { hostIp: string; portNumber?: number; vuln: Omit<InsertVulnerability, "hostId" | "portId" | "scanId"> }[];
  stats: { hostsUp: number; hostsDown: number; elapsed: number };
} {
  const result = {
    hosts: [] as Omit<InsertHost, "scanId">[],
    ports: [] as { hostIp: string; port: Omit<InsertPort, "hostId" | "scanId"> }[],
    vulns: [] as { hostIp: string; portNumber?: number; vuln: Omit<InsertVulnerability, "hostId" | "portId" | "scanId"> }[],
    stats: { hostsUp: 0, hostsDown: 0, elapsed: 0 },
  };

  // Parse runstats
  const elapsedMatch = xml.match(/elapsed="([\d.]+)"/);
  if (elapsedMatch) result.stats.elapsed = parseFloat(elapsedMatch[1]);

  const hostsUpMatch = xml.match(/hosts up="(\d+)"/);
  if (hostsUpMatch) result.stats.hostsUp = parseInt(hostsUpMatch[1]);

  const hostsDownMatch = xml.match(/hosts down="(\d+)"/);
  if (hostsDownMatch) result.stats.hostsDown = parseInt(hostsDownMatch[1]);

  // Parse hosts
  const hostRegex = /<host\b[^>]*>([\s\S]*?)<\/host>/g;
  let hostMatch;
  while ((hostMatch = hostRegex.exec(xml)) !== null) {
    const hostXml = hostMatch[1];

    // IP address
    const addrMatch = hostXml.match(/<address addr="([^"]+)" addrtype="ipv4"/);
    const ipv6Match = hostXml.match(/<address addr="([^"]+)" addrtype="ipv6"/);
    const macMatch = hostXml.match(/<address addr="([^"]+)" addrtype="mac"(?:\s+vendor="([^"]*)")?/);
    const ip = addrMatch?.[1] || ipv6Match?.[1] || "unknown";

    // Hostname
    const hostnameMatch = hostXml.match(/<hostname name="([^"]+)"/);

    // State
    const stateMatch = hostXml.match(/<status state="(\w+)"/);
    const state = stateMatch?.[1] === "up" ? "up" : stateMatch?.[1] === "down" ? "down" : "unknown";

    // OS detection
    const osMatch = hostXml.match(/<osmatch name="([^"]+)"[^>]*accuracy="(\d+)"/);
    const osFamilyMatch = hostXml.match(/<osclass[^>]*osfamily="([^"]+)"/);

    // Distance
    const hopsMatch = hostXml.match(/<distance value="(\d+)"/);

    // Latency
    const latencyMatch = hostXml.match(/<times srtt="(\d+)"/);

    const host: Omit<InsertHost, "scanId"> = {
      ip,
      hostname: hostnameMatch?.[1] || null,
      state: state as "up" | "down" | "unknown",
      osName: osMatch?.[1] || null,
      osFamily: osFamilyMatch?.[1] || null,
      osAccuracy: osMatch ? parseInt(osMatch[2]) : null,
      macAddress: macMatch?.[1] || null,
      macVendor: macMatch?.[2] || null,
      hops: hopsMatch ? parseInt(hopsMatch[1]) : null,
      latency: latencyMatch ? parseInt(latencyMatch[1]) / 1000000 : null,
      openPortCount: 0,
      filteredPortCount: 0,
      closedPortCount: 0,
    };

    // Parse ports for this host
    const portRegex = /<port protocol="(\w+)" portid="(\d+)">([\s\S]*?)<\/port>/g;
    let portMatch;
    while ((portMatch = portRegex.exec(hostXml)) !== null) {
      const protocol = portMatch[1] as "tcp" | "udp" | "sctp";
      const portNumber = parseInt(portMatch[2]);
      const portXml = portMatch[3];

      const portStateMatch = portXml.match(/<state state="([^"]+)"/);
      const portState = portStateMatch?.[1] || "unknown";

      const serviceMatch = portXml.match(/<service name="([^"]*)"(?:\s+product="([^"]*)")?(?:\s+version="([^"]*)")?(?:\s+extrainfo="([^"]*)")?/);
      const cpeMatch = portXml.match(/<cpe>([^<]+)<\/cpe>/);

      if (portState === "open") host.openPortCount = (host.openPortCount || 0) + 1;
      else if (portState === "filtered") host.filteredPortCount = (host.filteredPortCount || 0) + 1;
      else if (portState === "closed") host.closedPortCount = (host.closedPortCount || 0) + 1;

      result.ports.push({
        hostIp: ip,
        port: {
          portNumber,
          protocol,
          state: portState,
          service: serviceMatch?.[1] || null,
          product: serviceMatch?.[2] || null,
          version: serviceMatch?.[3] || null,
          extraInfo: serviceMatch?.[4] || null,
          cpe: cpeMatch?.[1] || null,
          riskLevel: null,
        },
      });

      // Parse NSE script output for vulnerabilities
      const scriptRegex = /<script id="([^"]+)"[^>]*output="([^"]*)"[^>]*(?:\/>|>([\s\S]*?)<\/script>)/g;
      let scriptMatch;
      while ((scriptMatch = scriptRegex.exec(portXml)) !== null) {
        const scriptId = scriptMatch[1];
        const output = scriptMatch[2] || scriptMatch[3] || "";

        // Detect severity from script output
        let severity: "critical" | "high" | "medium" | "low" | "info" = "info";
        const lowerOutput = output.toLowerCase();
        if (lowerOutput.includes("critical") || lowerOutput.includes("cvss: 9") || lowerOutput.includes("cvss: 10")) severity = "critical";
        else if (lowerOutput.includes("high") || lowerOutput.includes("vulnerable")) severity = "high";
        else if (lowerOutput.includes("medium") || lowerOutput.includes("warning")) severity = "medium";
        else if (lowerOutput.includes("low")) severity = "low";

        // Extract CVE
        const cveMatch2 = output.match(/(CVE-\d{4}-\d+)/i);
        const cvssMatch = output.match(/cvss[:\s]*([\d.]+)/i);

        result.vulns.push({
          hostIp: ip,
          portNumber,
          vuln: {
            scriptId,
            scriptName: scriptId,
            severity,
            cveId: cveMatch2?.[1] || null,
            cvssScore: cvssMatch ? parseFloat(cvssMatch[1]) : null,
            title: `${scriptId} on ${ip}:${portNumber}`,
            output,
            remediation: null,
            acknowledged: false,
          },
        });
      }
    }

    result.hosts.push(host);
  }

  return result;
}

/**
 * Execute an Nmap scan, stream output, and persist results.
 */
export async function executeScan(scanId: number): Promise<void> {
  const scan = await getScanById(scanId);
  if (!scan) throw new Error(`Scan ${scanId} not found`);

  const { command, args } = buildNmapCommand({
    target: scan.target,
    flags: scan.flags || undefined,
    profile: scan.profile || undefined,
    cudaEnabled: scan.cudaEnabled,
    cudaDevice: scan.cudaDevice || undefined,
  });

  const fullCommand = `${command} ${args.join(" ")}`;
  console.log(`[NmapService] Executing: ${fullCommand}`);

  await updateScan(scanId, {
    status: "running",
    command: fullCommand,
    startedAt: new Date(),
    progress: 5,
  });

  await createAuditEntry({
    userId: scan.userId,
    action: "scan_started",
    details: `Started scan: ${fullCommand}`,
    entityType: "scan",
    entityId: scanId,
  });

  return new Promise((resolve, reject) => {
    let xmlOutput = "";
    let stderrOutput = "";

    const proc = spawn(command, args, {
      timeout: 600_000, // 10 minute timeout
    });

    activeScans.set(scanId, proc);

    proc.stdout.on("data", (chunk: Buffer) => {
      xmlOutput += chunk.toString();
      // Update progress based on output markers
      if (xmlOutput.includes("<taskprogress")) {
        const progressMatch = xmlOutput.match(/percent="([\d.]+)"/g);
        if (progressMatch) {
          const lastProgress = progressMatch[progressMatch.length - 1];
          const pct = parseFloat(lastProgress.match(/[\d.]+/)?.[0] || "0");
          updateScan(scanId, { progress: Math.round(pct) }).catch(() => {});
        }
      }
    });

    proc.stderr.on("data", (chunk: Buffer) => {
      stderrOutput += chunk.toString();
    });

    proc.on("close", async (code) => {
      activeScans.delete(scanId);
      const endTime = new Date();

      if (code !== 0 && xmlOutput.length < 100) {
        await updateScan(scanId, {
          status: "failed",
          errorMessage: stderrOutput || `nmap exited with code ${code}`,
          completedAt: endTime,
          progress: 100,
        });
        await createAuditEntry({
          userId: scan.userId,
          action: "scan_failed",
          details: `Scan failed: ${stderrOutput.slice(0, 500)}`,
          entityType: "scan",
          entityId: scanId,
        });
        return reject(new Error(stderrOutput));
      }

      try {
        // Parse XML results
        const parsed = parseNmapXml(xmlOutput);

        // Persist hosts
        const hostIdMap = new Map<string, number>();
        for (const hostData of parsed.hosts) {
          const hostId = await createHost({ ...hostData, scanId });
          hostIdMap.set(hostData.ip, hostId);
        }

        // Persist ports
        const portIdMap = new Map<string, number>();
        for (const { hostIp, port } of parsed.ports) {
          const hostId = hostIdMap.get(hostIp);
          if (!hostId) continue;
          const portData: InsertPort = { ...port, hostId, scanId };
          // We need individual inserts to get IDs for vuln linking
          const { createPorts: _ } = await import("./db");
          await createPorts([portData]);
        }

        // Persist vulnerabilities
        const vulnData: InsertVulnerability[] = [];
        for (const { hostIp, vuln } of parsed.vulns) {
          const hostId = hostIdMap.get(hostIp);
          if (!hostId) continue;
          vulnData.push({ ...vuln, hostId, scanId, portId: null });
        }
        if (vulnData.length > 0) {
          await createVulnerabilities(vulnData);
        }

        // Calculate duration
        const durationMs = scan.startedAt
          ? endTime.getTime() - new Date(scan.startedAt).getTime()
          : parsed.stats.elapsed * 1000;

        // Update scan with final results
        await updateScan(scanId, {
          status: "completed",
          rawXml: xmlOutput.length < 10_000_000 ? xmlOutput : null, // Don't store huge XML
          hostsUp: parsed.stats.hostsUp,
          hostsDown: parsed.stats.hostsDown,
          openPorts: parsed.ports.filter(p => p.port.state === "open").length,
          filteredPorts: parsed.ports.filter(p => p.port.state === "filtered").length,
          vulnCount: vulnData.length,
          durationMs,
          completedAt: endTime,
          progress: 100,
        });

        await createAuditEntry({
          userId: scan.userId,
          action: "scan_completed",
          details: `Scan completed: ${parsed.stats.hostsUp} hosts up, ${parsed.ports.filter(p => p.port.state === "open").length} open ports, ${vulnData.length} vulns`,
          entityType: "scan",
          entityId: scanId,
        });

        // Evaluate alert rules against scan results and dispatch notifications
        try {
          const alertCount = await evaluateScanAlerts(scanId);
          if (alertCount > 0) {
            console.log(`[NmapService] Generated ${alertCount} alerts for scan ${scanId}`);
          }
        } catch (alertErr) {
          console.warn(`[NmapService] Alert evaluation failed for scan ${scanId}:`, alertErr);
        }

        resolve();
      } catch (parseError) {
        await updateScan(scanId, {
          status: "failed",
          errorMessage: `Parse error: ${(parseError as Error).message}`,
          completedAt: endTime,
          progress: 100,
        });
        reject(parseError);
      }
    });

    proc.on("error", async (err) => {
      activeScans.delete(scanId);
      await updateScan(scanId, {
        status: "failed",
        errorMessage: `Spawn error: ${err.message}`,
        completedAt: new Date(),
        progress: 100,
      });
      reject(err);
    });
  });
}

/**
 * Cancel a running scan.
 */
export function cancelScan(scanId: number): boolean {
  const proc = activeScans.get(scanId);
  if (proc) {
    proc.kill("SIGTERM");
    activeScans.delete(scanId);
    return true;
  }
  return false;
}

/**
 * Get list of currently running scan IDs.
 */
export function getActiveScans(): number[] {
  return Array.from(activeScans.keys());
}

/**
 * Check if nmap is installed and get version.
 */
export async function getNmapVersion(): Promise<string | null> {
  return new Promise((resolve) => {
    const proc = spawn("nmap", ["--version"]);
    let output = "";
    proc.stdout.on("data", (chunk: Buffer) => { output += chunk.toString(); });
    proc.on("close", (code) => {
      if (code === 0) {
        const versionMatch = output.match(/Nmap version ([\d.]+)/);
        resolve(versionMatch?.[1] || output.trim().split("\n")[0]);
      } else {
        resolve(null);
      }
    });
    proc.on("error", () => resolve(null));
  });
}

/**
 * Check CUDA availability (nvidia-smi).
 */
export async function checkCudaAvailability(): Promise<{
  available: boolean;
  devices: Array<{
    index: number;
    name: string;
    memory: string;
    utilization: string;
    temperature: string;
    driverVersion: string;
    cudaVersion: string;
  }>;
}> {
  return new Promise((resolve) => {
    const proc = spawn("nvidia-smi", [
      "--query-gpu=index,name,memory.total,utilization.gpu,temperature.gpu,driver_version",
      "--format=csv,noheader,nounits",
    ]);
    let output = "";
    proc.stdout.on("data", (chunk: Buffer) => { output += chunk.toString(); });
    proc.on("close", (code) => {
      if (code !== 0 || !output.trim()) {
        resolve({ available: false, devices: [] });
        return;
      }
      const devices = output.trim().split("\n").map(line => {
        const [index, name, memory, utilization, temperature, driverVersion] = line.split(",").map(s => s.trim());
        return {
          index: parseInt(index),
          name,
          memory: `${memory} MiB`,
          utilization: `${utilization}%`,
          temperature: `${temperature}C`,
          driverVersion,
          cudaVersion: "",
        };
      });
      resolve({ available: true, devices });
    });
    proc.on("error", () => resolve({ available: false, devices: [] }));
  });
}
