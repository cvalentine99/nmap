/**
 * Alert Service
 * Automated CVE alerting system that evaluates scan results against alert rules,
 * generates alerts for CRITICAL/HIGH severity vulnerabilities, and dispatches
 * notifications to the project owner via the built-in notification system.
 */
import { notifyOwner } from "./_core/notification";
import { getDb } from "./db";
import {
  alerts,
  alertRules,
  vulnerabilities,
  hosts,
  ports,
  scans,
  type InsertAlert,
  type AlertRule,
} from "../drizzle/schema";
import { eq, desc, and, gte, sql, inArray } from "drizzle-orm";

// Severity numeric weights for comparison
const SEVERITY_WEIGHT: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

/**
 * Evaluate scan results against all active alert rules and generate alerts.
 * Called automatically after a scan completes.
 */
export async function evaluateScanAlerts(scanId: number): Promise<number> {
  const db = await getDb();
  if (!db) {
    console.warn("[AlertService] Database not available, skipping alert evaluation");
    return 0;
  }

  // Get the scan
  const [scan] = await db.select().from(scans).where(eq(scans.id, scanId)).limit(1);
  if (!scan || scan.status !== "completed") return 0;

  // Get all active alert rules
  const rules = await db
    .select()
    .from(alertRules)
    .where(eq(alertRules.enabled, true));

  // If no rules exist, create a default rule for CRITICAL + HIGH
  if (rules.length === 0) {
    await createDefaultRules(db);
    const defaultRules = await db
      .select()
      .from(alertRules)
      .where(eq(alertRules.enabled, true));
    rules.push(...defaultRules);
  }

  // Get vulnerabilities from this scan
  const scanVulns = await db
    .select()
    .from(vulnerabilities)
    .where(eq(vulnerabilities.scanId, scanId));

  // Get hosts from this scan
  const scanHosts = await db
    .select()
    .from(hosts)
    .where(eq(hosts.scanId, scanId));

  // Get ports from this scan
  const scanPorts = await db
    .select()
    .from(ports)
    .where(eq(ports.scanId, scanId));

  const hostMap = new Map(scanHosts.map((h) => [h.id, h]));
  const portMap = new Map(scanPorts.map((p) => [p.id, p]));

  let alertCount = 0;

  for (const rule of rules) {
    const matchedAlerts = evaluateRule(rule, scanVulns, scanPorts, hostMap, portMap, scanId);

    for (const alertData of matchedAlerts) {
      // Check cooldown — don't re-alert for the same CVE+host within cooldown period
      const cooldownMinutes = rule.cooldownMinutes || 60;
      const cooldownCutoff = new Date(Date.now() - cooldownMinutes * 60 * 1000);

      const existing = await db
        .select({ id: alerts.id })
        .from(alerts)
        .where(
          and(
            eq(alerts.ruleId, rule.id),
            alertData.cveId ? eq(alerts.cveId, alertData.cveId) : sql`1=1`,
            alertData.targetIp ? eq(alerts.targetIp, alertData.targetIp) : sql`1=1`,
            gte(alerts.createdAt, cooldownCutoff)
          )
        )
        .limit(1);

      if (existing.length > 0) continue; // Skip — within cooldown

      await db.insert(alerts).values(alertData);
      alertCount++;

      // Dispatch notification for CRITICAL and HIGH
      if (
        alertData.severity === "critical" ||
        alertData.severity === "high"
      ) {
        await dispatchNotification(alertData, scan.target);
      }
    }
  }

  if (alertCount > 0) {
    console.log(
      `[AlertService] Generated ${alertCount} alerts for scan ${scanId}`
    );
  }

  return alertCount;
}

/**
 * Evaluate a single rule against scan vulnerabilities and ports.
 */
function evaluateRule(
  rule: AlertRule,
  vulns: (typeof vulnerabilities.$inferSelect)[],
  scanPorts: (typeof ports.$inferSelect)[],
  hostMap: Map<number, typeof hosts.$inferSelect>,
  portMap: Map<number, typeof ports.$inferSelect>,
  scanId: number
): InsertAlert[] {
  const results: InsertAlert[] = [];
  const thresholdWeight = SEVERITY_WEIGHT[rule.severityThreshold] || 3;

  // Parse watched lists
  const watchedServices = rule.watchedServices
    ? (rule.watchedServices as string[])
    : null;
  const watchedTargets = rule.watchedTargets
    ? (rule.watchedTargets as string[])
    : null;
  const watchedCveIds = rule.watchedCveIds
    ? (rule.watchedCveIds as string[])
    : null;

  // Evaluate vulnerabilities from NSE scripts
  for (const vuln of vulns) {
    const vulnWeight = SEVERITY_WEIGHT[vuln.severity] || 0;
    const host = hostMap.get(vuln.hostId);
    const port = vuln.portId ? portMap.get(vuln.portId) : null;

    // Check severity threshold
    const meetsThreshold = vulnWeight >= thresholdWeight;

    // Check CVSS threshold
    const meetsCvss = rule.cvssThreshold
      ? (vuln.cvssScore || 0) >= rule.cvssThreshold
      : true;

    // Check watched CVE IDs
    const isWatchedCve =
      watchedCveIds && vuln.cveId
        ? watchedCveIds.includes(vuln.cveId)
        : false;

    // Check watched services
    const matchesService = watchedServices
      ? port &&
        watchedServices.some(
          (s) =>
            port.service?.toLowerCase().includes(s.toLowerCase()) ||
            port.product?.toLowerCase().includes(s.toLowerCase())
        )
      : true;

    // Check watched targets
    const matchesTarget = watchedTargets
      ? host &&
        watchedTargets.some((t) => isIpInCidr(host.ip, t))
      : true;

    if ((meetsThreshold && meetsCvss && matchesService && matchesTarget) || isWatchedCve) {
      results.push({
        ruleId: rule.id,
        scanId,
        hostId: vuln.hostId,
        portId: vuln.portId,
        severity: vuln.severity,
        title: vuln.cveId
          ? `${vuln.cveId} detected on ${host?.ip || "unknown"}:${port?.portNumber || "?"}`
          : `${vuln.title || vuln.scriptId || "Vulnerability"} on ${host?.ip || "unknown"}`,
        message: buildAlertMessage(vuln, host, port),
        cveId: vuln.cveId,
        cvssScore: vuln.cvssScore,
        service: port?.service || null,
        serviceVersion: port?.version || null,
        targetIp: host?.ip || null,
        portNumber: port?.portNumber || null,
        status: "new",
        notificationSent: false,
      });
    }
  }

  // Also check for high-risk open ports (services with known critical CVEs)
  const criticalServices: Record<string, { severity: "critical" | "high"; reason: string }> = {
    "ms-wbt-server": { severity: "high" as const, reason: "RDP exposed — common attack vector (BlueKeep, etc.)" },
    "microsoft-ds": { severity: "high" as const, reason: "SMB exposed — risk of EternalBlue/WannaCry" },
    "telnet": { severity: "high" as const, reason: "Telnet transmits credentials in plaintext" },
    "ftp": { severity: "high" as const, reason: "FTP transmits credentials in plaintext" },
  };

  for (const port of scanPorts) {
    const host = hostMap.get(port.hostId);
    const service = port.service?.toLowerCase() || "";
    const critical = criticalServices[service];

    if (critical && SEVERITY_WEIGHT[critical.severity] >= thresholdWeight) {
      // Check if we already have a vuln-based alert for this port
      const alreadyAlerted = results.some(
        (r) => r.targetIp === host?.ip && r.portNumber === port.portNumber
      );
      if (alreadyAlerted) continue;

      // Check service/target filters
      const matchesService = watchedServices
        ? watchedServices.some((s) => service.includes(s.toLowerCase()))
        : true;
      const matchesTarget = watchedTargets
        ? host && watchedTargets.some((t) => isIpInCidr(host.ip, t))
        : true;

      if (matchesService && matchesTarget) {
        results.push({
          ruleId: rule.id,
          scanId,
          hostId: port.hostId,
          portId: port.id,
          severity: critical.severity,
          title: `${critical.reason.split("—")[0].trim()} on ${host?.ip || "unknown"}:${port.portNumber}`,
          message: `**Service:** ${port.service || "unknown"} ${port.product || ""} ${port.version || ""}\n**Host:** ${host?.ip || "unknown"} (${host?.hostname || "no hostname"})\n**Port:** ${port.portNumber}/${port.protocol}\n**Risk:** ${critical.reason}`,
          cveId: null,
          cvssScore: null,
          service: port.service,
          serviceVersion: port.version,
          targetIp: host?.ip || null,
          portNumber: port.portNumber,
          status: "new",
          notificationSent: false,
        });
      }
    }
  }

  return results;
}

/**
 * Build a detailed alert message from vulnerability data.
 */
function buildAlertMessage(
  vuln: typeof vulnerabilities.$inferSelect,
  host: (typeof hosts.$inferSelect) | undefined,
  port: (typeof ports.$inferSelect) | undefined | null
): string {
  const lines: string[] = [];

  if (vuln.cveId) lines.push(`**CVE:** ${vuln.cveId}`);
  if (vuln.cvssScore) lines.push(`**CVSS Score:** ${vuln.cvssScore}/10.0`);
  lines.push(`**Severity:** ${vuln.severity.toUpperCase()}`);
  if (host) lines.push(`**Host:** ${host.ip} (${host.hostname || "no hostname"})`);
  if (port) {
    lines.push(`**Port:** ${port.portNumber}/${port.protocol}`);
    lines.push(`**Service:** ${port.service || "unknown"} ${port.product || ""} ${port.version || ""}`);
  }
  if (vuln.scriptId) lines.push(`**NSE Script:** ${vuln.scriptId}`);
  if (vuln.output) lines.push(`\n**Details:**\n${vuln.output.slice(0, 500)}`);
  if (vuln.remediation) lines.push(`\n**Remediation:** ${vuln.remediation}`);

  return lines.join("\n");
}

/**
 * Dispatch a push notification to the project owner.
 */
async function dispatchNotification(
  alertData: InsertAlert,
  scanTarget: string
): Promise<boolean> {
  const severityEmoji: Record<string, string> = {
    critical: "🔴",
    high: "🟠",
    medium: "🟡",
    low: "🟢",
  };

  const sev = alertData.severity || "high";
  const emoji = severityEmoji[sev] || "⚪";
  const title = `${emoji} ${sev.toUpperCase()} CVE Alert — ${scanTarget}`;

  const content = [
    alertData.title,
    "",
    alertData.message || "",
    "",
    `Scan target: ${scanTarget}`,
    alertData.cveId ? `CVE: ${alertData.cveId}` : "",
    alertData.cvssScore ? `CVSS: ${alertData.cvssScore}/10.0` : "",
    `Host: ${alertData.targetIp || "unknown"}`,
    alertData.portNumber ? `Port: ${alertData.portNumber}` : "",
  ]
    .filter(Boolean)
    .join("\n");

  try {
    const sent = await notifyOwner({ title, content });
    if (sent) {
      console.log(`[AlertService] Notification sent: ${title}`);
    }
    return sent;
  } catch (err) {
    console.warn("[AlertService] Failed to send notification:", err);
    return false;
  }
}

/**
 * Simple CIDR matching for target filtering.
 */
function isIpInCidr(ip: string, cidr: string): boolean {
  if (!cidr.includes("/")) return ip === cidr;
  const [network, prefixStr] = cidr.split("/");
  const prefix = parseInt(prefixStr);
  if (isNaN(prefix)) return false;

  const ipNum = ipToNumber(ip);
  const netNum = ipToNumber(network);
  if (ipNum === null || netNum === null) return false;

  const mask = ~(2 ** (32 - prefix) - 1) >>> 0;
  return (ipNum & mask) === (netNum & mask);
}

function ipToNumber(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  return parts.reduce((acc, octet) => {
    const n = parseInt(octet);
    if (isNaN(n) || n < 0 || n > 255) return acc;
    return (acc << 8) + n;
  }, 0) >>> 0;
}

/**
 * Create default alert rules for new installations.
 */
async function createDefaultRules(
  db: NonNullable<Awaited<ReturnType<typeof getDb>>>
): Promise<void> {
  await db.insert(alertRules).values([
    {
      name: "Critical Vulnerability Alert",
      description:
        "Triggers when a scan discovers any CRITICAL severity vulnerability or CVE with CVSS >= 9.0",
      enabled: true,
      severityThreshold: "critical",
      cvssThreshold: 9.0,
      alertOnKev: true,
      channels: JSON.parse(JSON.stringify(["in_app", "push"])),
      cooldownMinutes: 30,
    },
    {
      name: "High Severity Alert",
      description:
        "Triggers when a scan discovers HIGH severity vulnerabilities or CVEs with CVSS >= 7.0",
      enabled: true,
      severityThreshold: "high",
      cvssThreshold: 7.0,
      alertOnKev: true,
      channels: JSON.parse(JSON.stringify(["in_app", "push"])),
      cooldownMinutes: 60,
    },
    {
      name: "Dangerous Service Exposure",
      description:
        "Alerts when commonly exploited services (RDP, SMB, Telnet) are found exposed",
      enabled: true,
      severityThreshold: "high",
      watchedServices: JSON.parse(
        JSON.stringify(["ms-wbt-server", "microsoft-ds", "telnet", "ftp", "vnc"])
      ),
      alertOnKev: false,
      channels: JSON.parse(JSON.stringify(["in_app", "push"])),
      cooldownMinutes: 120,
    },
  ]);
}

/**
 * Get alert statistics for the dashboard.
 */
export async function getAlertStats(): Promise<{
  total: number;
  newCount: number;
  criticalCount: number;
  highCount: number;
  acknowledgedCount: number;
  resolvedCount: number;
}> {
  const db = await getDb();
  if (!db) {
    return { total: 0, newCount: 0, criticalCount: 0, highCount: 0, acknowledgedCount: 0, resolvedCount: 0 };
  }

  const allAlerts = await db.select().from(alerts);

  return {
    total: allAlerts.length,
    newCount: allAlerts.filter((a) => a.status === "new").length,
    criticalCount: allAlerts.filter((a) => a.severity === "critical").length,
    highCount: allAlerts.filter((a) => a.severity === "high").length,
    acknowledgedCount: allAlerts.filter((a) => a.status === "acknowledged").length,
    resolvedCount: allAlerts.filter((a) => a.status === "resolved" || a.status === "dismissed").length,
  };
}

/**
 * Get recent alerts for the notification center.
 */
export async function getRecentAlerts(limit = 50): Promise<(typeof alerts.$inferSelect)[]> {
  const db = await getDb();
  if (!db) return [];

  return db
    .select()
    .from(alerts)
    .orderBy(desc(alerts.createdAt))
    .limit(limit);
}

/**
 * Update alert status (acknowledge, investigate, resolve, dismiss).
 */
export async function updateAlertStatus(
  alertId: number,
  status: "acknowledged" | "investigating" | "resolved" | "dismissed",
  userId?: number,
  notes?: string
): Promise<void> {
  const db = await getDb();
  if (!db) return;

  const updateData: Record<string, unknown> = { status };
  if (status === "resolved" || status === "dismissed") {
    updateData.resolvedBy = userId || null;
    updateData.resolvedAt = new Date();
    if (notes) updateData.resolutionNotes = notes;
  }

  await db.update(alerts).set(updateData).where(eq(alerts.id, alertId));
}

/**
 * Bulk dismiss alerts by IDs.
 */
export async function bulkDismissAlerts(
  alertIds: number[],
  userId?: number
): Promise<number> {
  const db = await getDb();
  if (!db) return 0;

  const result = await db
    .update(alerts)
    .set({
      status: "dismissed",
      resolvedBy: userId || null,
      resolvedAt: new Date(),
    })
    .where(inArray(alerts.id, alertIds));

  return alertIds.length;
}
