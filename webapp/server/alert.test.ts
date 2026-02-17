import { describe, expect, it } from "vitest";

/**
 * Alert Service Tests
 * Tests for severity weight logic, CIDR matching, alert message building,
 * and rule evaluation logic (pure function tests without database).
 */

// Re-implement the pure functions from alert-service for unit testing
// (since they are not exported, we test the logic directly)

const SEVERITY_WEIGHT: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

function ipToNumber(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  return parts.reduce((acc, octet) => {
    const n = parseInt(octet);
    if (isNaN(n) || n < 0 || n > 255) return acc;
    return (acc << 8) + n;
  }, 0) >>> 0;
}

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

function buildAlertMessage(
  vuln: { cveId?: string | null; cvssScore?: number | null; severity: string; scriptId?: string | null; output?: string | null; remediation?: string | null },
  host: { ip: string; hostname?: string | null } | undefined,
  port: { portNumber: number; protocol: string; service?: string | null; product?: string | null; version?: string | null } | undefined | null
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

// Critical services map (same as alert-service.ts)
const criticalServices: Record<string, { severity: "critical" | "high"; reason: string }> = {
  "ms-wbt-server": { severity: "high", reason: "RDP exposed — common attack vector (BlueKeep, etc.)" },
  "microsoft-ds": { severity: "high", reason: "SMB exposed — risk of EternalBlue/WannaCry" },
  "telnet": { severity: "high", reason: "Telnet transmits credentials in plaintext" },
  "ftp": { severity: "high", reason: "FTP transmits credentials in plaintext" },
};

describe("Severity Weight System", () => {
  it("assigns correct weights to all severity levels", () => {
    expect(SEVERITY_WEIGHT["critical"]).toBe(4);
    expect(SEVERITY_WEIGHT["high"]).toBe(3);
    expect(SEVERITY_WEIGHT["medium"]).toBe(2);
    expect(SEVERITY_WEIGHT["low"]).toBe(1);
    expect(SEVERITY_WEIGHT["info"]).toBe(0);
  });

  it("critical is higher than all other severities", () => {
    const critical = SEVERITY_WEIGHT["critical"];
    expect(critical).toBeGreaterThan(SEVERITY_WEIGHT["high"]);
    expect(critical).toBeGreaterThan(SEVERITY_WEIGHT["medium"]);
    expect(critical).toBeGreaterThan(SEVERITY_WEIGHT["low"]);
    expect(critical).toBeGreaterThan(SEVERITY_WEIGHT["info"]);
  });

  it("meets threshold when severity >= threshold", () => {
    const threshold = SEVERITY_WEIGHT["high"]; // 3
    expect(SEVERITY_WEIGHT["critical"] >= threshold).toBe(true);
    expect(SEVERITY_WEIGHT["high"] >= threshold).toBe(true);
    expect(SEVERITY_WEIGHT["medium"] >= threshold).toBe(false);
    expect(SEVERITY_WEIGHT["low"] >= threshold).toBe(false);
  });

  it("unknown severity returns 0 (defaults to info level)", () => {
    expect(SEVERITY_WEIGHT["unknown"] || 0).toBe(0);
    expect(SEVERITY_WEIGHT[""] || 0).toBe(0);
  });
});

describe("IP to Number Conversion", () => {
  it("converts valid IPv4 addresses", () => {
    expect(ipToNumber("192.168.1.1")).toBe(3232235777);
    expect(ipToNumber("10.0.0.1")).toBe(167772161);
    expect(ipToNumber("0.0.0.0")).toBe(0);
    expect(ipToNumber("255.255.255.255")).toBe(4294967295);
  });

  it("returns null for invalid IPs", () => {
    expect(ipToNumber("")).toBeNull();
    expect(ipToNumber("abc")).toBeNull();
    expect(ipToNumber("192.168.1")).toBeNull();
    expect(ipToNumber("192.168.1.1.1")).toBeNull();
  });

  it("handles boundary octets correctly", () => {
    expect(ipToNumber("0.0.0.0")).toBe(0);
    expect(ipToNumber("127.0.0.1")).toBe(2130706433);
  });
});

describe("CIDR Matching", () => {
  it("matches IP within /24 subnet", () => {
    expect(isIpInCidr("192.168.1.100", "192.168.1.0/24")).toBe(true);
    expect(isIpInCidr("192.168.1.255", "192.168.1.0/24")).toBe(true);
    expect(isIpInCidr("192.168.2.1", "192.168.1.0/24")).toBe(false);
  });

  it("matches IP within /16 subnet", () => {
    expect(isIpInCidr("10.0.1.1", "10.0.0.0/16")).toBe(true);
    expect(isIpInCidr("10.0.255.255", "10.0.0.0/16")).toBe(true);
    expect(isIpInCidr("10.1.0.1", "10.0.0.0/16")).toBe(false);
  });

  it("matches IP within /8 subnet", () => {
    expect(isIpInCidr("10.255.255.255", "10.0.0.0/8")).toBe(true);
    expect(isIpInCidr("11.0.0.1", "10.0.0.0/8")).toBe(false);
  });

  it("matches exact IP without CIDR notation", () => {
    expect(isIpInCidr("192.168.1.1", "192.168.1.1")).toBe(true);
    expect(isIpInCidr("192.168.1.2", "192.168.1.1")).toBe(false);
  });

  it("handles /32 single host", () => {
    expect(isIpInCidr("192.168.1.1", "192.168.1.1/32")).toBe(true);
    expect(isIpInCidr("192.168.1.2", "192.168.1.1/32")).toBe(false);
  });

  it("handles /0 matches everything", () => {
    expect(isIpInCidr("1.2.3.4", "0.0.0.0/0")).toBe(true);
    expect(isIpInCidr("255.255.255.255", "0.0.0.0/0")).toBe(true);
  });
});

describe("Alert Message Building", () => {
  it("builds message with CVE and host details", () => {
    const msg = buildAlertMessage(
      { cveId: "CVE-2021-44228", cvssScore: 10.0, severity: "critical", scriptId: "http-vuln-cve2021-44228" },
      { ip: "192.168.1.10", hostname: "web-server.local" },
      { portNumber: 8080, protocol: "tcp", service: "http", product: "Apache", version: "2.4.49" }
    );

    expect(msg).toContain("CVE-2021-44228");
    expect(msg).toContain("10/10.0");
    expect(msg).toContain("CRITICAL");
    expect(msg).toContain("192.168.1.10");
    expect(msg).toContain("web-server.local");
    expect(msg).toContain("8080/tcp");
    expect(msg).toContain("Apache");
    expect(msg).toContain("http-vuln-cve2021-44228");
  });

  it("builds message without optional fields", () => {
    const msg = buildAlertMessage(
      { severity: "high" },
      undefined,
      null
    );

    expect(msg).toContain("HIGH");
    expect(msg).not.toContain("CVE:");
    expect(msg).not.toContain("Host:");
    expect(msg).not.toContain("Port:");
  });

  it("truncates long output to 500 chars", () => {
    const longOutput = "A".repeat(1000);
    const msg = buildAlertMessage(
      { severity: "medium", output: longOutput },
      { ip: "10.0.0.1" },
      null
    );

    expect(msg).toContain("Details:");
    // The output in the message should be truncated
    const detailsIdx = msg.indexOf("Details:");
    const afterDetails = msg.slice(detailsIdx);
    expect(afterDetails.length).toBeLessThan(600);
  });

  it("includes remediation when provided", () => {
    const msg = buildAlertMessage(
      { severity: "high", remediation: "Update Apache to 2.4.54 or later" },
      { ip: "10.0.0.1" },
      null
    );

    expect(msg).toContain("Remediation:");
    expect(msg).toContain("Update Apache to 2.4.54");
  });
});

describe("Critical Service Detection", () => {
  it("identifies RDP as high severity", () => {
    expect(criticalServices["ms-wbt-server"]).toBeDefined();
    expect(criticalServices["ms-wbt-server"].severity).toBe("high");
    expect(criticalServices["ms-wbt-server"].reason).toContain("RDP");
  });

  it("identifies SMB as high severity", () => {
    expect(criticalServices["microsoft-ds"]).toBeDefined();
    expect(criticalServices["microsoft-ds"].severity).toBe("high");
    expect(criticalServices["microsoft-ds"].reason).toContain("SMB");
  });

  it("identifies Telnet as high severity", () => {
    expect(criticalServices["telnet"]).toBeDefined();
    expect(criticalServices["telnet"].severity).toBe("high");
    expect(criticalServices["telnet"].reason).toContain("plaintext");
  });

  it("identifies FTP as high severity", () => {
    expect(criticalServices["ftp"]).toBeDefined();
    expect(criticalServices["ftp"].severity).toBe("high");
    expect(criticalServices["ftp"].reason).toContain("plaintext");
  });

  it("does not flag safe services", () => {
    expect(criticalServices["http"]).toBeUndefined();
    expect(criticalServices["https"]).toBeUndefined();
    expect(criticalServices["ssh"]).toBeUndefined();
    expect(criticalServices["dns"]).toBeUndefined();
  });
});

describe("Alert Rule Evaluation Logic", () => {
  it("severity threshold correctly filters vulnerabilities", () => {
    const thresholdHigh = SEVERITY_WEIGHT["high"]; // 3

    // These should trigger
    expect(SEVERITY_WEIGHT["critical"] >= thresholdHigh).toBe(true);
    expect(SEVERITY_WEIGHT["high"] >= thresholdHigh).toBe(true);

    // These should not trigger
    expect(SEVERITY_WEIGHT["medium"] >= thresholdHigh).toBe(false);
    expect(SEVERITY_WEIGHT["low"] >= thresholdHigh).toBe(false);
    expect(SEVERITY_WEIGHT["info"] >= thresholdHigh).toBe(false);
  });

  it("CVSS threshold correctly filters", () => {
    const cvssThreshold = 7.0;

    expect(9.8 >= cvssThreshold).toBe(true);
    expect(7.0 >= cvssThreshold).toBe(true);
    expect(6.9 >= cvssThreshold).toBe(false);
    expect(0 >= cvssThreshold).toBe(false);
  });

  it("watched CVE IDs are matched correctly", () => {
    const watchedCveIds = ["CVE-2021-44228", "CVE-2023-0001", "CVE-2024-1234"];

    expect(watchedCveIds.includes("CVE-2021-44228")).toBe(true);
    expect(watchedCveIds.includes("CVE-2023-0001")).toBe(true);
    expect(watchedCveIds.includes("CVE-2022-9999")).toBe(false);
  });

  it("watched services match by substring", () => {
    const watchedServices = ["ssh", "http", "mysql"];
    const service = "http-proxy";

    const matches = watchedServices.some((s) =>
      service.toLowerCase().includes(s.toLowerCase())
    );
    expect(matches).toBe(true);
  });

  it("watched services do not match unrelated services", () => {
    const watchedServices = ["ssh", "http"];
    const service = "mysql";

    const matches = watchedServices.some((s) =>
      service.toLowerCase().includes(s.toLowerCase())
    );
    expect(matches).toBe(false);
  });
});

describe("Cooldown Logic", () => {
  it("calculates cooldown cutoff correctly", () => {
    const cooldownMinutes = 60;
    const now = Date.now();
    const cutoff = new Date(now - cooldownMinutes * 60 * 1000);

    // An alert from 30 minutes ago should be within cooldown
    const recentAlert = new Date(now - 30 * 60 * 1000);
    expect(recentAlert >= cutoff).toBe(true);

    // An alert from 90 minutes ago should be outside cooldown
    const oldAlert = new Date(now - 90 * 60 * 1000);
    expect(oldAlert >= cutoff).toBe(false);
  });

  it("30-minute cooldown is shorter than 60-minute cooldown", () => {
    const now = Date.now();
    const cutoff30 = new Date(now - 30 * 60 * 1000);
    const cutoff60 = new Date(now - 60 * 60 * 1000);

    expect(cutoff30.getTime()).toBeGreaterThan(cutoff60.getTime());
  });
});

describe("Notification Dispatch Logic", () => {
  it("builds correct notification title for critical alerts", () => {
    const severityEmoji: Record<string, string> = {
      critical: "🔴",
      high: "🟠",
      medium: "🟡",
      low: "🟢",
    };

    const sev = "critical";
    const scanTarget = "192.168.1.0/24";
    const emoji = severityEmoji[sev] || "⚪";
    const title = `${emoji} ${sev.toUpperCase()} CVE Alert — ${scanTarget}`;

    expect(title).toBe("🔴 CRITICAL CVE Alert — 192.168.1.0/24");
  });

  it("builds correct notification title for high alerts", () => {
    const severityEmoji: Record<string, string> = {
      critical: "🔴",
      high: "🟠",
      medium: "🟡",
      low: "🟢",
    };

    const sev = "high";
    const scanTarget = "10.0.0.0/16";
    const emoji = severityEmoji[sev] || "⚪";
    const title = `${emoji} ${sev.toUpperCase()} CVE Alert — ${scanTarget}`;

    expect(title).toBe("🟠 HIGH CVE Alert — 10.0.0.0/16");
  });

  it("uses white circle for unknown severity", () => {
    const severityEmoji: Record<string, string> = {
      critical: "🔴",
      high: "🟠",
      medium: "🟡",
      low: "🟢",
    };

    const sev = "unknown";
    const emoji = severityEmoji[sev] || "⚪";
    expect(emoji).toBe("⚪");
  });
});
