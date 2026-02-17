import {
  int,
  bigint,
  mysqlEnum,
  mysqlTable,
  text,
  timestamp,
  varchar,
  boolean,
  json,
  float,
} from "drizzle-orm/mysql-core";

/**
 * Core user table backing auth flow.
 */
export const users = mysqlTable("users", {
  id: int("id").autoincrement().primaryKey(),
  openId: varchar("openId", { length: 64 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  loginMethod: varchar("loginMethod", { length: 64 }),
  role: mysqlEnum("role", ["user", "admin"]).default("user").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull(),
});

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;

/**
 * Scans — each row represents one Nmap scan job.
 */
export const scans = mysqlTable("scans", {
  id: int("id").autoincrement().primaryKey(),
  /** User who initiated the scan */
  userId: int("userId").notNull(),
  /** Target specification (IP, CIDR, hostname, range) */
  target: varchar("target", { length: 1024 }).notNull(),
  /** Scan profile name (e.g., "Quick Scan", "Full TCP", "Stealth SYN") */
  profile: varchar("profile", { length: 128 }),
  /** Raw Nmap flags/arguments */
  flags: text("flags"),
  /** Full Nmap command that was executed */
  command: text("command"),
  /** Scan lifecycle status */
  status: mysqlEnum("status", [
    "queued",
    "running",
    "completed",
    "failed",
    "cancelled",
  ]).default("queued").notNull(),
  /** Whether CUDA GPU acceleration was enabled for this scan */
  cudaEnabled: boolean("cudaEnabled").default(false).notNull(),
  /** CUDA device used (e.g., "GPU 0: NVIDIA A100") */
  cudaDevice: varchar("cudaDevice", { length: 256 }),
  /** Progress percentage (0-100) */
  progress: int("progress").default(0),
  /** Number of hosts discovered */
  hostsUp: int("hostsUp").default(0),
  /** Number of hosts down */
  hostsDown: int("hostsDown").default(0),
  /** Total open ports found */
  openPorts: int("openPorts").default(0),
  /** Total filtered ports found */
  filteredPorts: int("filteredPorts").default(0),
  /** Total vulnerabilities detected */
  vulnCount: int("vulnCount").default(0),
  /** Scan duration in milliseconds */
  durationMs: bigint("durationMs", { mode: "number" }),
  /** Raw Nmap XML output stored for re-parsing */
  rawXml: text("rawXml"),
  /** Nmap version used */
  nmapVersion: varchar("nmapVersion", { length: 64 }),
  /** Error message if scan failed */
  errorMessage: text("errorMessage"),
  /** Scan start time */
  startedAt: timestamp("startedAt"),
  /** Scan completion time */
  completedAt: timestamp("completedAt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type Scan = typeof scans.$inferSelect;
export type InsertScan = typeof scans.$inferInsert;

/**
 * Hosts — discovered hosts from scans.
 */
export const hosts = mysqlTable("hosts", {
  id: int("id").autoincrement().primaryKey(),
  scanId: int("scanId").notNull(),
  /** IPv4 or IPv6 address */
  ip: varchar("ip", { length: 45 }).notNull(),
  /** Resolved hostname */
  hostname: varchar("hostname", { length: 512 }),
  /** Host state: up, down, unknown */
  state: mysqlEnum("state", ["up", "down", "unknown"]).default("up").notNull(),
  /** OS name from OS detection */
  osName: varchar("osName", { length: 256 }),
  /** OS family (e.g., "Linux", "Windows") */
  osFamily: varchar("osFamily", { length: 128 }),
  /** OS accuracy percentage (0-100) */
  osAccuracy: int("osAccuracy"),
  /** MAC address */
  macAddress: varchar("macAddress", { length: 17 }),
  /** MAC vendor */
  macVendor: varchar("macVendor", { length: 256 }),
  /** Network distance in hops */
  hops: int("hops"),
  /** Round-trip time in seconds */
  latency: float("latency"),
  /** Number of open ports on this host */
  openPortCount: int("openPortCount").default(0),
  /** Number of filtered ports */
  filteredPortCount: int("filteredPortCount").default(0),
  /** Number of closed ports */
  closedPortCount: int("closedPortCount").default(0),
  /** GeoIP latitude */
  latitude: float("latitude"),
  /** GeoIP longitude */
  longitude: float("longitude"),
  /** GeoIP country */
  country: varchar("country", { length: 128 }),
  /** GeoIP city */
  city: varchar("city", { length: 256 }),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type Host = typeof hosts.$inferSelect;
export type InsertHost = typeof hosts.$inferInsert;

/**
 * Ports — discovered ports on hosts.
 */
export const ports = mysqlTable("ports", {
  id: int("id").autoincrement().primaryKey(),
  hostId: int("hostId").notNull(),
  scanId: int("scanId").notNull(),
  /** Port number (1-65535) */
  portNumber: int("portNumber").notNull(),
  /** Protocol: tcp, udp, sctp */
  protocol: mysqlEnum("protocol", ["tcp", "udp", "sctp"]).default("tcp").notNull(),
  /** Port state: open, closed, filtered, unfiltered, open|filtered, closed|filtered */
  state: varchar("state", { length: 32 }).notNull(),
  /** Service name (e.g., "http", "ssh", "ftp") */
  service: varchar("service", { length: 128 }),
  /** Service product (e.g., "Apache httpd") */
  product: varchar("product", { length: 256 }),
  /** Service version (e.g., "2.4.54") */
  version: varchar("version", { length: 128 }),
  /** Extra info from service detection */
  extraInfo: text("extraInfo"),
  /** CPE identifiers */
  cpe: text("cpe"),
  /** Risk level derived from service/vuln analysis */
  riskLevel: mysqlEnum("riskLevel", [
    "critical",
    "high",
    "medium",
    "low",
    "info",
  ]),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type Port = typeof ports.$inferSelect;
export type InsertPort = typeof ports.$inferInsert;

/**
 * Vulnerabilities — NSE script findings and CVE detections.
 */
export const vulnerabilities = mysqlTable("vulnerabilities", {
  id: int("id").autoincrement().primaryKey(),
  hostId: int("hostId").notNull(),
  portId: int("portId"),
  scanId: int("scanId").notNull(),
  /** NSE script ID that produced this finding */
  scriptId: varchar("scriptId", { length: 256 }),
  /** Script name */
  scriptName: varchar("scriptName", { length: 256 }),
  /** Severity level */
  severity: mysqlEnum("severity", [
    "critical",
    "high",
    "medium",
    "low",
    "info",
  ]).default("info").notNull(),
  /** CVE identifier if applicable */
  cveId: varchar("cveId", { length: 64 }),
  /** CVSS score (0.0 - 10.0) */
  cvssScore: float("cvssScore"),
  /** Human-readable title */
  title: varchar("title", { length: 512 }),
  /** Detailed description / script output */
  output: text("output"),
  /** Remediation recommendation */
  remediation: text("remediation"),
  /** Whether this has been acknowledged/dismissed */
  acknowledged: boolean("acknowledged").default(false).notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type Vulnerability = typeof vulnerabilities.$inferSelect;
export type InsertVulnerability = typeof vulnerabilities.$inferInsert;

/**
 * Audit Log — tracks all user actions for compliance.
 */
export const auditLog = mysqlTable("audit_log", {
  id: int("id").autoincrement().primaryKey(),
  /** User who performed the action */
  userId: int("userId"),
  /** User display name (denormalized for fast reads) */
  userName: varchar("userName", { length: 256 }),
  /** Action category */
  action: mysqlEnum("action", [
    "scan_created",
    "scan_started",
    "scan_completed",
    "scan_failed",
    "scan_cancelled",
    "scan_deleted",
    "cidr_added",
    "cidr_removed",
    "cidr_toggled",
    "settings_changed",
    "user_login",
    "user_logout",
    "export_generated",
    "cuda_enabled",
    "cuda_disabled",
  ]).notNull(),
  /** Human-readable description */
  details: text("details"),
  /** Related entity type */
  entityType: varchar("entityType", { length: 64 }),
  /** Related entity ID */
  entityId: int("entityId"),
  /** Client IP address */
  ipAddress: varchar("ipAddress", { length: 45 }),
  /** Additional metadata as JSON */
  metadata: json("metadata"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type AuditLogEntry = typeof auditLog.$inferSelect;
export type InsertAuditLogEntry = typeof auditLog.$inferInsert;

/**
 * CIDR Rules — allowlist/denylist for scan scope enforcement.
 */
export const cidrRules = mysqlTable("cidr_rules", {
  id: int("id").autoincrement().primaryKey(),
  /** CIDR notation (e.g., "192.168.1.0/24") */
  cidr: varchar("cidr", { length: 64 }).notNull(),
  /** Human-readable label */
  label: varchar("label", { length: 256 }),
  /** Rule type: allow or deny */
  type: mysqlEnum("type", ["allow", "deny"]).default("allow").notNull(),
  /** Whether this rule is active */
  enabled: boolean("enabled").default(true).notNull(),
  /** User who created the rule */
  createdBy: int("createdBy"),
  /** Optional notes */
  notes: text("notes"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type CidrRule = typeof cidrRules.$inferSelect;
export type InsertCidrRule = typeof cidrRules.$inferInsert;

/**
 * CUDA Devices — tracks available GPU resources for acceleration.
 */
export const cudaDevices = mysqlTable("cuda_devices", {
  id: int("id").autoincrement().primaryKey(),
  /** Device index (e.g., 0, 1) */
  deviceIndex: int("deviceIndex").notNull(),
  /** Device name (e.g., "NVIDIA A100 80GB") */
  deviceName: varchar("deviceName", { length: 256 }).notNull(),
  /** CUDA compute capability (e.g., "8.0") */
  computeCapability: varchar("computeCapability", { length: 16 }),
  /** Total memory in bytes */
  totalMemory: bigint("totalMemory", { mode: "number" }),
  /** Available memory in bytes */
  freeMemory: bigint("freeMemory", { mode: "number" }),
  /** GPU utilization percentage */
  utilization: int("utilization"),
  /** GPU temperature in Celsius */
  temperature: int("temperature"),
  /** Power draw in watts */
  powerDraw: float("powerDraw"),
  /** Whether this device is available for scans */
  available: boolean("available").default(true).notNull(),
  /** CUDA driver version */
  driverVersion: varchar("driverVersion", { length: 32 }),
  /** CUDA runtime version */
  cudaVersion: varchar("cudaVersion", { length: 32 }),
  /** Last health check timestamp */
  lastCheckedAt: timestamp("lastCheckedAt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type CudaDevice = typeof cudaDevices.$inferSelect;
export type InsertCudaDevice = typeof cudaDevices.$inferInsert;

/**
 * Scan Templates — reusable scan configurations.
 */
export const scanTemplates = mysqlTable("scan_templates", {
  id: int("id").autoincrement().primaryKey(),
  /** Template name */
  name: varchar("name", { length: 256 }).notNull(),
  /** Description */
  description: text("description"),
  /** Nmap flags/arguments */
  flags: text("flags"),
  /** Scan profile category */
  category: varchar("category", { length: 128 }),
  /** Whether CUDA is recommended for this template */
  cudaRecommended: boolean("cudaRecommended").default(false).notNull(),
  /** Whether this is a system-provided template */
  isSystem: boolean("isSystem").default(false).notNull(),
  /** User who created (null for system templates) */
  createdBy: int("createdBy"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type ScanTemplate = typeof scanTemplates.$inferSelect;
export type InsertScanTemplate = typeof scanTemplates.$inferInsert;

/**
 * CVE Cache — cached CVE lookup results from NVD API to avoid rate limits.
 */
export const cveCache = mysqlTable("cve_cache", {
  id: int("id").autoincrement().primaryKey(),
  /** CVE identifier (e.g., "CVE-2021-44228") */
  cveId: varchar("cveId", { length: 64 }).notNull().unique(),
  /** Vulnerability description */
  description: text("description"),
  /** CVSS v3.1 base score (0.0 - 10.0) */
  cvssV3Score: float("cvssV3Score"),
  /** CVSS v3.1 severity: LOW, MEDIUM, HIGH, CRITICAL */
  cvssV3Severity: varchar("cvssV3Severity", { length: 16 }),
  /** CVSS v3.1 vector string */
  cvssV3Vector: varchar("cvssV3Vector", { length: 256 }),
  /** CVSS v4.0 base score if available */
  cvssV4Score: float("cvssV4Score"),
  /** CVSS v4.0 severity */
  cvssV4Severity: varchar("cvssV4Severity", { length: 16 }),
  /** CWE identifiers as JSON array */
  cweIds: json("cweIds"),
  /** Affected CPE configurations as JSON */
  affectedProducts: json("affectedProducts"),
  /** Reference URLs as JSON array */
  references: json("references"),
  /** Published date */
  publishedDate: timestamp("publishedDate"),
  /** Last modified date from NVD */
  lastModifiedDate: timestamp("lastModifiedDate"),
  /** Whether this CVE is in CISA KEV catalog */
  isKev: boolean("isKev").default(false).notNull(),
  /** Source of the data (nvd, circl, etc.) */
  source: varchar("source", { length: 32 }).default("nvd").notNull(),
  /** Raw JSON response for full details */
  rawJson: json("rawJson"),
  /** When this cache entry was fetched */
  fetchedAt: timestamp("fetchedAt").defaultNow().notNull(),
  /** Cache TTL - entries older than this should be refreshed */
  expiresAt: timestamp("expiresAt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type CveEntry = typeof cveCache.$inferSelect;
export type InsertCveEntry = typeof cveCache.$inferInsert;

/**
 * CVE Service Mapping — maps service+version to known CVEs for quick lookup.
 */
export const cveServiceMap = mysqlTable("cve_service_map", {
  id: int("id").autoincrement().primaryKey(),
  /** Service name (e.g., "openssh", "apache", "nginx") */
  serviceName: varchar("serviceName", { length: 256 }).notNull(),
  /** Product name (e.g., "OpenSSH", "Apache httpd") */
  product: varchar("product", { length: 256 }),
  /** Version string (e.g., "8.9", "2.4.52") */
  version: varchar("version", { length: 128 }),
  /** CPE string for this service */
  cpeName: varchar("cpeName", { length: 512 }),
  /** CVE ID linked to this service */
  cveId: varchar("cveId", { length: 64 }).notNull(),
  /** CVSS score for quick sorting */
  cvssScore: float("cvssScore"),
  /** Severity for quick filtering */
  severity: varchar("severity", { length: 16 }),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type CveServiceMapEntry = typeof cveServiceMap.$inferSelect;
export type InsertCveServiceMapEntry = typeof cveServiceMap.$inferInsert;

/**
 * Alert Rules — user-defined rules for automated CVE alerting.
 */
export const alertRules = mysqlTable("alert_rules", {
  id: int("id").autoincrement().primaryKey(),
  /** Rule name (e.g., "Critical CVE Alert") */
  name: varchar("name", { length: 256 }).notNull(),
  /** Rule description */
  description: text("description"),
  /** Whether this rule is active */
  enabled: boolean("enabled").default(true).notNull(),
  /** Minimum severity to trigger: critical, high, medium, low */
  severityThreshold: mysqlEnum("severityThreshold", [
    "critical",
    "high",
    "medium",
    "low",
  ]).default("high").notNull(),
  /** Minimum CVSS score to trigger (0.0 - 10.0), null means use severity only */
  cvssThreshold: float("cvssThreshold"),
  /** Specific services to watch (JSON array), null means all services */
  watchedServices: json("watchedServices"),
  /** Specific CIDR ranges to watch (JSON array), null means all targets */
  watchedTargets: json("watchedTargets"),
  /** Specific CVE IDs to always alert on (JSON array) */
  watchedCveIds: json("watchedCveIds"),
  /** Alert on CISA KEV entries regardless of severity */
  alertOnKev: boolean("alertOnKev").default(true).notNull(),
  /** Notification channels: in_app, push, email (JSON array) */
  channels: json("channels"),
  /** Cooldown period in minutes to avoid duplicate alerts */
  cooldownMinutes: int("cooldownMinutes").default(60),
  /** User who created the rule */
  createdBy: int("createdBy"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type AlertRule = typeof alertRules.$inferSelect;
export type InsertAlertRule = typeof alertRules.$inferInsert;

/**
 * Alerts — triggered alert instances from scan results.
 */
export const alerts = mysqlTable("alerts", {
  id: int("id").autoincrement().primaryKey(),
  /** Alert rule that triggered this */
  ruleId: int("ruleId"),
  /** Scan that triggered this alert */
  scanId: int("scanId"),
  /** Host where the vulnerability was found */
  hostId: int("hostId"),
  /** Port where the vulnerability was found */
  portId: int("portId"),
  /** Severity level of this alert */
  severity: mysqlEnum("severity", [
    "critical",
    "high",
    "medium",
    "low",
    "info",
  ]).default("high").notNull(),
  /** Alert title */
  title: varchar("title", { length: 512 }).notNull(),
  /** Alert message with details */
  message: text("message"),
  /** CVE ID if applicable */
  cveId: varchar("cveId", { length: 64 }),
  /** CVSS score */
  cvssScore: float("cvssScore"),
  /** Affected service name */
  service: varchar("service", { length: 128 }),
  /** Affected service version */
  serviceVersion: varchar("serviceVersion", { length: 128 }),
  /** Target IP address */
  targetIp: varchar("targetIp", { length: 45 }),
  /** Port number */
  portNumber: int("portNumber"),
  /** Alert status */
  status: mysqlEnum("status", [
    "new",
    "acknowledged",
    "investigating",
    "resolved",
    "dismissed",
  ]).default("new").notNull(),
  /** Whether owner notification was sent */
  notificationSent: boolean("notificationSent").default(false).notNull(),
  /** Notification sent timestamp */
  notifiedAt: timestamp("notifiedAt"),
  /** User who acknowledged/resolved */
  resolvedBy: int("resolvedBy"),
  /** Resolution notes */
  resolutionNotes: text("resolutionNotes"),
  /** Resolved timestamp */
  resolvedAt: timestamp("resolvedAt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type Alert = typeof alerts.$inferSelect;
export type InsertAlert = typeof alerts.$inferInsert;
