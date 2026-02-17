import { eq, desc, sql, and, count } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";
import {
  InsertUser, users,
  scans, InsertScan, Scan,
  hosts, InsertHost,
  ports, InsertPort,
  vulnerabilities, InsertVulnerability,
  auditLog, InsertAuditLogEntry,
  cidrRules, InsertCidrRule,
  cudaDevices, InsertCudaDevice,
  scanTemplates, InsertScanTemplate,
} from "../drizzle/schema";
import { ENV } from './_core/env';

let _db: ReturnType<typeof drizzle> | null = null;

export async function getDb() {
  if (!_db && process.env.DATABASE_URL) {
    try {
      _db = drizzle(process.env.DATABASE_URL);
    } catch (error) {
      console.warn("[Database] Failed to connect:", error);
      _db = null;
    }
  }
  return _db;
}

// ─── User Queries ────────────────────────────────────────────────

export async function upsertUser(user: InsertUser): Promise<void> {
  if (!user.openId) {
    throw new Error("User openId is required for upsert");
  }
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot upsert user: database not available");
    return;
  }
  try {
    const values: InsertUser = { openId: user.openId };
    const updateSet: Record<string, unknown> = {};
    const textFields = ["name", "email", "loginMethod"] as const;
    type TextField = (typeof textFields)[number];
    const assignNullable = (field: TextField) => {
      const value = user[field];
      if (value === undefined) return;
      const normalized = value ?? null;
      values[field] = normalized;
      updateSet[field] = normalized;
    };
    textFields.forEach(assignNullable);
    if (user.lastSignedIn !== undefined) {
      values.lastSignedIn = user.lastSignedIn;
      updateSet.lastSignedIn = user.lastSignedIn;
    }
    if (user.role !== undefined) {
      values.role = user.role;
      updateSet.role = user.role;
    } else if (user.openId === ENV.ownerOpenId) {
      values.role = 'admin';
      updateSet.role = 'admin';
    }
    if (!values.lastSignedIn) values.lastSignedIn = new Date();
    if (Object.keys(updateSet).length === 0) updateSet.lastSignedIn = new Date();
    await db.insert(users).values(values).onDuplicateKeyUpdate({ set: updateSet });
  } catch (error) {
    console.error("[Database] Failed to upsert user:", error);
    throw error;
  }
}

export async function getUserByOpenId(openId: string) {
  const db = await getDb();
  if (!db) return undefined;
  const result = await db.select().from(users).where(eq(users.openId, openId)).limit(1);
  return result.length > 0 ? result[0] : undefined;
}

// ─── Scan Queries ────────────────────────────────────────────────

export async function createScan(data: InsertScan) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const result = await db.insert(scans).values(data);
  return result[0].insertId;
}

export async function getScanById(id: number) {
  const db = await getDb();
  if (!db) return undefined;
  const result = await db.select().from(scans).where(eq(scans.id, id)).limit(1);
  return result[0];
}

export async function listScans(limit = 50, offset = 0) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(scans).orderBy(desc(scans.createdAt)).limit(limit).offset(offset);
}

export async function updateScan(id: number, data: Partial<Scan>) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  await db.update(scans).set(data).where(eq(scans.id, id));
}

export async function deleteScan(id: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  // Delete related records first
  await db.delete(vulnerabilities).where(eq(vulnerabilities.scanId, id));
  await db.delete(ports).where(eq(ports.scanId, id));
  await db.delete(hosts).where(eq(hosts.scanId, id));
  await db.delete(scans).where(eq(scans.id, id));
}

export async function getScanCount() {
  const db = await getDb();
  if (!db) return 0;
  const result = await db.select({ count: count() }).from(scans);
  return result[0]?.count ?? 0;
}

// ─── Host Queries ────────────────────────────────────────────────

export async function createHost(data: InsertHost) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const result = await db.insert(hosts).values(data);
  return result[0].insertId;
}

export async function createHosts(data: InsertHost[]) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  if (data.length === 0) return;
  await db.insert(hosts).values(data);
}

export async function getHostsByScanId(scanId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(hosts).where(eq(hosts.scanId, scanId));
}

export async function getHostById(id: number) {
  const db = await getDb();
  if (!db) return undefined;
  const result = await db.select().from(hosts).where(eq(hosts.id, id)).limit(1);
  return result[0];
}

// ─── Port Queries ────────────────────────────────────────────────

export async function createPorts(data: InsertPort[]) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  if (data.length === 0) return;
  await db.insert(ports).values(data);
}

export async function getPortsByHostId(hostId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(ports).where(eq(ports.hostId, hostId));
}

export async function getPortsByScanId(scanId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(ports).where(eq(ports.scanId, scanId));
}

// ─── Vulnerability Queries ───────────────────────────────────────

export async function createVulnerabilities(data: InsertVulnerability[]) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  if (data.length === 0) return;
  await db.insert(vulnerabilities).values(data);
}

export async function getVulnsByHostId(hostId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(vulnerabilities).where(eq(vulnerabilities.hostId, hostId));
}

export async function getVulnsByScanId(scanId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(vulnerabilities).where(eq(vulnerabilities.scanId, scanId));
}

// ─── Audit Log Queries ──────────────────────────────────────────

export async function createAuditEntry(data: InsertAuditLogEntry) {
  const db = await getDb();
  if (!db) return;
  await db.insert(auditLog).values(data);
}

export async function listAuditLog(limit = 100, offset = 0) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(auditLog).orderBy(desc(auditLog.createdAt)).limit(limit).offset(offset);
}

// ─── CIDR Rules Queries ─────────────────────────────────────────

export async function createCidrRule(data: InsertCidrRule) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const result = await db.insert(cidrRules).values(data);
  return result[0].insertId;
}

export async function listCidrRules() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(cidrRules).orderBy(desc(cidrRules.createdAt));
}

export async function updateCidrRule(id: number, data: Partial<InsertCidrRule>) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  await db.update(cidrRules).set(data).where(eq(cidrRules.id, id));
}

export async function deleteCidrRule(id: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  await db.delete(cidrRules).where(eq(cidrRules.id, id));
}

// ─── CUDA Device Queries ────────────────────────────────────────

export async function upsertCudaDevice(data: InsertCudaDevice) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  await db.insert(cudaDevices).values(data).onDuplicateKeyUpdate({
    set: {
      deviceName: data.deviceName,
      totalMemory: data.totalMemory,
      freeMemory: data.freeMemory,
      utilization: data.utilization,
      temperature: data.temperature,
      powerDraw: data.powerDraw,
      available: data.available,
      driverVersion: data.driverVersion,
      cudaVersion: data.cudaVersion,
      lastCheckedAt: new Date(),
    },
  });
}

export async function listCudaDevices() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(cudaDevices).orderBy(cudaDevices.deviceIndex);
}

// ─── Scan Templates Queries ─────────────────────────────────────

export async function listScanTemplates() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(scanTemplates).orderBy(scanTemplates.name);
}

export async function createScanTemplate(data: InsertScanTemplate) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const result = await db.insert(scanTemplates).values(data);
  return result[0].insertId;
}

// ─── Dashboard Stats ────────────────────────────────────────────

export async function getDashboardStats() {
  const db = await getDb();
  if (!db) return {
    totalScans: 0, activeScans: 0, totalHosts: 0,
    totalOpenPorts: 0, totalVulns: 0, criticalVulns: 0,
    recentScans: [],
  };

  const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

  const [scanStats] = await db.select({
    total: count(),
    active: sql<number>`SUM(CASE WHEN status IN ('queued', 'running') THEN 1 ELSE 0 END)`,
  }).from(scans);

  const [hostStats] = await db.select({
    total: count(),
  }).from(hosts);

  const [portStats] = await db.select({
    openPorts: sql<number>`SUM(CASE WHEN state = 'open' THEN 1 ELSE 0 END)`,
  }).from(ports);

  const [vulnStats] = await db.select({
    total: count(),
    critical: sql<number>`SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END)`,
  }).from(vulnerabilities);

  const recentScans = await db.select().from(scans)
    .orderBy(desc(scans.createdAt)).limit(10);

  return {
    totalScans: scanStats?.total ?? 0,
    activeScans: Number(scanStats?.active) || 0,
    totalHosts: hostStats?.total ?? 0,
    totalOpenPorts: Number(portStats?.openPorts) || 0,
    totalVulns: vulnStats?.total ?? 0,
    criticalVulns: Number(vulnStats?.critical) || 0,
    recentScans,
  };
}
