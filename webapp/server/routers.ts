import { COOKIE_NAME } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { publicProcedure, protectedProcedure, router } from "./_core/trpc";
import { z } from "zod";
import {
  createScan, getScanById, listScans, updateScan, deleteScan, getScanCount,
  getHostsByScanId, getHostById, getPortsByHostId, getPortsByScanId,
  getVulnsByHostId, getVulnsByScanId,
  listAuditLog, createAuditEntry,
  createCidrRule, listCidrRules, updateCidrRule, deleteCidrRule,
  listCudaDevices,
  listScanTemplates, createScanTemplate,
  getDashboardStats,
} from "./db";
import {
  executeScan, cancelScan, getActiveScans,
  getNmapVersion, checkCudaAvailability, buildNmapCommand,
} from "./nmap-service";
import {
  lookupCveById, searchCveByKeyword, searchCveByCpe,
  lookupCveForService, getCachedCves, buildCpeFromService,
} from "./cve-service";
import {
  getAlertStats, getRecentAlerts, updateAlertStatus, bulkDismissAlerts,
} from "./alert-service";
import { alertRules, alerts } from "../drizzle/schema";
import { eq, desc, and, sql } from "drizzle-orm";
import { getDb } from "./db";

export const appRouter = router({
  system: systemRouter,

  auth: router({
    me: publicProcedure.query(opts => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      return { success: true } as const;
    }),
  }),

  // ─── Scan Operations ────────────────────────────────────────────

  scan: router({
    /** Create and optionally execute a new scan */
    create: protectedProcedure
      .input(z.object({
        target: z.string().min(1).max(1024),
        profile: z.string().optional(),
        flags: z.string().optional(),
        cudaEnabled: z.boolean().optional().default(false),
        cudaDevice: z.string().optional(),
        autoStart: z.boolean().optional().default(true),
      }))
      .mutation(async ({ ctx, input }) => {
        const scanId = await createScan({
          userId: ctx.user.id,
          target: input.target,
          profile: input.profile || null,
          flags: input.flags || null,
          cudaEnabled: input.cudaEnabled,
          cudaDevice: input.cudaDevice || null,
          status: input.autoStart ? "queued" : "queued",
        });

        await createAuditEntry({
          userId: ctx.user.id,
          userName: ctx.user.name || ctx.user.email || "Unknown",
          action: "scan_created",
          details: `Created scan targeting ${input.target}${input.profile ? ` (profile: ${input.profile})` : ""}${input.cudaEnabled ? " [CUDA]" : ""}`,
          entityType: "scan",
          entityId: scanId,
        });

        // Auto-start scan execution in background
        if (input.autoStart) {
          executeScan(scanId).catch(err => {
            console.error(`[Scan ${scanId}] Execution failed:`, err.message);
          });
        }

        return { id: scanId, status: "queued" };
      }),

    /** List scans with pagination */
    list: protectedProcedure
      .input(z.object({
        limit: z.number().min(1).max(200).optional().default(50),
        offset: z.number().min(0).optional().default(0),
      }))
      .query(async ({ input }) => {
        const [scanList, total] = await Promise.all([
          listScans(input.limit, input.offset),
          getScanCount(),
        ]);
        return { scans: scanList, total };
      }),

    /** Get scan by ID with hosts and ports */
    getById: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        const scan = await getScanById(input.id);
        if (!scan) return null;
        const scanHosts = await getHostsByScanId(input.id);
        const scanPorts = await getPortsByScanId(input.id);
        const scanVulns = await getVulnsByScanId(input.id);
        return { ...scan, hosts: scanHosts, ports: scanPorts, vulnerabilities: scanVulns };
      }),

    /** Delete a scan and all related data */
    delete: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ ctx, input }) => {
        await deleteScan(input.id);
        await createAuditEntry({
          userId: ctx.user.id,
          userName: ctx.user.name || "Unknown",
          action: "scan_deleted",
          details: `Deleted scan #${input.id}`,
          entityType: "scan",
          entityId: input.id,
        });
        return { success: true };
      }),

    /** Cancel a running scan */
    cancel: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ ctx, input }) => {
        const cancelled = cancelScan(input.id);
        if (cancelled) {
          await updateScan(input.id, { status: "cancelled", completedAt: new Date(), progress: 100 });
          await createAuditEntry({
            userId: ctx.user.id,
            userName: ctx.user.name || "Unknown",
            action: "scan_cancelled",
            details: `Cancelled scan #${input.id}`,
            entityType: "scan",
            entityId: input.id,
          });
        }
        return { success: cancelled };
      }),

    /** Preview the nmap command that would be executed */
    preview: publicProcedure
      .input(z.object({
        target: z.string().min(1),
        profile: z.string().optional(),
        flags: z.string().optional(),
        cudaEnabled: z.boolean().optional().default(false),
        cudaDevice: z.string().optional(),
      }))
      .query(({ input }) => {
        const { command, args } = buildNmapCommand({
          target: input.target,
          flags: input.flags,
          profile: input.profile,
          cudaEnabled: input.cudaEnabled,
          cudaDevice: input.cudaDevice,
        });
        return { command: `${command} ${args.join(" ")}` };
      }),

    /** Get active/running scan IDs */
    active: protectedProcedure.query(() => {
      return { scanIds: getActiveScans() };
    }),
  }),

  // ─── Host Operations ────────────────────────────────────────────

  host: router({
    /** Get hosts for a scan */
    byScan: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .query(async ({ input }) => {
        return getHostsByScanId(input.scanId);
      }),

    /** Get host detail with ports and vulns */
    detail: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        const host = await getHostById(input.id);
        if (!host) return null;
        const hostPorts = await getPortsByHostId(input.id);
        const hostVulns = await getVulnsByHostId(input.id);
        return { ...host, ports: hostPorts, vulnerabilities: hostVulns };
      }),
  }),

  // ─── Dashboard Stats ───────────────────────────────────────────

  stats: router({
    dashboard: protectedProcedure.query(async () => {
      return getDashboardStats();
    }),
  }),

  // ─── Audit Log ─────────────────────────────────────────────────

  audit: router({
    list: protectedProcedure
      .input(z.object({
        limit: z.number().min(1).max(500).optional().default(100),
        offset: z.number().min(0).optional().default(0),
      }))
      .query(async ({ input }) => {
        return listAuditLog(input.limit, input.offset);
      }),
  }),

  // ─── CIDR Scope Rules ──────────────────────────────────────────

  cidr: router({
    list: protectedProcedure.query(async () => {
      return listCidrRules();
    }),

    create: protectedProcedure
      .input(z.object({
        cidr: z.string().min(1),
        label: z.string().optional(),
        type: z.enum(["allow", "deny"]),
        enabled: z.boolean().optional().default(true),
        notes: z.string().optional(),
      }))
      .mutation(async ({ ctx, input }) => {
        const id = await createCidrRule({
          cidr: input.cidr,
          label: input.label || null,
          type: input.type,
          enabled: input.enabled,
          notes: input.notes || null,
          createdBy: ctx.user.id,
        });
        await createAuditEntry({
          userId: ctx.user.id,
          userName: ctx.user.name || "Unknown",
          action: "cidr_added",
          details: `Added ${input.type} rule: ${input.cidr}${input.label ? ` (${input.label})` : ""}`,
          entityType: "cidr_rule",
          entityId: id,
        });
        return { id };
      }),

    update: protectedProcedure
      .input(z.object({
        id: z.number(),
        enabled: z.boolean().optional(),
        label: z.string().optional(),
        notes: z.string().optional(),
      }))
      .mutation(async ({ ctx, input }) => {
        const { id, ...data } = input;
        await updateCidrRule(id, data);
        if (input.enabled !== undefined) {
          await createAuditEntry({
            userId: ctx.user.id,
            userName: ctx.user.name || "Unknown",
            action: "cidr_toggled",
            details: `${input.enabled ? "Enabled" : "Disabled"} CIDR rule #${id}`,
            entityType: "cidr_rule",
            entityId: id,
          });
        }
        return { success: true };
      }),

    delete: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ ctx, input }) => {
        await deleteCidrRule(input.id);
        await createAuditEntry({
          userId: ctx.user.id,
          userName: ctx.user.name || "Unknown",
          action: "cidr_removed",
          details: `Removed CIDR rule #${input.id}`,
          entityType: "cidr_rule",
          entityId: input.id,
        });
        return { success: true };
      }),
  }),

  // ─── CUDA / GPU ────────────────────────────────────────────────

  cuda: router({
    /** Check CUDA availability from nvidia-smi */
    status: protectedProcedure.query(async () => {
      const cuda = await checkCudaAvailability();
      const devices = await listCudaDevices();
      return { ...cuda, persistedDevices: devices };
    }),
  }),

  // ─── CVE Lookup ────────────────────────────────────────────────

  cve: router({
    /** Look up a single CVE by ID */
    getById: publicProcedure
      .input(z.object({ cveId: z.string().min(1) }))
      .query(async ({ input }) => {
        const result = await lookupCveById(input.cveId);
        return result;
      }),

    /** Search CVEs by keyword */
    search: publicProcedure
      .input(z.object({
        query: z.string().min(1),
        severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).optional(),
        resultsPerPage: z.number().min(1).max(100).optional().default(20),
        startIndex: z.number().min(0).optional().default(0),
      }))
      .query(async ({ input }) => {
        // If it looks like a CVE ID, do a direct lookup
        if (/^CVE-\d{4}-\d{4,}$/i.test(input.query.trim())) {
          const result = await lookupCveById(input.query.trim().toUpperCase());
          return {
            totalResults: result ? 1 : 0,
            resultsPerPage: 1,
            startIndex: 0,
            results: result ? [result] : [],
          };
        }
        // If it looks like a CPE, search by CPE
        if (input.query.startsWith("cpe:")) {
          return searchCveByCpe(input.query, {
            resultsPerPage: input.resultsPerPage,
            startIndex: input.startIndex,
          });
        }
        // Otherwise keyword search
        return searchCveByKeyword(input.query, {
          resultsPerPage: input.resultsPerPage,
          startIndex: input.startIndex,
          severity: input.severity,
        });
      }),

    /** Look up CVEs for a discovered service+version */
    forService: publicProcedure
      .input(z.object({
        service: z.string().min(1),
        product: z.string().optional(),
        version: z.string().optional(),
      }))
      .query(async ({ input }) => {
        return lookupCveForService(input.service, input.product, input.version);
      }),

    /** Build CPE from service info (utility) */
    buildCpe: publicProcedure
      .input(z.object({
        service: z.string().min(1),
        product: z.string().optional(),
        version: z.string().optional(),
      }))
      .query(async ({ input }) => {
        const cpe = buildCpeFromService(input.service, input.product, input.version);
        return { cpe };
      }),

    /** Get cached CVEs from database */
    cached: publicProcedure
      .input(z.object({
        limit: z.number().min(1).max(100).optional().default(50),
        offset: z.number().min(0).optional().default(0),
        severity: z.string().optional(),
        search: z.string().optional(),
      }))
      .query(async ({ input }) => {
        return getCachedCves(input);
      }),
  }),

  // ─── System Info ───────────────────────────────────────────────

  info: router({
    /** Get nmap version */
    nmapVersion: publicProcedure.query(async () => {
      const version = await getNmapVersion();
      return { installed: !!version, version };
    }),
  }),

  // ─── Alerts ────────────────────────────────────────────────────

  alert: router({
    /** Get alert statistics for dashboard */
    stats: protectedProcedure.query(async () => {
      return getAlertStats();
    }),

    /** List recent alerts with optional filters */
    list: protectedProcedure
      .input(z.object({
        limit: z.number().min(1).max(200).optional().default(50),
        severity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
        status: z.enum(["new", "acknowledged", "investigating", "resolved", "dismissed"]).optional(),
      }))
      .query(async ({ input }) => {
        const db = await getDb();
        if (!db) return [];
        const conditions = [];
        if (input.severity) conditions.push(eq(alerts.severity, input.severity));
        if (input.status) conditions.push(eq(alerts.status, input.status));
        if (conditions.length > 0) {
          return db.select().from(alerts).where(and(...conditions)).orderBy(desc(alerts.createdAt)).limit(input.limit);
        }
        return db.select().from(alerts).orderBy(desc(alerts.createdAt)).limit(input.limit);
      }),

    /** Update alert status */
    updateStatus: protectedProcedure
      .input(z.object({
        id: z.number(),
        status: z.enum(["acknowledged", "investigating", "resolved", "dismissed"]),
        notes: z.string().optional(),
      }))
      .mutation(async ({ ctx, input }) => {
        await updateAlertStatus(input.id, input.status, ctx.user.id, input.notes);
        return { success: true };
      }),

    /** Bulk dismiss alerts */
    bulkDismiss: protectedProcedure
      .input(z.object({
        ids: z.array(z.number()).min(1),
      }))
      .mutation(async ({ ctx, input }) => {
        const count = await bulkDismissAlerts(input.ids, ctx.user.id);
        return { dismissed: count };
      }),
  }),

  // ─── Alert Rules ──────────────────────────────────────────────

  alertRule: router({
    /** List all alert rules */
    list: protectedProcedure.query(async () => {
      const db = await getDb();
      if (!db) return [];
      return db.select().from(alertRules).orderBy(desc(alertRules.createdAt));
    }),

    /** Create a new alert rule */
    create: protectedProcedure
      .input(z.object({
        name: z.string().min(1),
        description: z.string().optional(),
        severityThreshold: z.enum(["critical", "high", "medium", "low"]),
        cvssThreshold: z.number().min(0).max(10).optional(),
        watchedServices: z.array(z.string()).optional(),
        watchedTargets: z.array(z.string()).optional(),
        watchedCveIds: z.array(z.string()).optional(),
        alertOnKev: z.boolean().optional().default(true),
        channels: z.array(z.string()).optional(),
        cooldownMinutes: z.number().min(1).optional().default(60),
      }))
      .mutation(async ({ ctx, input }) => {
        const db = await getDb();
        if (!db) throw new Error("Database not available");
        const result = await db.insert(alertRules).values({
          name: input.name,
          description: input.description || null,
          severityThreshold: input.severityThreshold,
          cvssThreshold: input.cvssThreshold || null,
          watchedServices: input.watchedServices ? JSON.parse(JSON.stringify(input.watchedServices)) : null,
          watchedTargets: input.watchedTargets ? JSON.parse(JSON.stringify(input.watchedTargets)) : null,
          watchedCveIds: input.watchedCveIds ? JSON.parse(JSON.stringify(input.watchedCveIds)) : null,
          alertOnKev: input.alertOnKev,
          channels: input.channels ? JSON.parse(JSON.stringify(input.channels)) : JSON.parse(JSON.stringify(["in_app", "push"])),
          cooldownMinutes: input.cooldownMinutes,
          createdBy: ctx.user.id,
          enabled: true,
        });
        return { id: Number(result[0].insertId) };
      }),

    /** Toggle alert rule enabled/disabled */
    toggle: protectedProcedure
      .input(z.object({
        id: z.number(),
        enabled: z.boolean(),
      }))
      .mutation(async ({ input }) => {
        const db = await getDb();
        if (!db) throw new Error("Database not available");
        await db.update(alertRules).set({ enabled: input.enabled }).where(eq(alertRules.id, input.id));
        return { success: true };
      }),

    /** Delete an alert rule */
    delete: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input }) => {
        const db = await getDb();
        if (!db) throw new Error("Database not available");
        await db.delete(alertRules).where(eq(alertRules.id, input.id));
        return { success: true };
      }),
  }),

  // ─── Scan Templates ───────────────────────────────────────────

  templates: router({
    list: protectedProcedure.query(async () => {
      return listScanTemplates();
    }),

    create: protectedProcedure
      .input(z.object({
        name: z.string().min(1),
        description: z.string().optional(),
        flags: z.string().optional(),
        category: z.string().optional(),
        cudaRecommended: z.boolean().optional().default(false),
      }))
      .mutation(async ({ ctx, input }) => {
        const id = await createScanTemplate({
          name: input.name,
          description: input.description || null,
          flags: input.flags || null,
          category: input.category || null,
          cudaRecommended: input.cudaRecommended,
          isSystem: false,
          createdBy: ctx.user.id,
        });
        return { id };
      }),
  }),
});

export type AppRouter = typeof appRouter;
