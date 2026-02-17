# Full-Stack Upgrade TODO

## Phase 1: Upgrade to web-db-user
- [x] Run webdev_add_feature to add backend, database, user management
- [x] Review generated scaffolding and resolve merge conflicts

## Phase 2: Database Schema
- [x] Create scans table
- [x] Create hosts table
- [x] Create ports table
- [x] Create vulnerabilities table
- [x] Create audit_log table
- [x] Create cidr_rules table
- [x] Run migrations (9 tables, 0001_busy_odin.sql applied)

## Phase 3: Backend API Routes
- [x] POST /api/scans - Create and queue a new scan
- [x] GET /api/scans - List all scans with pagination
- [x] GET /api/scans/:id - Get scan details with hosts/ports
- [x] DELETE /api/scans/:id - Delete a scan
- [x] GET /api/stats - Dashboard statistics
- [x] GET /api/audit - Audit log entries
- [x] CRUD /api/cidr - CIDR scope rules
- [x] Nmap execution service (spawn nmap, parse XML)

## Phase 4: Frontend Integration
- [x] Wire Home.tsx to tRPC stats endpoint
- [x] Wire ScanCreate.tsx to tRPC scan.create mutation
- [x] Wire ScanHistory.tsx to tRPC scan.list query
- [x] Wire ScanResults.tsx to tRPC scan.getById query
- [x] Wire AuditLog.tsx to tRPC audit.list query
- [x] Wire CidrManager.tsx to tRPC cidr CRUD
- [x] Wire Settings.tsx to tRPC cuda.status and info.nmapVersion

## Phase 5: Test & Deliver
- [x] Write vitest tests for nmap-service (buildNmapCommand, parseNmapXml) — 24 tests passing
- [x] Write vitest tests for tRPC router procedures — 24 tests passing
- [x] Checkpoint and push to GitHub (version a970e550)

## CUDA GPU Acceleration
- [x] Add CUDA toggle to ScanCreate form
- [x] Add CUDA/GPU tab to Settings page
- [x] Display CUDA status badge on Home dashboard
- [x] Display Nmap version badge on Home dashboard
- [x] Track GPU availability and CUDA status in scan configuration
- [x] Support GPU-accelerated packet processing options

## CVE Lookup Integration
- [x] Research public CVE APIs (NVD NIST API 2.0)
- [x] Build backend CVE service with caching and rate limiting
- [x] Create tRPC routes for CVE search, detail, and service-based lookup
- [x] Add CVE database table for caching results
- [x] Build CVE Lookup page with search by keyword, CVE ID, CPE, service+version
- [x] Build CVE Detail view with severity, CVSS score, references, affected products
- [x] Add CVE column/badges to ScanResults port table
- [x] Add CVE links to HostDetail vulnerability cards and port table
- [x] Add navigation entry for CVE Lookup in sidebar + Home quick actions
- [x] Write vitest tests for CVE service — 30 tests passing (54 total)
- [ ] Checkpoint and push to GitHub
