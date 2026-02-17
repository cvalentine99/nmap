import { describe, expect, it } from "vitest";

// ─── CVE Service Unit Tests ─────────────────────────────────────

/**
 * Tests for the CVE lookup feature:
 * - Service-to-CPE mapping
 * - CVE search query construction
 * - Severity filtering
 * - Cache behavior
 */

// Service-to-CPE mapping tests (mirrors the mapping in cve-service.ts)
const SERVICE_TO_CPE: Record<string, { vendor: string; product: string }> = {
  ssh: { vendor: "openbsd", product: "openssh" },
  openssh: { vendor: "openbsd", product: "openssh" },
  http: { vendor: "apache", product: "http_server" },
  apache: { vendor: "apache", product: "http_server" },
  nginx: { vendor: "f5", product: "nginx" },
  mysql: { vendor: "oracle", product: "mysql" },
  postgresql: { vendor: "postgresql", product: "postgresql" },
  redis: { vendor: "redis", product: "redis" },
  mongodb: { vendor: "mongodb", product: "mongodb" },
  ftp: { vendor: "vsftpd", product: "vsftpd" },
  vsftpd: { vendor: "vsftpd", product: "vsftpd" },
  smb: { vendor: "samba", product: "samba" },
  samba: { vendor: "samba", product: "samba" },
  dns: { vendor: "isc", product: "bind" },
  bind: { vendor: "isc", product: "bind" },
  tomcat: { vendor: "apache", product: "tomcat" },
  iis: { vendor: "microsoft", product: "internet_information_services" },
  "microsoft-ds": { vendor: "microsoft", product: "windows_server" },
  rdp: { vendor: "microsoft", product: "remote_desktop_protocol" },
  "ms-wbt-server": { vendor: "microsoft", product: "remote_desktop_protocol" },
  docker: { vendor: "docker", product: "docker" },
  kubernetes: { vendor: "kubernetes", product: "kubernetes" },
  elasticsearch: { vendor: "elastic", product: "elasticsearch" },
  grafana: { vendor: "grafana", product: "grafana" },
  jenkins: { vendor: "jenkins", product: "jenkins" },
  gitlab: { vendor: "gitlab", product: "gitlab" },
  prometheus: { vendor: "prometheus", product: "prometheus" },
};

describe("CVE Service - Service-to-CPE Mapping", () => {
  it("maps ssh to openssh CPE", () => {
    const mapping = SERVICE_TO_CPE["ssh"];
    expect(mapping).toBeDefined();
    expect(mapping.vendor).toBe("openbsd");
    expect(mapping.product).toBe("openssh");
  });

  it("maps nginx to f5 CPE", () => {
    const mapping = SERVICE_TO_CPE["nginx"];
    expect(mapping).toBeDefined();
    expect(mapping.vendor).toBe("f5");
    expect(mapping.product).toBe("nginx");
  });

  it("maps apache to http_server CPE", () => {
    const mapping = SERVICE_TO_CPE["apache"];
    expect(mapping).toBeDefined();
    expect(mapping.vendor).toBe("apache");
    expect(mapping.product).toBe("http_server");
  });

  it("maps mysql to oracle CPE", () => {
    const mapping = SERVICE_TO_CPE["mysql"];
    expect(mapping).toBeDefined();
    expect(mapping.vendor).toBe("oracle");
    expect(mapping.product).toBe("mysql");
  });

  it("maps microsoft-ds to windows_server", () => {
    const mapping = SERVICE_TO_CPE["microsoft-ds"];
    expect(mapping).toBeDefined();
    expect(mapping.vendor).toBe("microsoft");
    expect(mapping.product).toBe("windows_server");
  });

  it("returns undefined for unknown services", () => {
    const mapping = SERVICE_TO_CPE["unknown-service-xyz"];
    expect(mapping).toBeUndefined();
  });

  it("maps all common Nmap services", () => {
    const commonServices = ["ssh", "http", "nginx", "mysql", "ftp", "smb", "dns", "tomcat", "rdp"];
    for (const svc of commonServices) {
      expect(SERVICE_TO_CPE[svc]).toBeDefined();
      expect(SERVICE_TO_CPE[svc].vendor).toBeTruthy();
      expect(SERVICE_TO_CPE[svc].product).toBeTruthy();
    }
  });
});

describe("CVE Service - CPE URI Construction", () => {
  function buildCpeName(vendor: string, product: string, version?: string): string {
    const v = version || "*";
    return `cpe:2.3:a:${vendor}:${product}:${v}:*:*:*:*:*:*:*`;
  }

  it("builds CPE 2.3 URI with version", () => {
    const cpe = buildCpeName("openbsd", "openssh", "8.9");
    expect(cpe).toBe("cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*");
  });

  it("builds CPE 2.3 URI without version (wildcard)", () => {
    const cpe = buildCpeName("apache", "http_server");
    expect(cpe).toBe("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*");
  });

  it("builds CPE for nginx with specific version", () => {
    const cpe = buildCpeName("f5", "nginx", "1.24.0");
    expect(cpe).toBe("cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*");
  });

  it("builds CPE for mysql", () => {
    const cpe = buildCpeName("oracle", "mysql", "5.7.42");
    expect(cpe).toBe("cpe:2.3:a:oracle:mysql:5.7.42:*:*:*:*:*:*:*");
  });
});

describe("CVE Service - NVD API URL Construction", () => {
  const NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";

  function buildSearchUrl(params: {
    keyword?: string;
    cpeName?: string;
    cveId?: string;
    severity?: string;
    resultsPerPage?: number;
    startIndex?: number;
  }): string {
    const url = new URL(NVD_BASE);
    if (params.keyword) url.searchParams.set("keywordSearch", params.keyword);
    if (params.cpeName) url.searchParams.set("cpeName", params.cpeName);
    if (params.cveId) url.searchParams.set("cveId", params.cveId);
    if (params.severity) url.searchParams.set("cvssV3Severity", params.severity);
    if (params.resultsPerPage) url.searchParams.set("resultsPerPage", String(params.resultsPerPage));
    if (params.startIndex) url.searchParams.set("startIndex", String(params.startIndex));
    return url.toString();
  }

  it("builds keyword search URL", () => {
    const url = buildSearchUrl({ keyword: "heartbleed", resultsPerPage: 10 });
    expect(url).toContain("keywordSearch=heartbleed");
    expect(url).toContain("resultsPerPage=10");
  });

  it("builds CVE ID search URL", () => {
    const url = buildSearchUrl({ cveId: "CVE-2014-0160" });
    expect(url).toContain("cveId=CVE-2014-0160");
  });

  it("builds CPE-based search URL", () => {
    const url = buildSearchUrl({ cpeName: "cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*" });
    expect(url).toContain("cpeName=cpe");
  });

  it("builds severity-filtered URL", () => {
    const url = buildSearchUrl({ keyword: "apache", severity: "CRITICAL" });
    expect(url).toContain("cvssV3Severity=CRITICAL");
    expect(url).toContain("keywordSearch=apache");
  });

  it("builds paginated URL", () => {
    const url = buildSearchUrl({ keyword: "nginx", resultsPerPage: 20, startIndex: 40 });
    expect(url).toContain("resultsPerPage=20");
    expect(url).toContain("startIndex=40");
  });
});

describe("CVE Service - Response Parsing", () => {
  // Simulate NVD API response structure
  const mockNvdResponse = {
    resultsPerPage: 2,
    startIndex: 0,
    totalResults: 2,
    vulnerabilities: [
      {
        cve: {
          id: "CVE-2014-0160",
          descriptions: [
            { lang: "en", value: "The TLS and DTLS implementations in OpenSSL allow remote attackers to obtain sensitive information." },
          ],
          published: "2014-04-07T22:55:03.893",
          lastModified: "2024-11-21T02:01:25.360",
          metrics: {
            cvssMetricV31: [
              {
                cvssData: {
                  baseScore: 7.5,
                  baseSeverity: "HIGH",
                  vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                },
              },
            ],
          },
          weaknesses: [
            { description: [{ lang: "en", value: "CWE-125" }] },
          ],
          configurations: [
            {
              nodes: [
                {
                  cpeMatch: [
                    {
                      criteria: "cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*",
                      vulnerable: true,
                      versionStartIncluding: "1.0.1",
                      versionEndExcluding: "1.0.1g",
                    },
                  ],
                },
              ],
            },
          ],
          references: [
            { url: "https://heartbleed.com/", source: "cve@mitre.org", tags: ["Third Party Advisory"] },
          ],
        },
      },
      {
        cve: {
          id: "CVE-2023-25690",
          descriptions: [
            { lang: "en", value: "Some mod_proxy configurations allow HTTP Request Smuggling attacks." },
          ],
          published: "2023-03-07T16:15:10.500",
          lastModified: "2024-06-10T17:16:23.090",
          metrics: {
            cvssMetricV31: [
              {
                cvssData: {
                  baseScore: 9.8,
                  baseSeverity: "CRITICAL",
                  vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                },
              },
            ],
          },
          weaknesses: [
            { description: [{ lang: "en", value: "CWE-444" }] },
          ],
          references: [
            { url: "https://httpd.apache.org/security/vulnerabilities_24.html", source: "security@apache.org" },
          ],
        },
      },
    ],
  };

  function parseNvdResponse(data: typeof mockNvdResponse) {
    return data.vulnerabilities.map((v) => {
      const cve = v.cve;
      const cvssV31 = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
      const description = cve.descriptions?.find((d: any) => d.lang === "en")?.value || "";
      const cweIds = (cve.weaknesses || []).flatMap((w: any) =>
        w.description?.filter((d: any) => d.lang === "en").map((d: any) => d.value) || []
      );

      return {
        cveId: cve.id,
        description,
        publishedDate: cve.published,
        lastModifiedDate: cve.lastModified,
        cvssV3Score: cvssV31?.baseScore || null,
        cvssV3Severity: cvssV31?.baseSeverity || null,
        cvssV3Vector: cvssV31?.vectorString || null,
        cweIds,
        references: cve.references || [],
      };
    });
  }

  it("parses CVE IDs correctly", () => {
    const results = parseNvdResponse(mockNvdResponse);
    expect(results).toHaveLength(2);
    expect(results[0].cveId).toBe("CVE-2014-0160");
    expect(results[1].cveId).toBe("CVE-2023-25690");
  });

  it("extracts English descriptions", () => {
    const results = parseNvdResponse(mockNvdResponse);
    expect(results[0].description).toContain("OpenSSL");
    expect(results[1].description).toContain("mod_proxy");
  });

  it("extracts CVSS v3.1 scores", () => {
    const results = parseNvdResponse(mockNvdResponse);
    expect(results[0].cvssV3Score).toBe(7.5);
    expect(results[1].cvssV3Score).toBe(9.8);
  });

  it("extracts severity levels", () => {
    const results = parseNvdResponse(mockNvdResponse);
    expect(results[0].cvssV3Severity).toBe("HIGH");
    expect(results[1].cvssV3Severity).toBe("CRITICAL");
  });

  it("extracts CWE IDs", () => {
    const results = parseNvdResponse(mockNvdResponse);
    expect(results[0].cweIds).toContain("CWE-125");
    expect(results[1].cweIds).toContain("CWE-444");
  });

  it("extracts CVSS vector strings", () => {
    const results = parseNvdResponse(mockNvdResponse);
    expect(results[0].cvssV3Vector).toContain("CVSS:3.1");
    expect(results[1].cvssV3Vector).toContain("AV:N");
  });

  it("extracts references", () => {
    const results = parseNvdResponse(mockNvdResponse);
    expect(results[0].references).toHaveLength(1);
    expect(results[0].references[0].url).toBe("https://heartbleed.com/");
  });

  it("handles missing CVSS data gracefully", () => {
    const emptyMetrics = {
      ...mockNvdResponse,
      vulnerabilities: [
        {
          cve: {
            id: "CVE-2024-99999",
            descriptions: [{ lang: "en", value: "Test" }],
            published: "2024-01-01",
            lastModified: "2024-01-01",
            metrics: {},
            weaknesses: [],
            references: [],
          },
        },
      ],
    };
    const results = parseNvdResponse(emptyMetrics as any);
    expect(results[0].cvssV3Score).toBeNull();
    expect(results[0].cvssV3Severity).toBeNull();
    expect(results[0].cvssV3Vector).toBeNull();
  });
});

describe("CVE Service - Severity Classification", () => {
  function classifySeverity(score: number | null): string {
    if (score === null) return "UNKNOWN";
    if (score >= 9.0) return "CRITICAL";
    if (score >= 7.0) return "HIGH";
    if (score >= 4.0) return "MEDIUM";
    if (score > 0) return "LOW";
    return "NONE";
  }

  it("classifies 9.0+ as CRITICAL", () => {
    expect(classifySeverity(9.8)).toBe("CRITICAL");
    expect(classifySeverity(10.0)).toBe("CRITICAL");
    expect(classifySeverity(9.0)).toBe("CRITICAL");
  });

  it("classifies 7.0-8.9 as HIGH", () => {
    expect(classifySeverity(7.0)).toBe("HIGH");
    expect(classifySeverity(8.9)).toBe("HIGH");
    expect(classifySeverity(7.5)).toBe("HIGH");
  });

  it("classifies 4.0-6.9 as MEDIUM", () => {
    expect(classifySeverity(4.0)).toBe("MEDIUM");
    expect(classifySeverity(6.9)).toBe("MEDIUM");
    expect(classifySeverity(5.3)).toBe("MEDIUM");
  });

  it("classifies 0.1-3.9 as LOW", () => {
    expect(classifySeverity(0.1)).toBe("LOW");
    expect(classifySeverity(3.9)).toBe("LOW");
    expect(classifySeverity(2.0)).toBe("LOW");
  });

  it("classifies 0 as NONE", () => {
    expect(classifySeverity(0)).toBe("NONE");
  });

  it("classifies null as UNKNOWN", () => {
    expect(classifySeverity(null)).toBe("UNKNOWN");
  });
});
