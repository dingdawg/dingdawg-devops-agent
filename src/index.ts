#!/usr/bin/env node
/**
 * dingdawg-devops-agent v2 — Thin Client MCP Server
 *
 * FREE tier: basic local deploy check + secret scan (the hook)
 * PAID tier: LLM-powered deep infra analysis via DingDawg API
 *
 * Install: npx dingdawg-devops-agent
 * Claude Code: claude mcp add dingdawg-devops-agent npx dingdawg-devops-agent
 *
 * Set DINGDAWG_API_KEY for paid features:
 *   export DINGDAWG_API_KEY=your_key
 *
 * Optional: set DINGDAWG_MODEL env var to override the analysis model
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as crypto from "crypto";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const API_ENDPOINT = "https://api.dingdawg.com/v1/govern/execute";
const API_KEY = process.env.DINGDAWG_API_KEY || "";
const MODEL = process.env.DINGDAWG_MODEL || "gpt-4o-mini";

// ---------------------------------------------------------------------------
// Persistent rate limiting
// ---------------------------------------------------------------------------

const TOOL_LIMITS: Record<string, number> = {
  deploy_check: 10,
  incident_analyze: 5,
  infra_audit: 10,
  runbook_generate: 5,
  cost_optimize: 10,
};

const RATE_FILE = path.join(os.homedir(), ".dingdawg", "usage.json");

const MACHINE_ID = crypto.createHash("sha256")
  .update(`${os.hostname()}-${os.userInfo().username}-${os.platform()}-${os.arch()}`)
  .digest("hex").slice(0, 16);

function checkFreeRateLimit(tool: string): { allowed: boolean; remaining: number; message?: string } {
  const limit = TOOL_LIMITS[tool] ?? 10;
  const key = `${MACHINE_ID}_devops_${tool}`;
  const now = Date.now();
  const dayMs = 24 * 60 * 60 * 1000;

  let store: Record<string, { count: number; resetAt: number }> = {};
  try {
    const dir = path.dirname(RATE_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    if (fs.existsSync(RATE_FILE)) {
      store = JSON.parse(fs.readFileSync(RATE_FILE, "utf-8"));
    }
  } catch { /* fresh start */ }

  const entry = store[key];
  if (!entry || now > entry.resetAt) {
    store[key] = { count: 1, resetAt: now + dayMs };
  } else if (entry.count >= limit) {
    try { fs.writeFileSync(RATE_FILE, JSON.stringify(store)); } catch {}
    return { allowed: false, remaining: 0, message: `Free tier limit reached (${limit}/day for ${tool}). Get unlimited access with an API key at https://dingdawg.com/developers` };
  } else {
    store[key].count++;
  }

  try { fs.writeFileSync(RATE_FILE, JSON.stringify(store)); } catch {}

  const current = store[key].count;
  return { allowed: true, remaining: limit - current };
}

// ---------------------------------------------------------------------------
// API Client
// ---------------------------------------------------------------------------

interface ApiResponse {
  success: boolean;
  data?: Record<string, unknown>;
  error?: string;
}

async function callApi(
  tool: string,
  input: Record<string, unknown>,
): Promise<ApiResponse> {
  if (!API_KEY) {
    return { success: false, error: "no_api_key" };
  }

  try {
    const res = await fetch(API_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${API_KEY}`,
      },
      body: JSON.stringify({
        agent: "devops",
        tool,
        input,
        model: MODEL,
      }),
    });

    if (!res.ok) {
      const body = await res.text().catch(() => "");
      return { success: false, error: `API returned ${res.status}: ${body}` };
    }

    const data = await res.json() as Record<string, unknown>;
    return { success: true, data };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { success: false, error: `API request failed: ${message}` };
  }
}

function upgradeMessage(): string {
  return [
    "",
    "━━━ Upgrade to DingDawg Pro ━━━",
    "Get LLM-powered incident analysis, deep infra audits,",
    "AI-generated runbooks, and cost optimization insights.",
    "",
    "  export DINGDAWG_API_KEY=your_key",
    "",
    "Get your key at: https://dingdawg.com/developers",
    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
  ].join("\n");
}

// ---------------------------------------------------------------------------
// Secret detection — local, lightweight
// ---------------------------------------------------------------------------

const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  { name: "AWS Access Key", pattern: /AKIA[0-9A-Z]{16}/ },
  { name: "AWS Secret Key", pattern: /(?:aws_secret_access_key|secret_key)\s*[=:]\s*["']?[A-Za-z0-9/+=]{40}["']?/i },
  { name: "GitHub Token", pattern: /gh[ps]_[A-Za-z0-9_]{36,}/ },
  { name: "Generic API Key", pattern: /(?:api[_-]?key|apikey)\s*[=:]\s*["']?[A-Za-z0-9_\-]{20,}["']?/i },
  { name: "JWT Token", pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}/ },
  { name: "Private Key", pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/ },
  { name: "Database URL", pattern: /(?:postgres|mysql|mongodb):\/\/[^\s"']+:[^\s"']+@/ },
];

function scanSecrets(text: string): string[] {
  const found: string[] = [];
  for (const { name, pattern } of SECRET_PATTERNS) {
    if (pattern.test(text)) found.push(name);
  }
  return found;
}

// ---------------------------------------------------------------------------
// MCP Server
// ---------------------------------------------------------------------------

const server = new McpServer({
  name: "dingdawg-devops-agent",
  version: "2.0.0",
});
// readOnlyHint: all tools are read-only analysis — no side effects
const rtool = (name: string, desc: string, schema: any, cb: (args: Record<string, any>) => any) =>
  server.registerTool(name, { description: desc, inputSchema: schema, annotations: { readOnlyHint: true } }, cb);


// ---------------------------------------------------------------------------
// deploy_check — FREE local config scan + API upgrade
// ---------------------------------------------------------------------------

rtool(
  "deploy_check",
  "Free pre-deployment verification. Scans for exposed secrets, insecure defaults, " +
  "and missing health checks. Deep LLM-powered analysis with API key.",
  {
    config: z.string().describe("Deployment config content (Dockerfile, docker-compose, k8s manifest, railway.toml, vercel.json, etc.)"),
    platform: z.string().optional().describe("Target platform (docker, k8s, railway, vercel, aws)"),
  },
  async ({ config, platform }) => {
    const rateCheck = checkFreeRateLimit("deploy_check");
    if (!rateCheck.allowed) {
      return {
        content: [{ type: "text" as const, text: JSON.stringify({
          error: rateCheck.message,
          governed: true,
        }) }],
      };
    }

    if (API_KEY) {
      const apiResult = await callApi("deploy_check", {
        config, platform: platform || "auto",
      });
      if (apiResult.success && apiResult.data) {
        return {
          content: [{ type: "text" as const, text: JSON.stringify({
            mode: "deep_analysis",
            powered_by: "DingDawg DevOps API",
            ...apiResult.data,
            receipt_id: `deploy_${Date.now().toString(36)}`,
            governed: true,
          }, null, 2) }],
        };
      }
    }

    const issues: string[] = [];
    const good: string[] = [];
    const configLower = config.toLowerCase();

    const secrets = scanSecrets(config);
    if (secrets.length > 0) {
      issues.push(`CRITICAL: Exposed secrets detected: ${secrets.join(", ")}`);
    }

    if (configLower.includes("root") && !configLower.includes("non-root")) {
      issues.push("HIGH: Container appears to run as root");
    }
    if (configLower.includes("latest")) {
      issues.push("MEDIUM: Using 'latest' tag — pin versions for reproducibility");
    }
    if (configLower.includes("healthcheck") || configLower.includes("health_check") || configLower.includes("/health")) {
      good.push("Health check configured");
    } else {
      issues.push("MEDIUM: No health check detected");
    }
    if (configLower.includes("https") || configLower.includes("tls") || configLower.includes("ssl")) {
      good.push("TLS/HTTPS configured");
    }
    if (configLower.includes("resource") || configLower.includes("memory") || configLower.includes("cpu")) {
      good.push("Resource limits configured");
    }

    const score = Math.max(0, Math.min(100, 80 - issues.length * 15 + good.length * 5));

    return {
      content: [{ type: "text" as const, text: JSON.stringify({
        mode: "local_basic",
        deploy_score: score,
        risk_level: score >= 70 ? "LOW" : score >= 40 ? "MEDIUM" : "HIGH",
        issues: issues.slice(0, 5),
        good_practices: good,
        teaser: issues.length > 0
          ? `Found ${issues.length} issue(s). Get detailed fix instructions and best practices: export DINGDAWG_API_KEY=your_key`
          : "Get full deployment audit with security hardening: export DINGDAWG_API_KEY=your_key",
        upgrade_url: "https://dingdawg.com/developers",
        also_available: {
          shield: "npx dingdawg-shield — AI security scanning",
          compliance: "npx dingdawg-compliance — AI compliance checks",
        },
        receipt_id: `deploy_${Date.now().toString(36)}`,
        free_checks_remaining: rateCheck.remaining,
        governed: true,
      }, null, 2) }],
    };
  },
);

// ---------------------------------------------------------------------------
// incident_analyze — PAID
// ---------------------------------------------------------------------------

rtool(
  "incident_analyze",
  "AI-powered incident analysis from logs or metrics. Root cause analysis, severity classification, " +
  "remediation steps. Requires DINGDAWG_API_KEY.",
  {
    logs: z.string().describe("Incident logs, error messages, or metrics dump"),
    service: z.string().optional().describe("Affected service name"),
    severity: z.string().optional().describe("Initial severity (sev1-sev4)"),
  },
  async ({ logs, service, severity }) => {
    const rateCheck = checkFreeRateLimit("incident_analyze");
    if (!rateCheck.allowed) {
      return { content: [{ type: "text" as const, text: JSON.stringify({ error: rateCheck.message, governed: true }) }] };
    }

    const apiResult = await callApi("incident_analyze", {
      logs, service: service || "unknown", severity: severity || "unknown",
    });

    if (apiResult.success && apiResult.data) {
      return {
        content: [{ type: "text" as const, text: JSON.stringify({
          success: true, ...apiResult.data, governed: true,
        }, null, 2) }],
      };
    }

    if (!API_KEY) {
      return {
        content: [{ type: "text" as const, text: JSON.stringify({
          success: false,
          requires_api_key: true,
          message: "Incident analysis requires LLM-powered root cause analysis via our API.",
          setup: [
            "1. Get your API key at https://dingdawg.com/developers",
            "2. export DINGDAWG_API_KEY=your_key",
            "3. Run incident_analyze again",
          ],
          free_alternative: "Use deploy_check for free pre-deployment scanning (no API key needed).",
          governed: true,
        }, null, 2) }],
      };
    }

    return {
      content: [{ type: "text" as const, text: JSON.stringify({
        success: false, error: apiResult.error,
        suggestion: "Check your API key. Contact support@dingdawg.com if the issue persists.",
        governed: true,
      }, null, 2) }],
    };
  },
);

// ---------------------------------------------------------------------------
// infra_audit — PAID
// ---------------------------------------------------------------------------

rtool(
  "infra_audit",
  "AI infrastructure audit for security, cost, compliance, and reliability. " +
  "Requires DINGDAWG_API_KEY.",
  {
    infrastructure: z.string().describe("Infrastructure description or IaC file content"),
    focus: z.enum(["security", "cost", "compliance", "reliability", "all"]).optional().describe("Audit focus area"),
  },
  async ({ infrastructure, focus }) => {
    const rateCheck = checkFreeRateLimit("infra_audit");
    if (!rateCheck.allowed) {
      return { content: [{ type: "text" as const, text: JSON.stringify({ error: rateCheck.message, governed: true }) }] };
    }

    const apiResult = await callApi("infra_audit", {
      infrastructure, focus: focus || "all",
    });

    if (apiResult.success && apiResult.data) {
      return {
        content: [{ type: "text" as const, text: JSON.stringify({
          success: true, ...apiResult.data, governed: true,
        }, null, 2) }],
      };
    }

    if (!API_KEY) {
      return {
        content: [{ type: "text" as const, text: JSON.stringify({
          success: false,
          requires_api_key: true,
          message: "Infrastructure audits require LLM-powered analysis via our API.",
          audit_areas: ["Security", "Cost optimization", "SOC2/HIPAA compliance", "Reliability"],
          setup: [
            "1. Get your API key at https://dingdawg.com/developers",
            "2. export DINGDAWG_API_KEY=your_key",
            "3. Run infra_audit again",
          ],
          free_alternative: "Use deploy_check for free pre-deployment scanning (no API key needed).",
          governed: true,
        }, null, 2) }],
      };
    }

    return {
      content: [{ type: "text" as const, text: JSON.stringify({
        success: false, error: apiResult.error,
        suggestion: "Check your API key. Contact support@dingdawg.com if the issue persists.",
        governed: true,
      }, null, 2) }],
    };
  },
);

// ---------------------------------------------------------------------------
// runbook_generate — PAID
// ---------------------------------------------------------------------------

rtool(
  "runbook_generate",
  "Generate operational runbooks with detection, triage, mitigation, and post-mortem steps. " +
  "Requires DINGDAWG_API_KEY.",
  {
    service: z.string().describe("Service name and description"),
    failure_modes: z.string().optional().describe("Known failure modes"),
    on_call_info: z.string().optional().describe("On-call escalation information"),
  },
  async ({ service, failure_modes, on_call_info }) => {
    const rateCheck = checkFreeRateLimit("runbook_generate");
    if (!rateCheck.allowed) {
      return { content: [{ type: "text" as const, text: JSON.stringify({ error: rateCheck.message, governed: true }) }] };
    }

    const apiResult = await callApi("runbook_generate", {
      service, failure_modes: failure_modes || "", on_call_info: on_call_info || "",
    });

    if (apiResult.success && apiResult.data) {
      return {
        content: [{ type: "text" as const, text: JSON.stringify({
          success: true, ...apiResult.data, governed: true,
        }, null, 2) }],
      };
    }

    if (!API_KEY) {
      return {
        content: [{ type: "text" as const, text: JSON.stringify({
          success: false,
          requires_api_key: true,
          message: "Runbook generation requires LLM-powered analysis via our API.",
          setup: [
            "1. Get your API key at https://dingdawg.com/developers",
            "2. export DINGDAWG_API_KEY=your_key",
            "3. Run runbook_generate again",
          ],
          free_alternative: "Use deploy_check for free pre-deployment scanning (no API key needed).",
          governed: true,
        }, null, 2) }],
      };
    }

    return {
      content: [{ type: "text" as const, text: JSON.stringify({
        success: false, error: apiResult.error,
        suggestion: "Check your API key. Contact support@dingdawg.com if the issue persists.",
        governed: true,
      }, null, 2) }],
    };
  },
);

// ---------------------------------------------------------------------------
// cost_optimize — PAID
// ---------------------------------------------------------------------------

rtool(
  "cost_optimize",
  "AI-powered cloud cost optimization. Right-sizing, reserved instances, savings estimates. " +
  "Requires DINGDAWG_API_KEY.",
  {
    services: z.string().describe("Service list with current resources and monthly costs"),
    cloud_provider: z.string().optional().describe("Cloud provider (aws, gcp, azure, railway, vercel)"),
  },
  async ({ services, cloud_provider }) => {
    const rateCheck = checkFreeRateLimit("cost_optimize");
    if (!rateCheck.allowed) {
      return { content: [{ type: "text" as const, text: JSON.stringify({ error: rateCheck.message, governed: true }) }] };
    }

    const apiResult = await callApi("cost_optimize", {
      services, cloud_provider: cloud_provider || "auto",
    });

    if (apiResult.success && apiResult.data) {
      return {
        content: [{ type: "text" as const, text: JSON.stringify({
          success: true, ...apiResult.data, governed: true,
        }, null, 2) }],
      };
    }

    if (!API_KEY) {
      return {
        content: [{ type: "text" as const, text: JSON.stringify({
          success: false,
          requires_api_key: true,
          message: "Cost optimization requires LLM-powered analysis via our API.",
          setup: [
            "1. Get your API key at https://dingdawg.com/developers",
            "2. export DINGDAWG_API_KEY=your_key",
            "3. Run cost_optimize again",
          ],
          free_alternative: "Use deploy_check for free pre-deployment scanning (no API key needed).",
          governed: true,
        }, null, 2) }],
      };
    }

    return {
      content: [{ type: "text" as const, text: JSON.stringify({
        success: false, error: apiResult.error,
        suggestion: "Check your API key. Contact support@dingdawg.com if the issue persists.",
        governed: true,
      }, null, 2) }],
    };
  },
);

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => { console.error("Server failed:", err); process.exit(1); });
