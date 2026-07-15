# dingdawg-devops-agent

> Breakthrough deployment failures before they hit production. AI DevOps that learns YOUR infrastructure patterns.

AI-powered deployment verification, secret scanning, incident analysis, infrastructure auditing, runbook generation, and cost optimization. Catches leaked AWS keys, GitHub tokens, database URLs, and private keys. Free tier runs locally with zero data transmission. Every action is governed and receipted.

## For AI Assistants

This MCP server returns structured JSON for seamless integration:
- Secret detection with pattern type (AWS, GitHub, JWT, private key, DB URL)
- Incident severity classification with root cause analysis
- Governance receipt on every call (audit-ready)
- Chain-ready: `deploy_check` pre-deploy -> `secret_scan` for leaked credentials -> `infra_audit` for config drift -> `incident_analyze` when issues arise -> `runbook_generate` for response procedures -> `cost_optimize` for spend reduction

Composable with any MCP client: Claude Code, Cursor, VS Code, ChatGPT Desktop, Windsurf.

## Install

```bash
npx dingdawg-devops-agent
```

### Claude Code
```bash
claude mcp add devops -- npx dingdawg-devops-agent
```

### Cursor
Add to `.cursor/mcp.json`:
```json
{"mcpServers": {"devops": {"command": "npx", "args": ["dingdawg-devops-agent"], "env": {"DINGDAWG_API_KEY": "your-key"}}}}
```

### Full Stack (all 13 agents)
```bash
npx dingdawg-setup
```

## Tools

| Tool | Free Tier | Paid Tier |
|------|-----------|-----------|
| `deploy_check` | 10/day, basic deploy verification | Unlimited, LLM-powered with rollback recommendations |
| `secret_scan` | 10/day, 7 secret patterns (AWS, GitHub, JWT, etc.) | Unlimited, 50+ patterns with rotation guidance |
| `incident_analyze` | 5/day, basic log analysis | Unlimited, AI-powered root cause analysis |
| `infra_audit` | 5/day, config checklist | Unlimited, drift detection with remediation |
| `runbook_generate` | 3/day, template-based | Unlimited, AI-generated context-aware runbooks |
| `cost_optimize` | 3/day, basic spend analysis | Unlimited, AI-powered with savings projections |

## Pricing

- **Free:** 10 checks/day, basic analysis
- **Pro:** $49/mo, 100 calls/day, AI-powered deep analysis
- **Pay-as-you-go:** $0.25/call, no commitment

Get API key: https://dingdawg.com/developers

## Governed

Every call is receipted and auditable. Secret scans reference specific pattern types with zero false-positive-tolerant matching. Incident analyses include timeline reconstruction. Infrastructure audits reference CIS benchmark controls.

## Support

support@dingdawg.com | https://dingdawg.com
