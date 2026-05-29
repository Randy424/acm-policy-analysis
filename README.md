<div align="center">

# ACM Policy Analysis

**LLM-first policy risk analysis for Red Hat Advanced Cluster Management.**

</div>

---

## How It Works

The system takes a raw ACM policy, extracts structural hints from its spec, sends an enriched payload to Claude for structured risk assessment, and returns a typed JSON result to the consumer. Here is the full sequence:

### 1. Consumer sends a raw policy

The backend route (`backend/src/routes/policy-analysis.ts`) receives a `POST` with the policy JSON, all fleet policies, and a provider preference (`auto`, `claude`, `ollama`, `deterministic`). The route calls `analyzeRawPolicy()` to parse the policy and extract structural hints before sending to the LLM.

### 2. Parse the raw policy into a typed structure

`lib/parser.ts:parsePolicy()` transforms the raw `oc get policy -o json` shape into a `ParsedPolicy` (`lib/types.ts:104`). It extracts:

- **Templates**: each policy-template's kind, severity, remediationAction, pruneObjectBehavior, namespaceSelector, and objectTemplates (complianceType, target kind/apiVersion/name/namespace)
- **Cluster status**: per-cluster compliance state (Compliant, NonCompliant, Pending, Unknown) from `status.status[]`
- **Compliance history**: parsed from propagated policy copies in managed cluster namespaces via `parsePropagatedPolicies()`

### 3. Extract structural hints

`lib/analyze.ts:analyzePolicyDeterministic()` runs a lightweight rule engine to produce hints that are passed to the LLM as context. These are not displayed to the user — they seed Claude's analysis with pattern matches it might otherwise miss:

- **Anti-pattern findings**: `anti-patterns.ts:runAntiPatterns()` — 25 pattern-matching rules that flag known dangerous configurations (e.g. enforce + mustnothave on system namespaces, operator-managed resource conflicts, missing namespace scoping)
- **Scoring and saturation data**: per-cluster risk scores and policy load ratings used as supplementary context

### 4. Select a provider

`providers/factory.ts:createProvider()` resolves the provider. In `auto` mode, the detection order is:

1. **Claude** (primary) — available if `CLAUDE_API_KEY` is set in environment
2. **Ollama** — available if a local Ollama server responds at `http://localhost:11434`
3. **Deterministic** (fallback) — always available; maps the structural hints directly into the output shape without LLM enrichment. Produces valid output but lacks contextual reasoning

### 5. Build the LLM context payload

When Claude is selected, `providers/claude.ts:formatContext()` (line 89) assembles a JSON payload from the parsed policy and structural hints:

```
{
  analysisMode:       "pre-deployment" | "deployed"
  policy:             full spec — templates, objectTemplates, namespaceSelectors, pruneObjectBehavior
  clusterStatus:      per-cluster compliance (or a note that no clusters are targeted yet)
  fleetContext:       up to 30 cluster names, up to 15 other policies (name, remediation, template kinds)
  deterministicHints: first 10 anti-pattern findings (id, riskLevel, title)
}
```

The hints give Claude a starting point — the rule engine's pattern matches are passed as context, not as ground truth. Claude performs independent analysis directly from the policy specification.

### 6. Single-call structured prompt

`providers/claude.ts:analyze()` (line 141) sends one API call with a system prompt and a user prompt. The system prompt (`claude.ts:6`) defines Claude's role and includes **severity calibration** — explicit definitions of CRITICAL, HIGH, MEDIUM, and LOW mapped to ACM-specific impact levels (fleet disruption, RBAC breach, core workload deletion vs. ConfigMaps in default namespace). Key rules prevent over-alerting:

- Distinguish "WILL cause damage" from "COULD cause damage under unlikely conditions"
- Disabled policies are not risks
- DeleteIfCreated on low-criticality resources is expected behavior
- Catastrophic assessment requires core workloads, system namespaces, or RBAC at fleet scale

The user prompt requests a single JSON object with word limits:

| Field | Limit |
|-------|-------|
| `summary` | 75 words |
| `risks[].title` | 10 words |
| `risks[].description` | 50 words |
| `risks[].recommendation` | 40 words |
| `recommendations[]` | 30 words each |
| `catastrophicAssessment.reasoning` | 100 words |
| `accidentalScenarios[].title` | 10 words |
| `accidentalScenarios[].description` | 50 words |

### 7. Parse and validate the response

`providers/claude.ts:208-219` extracts JSON from Claude's response via regex (`/\{[\s\S]*\}/`), parses it, and types it as `{ impactedClusters: string[], analysis: StructuredAnalysis }`. On parse failure, a fallback returns a valid structured shape with the raw text preserved in the reasoning field, so the consumer never receives an undefined response.

### 8. Wrap and return

`providers/provider.ts:analyzeWithProvider()` (line 28) wraps the provider result with metadata:

```typescript
{
  policy:           { name, namespace, disabled }
  provider:         "claude" | "ollama" | "deterministic"
  impactedClusters: ["cluster-1", "cluster-2", ...]
  analysis:         StructuredAnalysis    // summary, risks, recommendations, catastrophic, accidental
  timestamp:        ISO 8601
}
```

This is the `PolicyAnalysisResult` type (`lib/types.ts:250`) — the contract between the library and any consumer.

## Architecture

```
acm-policy-analysis/
├── lib/
│   ├── parser.ts             # RawPolicy → ParsedPolicy (templates, status, history)
│   ├── analyze.ts            # Entry points: analyzeRawPolicy(), analyzePolicyDeterministic()
│   ├── scoring.ts            # Supplementary scoring used as LLM context hints
│   ├── anti-patterns.ts      # 25 pattern-matching rules used as LLM context hints
│   ├── types.ts              # All types: ParsedPolicy, StructuredAnalysis, PolicyAnalysisResult
│   └── index.ts              # Barrel export
├── providers/
│   ├── provider.ts           # Provider interface + analyzeWithProvider()
│   ├── factory.ts            # Auto-detection: Claude → Ollama → Deterministic
│   ├── claude.ts             # Anthropic Messages API: context building, prompt, response parsing
│   ├── ollama.ts             # Ollama REST API (local LLM)
│   └── deterministic.ts      # Fallback: maps pattern hints → StructuredAnalysis (no LLM)
├── cli.ts                    # CLI: pipe policy JSON, get structured analysis
├── package.json
└── tsconfig.json
```

## Quick Start

```bash
git clone https://github.com/Randy424/acm-policy-analysis.git
cd acm-policy-analysis
npm install
```

### CLI

```bash
# Single policy
oc get policy <name> -n <namespace> -o json | npx tsx cli.ts

# Fleet analysis (all policies)
oc get policies.policy.open-cluster-management.io -A -o json | npx tsx cli.ts
```

### Programmatic

```typescript
import { analyzeRawPolicy } from '@acm-policy-skills/lib'
import { analyzeWithProvider, createProvider } from '@acm-policy-skills/lib/providers'

const { parsed, result } = analyzeRawPolicy(rawPolicyJson, allPoliciesJson)
const provider = await createProvider({ provider: 'auto' })
const analysis = await analyzeWithProvider(parsed, result, provider)
```

## Configuration

| Variable | Purpose | Default |
|----------|---------|---------|
| `CLAUDE_API_KEY` | Anthropic API key | — (disables Claude provider) |
| `CLAUDE_MODEL` | Model ID | `claude-sonnet-4-20250514` |
| `POLICY_ANALYSIS_PROVIDER` | Force a provider | `auto` |

## Prerequisites

- Node.js 20+, TypeScript 5.5+
- For CLI: `oc` authenticated to an ACM hub cluster (ACM 2.9+)
- For Claude provider: Anthropic API key

## License

[Apache 2.0](LICENSE)
