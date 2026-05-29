<div align="center">

# ACM Policy Analysis

**Deterministic policy analysis engine and modular LLM provider interface for ACM governance.**

</div>

---

## Overview

Transforms ACM policy governance from reactive (binary pass/fail after violation) to proactive (risk-scored predictions before violations occur). Provides a TypeScript library that codifies scoring formulas, anti-pattern detection, and drift analysis, with an optional LLM layer for natural-language summaries and catastrophic scenario reasoning.

### Capabilities

| # | Capability | Input | Output |
|---|-----------|-------|--------|
| C1 | Saturation Monitoring | Policy counts + reconciliation metrics | Per-cluster saturation rating (GREEN–RED) |
| C2 | Pre-deployment Analysis | Policy YAML | Risk assessment with anti-pattern findings |
| C3 | Drift Trend Prediction | Compliance history events | Velocity-based drift risk ranking with projections |
| C4 | Fleet Risk Scoring | All policy compliance data | Weighted risk scores per cluster (0–100), fleet summary |
| N1 | Catastrophic Placement Prediction | Policy + placement + fleet topology | Blast radius and cascading failure predictions |
| N2 | Accidental Scenario Detection | Policy + fleet context | 25 codified foot-gun patterns with recommendations |
| N3 | Readable Outcome Summary | Policy + deterministic results | Plain-English summary of what a policy will do |

C1–C4 and N2 are fully deterministic. N1 and N3 use an optional LLM provider for contextual reasoning.

## Quick Start

```bash
git clone https://github.com/Randy424/acm-policy-analysis.git
cd acm-policy-analysis
npm install
```

### CLI Demo

Pipe any ACM policy JSON into the CLI:

```bash
# Single policy
oc get policy <name> -n <namespace> -o json | npx tsx cli.ts

# All policies (fleet analysis)
oc get policies.policy.open-cluster-management.io -A -o json | npx tsx cli.ts
```

### Programmatic Usage

```typescript
import { analyzeRawPolicy, parsePolicy, analyzePolicyDeterministic } from '@acm-policy-skills/lib'

// From raw oc JSON
const { parsed, result } = analyzeRawPolicy(rawPolicyJson, allPoliciesJson)

// Or parse and analyze separately
const policy = parsePolicy(rawPolicyJson)
const result = analyzePolicyDeterministic(policy, { fleetContext })
```

## Architecture

```
acm-policy-analysis/
├── lib/                      # Deterministic scoring engine
│   ├── types.ts              # Core types, scoring constants
│   ├── parser.ts             # Console Policy → ParsedPolicy transformer
│   ├── scoring.ts            # Risk scores, velocity, saturation, fleet aggregation
│   ├── anti-patterns.ts      # 25 detection rules (registry pattern)
│   ├── analyze.ts            # Top-level entry points
│   └── index.ts              # Barrel export
├── providers/                # LLM provider implementations (planned)
│   ├── provider.ts           # Abstract interface
│   ├── deterministic.ts      # No-LLM fallback
│   ├── claude.ts             # Anthropic SDK
│   └── ollama.ts             # Ollama REST API (on-prem)
├── cli.ts                    # CLI demo script
├── package.json
└── tsconfig.json
```

### Design Principles

- **Deterministic first**: All scoring formulas and anti-pattern rules are hardcoded, not LLM-generated. Results are reproducible and auditable.
- **LLM as progressive enhancement**: The deterministic layer always runs. The LLM provider adds readable summaries and contextual reasoning but is never required.
- **Modular providers**: Swap between Claude, Ollama, or no-LLM fallback via configuration. No code changes needed.
- **Console-compatible types**: The parser accepts the console's `Policy` type directly — no conversion layer.

## Scoring Formulas

### Per-Cluster Risk Score

```
cluster_risk = SUM(violation_weight × severity_weight × remediation_modifier)
```

| Compliance | Weight | | Severity | Weight | | Remediation | Modifier |
|-----------|--------|-|----------|--------|-|-------------|----------|
| NonCompliant | 1.0 | | Critical | 4 | | inform | 1.5 |
| Pending/Unknown | 0.3 | | High | 3 | | enforce | 0.8 |
| Compliant | 0.0 | | Medium | 2 | | informOnly | 1.0 |
| | | | Low | 1 | | | |

Normalized to 0–100 and classified: NONE (0), LOW (1–25), MEDIUM (26–50), HIGH (51–75), CRITICAL (76–100).

### Anti-Pattern Detection Rules

25 rules across three categories:

| Category | IDs | Count | Examples |
|----------|-----|-------|---------|
| Existing | AP-001 – AP-007 | 7 | Operator-managed resource conflict, destructive prune, missing namespace scoping |
| Catastrophic Placement | CAT-001 – CAT-005 | 5 | Policy controller self-destruction, cascading CRD deletion, system namespace infection |
| Accidental Scenario | ACC-001 – ACC-013 | 13 | RBAC breaking ACM agent, Helm/ArgoCD conflict, namespace deletion, placement creep |

## Related Projects

| Repo | Role |
|------|------|
| [acm-policy-skills](https://github.com/Randy424/acm-policy-skills) | Claude Code skill files for policy drift prediction (CLI/conversational use) |
| [console](https://github.com/Randy424/console) | ACM console fork — UI modal integration (planned) |

## Prerequisites

- Node.js 20+
- TypeScript 5.5+
- For CLI usage: `oc` CLI authenticated to an ACM hub cluster (ACM 2.9+)

## License

[Apache 2.0](LICENSE)
