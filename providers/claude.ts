/* Copyright Contributors to the Open Cluster Management project */

import type { StructuredAnalysis } from '../lib/types'
import type { PolicyAnalysisContext, PolicyAnalysisProvider } from './provider'

const SYSTEM_PROMPT = `You are an ACM (Red Hat Advanced Cluster Management) policy governance expert. You analyze Kubernetes policy specifications and return structured risk assessments as JSON.

You receive a policy specification — templates, object definitions, remediation actions, namespace selectors, prune behavior — along with fleet context when available. You perform thorough, independent risk analysis directly from the specification.

When cluster compliance data is present, incorporate it. When absent (pre-deployment), reason about what WOULD happen when deployed.

SEVERITY CALIBRATION — use these definitions strictly:

CRITICAL: Fleet-wide service disruption is certain or near-certain. Irreversible data loss across namespaces. Security boundary breach (RBAC deletion, namespace removal, secret exposure). Enforcement of mustnothave/DeleteAll on core workload resources (Deployments, StatefulSets, Services, PersistentVolumeClaims) in production or system namespaces.

HIGH: Production workload impact on multiple clusters. Irreversible enforcement on important but non-core resources. Wide blast radius due to missing namespace scoping or overly broad selectors. Conflicts with critical cluster operators (OLM, cert-manager, ArgoCD).

MEDIUM: Scoping gaps that could lead to unintended enforcement. Enforce mode on non-critical resources (ConfigMaps, labels, annotations) with some deletion risk. Missing guardrails that a mature policy should have.

LOW: Informational observations. Best practice suggestions. Expected behaviors that are worth noting (e.g. disabled policies, inform-only mode, narrow scope). Things the operator probably already knows.

KEY RULES:
- Distinguish "WILL cause damage" from "COULD cause damage under specific conditions." Bias toward the lower severity when the triggering conditions are unlikely or require deliberate human action.
- A disabled policy is not a risk — it is a policy that is not yet active. Do not flag "latent risk" from disabled state.
- DeleteIfCreated on low-criticality resources (ConfigMaps, labels) in non-system namespaces is expected behavior, not a critical risk.
- The catastrophic assessment section should only reach MEDIUM or above when enforcement targets core workload resources, system namespaces, or RBAC objects at fleet scale. A single ConfigMap in the default namespace is not catastrophic.
- Reserve the catastrophic cascading-failures array for scenarios where a realistic chain of events leads to fleet-wide outage. Do not fabricate speculative dependency chains.

You MUST respond with valid JSON only — no markdown, no explanation outside the JSON. Follow the exact schema and word limits specified in each request.`

interface ClaudeMessage {
  role: 'user' | 'assistant'
  content: string
}

interface ClaudeResponse {
  content: { type: string; text: string }[]
}

export interface ClaudeProviderConfig {
  apiKey?: string
  model?: string
  baseUrl?: string
  maxTokens?: number
}

export class ClaudeProvider implements PolicyAnalysisProvider {
  readonly name = 'claude'
  private apiKey: string
  private model: string
  private baseUrl: string
  private maxTokens: number

  constructor(config?: ClaudeProviderConfig) {
    this.apiKey = config?.apiKey ?? process.env.CLAUDE_API_KEY ?? ''
    this.model = config?.model ?? process.env.CLAUDE_MODEL ?? 'claude-sonnet-4-20250514'
    this.baseUrl = config?.baseUrl ?? 'https://api.anthropic.com'
    this.maxTokens = config?.maxTokens ?? 4096
  }

  async isAvailable(): Promise<boolean> {
    return this.apiKey.length > 0
  }

  private async chat(messages: ClaudeMessage[]): Promise<string> {
    const response = await fetch(`${this.baseUrl}/v1/messages`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': this.apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: this.model,
        max_tokens: this.maxTokens,
        system: SYSTEM_PROMPT,
        messages,
      }),
    })

    if (!response.ok) {
      const text = await response.text()
      throw new Error(`Claude API error ${response.status}: ${text}`)
    }

    const data = (await response.json()) as ClaudeResponse
    return data.content.find((c) => c.type === 'text')?.text ?? ''
  }

  private formatContext(ctx: PolicyAnalysisContext): string {
    const { policy, deterministicResult, fleetContext } = ctx
    const isPreDeployment = policy.clusterStatus.length === 0

    return JSON.stringify(
      {
        analysisMode: isPreDeployment ? 'pre-deployment' : 'deployed',
        policy: {
          name: policy.name,
          namespace: policy.namespace,
          disabled: policy.disabled,
          remediationAction: policy.remediationAction,
          templates: policy.templates.map((t) => ({
            name: t.name,
            kind: t.kind,
            severity: t.severity,
            remediationAction: t.remediationAction,
            pruneObjectBehavior: t.pruneObjectBehavior,
            namespaceSelector: t.namespaceSelector,
            objectTemplates: t.objectTemplates.map((ot) => ({
              complianceType: ot.complianceType,
              kind: ot.kind,
              apiVersion: ot.apiVersion,
              name: ot.name,
              namespace: ot.namespace,
            })),
          })),
          clusterStatus: isPreDeployment
            ? '(pre-deployment — no clusters targeted yet)'
            : policy.clusterStatus.map((s) => ({
                cluster: s.clusterName,
                compliant: s.compliant,
              })),
        },
        fleetContext: fleetContext
          ? {
              totalClusters: fleetContext.clusterNames.length,
              clusterNames: fleetContext.clusterNames.slice(0, 30),
              totalPolicies: fleetContext.allPolicies.length,
              otherPolicies: fleetContext.allPolicies
                .filter((p) => p.name !== policy.name)
                .slice(0, 15)
                .map((p) => ({
                  name: p.name,
                  namespace: p.namespace,
                  remediationAction: p.remediationAction,
                  templates: p.templates.map((t) => ({
                    kind: t.kind,
                    objectKinds: t.objectTemplates.map((ot) => ot.kind),
                    complianceTypes: t.objectTemplates.map((ot) => ot.complianceType),
                  })),
                })),
            }
          : undefined,
        deterministicHints: {
          antiPatternCount: deterministicResult.antiPatterns.length,
          findings: deterministicResult.antiPatterns.slice(0, 10).map((f) => ({
            id: f.id,
            riskLevel: f.riskLevel,
            title: f.title,
          })),
        },
      },
      null,
      2
    )
  }

  async analyze(ctx: PolicyAnalysisContext): Promise<{
    impactedClusters: string[]
    analysis: StructuredAnalysis
  }> {
    const context = this.formatContext(ctx)
    const isPreDeployment = ctx.policy.clusterStatus.length === 0

    const result = await this.chat([
      {
        role: 'user',
        content: `Analyze this ACM policy and return a single JSON object. Follow the schema and word limits exactly.

${isPreDeployment ? 'This is a PRE-DEPLOYMENT analysis — no clusters are targeted yet. For impactedClusters, reason about which clusters WOULD be affected based on the policy spec and fleet context. If you cannot determine specific clusters, return descriptive entries like "all clusters matching placement selector".' : 'This policy is deployed. Use the cluster compliance data to identify impacted clusters.'}

Return this exact JSON structure:
{
  "impactedClusters": ["cluster names or descriptions of affected clusters"],
  "analysis": {
    "summary": "2-3 sentence overview of what this policy does and its risk posture. MAX 75 WORDS.",
    "risks": [
      {
        "severity": "CRITICAL|HIGH|MEDIUM|LOW",
        "title": "Short risk title. MAX 10 WORDS.",
        "description": "What goes wrong and why. MAX 50 WORDS.",
        "recommendation": "Specific action to fix this. MAX 40 WORDS."
      }
    ],
    "recommendations": [
      "Top 3-5 actionable steps to make this policy safer. MAX 30 WORDS EACH."
    ],
    "catastrophicAssessment": {
      "severity": "LOW|MEDIUM|HIGH|CATASTROPHIC",
      "reasoning": "Why this policy could or could not cause catastrophic damage. MAX 100 WORDS.",
      "cascadingFailures": [
        {
          "trigger": "What initiates the failure",
          "chain": ["Step 1", "Step 2"],
          "finalImpact": "Ultimate consequence"
        }
      ]
    },
    "accidentalScenarios": [
      {
        "title": "Short scenario title. MAX 10 WORDS.",
        "description": "What could go wrong accidentally. MAX 50 WORDS.",
        "likelihood": "LOW|MEDIUM|HIGH",
        "impact": "LOW|MEDIUM|HIGH|CRITICAL",
        "recommendation": "How to prevent this. MAX 40 WORDS."
      }
    ]
  }
}

Risk analysis priorities:
- Enforce on dangerous resources, prune behavior, namespace scoping gaps, operator conflicts
- Cascading failures from enforcement on wrong cluster/namespace/resource
- Interactions with other fleet policies or cluster operators (OLM, ArgoCD, Helm, cert-manager)
- Blast radius at scale

If no risks/scenarios are found for a section, return empty arrays. If no catastrophic risk, return severity "LOW" with reasoning.

RESPOND WITH VALID JSON ONLY.

${context}`,
      },
    ])

    try {
      const jsonMatch = result.match(/\{[\s\S]*\}/)
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]) as {
          impactedClusters: string[]
          analysis: StructuredAnalysis
        }
        return parsed
      }
    } catch {
      // Fall through to default
    }

    return {
      impactedClusters: ctx.policy.clusterStatus.map((s) => s.clusterName),
      analysis: {
        summary: 'Analysis completed but structured output could not be parsed.',
        risks: [],
        recommendations: [],
        catastrophicAssessment: {
          severity: 'LOW',
          reasoning: result.slice(0, 200),
          cascadingFailures: [],
        },
        accidentalScenarios: [],
      },
    }
  }
}
