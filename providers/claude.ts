/* Copyright Contributors to the Open Cluster Management project */

import type { AccidentalScenario, CatastrophicPrediction } from '../lib/types'
import type { PolicyAnalysisContext, PolicyAnalysisProvider } from './provider'

const SYSTEM_PROMPT = `You are an ACM (Red Hat Advanced Cluster Management) policy governance expert. You analyze Kubernetes policies deployed across managed cluster fleets and provide risk assessments.

You receive deterministic analysis results (risk scores, anti-pattern findings) alongside the raw policy data. Your role is to add contextual reasoning that the deterministic rules cannot provide:
- Explain WHY findings are dangerous in the user's specific fleet context
- Predict cascading failures across interconnected systems
- Detect subtle interaction risks between multiple policies
- Generate plain-English summaries accessible to non-experts

Be specific and actionable. Reference concrete resource names, namespaces, and cluster names from the data. Do not repeat the deterministic findings verbatim — add insight the rules cannot.`

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
    this.maxTokens = config?.maxTokens ?? 1024
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
    return JSON.stringify(
      {
        policy: {
          name: policy.name,
          namespace: policy.namespace,
          remediationAction: policy.remediationAction,
          disabled: policy.disabled,
          templates: policy.templates.map((t) => ({
            name: t.name,
            kind: t.kind,
            severity: t.severity,
            remediationAction: t.remediationAction,
            pruneObjectBehavior: t.pruneObjectBehavior,
            objectTemplates: t.objectTemplates,
          })),
          clusterStatus: policy.clusterStatus,
        },
        deterministicResult: {
          riskScores: deterministicResult.riskScores,
          antiPatternCount: deterministicResult.antiPatterns.length,
          antiPatterns: deterministicResult.antiPatterns.slice(0, 10),
          fleetRisk: deterministicResult.fleetRisk
            ? {
                fleetScore: deterministicResult.fleetRisk.fleetScore,
                fleetLevel: deterministicResult.fleetRisk.fleetLevel,
                worstCluster: deterministicResult.fleetRisk.worstCluster,
              }
            : undefined,
        },
        fleetContext: fleetContext
          ? {
              totalClusters: fleetContext.clusterNames.length,
              clusterNames: fleetContext.clusterNames.slice(0, 20),
              totalPolicies: fleetContext.allPolicies.length,
            }
          : undefined,
      },
      null,
      2
    )
  }

  async summarize(ctx: PolicyAnalysisContext): Promise<string> {
    const context = this.formatContext(ctx)
    const result = await this.chat([
      {
        role: 'user',
        content: `Summarize this ACM policy in 2-4 sentences of plain English. Describe what the policy does, which clusters it affects, and its current risk posture. Write for someone who cannot read YAML.\n\n${context}`,
      },
    ])
    return result
  }

  async explainRisk(ctx: PolicyAnalysisContext): Promise<string> {
    const context = this.formatContext(ctx)
    const result = await this.chat([
      {
        role: 'user',
        content: `The deterministic analysis found the anti-pattern findings shown below. Explain WHY these findings are dangerous in the context of this specific fleet. Focus on cascading effects, interaction risks, and operational impact. Do not repeat the finding descriptions verbatim — add contextual insight.\n\n${context}`,
      },
    ])
    return result
  }

  async predictCatastrophicPlacement(ctx: PolicyAnalysisContext): Promise<CatastrophicPrediction> {
    const context = this.formatContext(ctx)
    const result = await this.chat([
      {
        role: 'user',
        content: `Analyze this policy for catastrophic placement risks. Consider:
1. What happens if this policy is deployed to all targeted clusters simultaneously?
2. Could enforcement cause cascading failures (e.g., breaking the policy controller itself, disrupting cluster networking, removing RBAC needed by operators)?
3. What is the blast radius if the placement selector is broader than intended?

Respond in valid JSON matching this structure:
{
  "blastRadius": { "affectedClusters": [...], "affectedResources": [...], "severity": "LOW|MEDIUM|HIGH|CATASTROPHIC" },
  "cascadingFailures": [{ "trigger": "...", "chain": ["step1", "step2"], "finalImpact": "..." }],
  "confidence": 0.0-1.0,
  "reasoning": "..."
}

${context}`,
      },
    ])

    try {
      const jsonMatch = result.match(/\{[\s\S]*\}/)
      if (jsonMatch) {
        return JSON.parse(jsonMatch[0]) as CatastrophicPrediction
      }
    } catch {
      // Fall through to default
    }

    return {
      blastRadius: {
        affectedClusters: ctx.policy.clusterStatus.map((s) => s.clusterName),
        affectedResources: [],
        severity: 'MEDIUM',
      },
      cascadingFailures: [],
      confidence: 0.3,
      reasoning: result,
    }
  }

  async detectAccidentalScenarios(ctx: PolicyAnalysisContext): Promise<AccidentalScenario[]> {
    const context = this.formatContext(ctx)
    const result = await this.chat([
      {
        role: 'user',
        content: `Look for subtle accidental scenarios that deterministic rules might miss. Consider:
1. Interactions between this policy and other policies in the fleet
2. Timing-dependent failures (e.g., policy applied before a dependency exists)
3. Label selector drift that could target unintended clusters over time
4. Version skew between hub and managed cluster policy controllers

Respond in valid JSON as an array:
[{ "id": "LLM-001", "title": "...", "description": "...", "triggerCondition": "...", "likelihood": "LOW|MEDIUM|HIGH", "impact": "LOW|MEDIUM|HIGH|CRITICAL", "recommendation": "..." }]

Return an empty array [] if no additional scenarios are detected beyond the deterministic findings.

${context}`,
      },
    ])

    try {
      const jsonMatch = result.match(/\[[\s\S]*\]/)
      if (jsonMatch) {
        return JSON.parse(jsonMatch[0]) as AccidentalScenario[]
      }
    } catch {
      // Fall through to empty
    }

    return []
  }
}
