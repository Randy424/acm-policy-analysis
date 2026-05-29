/* Copyright Contributors to the Open Cluster Management project */

import type { AccidentalScenario, CatastrophicPrediction } from '../lib/types'
import type { PolicyAnalysisContext, PolicyAnalysisProvider } from './provider'

const SYSTEM_PROMPT = `You are an ACM (Red Hat Advanced Cluster Management) policy governance expert. You analyze Kubernetes policies deployed across managed cluster fleets and provide risk assessments.

You receive deterministic analysis results (risk scores, anti-pattern findings) alongside the raw policy data. Your role is to add contextual reasoning:
- Explain WHY findings are dangerous in the user's specific fleet context
- Predict cascading failures across interconnected systems
- Generate plain-English summaries accessible to non-experts

Be specific and actionable. Reference concrete resource names and cluster names from the data.`

interface OllamaGenerateResponse {
  response: string
  done: boolean
}

export interface OllamaProviderConfig {
  baseUrl?: string
  model?: string
}

export class OllamaProvider implements PolicyAnalysisProvider {
  readonly name = 'ollama'
  private baseUrl: string
  private model: string

  constructor(config?: OllamaProviderConfig) {
    this.baseUrl = config?.baseUrl ?? process.env.OLLAMA_BASE_URL ?? 'http://localhost:11434'
    this.model = config?.model ?? process.env.OLLAMA_MODEL ?? 'llama3.1'
  }

  async isAvailable(): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseUrl}/api/tags`, { signal: AbortSignal.timeout(3000) })
      return response.ok
    } catch {
      return false
    }
  }

  private async generate(prompt: string): Promise<string> {
    const response = await fetch(`${this.baseUrl}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: this.model,
        system: SYSTEM_PROMPT,
        prompt,
        stream: false,
      }),
    })

    if (!response.ok) {
      const text = await response.text()
      throw new Error(`Ollama API error ${response.status}: ${text}`)
    }

    const data = (await response.json()) as OllamaGenerateResponse
    return data.response
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
            severity: t.severity,
            objectTemplates: t.objectTemplates.slice(0, 5),
          })),
          clusterCount: policy.clusterStatus.length,
          nonCompliantClusters: policy.clusterStatus
            .filter((s) => s.compliant === 'NonCompliant')
            .map((s) => s.clusterName),
        },
        findings: deterministicResult.antiPatterns.slice(0, 8).map((f) => ({
          id: f.id,
          riskLevel: f.riskLevel,
          title: f.title,
        })),
        fleet: fleetContext
          ? { totalClusters: fleetContext.clusterNames.length, totalPolicies: fleetContext.allPolicies.length }
          : undefined,
      },
      null,
      2
    )
  }

  async summarize(ctx: PolicyAnalysisContext): Promise<string> {
    const context = this.formatContext(ctx)
    return this.generate(
      `Summarize this ACM policy in 2-3 sentences of plain English. Describe what it does, which clusters it affects, and its risk level.\n\n${context}`
    )
  }

  async explainRisk(ctx: PolicyAnalysisContext): Promise<string> {
    const context = this.formatContext(ctx)
    return this.generate(
      `Explain why the detected findings are dangerous for this fleet. Focus on cascading effects and operational impact. Be concise.\n\n${context}`
    )
  }

  async predictCatastrophicPlacement(ctx: PolicyAnalysisContext): Promise<CatastrophicPrediction> {
    const context = this.formatContext(ctx)
    const result = await this.generate(
      `Analyze this policy for catastrophic placement risks. What happens if deployed to all clusters simultaneously? Could it break the policy controller or cluster networking? Respond in JSON: { "blastRadius": { "affectedClusters": [], "affectedResources": [], "severity": "LOW|MEDIUM|HIGH|CATASTROPHIC" }, "cascadingFailures": [{ "trigger": "...", "chain": ["..."], "finalImpact": "..." }], "confidence": 0.0-1.0, "reasoning": "..." }\n\n${context}`
    )

    try {
      const jsonMatch = result.match(/\{[\s\S]*\}/)
      if (jsonMatch) return JSON.parse(jsonMatch[0]) as CatastrophicPrediction
    } catch {
      // Fall through
    }

    return {
      blastRadius: {
        affectedClusters: ctx.policy.clusterStatus.map((s) => s.clusterName),
        affectedResources: [],
        severity: 'MEDIUM',
      },
      cascadingFailures: [],
      confidence: 0.2,
      reasoning: result,
    }
  }

  async detectAccidentalScenarios(ctx: PolicyAnalysisContext): Promise<AccidentalScenario[]> {
    const context = this.formatContext(ctx)
    const result = await this.generate(
      `Look for subtle accidental scenarios beyond what deterministic rules catch. Consider policy interactions, timing issues, and label selector drift. Respond as a JSON array: [{ "id": "LLM-001", "title": "...", "description": "...", "triggerCondition": "...", "likelihood": "LOW|MEDIUM|HIGH", "impact": "LOW|MEDIUM|HIGH|CRITICAL", "recommendation": "..." }]. Return [] if none found.\n\n${context}`
    )

    try {
      const jsonMatch = result.match(/\[[\s\S]*\]/)
      if (jsonMatch) return JSON.parse(jsonMatch[0]) as AccidentalScenario[]
    } catch {
      // Fall through
    }

    return []
  }
}
