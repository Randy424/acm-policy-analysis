/* Copyright Contributors to the Open Cluster Management project */

import type { StructuredAnalysis } from '../lib/types'
import type { PolicyAnalysisContext, PolicyAnalysisProvider } from './provider'

const SYSTEM_PROMPT = `You are an ACM (Red Hat Advanced Cluster Management) policy governance expert. You analyze Kubernetes policy specifications and return structured risk assessments as JSON. Respond with valid JSON only.`

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

  async analyze(ctx: PolicyAnalysisContext): Promise<{
    impactedClusters: string[]
    analysis: StructuredAnalysis
  }> {
    const { policy, deterministicResult } = ctx
    const context = JSON.stringify(
      {
        policy: {
          name: policy.name,
          namespace: policy.namespace,
          remediationAction: policy.remediationAction,
          templates: policy.templates.map((t) => ({
            name: t.name,
            severity: t.severity,
            objectTemplates: t.objectTemplates.slice(0, 5),
          })),
          clusterCount: policy.clusterStatus.length,
        },
        findings: deterministicResult.antiPatterns.slice(0, 8).map((f) => ({
          id: f.id,
          riskLevel: f.riskLevel,
          title: f.title,
        })),
      },
      null,
      2
    )

    const result = await this.generate(
      `Analyze this ACM policy. Return JSON: { "impactedClusters": [...], "analysis": { "summary": "max 75 words", "risks": [{ "severity": "CRITICAL|HIGH|MEDIUM|LOW", "title": "max 10 words", "description": "max 50 words", "recommendation": "max 40 words" }], "recommendations": ["max 30 words each"], "catastrophicAssessment": { "severity": "LOW|MEDIUM|HIGH|CATASTROPHIC", "reasoning": "max 100 words", "cascadingFailures": [] }, "accidentalScenarios": [] } }\n\n${context}`
    )

    try {
      const jsonMatch = result.match(/\{[\s\S]*\}/)
      if (jsonMatch) {
        return JSON.parse(jsonMatch[0]) as {
          impactedClusters: string[]
          analysis: StructuredAnalysis
        }
      }
    } catch {
      // Fall through
    }

    return {
      impactedClusters: policy.clusterStatus.map((s) => s.clusterName),
      analysis: {
        summary: 'Ollama analysis could not be parsed.',
        risks: [],
        recommendations: [],
        catastrophicAssessment: { severity: 'LOW', reasoning: result.slice(0, 200), cascadingFailures: [] },
        accidentalScenarios: [],
      },
    }
  }
}
