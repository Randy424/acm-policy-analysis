/* Copyright Contributors to the Open Cluster Management project */

import type { AccidentalScenario, CatastrophicPrediction } from '../lib/types'
import type { PolicyAnalysisContext, PolicyAnalysisProvider } from './provider'

/**
 * No-LLM fallback provider. Generates structured text from deterministic results
 * using templates — no external API calls, always available, instant response.
 */
export class DeterministicOnlyProvider implements PolicyAnalysisProvider {
  readonly name = 'deterministic'

  async isAvailable(): Promise<boolean> {
    return true
  }

  async summarize(ctx: PolicyAnalysisContext): Promise<string> {
    const { policy, deterministicResult } = ctx
    const { antiPatterns, riskScores } = deterministicResult

    const templateKinds = policy.templates
      .flatMap((t) => t.objectTemplates.map((ot) => ot.kind))
      .filter((v, i, a) => a.indexOf(v) === i)

    const clusterCount = policy.clusterStatus.length
    const nonCompliantCount = policy.clusterStatus.filter((s) => s.compliant === 'NonCompliant').length

    const criticalFindings = antiPatterns.filter((f) => f.riskLevel === 'CRITICAL').length
    const highFindings = antiPatterns.filter((f) => f.riskLevel === 'HIGH').length

    const lines: string[] = []

    lines.push(
      `Policy "${policy.name}" in namespace "${policy.namespace}" ` +
      `targets ${templateKinds.join(', ')} resources ` +
      `with remediation action "${policy.remediationAction}".`
    )

    if (clusterCount > 0) {
      lines.push(
        `It is deployed to ${clusterCount} cluster${clusterCount !== 1 ? 's' : ''}` +
        (nonCompliantCount > 0 ? `, ${nonCompliantCount} currently non-compliant.` : ', all compliant.')
      )
    }

    if (criticalFindings > 0 || highFindings > 0) {
      lines.push(
        `Analysis found ${criticalFindings} critical and ${highFindings} high-risk findings.`
      )
    } else if (antiPatterns.length > 0) {
      lines.push(`Analysis found ${antiPatterns.length} finding${antiPatterns.length !== 1 ? 's' : ''} (medium risk or below).`)
    } else {
      lines.push('No anti-pattern findings detected.')
    }

    if (riskScores.length > 0) {
      const maxScore = riskScores.reduce((max, s) => s.score.normalized > max.score.normalized ? s : max)
      lines.push(`Highest cluster risk: ${maxScore.cluster} at ${maxScore.score.normalized}/100 (${maxScore.score.level}).`)
    }

    return lines.join(' ')
  }

  async explainRisk(ctx: PolicyAnalysisContext): Promise<string> {
    const { antiPatterns } = ctx.deterministicResult

    if (antiPatterns.length === 0) {
      return 'No risk findings to explain. The policy follows known best practices.'
    }

    const grouped = {
      CRITICAL: antiPatterns.filter((f) => f.riskLevel === 'CRITICAL'),
      HIGH: antiPatterns.filter((f) => f.riskLevel === 'HIGH'),
      MEDIUM: antiPatterns.filter((f) => f.riskLevel === 'MEDIUM'),
    }

    const sections: string[] = []

    for (const [level, findings] of Object.entries(grouped)) {
      if (findings.length === 0) continue
      sections.push(
        `**${level}** (${findings.length}):\n` +
        findings.map((f) => `- ${f.title}: ${f.description}`).join('\n')
      )
    }

    return sections.join('\n\n')
  }

  async predictCatastrophicPlacement(ctx: PolicyAnalysisContext): Promise<CatastrophicPrediction> {
    const { antiPatterns } = ctx.deterministicResult
    const catastrophicFindings = antiPatterns.filter((f) => f.category === 'catastrophic-placement')

    const affectedClusters = ctx.policy.clusterStatus.map((s) => s.clusterName)
    const affectedResources = catastrophicFindings
      .filter((f) => f.affectedResource)
      .map((f) => `${f.affectedResource!.kind}/${f.affectedResource!.name}`)

    let severity: CatastrophicPrediction['blastRadius']['severity']
    if (catastrophicFindings.length === 0) {
      severity = 'LOW'
    } else if (catastrophicFindings.length <= 2) {
      severity = 'MEDIUM'
    } else if (catastrophicFindings.length <= 4) {
      severity = 'HIGH'
    } else {
      severity = 'CATASTROPHIC'
    }

    return {
      blastRadius: {
        affectedClusters,
        affectedResources,
        severity,
      },
      cascadingFailures: catastrophicFindings.map((f) => ({
        trigger: f.title,
        chain: [f.description],
        finalImpact: f.recommendation,
      })),
      confidence: catastrophicFindings.length > 0 ? 0.7 : 0.9,
      reasoning: catastrophicFindings.length > 0
        ? `Deterministic analysis detected ${catastrophicFindings.length} catastrophic pattern(s). LLM provider not configured — enable one for deeper contextual reasoning.`
        : 'No catastrophic patterns detected by deterministic rules.',
    }
  }

  async detectAccidentalScenarios(ctx: PolicyAnalysisContext): Promise<AccidentalScenario[]> {
    const { antiPatterns } = ctx.deterministicResult

    return antiPatterns
      .filter((f) => f.category === 'accidental-scenario')
      .map((f) => ({
        id: f.id,
        title: f.title,
        description: f.description,
        triggerCondition: f.affectedResource
          ? `Policy targets ${f.affectedResource.kind} "${f.affectedResource.name}"${f.affectedResource.namespace ? ` in ${f.affectedResource.namespace}` : ''}`
          : f.description,
        likelihood: (f.riskLevel === 'CRITICAL' ? 'HIGH' : f.riskLevel === 'HIGH' ? 'MEDIUM' : 'LOW') as AccidentalScenario['likelihood'],
        impact: f.riskLevel as AccidentalScenario['impact'],
        recommendation: f.recommendation,
      }))
  }
}
