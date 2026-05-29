/* Copyright Contributors to the Open Cluster Management project */

import type { StructuredAnalysis } from '../lib/types'
import type { PolicyAnalysisContext, PolicyAnalysisProvider } from './provider'

export class DeterministicOnlyProvider implements PolicyAnalysisProvider {
  readonly name = 'deterministic'

  async isAvailable(): Promise<boolean> {
    return true
  }

  async analyze(ctx: PolicyAnalysisContext): Promise<{
    impactedClusters: string[]
    analysis: StructuredAnalysis
  }> {
    const { policy, deterministicResult } = ctx
    const { antiPatterns } = deterministicResult

    const impactedClusters = policy.clusterStatus.map((s) => s.clusterName)

    const templateKinds = policy.templates
      .flatMap((t) => t.objectTemplates.map((ot) => ot.kind))
      .filter((v, i, a) => a.indexOf(v) === i)

    const clusterCount = policy.clusterStatus.length
    const nonCompliantCount = policy.clusterStatus.filter((s) => s.compliant === 'NonCompliant').length

    const summaryParts: string[] = []
    summaryParts.push(
      `Policy "${policy.name}" targets ${templateKinds.join(', ')} resources with "${policy.remediationAction}" remediation.`
    )
    if (clusterCount > 0) {
      summaryParts.push(
        `Deployed to ${clusterCount} cluster${clusterCount !== 1 ? 's' : ''}${nonCompliantCount > 0 ? `, ${nonCompliantCount} non-compliant` : ''}.`
      )
    } else {
      summaryParts.push('Not yet deployed (pre-deployment analysis).')
    }
    if (antiPatterns.length > 0) {
      summaryParts.push(`${antiPatterns.length} finding${antiPatterns.length !== 1 ? 's' : ''} detected.`)
    }

    const risks = antiPatterns
      .filter((f) => f.category !== 'catastrophic-placement' && f.category !== 'accidental-scenario')
      .map((f) => ({
        severity: f.riskLevel as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
        title: f.title,
        description: f.description,
        recommendation: f.recommendation,
      }))

    const recommendations: string[] = []
    if (antiPatterns.some((f) => f.riskLevel === 'CRITICAL')) {
      recommendations.push('Address all critical findings before deployment.')
    }
    if (policy.remediationAction === 'enforce') {
      recommendations.push('Consider using "inform" mode for initial deployment to observe impact.')
    }
    if (policy.templates.some((t) => t.pruneObjectBehavior === 'DeleteAll')) {
      recommendations.push('Change pruneObjectBehavior from "DeleteAll" to "DeleteIfCreated" or "None".')
    }

    const catastrophicFindings = antiPatterns.filter((f) => f.category === 'catastrophic-placement')
    const catastrophicSeverity =
      catastrophicFindings.length === 0
        ? 'LOW'
        : catastrophicFindings.length <= 2
          ? 'MEDIUM'
          : catastrophicFindings.length <= 4
            ? 'HIGH'
            : 'CATASTROPHIC'

    const accidentalScenarios = antiPatterns
      .filter((f) => f.category === 'accidental-scenario')
      .map((f) => ({
        title: f.title,
        description: f.description,
        likelihood: (f.riskLevel === 'CRITICAL' ? 'HIGH' : f.riskLevel === 'HIGH' ? 'MEDIUM' : 'LOW') as
          | 'LOW'
          | 'MEDIUM'
          | 'HIGH',
        impact: f.riskLevel as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
        recommendation: f.recommendation,
      }))

    return {
      impactedClusters,
      analysis: {
        summary: summaryParts.join(' '),
        risks,
        recommendations,
        catastrophicAssessment: {
          severity: catastrophicSeverity as 'LOW' | 'MEDIUM' | 'HIGH' | 'CATASTROPHIC',
          reasoning:
            catastrophicFindings.length > 0
              ? `Detected ${catastrophicFindings.length} catastrophic pattern(s). Enable an LLM provider for deeper contextual reasoning.`
              : 'No catastrophic patterns detected by deterministic rules.',
          cascadingFailures: catastrophicFindings.map((f) => ({
            trigger: f.title,
            chain: [f.description],
            finalImpact: f.recommendation,
          })),
        },
        accidentalScenarios,
      },
    }
  }
}
