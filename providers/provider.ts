/* Copyright Contributors to the Open Cluster Management project */

import type {
  DeterministicResult,
  FleetContext,
  ParsedPolicy,
  PolicyAnalysisResult,
  StructuredAnalysis,
} from '../lib/types'

export interface PolicyAnalysisContext {
  policy: ParsedPolicy
  deterministicResult: DeterministicResult
  fleetContext?: FleetContext
}

export interface PolicyAnalysisProvider {
  readonly name: string

  isAvailable(): Promise<boolean>

  analyze(ctx: PolicyAnalysisContext): Promise<{
    impactedClusters: string[]
    analysis: StructuredAnalysis
  }>
}

export async function analyzeWithProvider(
  policy: ParsedPolicy,
  deterministicResult: DeterministicResult,
  provider: PolicyAnalysisProvider,
  fleetContext?: FleetContext
): Promise<PolicyAnalysisResult> {
  const ctx: PolicyAnalysisContext = { policy, deterministicResult, fleetContext }

  const { impactedClusters, analysis } = await provider.analyze(ctx)

  return {
    policy: { name: policy.name, namespace: policy.namespace, disabled: policy.disabled },
    provider: provider.name,
    impactedClusters,
    analysis,
    timestamp: new Date().toISOString(),
  }
}
