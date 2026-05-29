/* Copyright Contributors to the Open Cluster Management project */

import type {
  AccidentalScenario,
  CatastrophicPrediction,
  DeterministicResult,
  FleetContext,
  ParsedPolicy,
  PolicyAnalysisResult,
} from '../lib/types'

export interface PolicyAnalysisContext {
  policy: ParsedPolicy
  deterministicResult: DeterministicResult
  fleetContext?: FleetContext
}

export interface PolicyAnalysisProvider {
  readonly name: string

  isAvailable(): Promise<boolean>

  /** Generate a plain-English summary of what the policy does and its risk posture (N3). */
  summarize(ctx: PolicyAnalysisContext): Promise<string>

  /** Explain WHY the detected findings are dangerous in this specific fleet context. */
  explainRisk(ctx: PolicyAnalysisContext): Promise<string>

  /** Predict blast radius and cascading failures before placement deployment (N1). */
  predictCatastrophicPlacement(ctx: PolicyAnalysisContext): Promise<CatastrophicPrediction>

  /** Detect subtle accidental scenarios the deterministic rules may miss (N2). */
  detectAccidentalScenarios(ctx: PolicyAnalysisContext): Promise<AccidentalScenario[]>
}

function settledValue<T>(result: PromiseSettledResult<T>): T | undefined {
  return result.status === 'fulfilled' ? result.value : undefined
}

/**
 * Run full analysis: deterministic first, then LLM enrichment via the provider.
 * LLM failures never block deterministic results.
 */
export async function analyzeWithProvider(
  policy: ParsedPolicy,
  deterministicResult: DeterministicResult,
  provider: PolicyAnalysisProvider,
  fleetContext?: FleetContext
): Promise<PolicyAnalysisResult> {
  const ctx: PolicyAnalysisContext = { policy, deterministicResult, fleetContext }

  const [summary, riskExplanation, catastrophicPrediction, accidentalScenarios] =
    await Promise.allSettled([
      provider.summarize(ctx),
      provider.explainRisk(ctx),
      provider.predictCatastrophicPlacement(ctx),
      provider.detectAccidentalScenarios(ctx),
    ])

  return {
    deterministic: deterministicResult,
    summary: settledValue(summary),
    riskExplanation: settledValue(riskExplanation),
    catastrophicPrediction: settledValue(catastrophicPrediction),
    accidentalScenarios: settledValue(accidentalScenarios),
    provider: provider.name,
    timestamp: new Date().toISOString(),
  }
}
