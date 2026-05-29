/* Copyright Contributors to the Open Cluster Management project */

import { runAntiPatterns } from './anti-patterns'
import type { RawPolicy } from './parser'
import { parsePolicy, parsePropagatedPolicies } from './parser'
import { assessDrift, assessSaturation, calculateClusterRiskScore, calculateFleetRisk } from './scoring'
import type { DeterministicResult, FleetContext, ParsedPolicy } from './types'

export interface AnalysisOptions {
  fleetContext?: FleetContext
  allRawPolicies?: RawPolicy[]
}

export function analyzePolicyDeterministic(
  policy: ParsedPolicy,
  options?: AnalysisOptions
): DeterministicResult {
  const clusterNames = policy.clusterStatus.map((s) => s.clusterName)

  const riskScores = clusterNames.map((cluster) => ({
    cluster,
    score: calculateClusterRiskScore([policy], cluster),
  }))

  const antiPatterns = runAntiPatterns(policy, options?.fleetContext)

  const saturation = clusterNames.map((cluster) => {
    const policyCount = options?.fleetContext
      ? options.fleetContext.allPolicies.filter((p) =>
          p.clusterStatus.some((s) => s.clusterName === cluster)
        ).length
      : 1
    return assessSaturation(cluster, policyCount)
  })

  const drift = policy.complianceHistory.length > 0
    ? assessDrift(policy.complianceHistory)
    : undefined

  const fleetRisk = options?.fleetContext
    ? calculateFleetRisk(options.fleetContext.allPolicies)
    : undefined

  return { riskScores, antiPatterns, saturation, drift, fleetRisk }
}

/**
 * Convenience: parse raw policies and run deterministic analysis.
 * Accepts the same JSON shape that `oc get policies -A -o json` produces.
 */
export function analyzeRawPolicy(
  rawPolicy: RawPolicy,
  allRawPolicies?: RawPolicy[]
): { parsed: ParsedPolicy; result: DeterministicResult } {
  const parsed = parsePolicy(rawPolicy)

  if (allRawPolicies) {
    parsed.complianceHistory = parsePropagatedPolicies(allRawPolicies)
  }

  const fleetContext: FleetContext | undefined = allRawPolicies
    ? {
        allPolicies: allRawPolicies
          .filter((p) => !p.metadata.labels?.['policy.open-cluster-management.io/root-policy'])
          .map(parsePolicy),
        clusterNames: Array.from(
          new Set(
            allRawPolicies.flatMap((p) =>
              (p.status?.status ?? []).map((s) => s.clustername)
            )
          )
        ),
      }
    : undefined

  const result = analyzePolicyDeterministic(parsed, { fleetContext })
  return { parsed, result }
}
