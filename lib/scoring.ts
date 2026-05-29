/* Copyright Contributors to the Open Cluster Management project */

import type {
  ClusterComplianceStatus,
  ComplianceHistoryEntry,
  DriftAssessment,
  DriftRisk,
  FleetRiskAssessment,
  ParsedPolicy,
  RemediationAction,
  RiskLevel,
  RiskScore,
  SaturationAssessment,
  SaturationLevel,
  Severity,
  VelocityAssessment,
} from './types'

import {
  HEURISTIC_SATURATION,
  REMEDIATION_MODIFIERS,
  RISK_LEVEL_THRESHOLDS,
  SATURATION_THRESHOLDS,
  SEVERITY_WEIGHTS,
  VIOLATION_WEIGHTS,
} from './types'

// --- Risk level classification ---

export function classifyRiskLevel(normalized: number): RiskLevel {
  if (normalized <= 0) return 'NONE'
  for (const { max, level } of RISK_LEVEL_THRESHOLDS) {
    if (normalized <= max) return level
  }
  return 'CRITICAL'
}

// --- Per-cluster risk scoring ---

function getEffectiveRemediation(policy: ParsedPolicy, templateRemediation?: RemediationAction): RemediationAction {
  return templateRemediation ?? policy.remediationAction
}

function getMaxSeverity(policy: ParsedPolicy): Severity {
  if (policy.templates.length === 0) return 'high'
  let max: Severity = 'low'
  const order: Severity[] = ['low', 'medium', 'high', 'critical']
  for (const t of policy.templates) {
    if (order.indexOf(t.severity) > order.indexOf(max)) {
      max = t.severity
    }
  }
  return max
}

export function calculatePolicyRiskContribution(
  complianceState: string,
  severity: Severity,
  remediation: RemediationAction
): number {
  const violationWeight = VIOLATION_WEIGHTS[complianceState] ?? 0.3
  const severityWeight = SEVERITY_WEIGHTS[severity]
  const remediationModifier = REMEDIATION_MODIFIERS[remediation]
  return violationWeight * severityWeight * remediationModifier
}

export function calculateClusterRiskScore(
  policies: ParsedPolicy[],
  clusterName: string
): RiskScore {
  let rawScore = 0
  let maxPossibleScore = 0

  for (const policy of policies) {
    if (policy.disabled) continue

    const clusterStatus = policy.clusterStatus.find((s) => s.clusterName === clusterName)
    if (!clusterStatus) continue

    const severity = getMaxSeverity(policy)
    const remediation = getEffectiveRemediation(policy)

    rawScore += calculatePolicyRiskContribution(clusterStatus.compliant, severity, remediation)
    maxPossibleScore += 1.0 * SEVERITY_WEIGHTS[severity] * 1.5
  }

  const normalized = maxPossibleScore > 0 ? Math.round((rawScore / maxPossibleScore) * 100) : 0

  return {
    raw: Math.round(rawScore * 100) / 100,
    normalized: Math.min(normalized, 100),
    level: classifyRiskLevel(normalized),
  }
}

// --- Compliance velocity ---

const DRIFT_RISK_ORDER: DriftRisk[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

function clampDriftRisk(index: number): DriftRisk {
  return DRIFT_RISK_ORDER[Math.max(0, Math.min(index, DRIFT_RISK_ORDER.length - 1))]
}

function classifyBaseVelocity(velocity: number, currentState: string): DriftRisk {
  if (velocity > 0.1) return 'CRITICAL'
  if (velocity >= 0.01) {
    return currentState === 'NonCompliant' ? 'HIGH' : 'MEDIUM'
  }
  return currentState === 'NonCompliant' ? 'HIGH' : 'LOW'
}

function detectTrend(events: { compliance: string }[]): 'worsening' | 'improving' | 'stable' {
  if (events.length < 3) return 'stable'
  const recent = events.slice(-3)
  const lastIsNonCompliant = recent[recent.length - 1].compliance.includes('NonCompliant')
  const firstIsCompliant = recent[0].compliance.includes('Compliant') && !recent[0].compliance.includes('Non')

  if (firstIsCompliant && lastIsNonCompliant) return 'worsening'
  if (!firstIsCompliant && !lastIsNonCompliant) return 'improving'
  return 'stable'
}

export function calculateComplianceVelocity(entry: ComplianceHistoryEntry): VelocityAssessment[] {
  const assessments: VelocityAssessment[] = []

  for (const th of entry.templateHistory) {
    if (th.events.length < 2) {
      assessments.push({
        cluster: entry.cluster,
        policy: entry.policy,
        velocity: 0,
        currentState: th.currentCompliance,
        driftRisk: th.currentCompliance === 'NonCompliant' ? 'HIGH' : 'LOW',
      })
      continue
    }

    const sorted = [...th.events].sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    )

    let transitions = 0
    for (let i = 1; i < sorted.length; i++) {
      if (sorted[i].compliance !== sorted[i - 1].compliance) {
        transitions++
      }
    }

    const firstTime = new Date(sorted[0].timestamp).getTime()
    const lastTime = new Date(sorted[sorted.length - 1].timestamp).getTime()
    const hoursSpan = (lastTime - firstTime) / (1000 * 60 * 60)

    const velocity = hoursSpan > 0 ? transitions / hoursSpan : 0
    let baseRisk = classifyBaseVelocity(velocity, th.currentCompliance)

    const trend = detectTrend(sorted)
    let riskIndex = DRIFT_RISK_ORDER.indexOf(baseRisk)
    if (trend === 'worsening') riskIndex++
    if (trend === 'improving') riskIndex--

    const driftRisk = clampDriftRisk(riskIndex)

    assessments.push({
      cluster: entry.cluster,
      policy: entry.policy,
      velocity: Math.round(velocity * 1000) / 1000,
      currentState: th.currentCompliance,
      driftRisk,
      projection: velocity > 0.01
        ? `Drift velocity: ${velocity.toFixed(3)} transitions/hr. Trend: ${trend}.`
        : undefined,
    })
  }

  return assessments
}

export function assessDrift(historyEntries: ComplianceHistoryEntry[]): DriftAssessment {
  const velocities: VelocityAssessment[] = []
  for (const entry of historyEntries) {
    velocities.push(...calculateComplianceVelocity(entry))
  }

  const highRiskCount = velocities.filter(
    (v) => v.driftRisk === 'HIGH' || v.driftRisk === 'CRITICAL'
  ).length

  return { velocities, highRiskCount }
}

// --- Saturation ---

export function assessSaturation(
  cluster: string,
  policyCount: number,
  reconcileP99?: number
): SaturationAssessment {
  let level: SaturationLevel
  let action: string

  if (reconcileP99 != null) {
    if (policyCount <= SATURATION_THRESHOLDS.GREEN.maxPolicies && reconcileP99 <= SATURATION_THRESHOLDS.GREEN.maxP99) {
      level = 'GREEN'
      action = 'No action needed'
    } else if (policyCount <= SATURATION_THRESHOLDS.YELLOW.maxPolicies && reconcileP99 <= SATURATION_THRESHOLDS.YELLOW.maxP99) {
      level = 'YELLOW'
      action = 'Monitor trends'
    } else if (policyCount <= SATURATION_THRESHOLDS.ORANGE.maxPolicies && reconcileP99 <= SATURATION_THRESHOLDS.ORANGE.maxP99) {
      level = 'ORANGE'
      action = 'Consider policy consolidation'
    } else {
      level = 'RED'
      action = 'Immediate attention: controller may fall behind'
    }
  } else {
    if (policyCount > HEURISTIC_SATURATION.RED) {
      level = 'RED'
      action = 'Immediate attention: controller may fall behind'
    } else if (policyCount > HEURISTIC_SATURATION.ORANGE) {
      level = 'ORANGE'
      action = 'Consider policy consolidation'
    } else {
      level = 'GREEN'
      action = 'No action needed'
    }
  }

  return { cluster, policyCount, reconcileP99, level, action }
}

// --- Fleet-level aggregation ---

export function calculateFleetRisk(policies: ParsedPolicy[]): FleetRiskAssessment {
  const clusterSet = new Set<string>()
  for (const p of policies) {
    for (const cs of p.clusterStatus) {
      clusterSet.add(cs.clusterName)
    }
  }
  const clusterNames = Array.from(clusterSet)

  const clusterScores = clusterNames.map((cluster) => ({
    cluster,
    score: calculateClusterRiskScore(policies, cluster),
  }))

  const riskDistribution: Record<RiskLevel, number> = { NONE: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 }
  for (const cs of clusterScores) {
    riskDistribution[cs.score.level]++
  }

  const fleetScore = clusterScores.length > 0
    ? Math.round(clusterScores.reduce((sum, cs) => sum + cs.score.normalized, 0) / clusterScores.length)
    : 0

  const worstCluster = clusterScores.length > 0
    ? clusterScores.reduce((worst, cs) => (cs.score.normalized > worst.score.normalized ? cs : worst))
    : undefined

  const policyViolationCounts = new Map<string, number>()
  for (const p of policies) {
    if (p.disabled) continue
    const ncCount = p.clusterStatus.filter((s) => s.compliant === 'NonCompliant').length
    if (ncCount > 0) {
      policyViolationCounts.set(p.name, ncCount)
    }
  }

  let mostViolatedPolicy: { name: string; nonCompliantCount: number } | undefined
  let maxViolations = 0
  for (const [name, count] of policyViolationCounts) {
    if (count > maxViolations) {
      maxViolations = count
      mostViolatedPolicy = { name, nonCompliantCount: count }
    }
  }

  const severityBuckets = { synced: 0, critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }
  for (const policy of policies) {
    if (policy.disabled) continue
    const severity = getMaxSeverity(policy)
    for (const cs of policy.clusterStatus) {
      if (cs.compliant === 'Compliant') {
        severityBuckets.synced++
      } else if (cs.compliant === 'NonCompliant') {
        severityBuckets[severity]++
      } else {
        severityBuckets.unknown++
      }
    }
  }

  return {
    fleetScore,
    fleetLevel: classifyRiskLevel(fleetScore),
    clusterScores,
    riskDistribution,
    worstCluster: worstCluster ? { cluster: worstCluster.cluster, score: worstCluster.score.normalized } : undefined,
    mostViolatedPolicy,
    severityBuckets,
  }
}
