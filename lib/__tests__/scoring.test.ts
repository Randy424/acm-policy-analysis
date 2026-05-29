import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  calculatePolicyRiskContribution,
  calculateClusterRiskScore,
  classifyRiskLevel,
  assessSaturation,
  calculateComplianceVelocity,
  calculateFleetRisk,
} from '../scoring'
import type { ParsedPolicy, ComplianceHistoryEntry } from '../types'

// --- Helper to build minimal ParsedPolicy ---

function makePolicy(overrides: Partial<ParsedPolicy> = {}): ParsedPolicy {
  return {
    name: 'test-policy',
    namespace: 'default',
    disabled: false,
    remediationAction: 'inform',
    templates: [{
      name: 'cfg',
      kind: 'ConfigurationPolicy',
      severity: 'high',
      objectTemplates: [],
    }],
    clusterStatus: [],
    complianceHistory: [],
    ...overrides,
  }
}

// =========================
// Risk contribution formula
// =========================

describe('calculatePolicyRiskContribution', () => {
  it('NonCompliant + critical + inform = 1.0 * 4 * 1.5 = 6.0', () => {
    assert.equal(calculatePolicyRiskContribution('NonCompliant', 'critical', 'inform'), 6.0)
  })

  it('NonCompliant + high + enforce = 1.0 * 3 * 0.8 = 2.4', () => {
    const result = calculatePolicyRiskContribution('NonCompliant', 'high', 'enforce')
    assert.equal(Math.round(result * 100) / 100, 2.4)
  })

  it('Compliant + critical + inform = 0.0', () => {
    assert.equal(calculatePolicyRiskContribution('Compliant', 'critical', 'inform'), 0)
  })

  it('Pending + medium + informOnly = 0.3 * 2 * 1.0 = 0.6', () => {
    assert.equal(calculatePolicyRiskContribution('Pending', 'medium', 'informOnly'), 0.6)
  })

  it('NonCompliant + low + enforce = 1.0 * 1 * 0.8 = 0.8', () => {
    const result = calculatePolicyRiskContribution('NonCompliant', 'low', 'enforce')
    assert.equal(Math.round(result * 100) / 100, 0.8)
  })
})

// ========================
// Risk level classification
// ========================

describe('classifyRiskLevel', () => {
  it('0 = NONE', () => assert.equal(classifyRiskLevel(0), 'NONE'))
  it('1 = LOW', () => assert.equal(classifyRiskLevel(1), 'LOW'))
  it('25 = LOW', () => assert.equal(classifyRiskLevel(25), 'LOW'))
  it('26 = MEDIUM', () => assert.equal(classifyRiskLevel(26), 'MEDIUM'))
  it('50 = MEDIUM', () => assert.equal(classifyRiskLevel(50), 'MEDIUM'))
  it('51 = HIGH', () => assert.equal(classifyRiskLevel(51), 'HIGH'))
  it('75 = HIGH', () => assert.equal(classifyRiskLevel(75), 'HIGH'))
  it('76 = CRITICAL', () => assert.equal(classifyRiskLevel(76), 'CRITICAL'))
  it('100 = CRITICAL', () => assert.equal(classifyRiskLevel(100), 'CRITICAL'))
})

// ==========================
// Per-cluster risk scoring
// ==========================

describe('calculateClusterRiskScore', () => {
  it('single NonCompliant high/inform policy scores 53 (HIGH)', () => {
    const policy = makePolicy({
      remediationAction: 'inform',
      templates: [{ name: 'cfg', kind: 'ConfigurationPolicy', severity: 'high', objectTemplates: [] }],
      clusterStatus: [{ clusterName: 'cluster-1', clusterNamespace: 'cluster-1', compliant: 'NonCompliant' }],
    })

    const score = calculateClusterRiskScore([policy], 'cluster-1')
    // raw = 1.0 * 3 * 1.5 = 4.5, max = 1.0 * 3 * 1.5 = 4.5, normalized = 100
    assert.equal(score.normalized, 100)
    assert.equal(score.level, 'CRITICAL')
  })

  it('single Compliant policy scores 0 (NONE)', () => {
    const policy = makePolicy({
      clusterStatus: [{ clusterName: 'cluster-1', clusterNamespace: 'cluster-1', compliant: 'Compliant' }],
    })
    const score = calculateClusterRiskScore([policy], 'cluster-1')
    assert.equal(score.normalized, 0)
    assert.equal(score.level, 'NONE')
  })

  it('disabled policies are skipped', () => {
    const policy = makePolicy({
      disabled: true,
      clusterStatus: [{ clusterName: 'cluster-1', clusterNamespace: 'cluster-1', compliant: 'NonCompliant' }],
    })
    const score = calculateClusterRiskScore([policy], 'cluster-1')
    assert.equal(score.normalized, 0)
    assert.equal(score.level, 'NONE')
  })

  it('cluster not in policy returns 0', () => {
    const policy = makePolicy({
      clusterStatus: [{ clusterName: 'other-cluster', clusterNamespace: 'other-cluster', compliant: 'NonCompliant' }],
    })
    const score = calculateClusterRiskScore([policy], 'cluster-1')
    assert.equal(score.normalized, 0)
  })

  it('mixed compliance across two policies', () => {
    const policies: ParsedPolicy[] = [
      makePolicy({
        name: 'p1',
        remediationAction: 'inform',
        templates: [{ name: 'cfg1', kind: 'ConfigurationPolicy', severity: 'critical', objectTemplates: [] }],
        clusterStatus: [{ clusterName: 'c1', clusterNamespace: 'c1', compliant: 'NonCompliant' }],
      }),
      makePolicy({
        name: 'p2',
        remediationAction: 'enforce',
        templates: [{ name: 'cfg2', kind: 'ConfigurationPolicy', severity: 'low', objectTemplates: [] }],
        clusterStatus: [{ clusterName: 'c1', clusterNamespace: 'c1', compliant: 'Compliant' }],
      }),
    ]
    const score = calculateClusterRiskScore(policies, 'c1')
    // p1: 1.0 * 4 * 1.5 = 6.0, p2: 0.0 * 1 * 0.8 = 0.0
    // max: (4 * 1.5) + (1 * 1.5) = 7.5
    // normalized: (6.0 / 7.5) * 100 = 80
    assert.equal(score.normalized, 80)
    assert.equal(score.level, 'CRITICAL')
  })
})

// ==============
// Saturation
// ==============

describe('assessSaturation', () => {
  it('low count + low p99 = GREEN', () => {
    const result = assessSaturation('c1', 10, 2)
    assert.equal(result.level, 'GREEN')
  })

  it('medium count + medium p99 = YELLOW', () => {
    const result = assessSaturation('c1', 35, 10)
    assert.equal(result.level, 'YELLOW')
  })

  it('high count + high p99 = ORANGE', () => {
    const result = assessSaturation('c1', 80, 25)
    assert.equal(result.level, 'ORANGE')
  })

  it('very high count + very high p99 = RED', () => {
    const result = assessSaturation('c1', 150, 45)
    assert.equal(result.level, 'RED')
  })

  it('heuristic fallback: >100 policies without metrics = RED', () => {
    const result = assessSaturation('c1', 101)
    assert.equal(result.level, 'RED')
  })

  it('heuristic fallback: >50 policies without metrics = ORANGE', () => {
    const result = assessSaturation('c1', 60)
    assert.equal(result.level, 'ORANGE')
  })

  it('heuristic fallback: <50 policies without metrics = GREEN', () => {
    const result = assessSaturation('c1', 30)
    assert.equal(result.level, 'GREEN')
  })
})

// =======================
// Compliance velocity
// =======================

describe('calculateComplianceVelocity', () => {
  it('single event = velocity 0, risk based on current state', () => {
    const entry: ComplianceHistoryEntry = {
      cluster: 'c1',
      policy: 'p1',
      rootPolicy: 'default.p1',
      overallCompliance: 'Compliant',
      templateHistory: [{
        templateName: 'cfg',
        currentCompliance: 'Compliant',
        events: [{ timestamp: '2026-05-01T10:00:00Z', compliance: 'Compliant' }],
      }],
    }
    const results = calculateComplianceVelocity(entry)
    assert.equal(results.length, 1)
    assert.equal(results[0].velocity, 0)
    assert.equal(results[0].driftRisk, 'LOW')
  })

  it('stable NonCompliant = HIGH risk', () => {
    const entry: ComplianceHistoryEntry = {
      cluster: 'c1',
      policy: 'p1',
      rootPolicy: 'default.p1',
      overallCompliance: 'NonCompliant',
      templateHistory: [{
        templateName: 'cfg',
        currentCompliance: 'NonCompliant',
        events: [
          { timestamp: '2026-05-01T10:00:00Z', compliance: 'NonCompliant' },
          { timestamp: '2026-05-01T11:00:00Z', compliance: 'NonCompliant' },
        ],
      }],
    }
    const results = calculateComplianceVelocity(entry)
    assert.equal(results[0].velocity, 0)
    assert.equal(results[0].driftRisk, 'HIGH')
  })

  it('flip-flopping > 0.1/hr = CRITICAL', () => {
    const entry: ComplianceHistoryEntry = {
      cluster: 'c1',
      policy: 'p1',
      rootPolicy: 'default.p1',
      overallCompliance: 'NonCompliant',
      templateHistory: [{
        templateName: 'cfg',
        currentCompliance: 'NonCompliant',
        events: [
          { timestamp: '2026-05-01T10:00:00Z', compliance: 'Compliant' },
          { timestamp: '2026-05-01T10:10:00Z', compliance: 'NonCompliant' },
          { timestamp: '2026-05-01T10:20:00Z', compliance: 'Compliant' },
          { timestamp: '2026-05-01T10:30:00Z', compliance: 'NonCompliant' },
        ],
      }],
    }
    const results = calculateComplianceVelocity(entry)
    assert.ok(results[0].velocity > 0.1, `velocity ${results[0].velocity} should be > 0.1`)
    assert.equal(results[0].driftRisk, 'CRITICAL')
  })
})

// ==================
// Fleet risk
// ==================

describe('calculateFleetRisk', () => {
  it('all compliant = fleet score 0, NONE', () => {
    const policies: ParsedPolicy[] = [
      makePolicy({
        clusterStatus: [
          { clusterName: 'c1', clusterNamespace: 'c1', compliant: 'Compliant' },
          { clusterName: 'c2', clusterNamespace: 'c2', compliant: 'Compliant' },
        ],
      }),
    ]
    const fleet = calculateFleetRisk(policies)
    assert.equal(fleet.fleetScore, 0)
    assert.equal(fleet.fleetLevel, 'NONE')
    assert.equal(fleet.riskDistribution.NONE, 2)
    assert.equal(fleet.severityBuckets.synced, 2)
  })

  it('identifies worst cluster and most violated policy', () => {
    const policies: ParsedPolicy[] = [
      makePolicy({
        name: 'bad-policy',
        remediationAction: 'inform',
        templates: [{ name: 'cfg', kind: 'ConfigurationPolicy', severity: 'critical', objectTemplates: [] }],
        clusterStatus: [
          { clusterName: 'c1', clusterNamespace: 'c1', compliant: 'NonCompliant' },
          { clusterName: 'c2', clusterNamespace: 'c2', compliant: 'NonCompliant' },
        ],
      }),
    ]
    const fleet = calculateFleetRisk(policies)
    assert.ok(fleet.fleetScore > 0)
    assert.equal(fleet.mostViolatedPolicy?.name, 'bad-policy')
    assert.equal(fleet.mostViolatedPolicy?.nonCompliantCount, 2)
    assert.equal(fleet.severityBuckets.critical, 2)
  })

  it('empty fleet returns zero', () => {
    const fleet = calculateFleetRisk([])
    assert.equal(fleet.fleetScore, 0)
    assert.equal(fleet.clusterScores.length, 0)
  })
})
