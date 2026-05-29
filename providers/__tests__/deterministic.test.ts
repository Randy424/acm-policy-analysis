import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { DeterministicOnlyProvider } from '../deterministic'
import { analyzePolicyDeterministic } from '../../lib/analyze'
import type { ParsedPolicy } from '../../lib/types'
import type { PolicyAnalysisContext } from '../provider'
import { analyzeWithProvider } from '../provider'

function makePolicy(overrides: Partial<ParsedPolicy> = {}): ParsedPolicy {
  return {
    name: 'test-policy',
    namespace: 'default',
    disabled: false,
    remediationAction: 'enforce',
    templates: [{
      name: 'cfg',
      kind: 'ConfigurationPolicy',
      severity: 'high',
      objectTemplates: [{
        complianceType: 'mustnothave',
        kind: 'ConfigMap',
        apiVersion: 'v1',
        name: 'cluster-monitoring-config',
        namespace: 'openshift-monitoring',
      }],
    }],
    clusterStatus: [
      { clusterName: 'prod-east-1', clusterNamespace: 'prod-east-1', compliant: 'NonCompliant' },
    ],
    complianceHistory: [],
    ...overrides,
  }
}

describe('DeterministicOnlyProvider', () => {
  const provider = new DeterministicOnlyProvider()

  it('is always available', async () => {
    assert.equal(await provider.isAvailable(), true)
  })

  it('name is "deterministic"', () => {
    assert.equal(provider.name, 'deterministic')
  })

  it('summarize produces readable text', async () => {
    const policy = makePolicy()
    const result = analyzePolicyDeterministic(policy)
    const ctx: PolicyAnalysisContext = { policy, deterministicResult: result }

    const summary = await provider.summarize(ctx)
    assert.ok(summary.includes('test-policy'))
    assert.ok(summary.includes('prod-east-1'))
    assert.ok(summary.includes('non-compliant') || summary.includes('critical') || summary.includes('HIGH'))
  })

  it('explainRisk groups findings by severity', async () => {
    const policy = makePolicy()
    const result = analyzePolicyDeterministic(policy)
    const ctx: PolicyAnalysisContext = { policy, deterministicResult: result }

    const explanation = await provider.explainRisk(ctx)
    assert.ok(explanation.includes('CRITICAL'))
  })

  it('explainRisk returns clean message when no findings', async () => {
    const policy = makePolicy({
      remediationAction: 'inform',
      templates: [{
        name: 'cfg', kind: 'ConfigurationPolicy', severity: 'low',
        remediationAction: 'inform',
        namespaceSelector: { include: ['my-app'] },
        objectTemplates: [{
          complianceType: 'musthave', kind: 'ConfigMap', apiVersion: 'v1',
          name: 'my-config', namespace: 'my-app',
        }],
      }],
      clusterStatus: [{ clusterName: 'c1', clusterNamespace: 'c1', compliant: 'Compliant' }],
    })
    const result = analyzePolicyDeterministic(policy)
    const ctx: PolicyAnalysisContext = { policy, deterministicResult: result }

    const explanation = await provider.explainRisk(ctx)
    assert.ok(explanation.includes('No risk findings'))
  })

  it('predictCatastrophicPlacement returns structured result', async () => {
    const policy = makePolicy()
    const result = analyzePolicyDeterministic(policy)
    const ctx: PolicyAnalysisContext = { policy, deterministicResult: result }

    const prediction = await provider.predictCatastrophicPlacement(ctx)
    assert.ok(prediction.blastRadius)
    assert.ok(Array.isArray(prediction.blastRadius.affectedClusters))
    assert.ok(typeof prediction.confidence === 'number')
    assert.ok(prediction.reasoning.length > 0)
  })

  it('detectAccidentalScenarios maps from anti-pattern findings', async () => {
    const policy = makePolicy({
      disabled: true,
      remediationAction: 'enforce',
    })
    const result = analyzePolicyDeterministic(policy)
    const ctx: PolicyAnalysisContext = { policy, deterministicResult: result }

    const scenarios = await provider.detectAccidentalScenarios(ctx)
    assert.ok(scenarios.some((s) => s.id === 'ACC-013'))
  })
})

describe('analyzeWithProvider (full pipeline)', () => {
  it('produces complete PolicyAnalysisResult', async () => {
    const provider = new DeterministicOnlyProvider()
    const policy = makePolicy()
    const deterministic = analyzePolicyDeterministic(policy)

    const result = await analyzeWithProvider(policy, deterministic, provider)

    assert.equal(result.provider, 'deterministic')
    assert.ok(result.timestamp)
    assert.ok(result.deterministic === deterministic)
    assert.ok(typeof result.summary === 'string')
    assert.ok(typeof result.riskExplanation === 'string')
    assert.ok(result.catastrophicPrediction)
    assert.ok(Array.isArray(result.accidentalScenarios))
  })
})
