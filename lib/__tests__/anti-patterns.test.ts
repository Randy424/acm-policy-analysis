import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { runAntiPatterns } from '../anti-patterns'
import type { ParsedPolicy, FleetContext } from '../types'

function makePolicy(overrides: Partial<ParsedPolicy> = {}): ParsedPolicy {
  return {
    name: 'test-policy',
    namespace: 'default',
    disabled: false,
    remediationAction: 'inform',
    templates: [],
    clusterStatus: [],
    complianceHistory: [],
    ...overrides,
  }
}

// ========================
// Existing rules AP-001–007
// ========================

describe('AP-001: Operator-managed resource', () => {
  it('detects ConfigMap in openshift-* namespace', () => {
    const policy = makePolicy({
      templates: [{
        name: 'cfg', kind: 'ConfigurationPolicy', severity: 'high',
        objectTemplates: [{
          complianceType: 'musthave', kind: 'ConfigMap', apiVersion: 'v1',
          name: 'cluster-monitoring-config', namespace: 'openshift-monitoring',
        }],
      }],
    })
    const findings = runAntiPatterns(policy)
    assert.ok(findings.some((f) => f.id === 'AP-001'))
  })

  it('ignores non-openshift namespaces', () => {
    const policy = makePolicy({
      templates: [{
        name: 'cfg', kind: 'ConfigurationPolicy', severity: 'high',
        objectTemplates: [{
          complianceType: 'musthave', kind: 'ConfigMap', apiVersion: 'v1',
          name: 'my-config', namespace: 'my-app',
        }],
      }],
    })
    const findings = runAntiPatterns(policy)
    assert.ok(!findings.some((f) => f.id === 'AP-001'))
  })
})

describe('AP-002: Destructive prune', () => {
  it('detects DeleteAll + enforce', () => {
    const policy = makePolicy({
      remediationAction: 'enforce',
      templates: [{
        name: 'cfg', kind: 'ConfigurationPolicy', severity: 'high',
        pruneObjectBehavior: 'DeleteAll',
        objectTemplates: [{ complianceType: 'musthave', kind: 'ConfigMap', apiVersion: 'v1', name: 'x' }],
      }],
    })
    const findings = runAntiPatterns(policy)
    assert.ok(findings.some((f) => f.id === 'AP-002'))
  })

  it('ignores DeleteAll + inform', () => {
    const policy = makePolicy({
      remediationAction: 'inform',
      templates: [{
        name: 'cfg', kind: 'ConfigurationPolicy', severity: 'high',
        pruneObjectBehavior: 'DeleteAll',
        objectTemplates: [{ complianceType: 'musthave', kind: 'ConfigMap', apiVersion: 'v1', name: 'x' }],
      }],
    })
    const findings = runAntiPatterns(policy)
    assert.ok(!findings.some((f) => f.id === 'AP-002'))
  })
})

describe('AP-003: Active deletion', () => {
  it('detects mustnothave + enforce', () => {
    const policy = makePolicy({
      remediationAction: 'enforce',
      templates: [{
        name: 'cfg', kind: 'ConfigurationPolicy', severity: 'high',
        objectTemplates: [{
          complianceType: 'mustnothave', kind: 'Secret', apiVersion: 'v1', name: 'old-secret',
        }],
      }],
    })
    const findings = runAntiPatterns(policy)
    assert.ok(findings.some((f) => f.id === 'AP-003'))
  })
})

describe('AP-006: Enforce without inform', () => {
  it('detects root-level enforce with no template overrides', () => {
    const policy = makePolicy({
      remediationAction: 'enforce',
      templates: [{
        name: 'cfg', kind: 'ConfigurationPolicy', severity: 'high',
        objectTemplates: [{ complianceType: 'musthave', kind: 'ConfigMap', apiVersion: 'v1', name: 'x' }],
      }],
    })
    const findings = runAntiPatterns(policy)
    assert.ok(findings.some((f) => f.id === 'AP-006'))
  })

  it('skips if template has its own remediationAction', () => {
    const policy = makePolicy({
      remediationAction: 'enforce',
      templates: [{
        name: 'cfg', kind: 'ConfigurationPolicy', severity: 'high',
        remediationAction: 'inform',
        objectTemplates: [{ complianceType: 'musthave', kind: 'ConfigMap', apiVersion: 'v1', name: 'x' }],
      }],
    })
    const findings = runAntiPatterns(policy)
    assert.ok(!findings.some((f) => f.id === 'AP-006'))
  })
})

describe('AP-007: Mixed severity', () => {
  it('detects mixed severity across templates', () => {
    const policy = makePolicy({
      templates: [
        { name: 'cfg1', kind: 'ConfigurationPolicy', severity: 'critical', objectTemplates: [] },
        { name: 'cfg2', kind: 'ConfigurationPolicy', severity: 'low', objectTemplates: [] },
      ],
    })
    const findings = runAntiPatterns(policy)
    assert.ok(findings.some((f) => f.id === 'AP-007'))
  })

  it('skips single-template policies', () => {
    const policy = makePolicy({
      templates: [{ name: 'cfg', kind: 'ConfigurationPolicy', severity: 'critical', objectTemplates: [] }],
    })
    const findings = runAntiPatterns(policy)
    assert.ok(!findings.some((f) => f.id === 'AP-007'))
  })
})

// ==============================
// Catastrophic rules CAT-001–005
// ==============================

describe('CAT-001: Policy controller self-destruction', () => {
  it('detects enforce targeting ACM agent namespace', () => {
    const policy = makePolicy({
      remediationAction: 'enforce',
      templates: [{
        name: 'cfg', kind: 'ConfigurationPolicy', severity: 'high',
        namespaceSelector: { include: ['open-cluster-management-agent'] },
        objectTemplates: [{ complianceType: 'musthave', kind: 'ConfigMap', apiVersion: 'v1', name: 'x' }],
      }],
    })
    const findings = runAntiPatterns(policy)
    assert.ok(findings.some((f) => f.id === 'CAT-001'))
  })

  it('detects mustnothave on ClusterRole with enforce', () => {
    const policy = makePolicy({
      remediationAction: 'enforce',
      templates: [{
        name: 'cfg', kind: 'ConfigurationPolicy', severity: 'high',
        objectTemplates: [{
          complianceType: 'mustnothave', kind: 'ClusterRole', apiVersion: 'rbac.authorization.k8s.io/v1', name: 'admin',
        }],
      }],
    })
    const findings = runAntiPatterns(policy)
    assert.ok(findings.some((f) => f.id === 'CAT-001'))
  })
})

describe('CAT-002: Cascading CRD deletion', () => {
  it('detects mustnothave on CRD with enforce', () => {
    const policy = makePolicy({
      remediationAction: 'enforce',
      templates: [{
        name: 'cfg', kind: 'ConfigurationPolicy', severity: 'critical',
        objectTemplates: [{
          complianceType: 'mustnothave', kind: 'CustomResourceDefinition',
          apiVersion: 'apiextensions.k8s.io/v1', name: 'widgets.example.com',
        }],
      }],
    })
    const findings = runAntiPatterns(policy)
    assert.ok(findings.some((f) => f.id === 'CAT-002'))
  })
})

describe('CAT-003: System namespace infection', () => {
  it('detects mustonlyhave + enforce in kube-system', () => {
    const policy = makePolicy({
      remediationAction: 'enforce',
      templates: [{
        name: 'cfg', kind: 'ConfigurationPolicy', severity: 'high',
        objectTemplates: [{
          complianceType: 'mustonlyhave', kind: 'ConfigMap', apiVersion: 'v1',
          name: 'coredns', namespace: 'kube-system',
        }],
      }],
    })
    const findings = runAntiPatterns(policy)
    assert.ok(findings.some((f) => f.id === 'CAT-003'))
  })
})

describe('CAT-005: Unintended production targeting', () => {
  it('detects destructive enforce targeting >80% of fleet', () => {
    const policy = makePolicy({
      remediationAction: 'enforce',
      templates: [{
        name: 'cfg', kind: 'ConfigurationPolicy', severity: 'high',
        objectTemplates: [{ complianceType: 'mustnothave', kind: 'ConfigMap', apiVersion: 'v1', name: 'x' }],
      }],
      clusterStatus: [
        { clusterName: 'c1', clusterNamespace: 'c1', compliant: 'NonCompliant' },
        { clusterName: 'c2', clusterNamespace: 'c2', compliant: 'NonCompliant' },
        { clusterName: 'c3', clusterNamespace: 'c3', compliant: 'NonCompliant' },
        { clusterName: 'c4', clusterNamespace: 'c4', compliant: 'NonCompliant' },
        { clusterName: 'c5', clusterNamespace: 'c5', compliant: 'NonCompliant' },
      ],
    })
    const context: FleetContext = {
      allPolicies: [policy],
      clusterNames: ['c1', 'c2', 'c3', 'c4', 'c5'],
    }
    const findings = runAntiPatterns(policy, context)
    assert.ok(findings.some((f) => f.id === 'CAT-005'))
  })

  it('skips small fleets', () => {
    const policy = makePolicy({
      remediationAction: 'enforce',
      templates: [{
        name: 'cfg', kind: 'ConfigurationPolicy', severity: 'high',
        objectTemplates: [{ complianceType: 'mustnothave', kind: 'ConfigMap', apiVersion: 'v1', name: 'x' }],
      }],
      clusterStatus: [
        { clusterName: 'c1', clusterNamespace: 'c1', compliant: 'NonCompliant' },
        { clusterName: 'c2', clusterNamespace: 'c2', compliant: 'NonCompliant' },
      ],
    })
    const context: FleetContext = { allPolicies: [policy], clusterNames: ['c1', 'c2'] }
    const findings = runAntiPatterns(policy, context)
    assert.ok(!findings.some((f) => f.id === 'CAT-005'))
  })
})

// ============================
// Accidental rules ACC-001–013
// ============================

describe('ACC-003: Multi-policy conflict', () => {
  it('detects conflicting complianceType on same resource', () => {
    const policy = makePolicy({
      templates: [{
        name: 'cfg', kind: 'ConfigurationPolicy', severity: 'high',
        objectTemplates: [{ complianceType: 'musthave', kind: 'ConfigMap', apiVersion: 'v1', name: 'shared-config' }],
      }],
    })
    const otherPolicy = makePolicy({
      name: 'other-policy',
      namespace: 'other-ns',
      templates: [{
        name: 'cfg2', kind: 'ConfigurationPolicy', severity: 'high',
        objectTemplates: [{ complianceType: 'mustnothave', kind: 'ConfigMap', apiVersion: 'v1', name: 'shared-config' }],
      }],
    })
    const context: FleetContext = { allPolicies: [policy, otherPolicy], clusterNames: [] }
    const findings = runAntiPatterns(policy, context)
    assert.ok(findings.some((f) => f.id === 'ACC-003'))
  })
})

describe('ACC-004: Namespace deletion', () => {
  it('detects mustnothave + enforce on Namespace', () => {
    const policy = makePolicy({
      remediationAction: 'enforce',
      templates: [{
        name: 'cfg', kind: 'ConfigurationPolicy', severity: 'critical',
        objectTemplates: [{
          complianceType: 'mustnothave', kind: 'Namespace', apiVersion: 'v1', name: 'my-app',
        }],
      }],
    })
    const findings = runAntiPatterns(policy)
    assert.ok(findings.some((f) => f.id === 'ACC-004'))
  })
})

describe('ACC-013: Disabled enforce policy', () => {
  it('detects disabled policy with enforce', () => {
    const policy = makePolicy({
      disabled: true,
      remediationAction: 'enforce',
    })
    const findings = runAntiPatterns(policy)
    assert.ok(findings.some((f) => f.id === 'ACC-013'))
  })

  it('skips disabled inform policy', () => {
    const policy = makePolicy({
      disabled: true,
      remediationAction: 'inform',
    })
    const findings = runAntiPatterns(policy)
    assert.ok(!findings.some((f) => f.id === 'ACC-013'))
  })
})

// ====================
// Result ordering
// ====================

describe('runAntiPatterns result ordering', () => {
  it('sorts findings by severity: CRITICAL first, then HIGH, then MEDIUM', () => {
    const policy = makePolicy({
      remediationAction: 'enforce',
      templates: [
        {
          name: 'cfg1', kind: 'ConfigurationPolicy', severity: 'critical',
          pruneObjectBehavior: 'DeleteAll',
          objectTemplates: [{
            complianceType: 'mustnothave', kind: 'ConfigMap', apiVersion: 'v1',
            name: 'cm', namespace: 'openshift-monitoring',
          }],
        },
        {
          name: 'cfg2', kind: 'ConfigurationPolicy', severity: 'low',
          objectTemplates: [{ complianceType: 'musthave', kind: 'Deployment', apiVersion: 'apps/v1', name: 'd' }],
        },
      ],
    })
    const findings = runAntiPatterns(policy)
    assert.ok(findings.length >= 3)

    const levels = findings.map((f) => f.riskLevel)
    const criticalIdx = levels.indexOf('CRITICAL')
    const highIdx = levels.indexOf('HIGH')
    const mediumIdx = levels.indexOf('MEDIUM')

    if (criticalIdx >= 0 && highIdx >= 0) assert.ok(criticalIdx < highIdx)
    if (highIdx >= 0 && mediumIdx >= 0) assert.ok(highIdx < mediumIdx)
  })
})
