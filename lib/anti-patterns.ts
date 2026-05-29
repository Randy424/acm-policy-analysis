/* Copyright Contributors to the Open Cluster Management project */

import type { AntiPatternFinding, FleetContext, ParsedPolicy, ParsedTemplate, ObjectTemplate } from './types'

// --- Rule registry ---

interface AntiPatternRule {
  id: string
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM'
  category: string
  check: (policy: ParsedPolicy, context?: FleetContext) => AntiPatternFinding | null
}

const SYSTEM_NAMESPACES = [
  'kube-system',
  'kube-public',
  'kube-node-lease',
  'default',
  'openshift',
  'openshift-apiserver',
  'openshift-authentication',
  'openshift-config',
  'openshift-console',
  'openshift-controller-manager',
  'openshift-dns',
  'openshift-etcd',
  'openshift-image-registry',
  'openshift-ingress',
  'openshift-kube-apiserver',
  'openshift-kube-controller-manager',
  'openshift-kube-scheduler',
  'openshift-machine-api',
  'openshift-machine-config-operator',
  'openshift-monitoring',
  'openshift-multus',
  'openshift-network-operator',
  'openshift-node',
  'openshift-operators',
  'openshift-ovn-kubernetes',
  'openshift-sdn',
]

const ACM_AGENT_NAMESPACES = [
  'open-cluster-management',
  'open-cluster-management-agent',
  'open-cluster-management-agent-addon',
  'open-cluster-management-hub',
]

const CLUSTER_SCOPED_SECURITY_KINDS = ['ClusterRole', 'ClusterRoleBinding', 'SecurityContextConstraints']

function getEffectiveRemediation(policy: ParsedPolicy, template?: ParsedTemplate): string {
  return template?.remediationAction ?? policy.remediationAction
}

function isNamespaceScoped(kind: string): boolean {
  const clusterScoped = [
    'ClusterRole', 'ClusterRoleBinding', 'SecurityContextConstraints',
    'CustomResourceDefinition', 'Namespace', 'Node', 'PersistentVolume',
    'StorageClass', 'ClusterIssuer', 'MutatingWebhookConfiguration',
    'ValidatingWebhookConfiguration',
  ]
  return !clusterScoped.includes(kind)
}

function targetsSystemNamespace(ot: ObjectTemplate): boolean {
  if (!ot.namespace) return false
  return SYSTEM_NAMESPACES.some((ns) => ot.namespace === ns || ot.namespace!.startsWith('openshift-'))
}

function templateTargetsNamespace(template: ParsedTemplate, namespacePrefixes: string[]): boolean {
  if (template.namespaceSelector?.include) {
    return template.namespaceSelector.include.some((ns: string) =>
      namespacePrefixes.some((prefix: string) => ns === prefix || ns.startsWith(prefix))
    )
  }
  for (const ot of template.objectTemplates) {
    if (ot.namespace && namespacePrefixes.some((prefix: string) => ot.namespace === prefix || ot.namespace!.startsWith(prefix))) {
      return true
    }
  }
  return false
}

// ===========================
// EXISTING RULES (AP-001–007)
// ===========================

const AP001_OperatorManagedResource: AntiPatternRule = {
  id: 'AP-001',
  riskLevel: 'CRITICAL',
  category: 'resource-conflict',
  check: (policy) => {
    for (const t of policy.templates) {
      for (const ot of t.objectTemplates) {
        if (
          ot.namespace?.startsWith('openshift-') &&
          (ot.kind === 'ConfigMap' || ot.kind === 'Secret')
        ) {
          return {
            id: 'AP-001',
            riskLevel: 'CRITICAL',
            category: 'resource-conflict',
            title: 'Operator-managed resource modification',
            description: `Policy targets ${ot.kind} "${ot.name}" in ${ot.namespace}, which is likely managed by an OpenShift operator. This causes reconciliation flip-flop.`,
            affectedResource: { kind: ot.kind, name: ot.name, namespace: ot.namespace },
            recommendation: 'Use inform mode to monitor without conflicting with the operator, or verify the resource is not operator-managed.',
          }
        }
      }
    }
    return null
  },
}

const AP002_DestructivePrune: AntiPatternRule = {
  id: 'AP-002',
  riskLevel: 'CRITICAL',
  category: 'destructive',
  check: (policy) => {
    for (const t of policy.templates) {
      if (t.pruneObjectBehavior?.startsWith('Delete') && getEffectiveRemediation(policy, t) === 'enforce') {
        return {
          id: 'AP-002',
          riskLevel: 'CRITICAL',
          category: 'destructive',
          title: 'Destructive prune behavior with enforce',
          description: `Template "${t.name}" has pruneObjectBehavior="${t.pruneObjectBehavior}" with enforce. Deleting or disabling this policy will delete the managed resources.`,
          recommendation: 'Change pruneObjectBehavior to "None" unless resource cleanup on policy removal is explicitly intended.',
        }
      }
    }
    return null
  },
}

const AP003_ActiveDeletion: AntiPatternRule = {
  id: 'AP-003',
  riskLevel: 'CRITICAL',
  category: 'destructive',
  check: (policy) => {
    for (const t of policy.templates) {
      if (getEffectiveRemediation(policy, t) !== 'enforce') continue
      for (const ot of t.objectTemplates) {
        if (ot.complianceType === 'mustnothave') {
          return {
            id: 'AP-003',
            riskLevel: 'CRITICAL',
            category: 'destructive',
            title: 'Active resource deletion via mustnothave + enforce',
            description: `Policy will actively delete ${ot.kind} "${ot.name}" on targeted clusters.`,
            affectedResource: { kind: ot.kind, name: ot.name, namespace: ot.namespace },
            recommendation: 'Use inform mode to detect the resource without deleting it, unless deletion is explicitly intended.',
          }
        }
      }
    }
    return null
  },
}

const AP004_ClusterScopedSecurity: AntiPatternRule = {
  id: 'AP-004',
  riskLevel: 'HIGH',
  category: 'security',
  check: (policy) => {
    for (const t of policy.templates) {
      for (const ot of t.objectTemplates) {
        if (CLUSTER_SCOPED_SECURITY_KINDS.includes(ot.kind)) {
          return {
            id: 'AP-004',
            riskLevel: 'HIGH',
            category: 'security',
            title: 'Cluster-scoped security resource modification',
            description: `Policy targets ${ot.kind} "${ot.name}", which has cluster-wide security impact. Misconfiguration has broad blast radius.`,
            affectedResource: { kind: ot.kind, name: ot.name },
            recommendation: 'Review carefully and test in inform mode on a non-production cluster first.',
          }
        }
      }
    }
    return null
  },
}

const AP005_MissingNamespaceScoping: AntiPatternRule = {
  id: 'AP-005',
  riskLevel: 'HIGH',
  category: 'scoping',
  check: (policy) => {
    for (const t of policy.templates) {
      const hasNamespaceScopedResources = t.objectTemplates.some((ot) => isNamespaceScoped(ot.kind))
      if (hasNamespaceScopedResources && !t.namespaceSelector) {
        return {
          id: 'AP-005',
          riskLevel: 'HIGH',
          category: 'scoping',
          title: 'Missing namespace scoping for namespace-scoped resources',
          description: `Template "${t.name}" targets namespace-scoped resources without a namespaceSelector, which may apply to system namespaces.`,
          recommendation: 'Add a namespaceSelector to restrict which namespaces are affected.',
        }
      }
    }
    return null
  },
}

const AP006_EnforceWithoutInform: AntiPatternRule = {
  id: 'AP-006',
  riskLevel: 'MEDIUM',
  category: 'practice',
  check: (policy) => {
    if (policy.remediationAction !== 'enforce') return null
    const hasTemplateOverrides = policy.templates.some((t) => t.remediationAction != null)
    if (!hasTemplateOverrides) {
      return {
        id: 'AP-006',
        riskLevel: 'MEDIUM',
        category: 'practice',
        title: 'Enforce without inform trial',
        description: 'All templates enforce at root level with no template-level overrides. Consider running in inform mode first to observe impact.',
        recommendation: 'Start with remediationAction: inform to validate before switching to enforce.',
      }
    }
    return null
  },
}

const AP007_MixedSeverity: AntiPatternRule = {
  id: 'AP-007',
  riskLevel: 'MEDIUM',
  category: 'practice',
  check: (policy) => {
    if (policy.templates.length < 2) return null
    const severities = new Set(policy.templates.map((t) => t.severity))
    if (severities.size > 1) {
      return {
        id: 'AP-007',
        riskLevel: 'MEDIUM',
        category: 'practice',
        title: 'Mixed severity templates in single policy',
        description: `Policy has templates with mixed severities: ${Array.from(severities).join(', ')}. A low-severity failure may cause unnecessary alerts for the whole policy.`,
        recommendation: 'Split templates into separate policies grouped by severity level.',
      }
    }
    return null
  },
}

// =========================================
// CATASTROPHIC PLACEMENT RULES (CAT-001–005)
// =========================================

const CAT001_PolicyControllerSelfDestruction: AntiPatternRule = {
  id: 'CAT-001',
  riskLevel: 'CRITICAL',
  category: 'catastrophic-placement',
  check: (policy) => {
    for (const t of policy.templates) {
      if (getEffectiveRemediation(policy, t) !== 'enforce') continue
      if (templateTargetsNamespace(t, ACM_AGENT_NAMESPACES)) {
        return {
          id: 'CAT-001',
          riskLevel: 'CRITICAL',
          category: 'catastrophic-placement',
          title: 'Policy targets ACM agent namespace with enforce',
          description: 'Modifying resources in ACM agent namespaces can break the policy controller itself, causing managed clusters to become orphaned.',
          recommendation: 'Never enforce policies on open-cluster-management-* namespaces. Use inform mode only.',
        }
      }
      for (const ot of t.objectTemplates) {
        if (
          CLUSTER_SCOPED_SECURITY_KINDS.includes(ot.kind) &&
          ot.complianceType === 'mustnothave'
        ) {
          return {
            id: 'CAT-001',
            riskLevel: 'CRITICAL',
            category: 'catastrophic-placement',
            title: 'Policy deletes RBAC that may be required by the policy controller',
            description: `Deleting ${ot.kind} "${ot.name}" via mustnothave + enforce could remove permissions the ACM agent needs to function.`,
            affectedResource: { kind: ot.kind, name: ot.name },
            recommendation: 'Verify this RBAC resource is not used by klusterlet, work-agent, or policy-controller service accounts.',
          }
        }
      }
    }
    return null
  },
}

const CAT002_CascadingCRDDeletion: AntiPatternRule = {
  id: 'CAT-002',
  riskLevel: 'CRITICAL',
  category: 'catastrophic-placement',
  check: (policy) => {
    for (const t of policy.templates) {
      if (getEffectiveRemediation(policy, t) !== 'enforce') continue
      for (const ot of t.objectTemplates) {
        if (
          ot.kind === 'CustomResourceDefinition' &&
          (ot.complianceType === 'mustnothave' || t.pruneObjectBehavior?.startsWith('Delete'))
        ) {
          return {
            id: 'CAT-002',
            riskLevel: 'CRITICAL',
            category: 'catastrophic-placement',
            title: 'CRD deletion causes cascading resource loss',
            description: `Deleting CRD "${ot.name}" will cascade-delete all custom resources of that type across the cluster. This is irreversible.`,
            affectedResource: { kind: ot.kind, name: ot.name },
            recommendation: 'Remove CRD from policy targets. If CRD cleanup is intended, delete custom resources first, then the CRD manually.',
          }
        }
      }
    }
    return null
  },
}

const CAT003_SystemNamespaceInfection: AntiPatternRule = {
  id: 'CAT-003',
  riskLevel: 'CRITICAL',
  category: 'catastrophic-placement',
  check: (policy) => {
    for (const t of policy.templates) {
      if (getEffectiveRemediation(policy, t) !== 'enforce') continue
      for (const ot of t.objectTemplates) {
        if (
          targetsSystemNamespace(ot) &&
          (ot.complianceType === 'mustonlyhave' || ot.complianceType === 'mustnothave')
        ) {
          return {
            id: 'CAT-003',
            riskLevel: 'CRITICAL',
            category: 'catastrophic-placement',
            title: 'Enforce with mustonlyhave/mustnothave on system namespace',
            description: `Policy enforces ${ot.complianceType} on ${ot.kind} "${ot.name}" in system namespace ${ot.namespace}. This can degrade control plane services.`,
            affectedResource: { kind: ot.kind, name: ot.name, namespace: ot.namespace },
            recommendation: 'System namespaces should only be monitored with inform mode. Never use mustonlyhave or mustnothave + enforce on system resources.',
          }
        }
      }
    }
    return null
  },
}

const CAT004_OperatorFlipFlop: AntiPatternRule = {
  id: 'CAT-004',
  riskLevel: 'CRITICAL',
  category: 'catastrophic-placement',
  check: (policy) => {
    for (const t of policy.templates) {
      if (getEffectiveRemediation(policy, t) !== 'enforce') continue
      if (t.objectTemplates.some((ot) => ot.complianceType === 'mustonlyhave')) {
        for (const ot of t.objectTemplates) {
          if (ot.namespace?.startsWith('openshift-') && ot.complianceType === 'mustonlyhave') {
            return {
              id: 'CAT-004',
              riskLevel: 'CRITICAL',
              category: 'catastrophic-placement',
              title: 'mustonlyhave + enforce on operator-managed namespace risks infinite reconciliation loop',
              description: `Enforcing mustonlyhave on ${ot.kind} "${ot.name}" in ${ot.namespace} will conflict with the namespace operator, causing both to continuously overwrite each other and consuming API server throughput.`,
              affectedResource: { kind: ot.kind, name: ot.name, namespace: ot.namespace },
              recommendation: 'Use musthave instead of mustonlyhave, or switch to inform mode.',
            }
          }
        }
      }
    }
    return null
  },
}

const CAT005_UnintendedProductionTargeting: AntiPatternRule = {
  id: 'CAT-005',
  riskLevel: 'CRITICAL',
  category: 'catastrophic-placement',
  check: (policy, context) => {
    if (!context) return null

    const targetedClusters = policy.clusterStatus.map((s) => s.clusterName)
    if (targetedClusters.length === 0) return null

    const totalClusters = context.clusterNames.length
    if (totalClusters === 0) return null

    const ratio = targetedClusters.length / totalClusters
    const hasDestructiveAction = policy.templates.some((t) =>
      t.objectTemplates.some((ot) => ot.complianceType === 'mustnothave') ||
      t.pruneObjectBehavior?.startsWith('Delete')
    )
    const isEnforce = policy.remediationAction === 'enforce' ||
      policy.templates.some((t) => t.remediationAction === 'enforce')

    if (ratio > 0.8 && hasDestructiveAction && isEnforce && totalClusters > 3) {
      return {
        id: 'CAT-005',
        riskLevel: 'CRITICAL',
        category: 'catastrophic-placement',
        title: 'Destructive enforce policy targets majority of fleet',
        description: `Policy targets ${targetedClusters.length} of ${totalClusters} clusters (${Math.round(ratio * 100)}%) with destructive actions + enforce. A placement misconfiguration could cause fleet-wide damage.`,
        recommendation: 'Narrow the placement selector. Use staged rollout: deploy to a test cluster first, then expand incrementally.',
      }
    }
    return null
  },
}

// ============================================
// ACCIDENTAL SCENARIO RULES (ACC-001–013)
// ============================================

const ACC001_RBACBreakingACMAgent: AntiPatternRule = {
  id: 'ACC-001',
  riskLevel: 'HIGH',
  category: 'accidental-scenario',
  check: (policy) => {
    for (const t of policy.templates) {
      if (getEffectiveRemediation(policy, t) !== 'enforce') continue
      for (const ot of t.objectTemplates) {
        if (
          (ot.kind === 'ClusterRole' || ot.kind === 'ClusterRoleBinding') &&
          ot.complianceType === 'mustonlyhave'
        ) {
          return {
            id: 'ACC-001',
            riskLevel: 'HIGH',
            category: 'accidental-scenario',
            title: 'mustonlyhave on ClusterRole/Binding may break ACM agent',
            description: `Enforcing mustonlyhave on ${ot.kind} "${ot.name}" will overwrite all rules/subjects. If the ACM agent depends on this resource, it will lose access.`,
            affectedResource: { kind: ot.kind, name: ot.name },
            recommendation: 'Use musthave to add required rules without removing existing ones, or verify ACM agents do not use this resource.',
          }
        }
      }
    }
    return null
  },
}

const ACC002_HelmArgoCDConflict: AntiPatternRule = {
  id: 'ACC-002',
  riskLevel: 'HIGH',
  category: 'accidental-scenario',
  check: (policy) => {
    for (const t of policy.templates) {
      if (getEffectiveRemediation(policy, t) !== 'enforce') continue
      for (const ot of t.objectTemplates) {
        if (ot.kind === 'Deployment' || ot.kind === 'StatefulSet' || ot.kind === 'DaemonSet') {
          return {
            id: 'ACC-002',
            riskLevel: 'HIGH',
            category: 'accidental-scenario',
            title: 'Enforce on workload resources may conflict with Helm/ArgoCD',
            description: `Enforcing on ${ot.kind} "${ot.name}" may conflict with Helm releases or ArgoCD applications that manage the same resource, causing continuous sync conflicts.`,
            affectedResource: { kind: ot.kind, name: ot.name, namespace: ot.namespace },
            recommendation: 'Check if this resource is managed by Helm or ArgoCD before enforcing. Use inform mode if GitOps manages the resource.',
          }
        }
      }
    }
    return null
  },
}

const ACC003_MultiPolicyConflict: AntiPatternRule = {
  id: 'ACC-003',
  riskLevel: 'HIGH',
  category: 'accidental-scenario',
  check: (policy, context) => {
    if (!context) return null

    for (const t of policy.templates) {
      for (const ot of t.objectTemplates) {
        for (const other of context.allPolicies) {
          if (other.name === policy.name && other.namespace === policy.namespace) continue

          for (const otherT of other.templates) {
            for (const otherOt of otherT.objectTemplates) {
              if (otherOt.kind === ot.kind && otherOt.name === ot.name) {
                if (ot.complianceType !== otherOt.complianceType) {
                  return {
                    id: 'ACC-003',
                    riskLevel: 'HIGH',
                    category: 'accidental-scenario',
                    title: 'Conflicting policies on same resource',
                    description: `This policy uses ${ot.complianceType} on ${ot.kind} "${ot.name}", but policy "${other.name}" uses ${otherOt.complianceType} on the same resource. These will conflict.`,
                    affectedResource: { kind: ot.kind, name: ot.name, namespace: ot.namespace },
                    recommendation: 'Resolve the conflict by aligning complianceType across policies or removing the duplicate target.',
                  }
                }
              }
            }
          }
        }
      }
    }
    return null
  },
}

const ACC004_NamespaceDeletion: AntiPatternRule = {
  id: 'ACC-004',
  riskLevel: 'CRITICAL',
  category: 'accidental-scenario',
  check: (policy) => {
    for (const t of policy.templates) {
      if (getEffectiveRemediation(policy, t) !== 'enforce') continue
      for (const ot of t.objectTemplates) {
        if (ot.kind === 'Namespace' && ot.complianceType === 'mustnothave') {
          return {
            id: 'ACC-004',
            riskLevel: 'CRITICAL',
            category: 'accidental-scenario',
            title: 'Policy deletes entire namespace',
            description: `Enforcing mustnothave on Namespace "${ot.name}" will delete the namespace and all resources within it.`,
            affectedResource: { kind: 'Namespace', name: ot.name },
            recommendation: 'This is almost never intentional. Remove the namespace target or switch to inform mode.',
          }
        }
      }
    }
    return null
  },
}

const ACC005_WebhookModification: AntiPatternRule = {
  id: 'ACC-005',
  riskLevel: 'HIGH',
  category: 'accidental-scenario',
  check: (policy) => {
    for (const t of policy.templates) {
      for (const ot of t.objectTemplates) {
        if (
          ot.kind === 'ValidatingWebhookConfiguration' ||
          ot.kind === 'MutatingWebhookConfiguration'
        ) {
          return {
            id: 'ACC-005',
            riskLevel: 'HIGH',
            category: 'accidental-scenario',
            title: 'Policy modifies admission webhook configuration',
            description: `Modifying ${ot.kind} "${ot.name}" can break admission control. If the webhook becomes unavailable, requests may be silently admitted or rejected.`,
            affectedResource: { kind: ot.kind, name: ot.name },
            recommendation: 'Webhook configurations are security-critical. Test in inform mode and verify webhook availability after any change.',
          }
        }
      }
    }
    return null
  },
}

const ACC006_PlacementCreep: AntiPatternRule = {
  id: 'ACC-006',
  riskLevel: 'MEDIUM',
  category: 'accidental-scenario',
  check: (policy, context) => {
    if (!context) return null

    const targetedClusters = policy.clusterStatus.map((s) => s.clusterName)
    const totalClusters = context.clusterNames.length

    if (totalClusters > 5 && targetedClusters.length === totalClusters) {
      return {
        id: 'ACC-006',
        riskLevel: 'MEDIUM',
        category: 'accidental-scenario',
        title: 'Policy targets all clusters in fleet',
        description: `Policy targets all ${totalClusters} clusters. This may indicate an overly broad placement selector that will automatically include new clusters as they join.`,
        recommendation: 'Use explicit label selectors to control which clusters are targeted. Consider excluding production clusters from broad policies.',
      }
    }
    return null
  },
}

const ACC007_NetworkPolicySystemNs: AntiPatternRule = {
  id: 'ACC-007',
  riskLevel: 'HIGH',
  category: 'accidental-scenario',
  check: (policy) => {
    for (const t of policy.templates) {
      if (getEffectiveRemediation(policy, t) !== 'enforce') continue
      for (const ot of t.objectTemplates) {
        if (ot.kind === 'NetworkPolicy' && targetsSystemNamespace(ot)) {
          return {
            id: 'ACC-007',
            riskLevel: 'HIGH',
            category: 'accidental-scenario',
            title: 'NetworkPolicy enforced on system namespace',
            description: `Enforcing NetworkPolicy "${ot.name}" in ${ot.namespace} can block control plane communication (DNS, API server, kubelet).`,
            affectedResource: { kind: ot.kind, name: ot.name, namespace: ot.namespace },
            recommendation: 'System namespaces typically require unrestricted internal networking. Remove the system namespace from the target scope.',
          }
        }
      }
    }
    return null
  },
}

const ACC008_SCCModification: AntiPatternRule = {
  id: 'ACC-008',
  riskLevel: 'HIGH',
  category: 'accidental-scenario',
  check: (policy) => {
    for (const t of policy.templates) {
      if (getEffectiveRemediation(policy, t) !== 'enforce') continue
      for (const ot of t.objectTemplates) {
        if (ot.kind === 'SecurityContextConstraints' && ot.complianceType === 'mustonlyhave') {
          return {
            id: 'ACC-008',
            riskLevel: 'HIGH',
            category: 'accidental-scenario',
            title: 'mustonlyhave on SCC may break workloads',
            description: `Enforcing mustonlyhave on SecurityContextConstraints "${ot.name}" will overwrite all settings. Workloads depending on specific SCC fields may fail to schedule.`,
            affectedResource: { kind: ot.kind, name: ot.name },
            recommendation: 'Use musthave to ensure required fields are present without removing others.',
          }
        }
      }
    }
    return null
  },
}

const ACC009_LimitRangeConflict: AntiPatternRule = {
  id: 'ACC-009',
  riskLevel: 'MEDIUM',
  category: 'accidental-scenario',
  check: (policy) => {
    for (const t of policy.templates) {
      if (getEffectiveRemediation(policy, t) !== 'enforce') continue
      for (const ot of t.objectTemplates) {
        if ((ot.kind === 'LimitRange' || ot.kind === 'ResourceQuota') && !t.namespaceSelector) {
          return {
            id: 'ACC-009',
            riskLevel: 'MEDIUM',
            category: 'accidental-scenario',
            title: 'LimitRange/ResourceQuota without namespace scoping',
            description: `Enforcing ${ot.kind} "${ot.name}" without a namespaceSelector applies to all namespaces, including system namespaces where it may prevent pods from scheduling.`,
            affectedResource: { kind: ot.kind, name: ot.name },
            recommendation: 'Add a namespaceSelector to exclude system namespaces.',
          }
        }
      }
    }
    return null
  },
}

const ACC010_PodSecuritySystemNs: AntiPatternRule = {
  id: 'ACC-010',
  riskLevel: 'HIGH',
  category: 'accidental-scenario',
  check: (policy) => {
    for (const t of policy.templates) {
      if (getEffectiveRemediation(policy, t) !== 'enforce') continue
      for (const ot of t.objectTemplates) {
        if (
          (ot.kind === 'PodSecurityPolicy' || ot.kind === 'Pod') &&
          targetsSystemNamespace(ot)
        ) {
          return {
            id: 'ACC-010',
            riskLevel: 'HIGH',
            category: 'accidental-scenario',
            title: 'Pod security enforcement on system namespace',
            description: `Enforcing ${ot.kind} constraints in ${ot.namespace} may prevent control plane pods from running.`,
            affectedResource: { kind: ot.kind, name: ot.name, namespace: ot.namespace },
            recommendation: 'Exclude system namespaces from pod security enforcement.',
          }
        }
      }
    }
    return null
  },
}

const ACC011_StorageClassDeletion: AntiPatternRule = {
  id: 'ACC-011',
  riskLevel: 'HIGH',
  category: 'accidental-scenario',
  check: (policy) => {
    for (const t of policy.templates) {
      if (getEffectiveRemediation(policy, t) !== 'enforce') continue
      for (const ot of t.objectTemplates) {
        if (ot.kind === 'StorageClass' && ot.complianceType === 'mustnothave') {
          return {
            id: 'ACC-011',
            riskLevel: 'HIGH',
            category: 'accidental-scenario',
            title: 'StorageClass deletion affects persistent volumes',
            description: `Deleting StorageClass "${ot.name}" prevents new PersistentVolumeClaims from being provisioned and may affect existing volumes depending on reclaim policy.`,
            affectedResource: { kind: ot.kind, name: ot.name },
            recommendation: 'Verify no PVCs depend on this StorageClass before deleting it.',
          }
        }
      }
    }
    return null
  },
}

const ACC012_IngressModification: AntiPatternRule = {
  id: 'ACC-012',
  riskLevel: 'MEDIUM',
  category: 'accidental-scenario',
  check: (policy) => {
    for (const t of policy.templates) {
      if (getEffectiveRemediation(policy, t) !== 'enforce') continue
      for (const ot of t.objectTemplates) {
        if (
          (ot.kind === 'IngressController' || ot.kind === 'Ingress') &&
          ot.namespace?.startsWith('openshift-')
        ) {
          return {
            id: 'ACC-012',
            riskLevel: 'MEDIUM',
            category: 'accidental-scenario',
            title: 'Ingress modification in system namespace',
            description: `Modifying ${ot.kind} "${ot.name}" in ${ot.namespace} can break cluster ingress routing.`,
            affectedResource: { kind: ot.kind, name: ot.name, namespace: ot.namespace },
            recommendation: 'Use inform mode to monitor ingress configuration without risking routing disruption.',
          }
        }
      }
    }
    return null
  },
}

const ACC013_DisabledPolicyEnforce: AntiPatternRule = {
  id: 'ACC-013',
  riskLevel: 'MEDIUM',
  category: 'accidental-scenario',
  check: (policy) => {
    if (policy.disabled && policy.remediationAction === 'enforce') {
      return {
        id: 'ACC-013',
        riskLevel: 'MEDIUM',
        category: 'accidental-scenario',
        title: 'Disabled enforce policy is a latent risk',
        description: 'This policy is disabled but set to enforce. Enabling it will immediately begin enforcement without an inform trial period.',
        recommendation: 'Change remediationAction to inform before enabling, then switch to enforce after validating.',
      }
    }
    return null
  },
}

// --- Rule registry ---

const ALL_RULES: AntiPatternRule[] = [
  // Existing (AP-001 through AP-007)
  AP001_OperatorManagedResource,
  AP002_DestructivePrune,
  AP003_ActiveDeletion,
  AP004_ClusterScopedSecurity,
  AP005_MissingNamespaceScoping,
  AP006_EnforceWithoutInform,
  AP007_MixedSeverity,
  // Catastrophic placement (CAT-001 through CAT-005)
  CAT001_PolicyControllerSelfDestruction,
  CAT002_CascadingCRDDeletion,
  CAT003_SystemNamespaceInfection,
  CAT004_OperatorFlipFlop,
  CAT005_UnintendedProductionTargeting,
  // Accidental scenarios (ACC-001 through ACC-013)
  ACC001_RBACBreakingACMAgent,
  ACC002_HelmArgoCDConflict,
  ACC003_MultiPolicyConflict,
  ACC004_NamespaceDeletion,
  ACC005_WebhookModification,
  ACC006_PlacementCreep,
  ACC007_NetworkPolicySystemNs,
  ACC008_SCCModification,
  ACC009_LimitRangeConflict,
  ACC010_PodSecuritySystemNs,
  ACC011_StorageClassDeletion,
  ACC012_IngressModification,
  ACC013_DisabledPolicyEnforce,
]

export function runAntiPatterns(policy: ParsedPolicy, context?: FleetContext): AntiPatternFinding[] {
  const findings: AntiPatternFinding[] = []
  for (const rule of ALL_RULES) {
    const finding = rule.check(policy, context)
    if (finding) findings.push(finding)
  }
  return findings.sort((a, b) => {
    const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2 }
    return order[a.riskLevel] - order[b.riskLevel]
  })
}
