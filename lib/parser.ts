/* Copyright Contributors to the Open Cluster Management project */

import type {
  ClusterComplianceStatus,
  ComplianceHistoryEntry,
  ComplianceState,
  ObjectTemplate,
  ParsedPolicy,
  ParsedTemplate,
  RemediationAction,
  Severity,
} from './types'

interface RawPolicyTemplate {
  objectDefinition: {
    apiVersion: string
    kind: string
    metadata: { name: string }
    spec?: {
      namespaceSelector?: {
        exclude?: string[]
        include?: string[]
        matchLabels?: Record<string, string>
        matchExpressions?: { key: string; operator: string; values?: string[] }[]
      }
      'object-templates'?: {
        complianceType: string
        objectDefinition: {
          apiVersion: string
          kind: string
          metadata: { name: string; namespace?: string }
        }
      }[]
      remediationAction?: string
      severity?: string
      pruneObjectBehavior?: string
    }
  }
}

interface RawPolicyStatusDetails {
  compliant: string
  history?: { eventName: string; lastTimestamp: string; message: string }[]
  templateMeta: { name: string }
}

/**
 * Raw Policy type matching the console's Policy interface.
 * Accepts the JSON shape from both `oc get policy -o json` and the console's Recoil state.
 */
export interface RawPolicy {
  apiVersion: string
  kind: string
  metadata: {
    name: string
    namespace: string
    labels?: Record<string, string>
  }
  spec: {
    disabled: boolean
    'policy-templates'?: RawPolicyTemplate[]
    remediationAction?: string
  }
  status?: {
    compliant?: string
    details?: RawPolicyStatusDetails[]
    placement?: { placementBinding: string; placement?: string; policySet?: string }[]
    status?: { clustername: string; clusternamespace: string; compliant?: string }[]
  }
}

function parseRemediationAction(raw?: string): RemediationAction {
  if (!raw) return 'inform'
  const lower = raw.toLowerCase()
  if (lower === 'enforce') return 'enforce'
  if (lower === 'informonly') return 'informOnly'
  return 'inform'
}

function parseSeverity(raw?: string): Severity {
  if (!raw) return 'high'
  const lower = raw.toLowerCase()
  if (lower === 'critical' || lower === 'high' || lower === 'medium' || lower === 'low') {
    return lower
  }
  return 'high'
}

function parseComplianceState(raw?: string): ComplianceState {
  if (!raw) return 'Unknown'
  if (raw === 'Compliant') return 'Compliant'
  if (raw === 'NonCompliant') return 'NonCompliant'
  if (raw === 'Pending') return 'Pending'
  return 'Unknown'
}

function parseTemplate(raw: RawPolicyTemplate): ParsedTemplate {
  const spec = raw.objectDefinition.spec
  const objectTemplates: ObjectTemplate[] = (spec?.['object-templates'] ?? []).map((ot) => ({
    complianceType: (ot.complianceType as ObjectTemplate['complianceType']) ?? 'musthave',
    kind: ot.objectDefinition?.kind ?? '',
    apiVersion: ot.objectDefinition?.apiVersion ?? '',
    name: ot.objectDefinition?.metadata?.name ?? '',
    namespace: ot.objectDefinition?.metadata?.namespace,
  }))

  return {
    name: raw.objectDefinition.metadata.name,
    kind: raw.objectDefinition.kind,
    severity: parseSeverity(spec?.severity),
    remediationAction: spec?.remediationAction ? parseRemediationAction(spec.remediationAction) : undefined,
    pruneObjectBehavior: spec?.pruneObjectBehavior,
    namespaceSelector: spec?.namespaceSelector,
    objectTemplates,
  }
}

function parseClusterStatus(raw: RawPolicy): ClusterComplianceStatus[] {
  return (raw.status?.status ?? []).map((s) => ({
    clusterName: s.clustername,
    clusterNamespace: s.clusternamespace,
    compliant: parseComplianceState(s.compliant),
  }))
}

export function parsePolicy(raw: RawPolicy): ParsedPolicy {
  return {
    name: raw.metadata.name,
    namespace: raw.metadata.namespace,
    disabled: raw.spec.disabled ?? false,
    remediationAction: parseRemediationAction(raw.spec.remediationAction),
    templates: (raw.spec['policy-templates'] ?? []).map(parseTemplate),
    clusterStatus: parseClusterStatus(raw),
    complianceHistory: [],
  }
}

function extractComplianceFromMessage(message: string): string {
  const parts = message.split(';')
  return parts[0]?.trim() ?? ''
}

/**
 * Parse propagated policies (those with the root-policy label) to extract compliance history.
 * Root policies don't carry history — only propagated copies in managed cluster namespaces do.
 */
export function parsePropagatedPolicies(rawPolicies: RawPolicy[]): ComplianceHistoryEntry[] {
  return rawPolicies
    .filter((p) => p.metadata.labels?.['policy.open-cluster-management.io/root-policy'] != null)
    .map((p) => {
      const rootPolicy = p.metadata.labels!['policy.open-cluster-management.io/root-policy']
      const cluster = p.metadata.labels?.['policy.open-cluster-management.io/cluster-name'] ?? p.metadata.namespace

      return {
        cluster,
        policy: rootPolicy.split('.').pop() ?? rootPolicy,
        rootPolicy,
        overallCompliance: p.status?.compliant ?? 'Unknown',
        templateHistory: (p.status?.details ?? []).map((d) => ({
          templateName: d.templateMeta.name,
          currentCompliance: d.compliant,
          events: (d.history ?? []).map((h) => ({
            timestamp: h.lastTimestamp,
            compliance: extractComplianceFromMessage(h.message),
          })),
        })),
      }
    })
}
