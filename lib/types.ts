/* Copyright Contributors to the Open Cluster Management project */

// --- Risk levels and classifications ---

export type RiskLevel = 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
export type SaturationLevel = 'GREEN' | 'YELLOW' | 'ORANGE' | 'RED'
export type DriftRisk = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
export type ComplianceState = 'Compliant' | 'NonCompliant' | 'Pending' | 'Unknown'
export type RemediationAction = 'inform' | 'enforce' | 'informOnly'
export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type ComplianceType = 'musthave' | 'mustnothave' | 'mustonlyhave'

// --- Scoring constants ---

export const VIOLATION_WEIGHTS: Record<string, number> = {
  NonCompliant: 1.0,
  Pending: 0.3,
  Unknown: 0.3,
  Compliant: 0.0,
}

export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
}

export const REMEDIATION_MODIFIERS: Record<RemediationAction, number> = {
  inform: 1.5,
  enforce: 0.8,
  informOnly: 1.0,
}

export const RISK_LEVEL_THRESHOLDS: { max: number; level: RiskLevel }[] = [
  { max: 0, level: 'NONE' },
  { max: 25, level: 'LOW' },
  { max: 50, level: 'MEDIUM' },
  { max: 75, level: 'HIGH' },
  { max: 100, level: 'CRITICAL' },
]

export const SATURATION_THRESHOLDS = {
  GREEN: { maxPolicies: 20, maxP99: 5 },
  YELLOW: { maxPolicies: 50, maxP99: 15 },
  ORANGE: { maxPolicies: 100, maxP99: 30 },
} as const

export const HEURISTIC_SATURATION = {
  ORANGE: 50,
  RED: 100,
} as const

// --- Parsed policy types ---

export interface ObjectTemplate {
  complianceType: ComplianceType
  kind: string
  apiVersion: string
  name: string
  namespace?: string
}

export interface ParsedTemplate {
  name: string
  kind: string
  severity: Severity
  remediationAction?: RemediationAction
  pruneObjectBehavior?: string
  namespaceSelector?: {
    include?: string[]
    exclude?: string[]
    matchLabels?: Record<string, string>
    matchExpressions?: { key: string; operator: string; values?: string[] }[]
  }
  objectTemplates: ObjectTemplate[]
}

export interface ClusterComplianceStatus {
  clusterName: string
  clusterNamespace: string
  compliant: ComplianceState
}

export interface ComplianceHistoryEvent {
  timestamp: string
  compliance: string
}

export interface TemplateHistory {
  templateName: string
  currentCompliance: string
  events: ComplianceHistoryEvent[]
}

export interface ComplianceHistoryEntry {
  cluster: string
  policy: string
  rootPolicy: string
  overallCompliance: string
  templateHistory: TemplateHistory[]
}

export interface ParsedPolicy {
  name: string
  namespace: string
  disabled: boolean
  remediationAction: RemediationAction
  templates: ParsedTemplate[]
  clusterStatus: ClusterComplianceStatus[]
  complianceHistory: ComplianceHistoryEntry[]
}

// --- Fleet context ---

export interface FleetContext {
  allPolicies: ParsedPolicy[]
  clusterNames: string[]
  clusterLabels?: Record<string, Record<string, string>>
}

// --- Result types ---

export interface RiskScore {
  raw: number
  normalized: number
  level: RiskLevel
}

export interface AntiPatternFinding {
  id: string
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM'
  category: string
  title: string
  description: string
  affectedResource?: { kind: string; name: string; namespace?: string }
  recommendation: string
}

export interface SaturationAssessment {
  cluster: string
  policyCount: number
  reconcileP99?: number
  level: SaturationLevel
  action: string
}

export interface VelocityAssessment {
  cluster: string
  policy: string
  velocity: number
  currentState: string
  driftRisk: DriftRisk
  projection?: string
}

export interface DriftAssessment {
  velocities: VelocityAssessment[]
  highRiskCount: number
}

export interface FleetRiskAssessment {
  fleetScore: number
  fleetLevel: RiskLevel
  clusterScores: { cluster: string; score: RiskScore }[]
  riskDistribution: Record<RiskLevel, number>
  worstCluster?: { cluster: string; score: number }
  mostViolatedPolicy?: { name: string; nonCompliantCount: number }
  severityBuckets: {
    synced: number
    critical: number
    high: number
    medium: number
    low: number
    unknown: number
  }
}

export interface DeterministicResult {
  riskScores: { cluster: string; score: RiskScore }[]
  antiPatterns: AntiPatternFinding[]
  saturation: SaturationAssessment[]
  drift?: DriftAssessment
  fleetRisk?: FleetRiskAssessment
}

// --- LLM-enriched result types ---

export interface CatastrophicPrediction {
  blastRadius: {
    affectedClusters: string[]
    affectedResources: string[]
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CATASTROPHIC'
  }
  cascadingFailures: {
    trigger: string
    chain: string[]
    finalImpact: string
  }[]
  confidence: number
  reasoning: string
}

export interface AccidentalScenario {
  id: string
  title: string
  description: string
  triggerCondition: string
  likelihood: 'LOW' | 'MEDIUM' | 'HIGH'
  impact: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  interactingPolicies?: string[]
  recommendation: string
}

export interface PolicyAnalysisResult {
  deterministic: DeterministicResult
  summary?: string
  riskExplanation?: string
  catastrophicPrediction?: CatastrophicPrediction
  accidentalScenarios?: AccidentalScenario[]
  provider: string
  timestamp: string
}
