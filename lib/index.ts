/* Copyright Contributors to the Open Cluster Management project */

export { analyzePolicyDeterministic, analyzeRawPolicy } from './analyze'
export type { AnalysisOptions } from './analyze'
export { runAntiPatterns } from './anti-patterns'
export { parsePolicy, parsePropagatedPolicies } from './parser'
export type { RawPolicy } from './parser'
export {
  assessDrift,
  assessSaturation,
  calculateClusterRiskScore,
  calculateComplianceVelocity,
  calculateFleetRisk,
  calculatePolicyRiskContribution,
  classifyRiskLevel,
} from './scoring'
export type {
  AccidentalScenario,
  AntiPatternFinding,
  CatastrophicPrediction,
  ClusterComplianceStatus,
  ComplianceHistoryEntry,
  ComplianceHistoryEvent,
  ComplianceState,
  ComplianceType,
  DeterministicResult,
  DriftAssessment,
  DriftRisk,
  FleetContext,
  FleetRiskAssessment,
  ObjectTemplate,
  ParsedPolicy,
  ParsedTemplate,
  PolicyAnalysisResult,
  StructuredAccidentalScenario,
  StructuredAnalysis,
  StructuredCatastrophicAssessment,
  StructuredRisk,
  RemediationAction,
  RiskLevel,
  RiskScore,
  SaturationAssessment,
  SaturationLevel,
  Severity,
  TemplateHistory,
  VelocityAssessment,
} from './types'
export {
  HEURISTIC_SATURATION,
  REMEDIATION_MODIFIERS,
  RISK_LEVEL_THRESHOLDS,
  SATURATION_THRESHOLDS,
  SEVERITY_WEIGHTS,
  VIOLATION_WEIGHTS,
} from './types'
