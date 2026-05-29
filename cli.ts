#!/usr/bin/env tsx
/* Copyright Contributors to the Open Cluster Management project */

import { readFileSync } from 'node:fs'
import { analyzeRawPolicy } from './lib/index'
import type { RawPolicy } from './lib/index'
import { analyzeWithProvider } from './providers/provider'
import { createProvider } from './providers/factory'
import type { ProviderType } from './providers/factory'

function readStdin(): string {
  return readFileSync('/dev/stdin', 'utf-8')
}

function parseArgs(args: string[]): { filePath?: string; provider?: ProviderType } {
  let filePath: string | undefined
  let provider: ProviderType | undefined

  for (const arg of args) {
    if (arg.startsWith('--provider=')) {
      provider = arg.split('=')[1] as ProviderType
    } else if (!arg.startsWith('--')) {
      filePath = arg
    }
  }

  return { filePath, provider }
}

async function main() {
  const { filePath, provider: providerType } = parseArgs(process.argv.slice(2))

  let input: string
  if (filePath) {
    input = readFileSync(filePath, 'utf-8')
  } else {
    input = readStdin()
  }

  const raw = JSON.parse(input) as RawPolicy | { items: RawPolicy[] }

  let policy: RawPolicy
  let allPolicies: RawPolicy[] | undefined

  if ('items' in raw) {
    if (raw.items.length === 0) {
      console.error('No policies found in input.')
      process.exit(1)
    }
    const rootPolicies = raw.items.filter(
      (p) => !p.metadata.labels?.['policy.open-cluster-management.io/root-policy']
    )
    policy = rootPolicies[0] ?? raw.items[0]
    allPolicies = raw.items
    console.error(`Analyzing "${policy.metadata.name}" (${rootPolicies.length} root policies, ${raw.items.length} total)`)
  } else {
    policy = raw
    console.error(`Analyzing "${policy.metadata.name}"`)
  }

  const { parsed, result } = analyzeRawPolicy(policy, allPolicies)

  const analysisProvider = await createProvider({ provider: providerType })
  console.error(`Provider: ${analysisProvider.name}`)

  const fullResult = await analyzeWithProvider(parsed, result, analysisProvider)

  const output = {
    policy: { name: parsed.name, namespace: parsed.namespace, disabled: parsed.disabled },
    provider: fullResult.provider,
    riskScores: result.riskScores,
    antiPatterns: result.antiPatterns,
    saturation: result.saturation,
    drift: result.drift,
    fleetRisk: result.fleetRisk ? {
      fleetScore: result.fleetRisk.fleetScore,
      fleetLevel: result.fleetRisk.fleetLevel,
      worstCluster: result.fleetRisk.worstCluster,
      mostViolatedPolicy: result.fleetRisk.mostViolatedPolicy,
      severityBuckets: result.fleetRisk.severityBuckets,
      riskDistribution: result.fleetRisk.riskDistribution,
    } : undefined,
    summary: fullResult.summary,
    riskExplanation: fullResult.riskExplanation,
    catastrophicPrediction: fullResult.catastrophicPrediction,
    accidentalScenarios: fullResult.accidentalScenarios,
  }

  console.log(JSON.stringify(output, null, 2))
}

main()
