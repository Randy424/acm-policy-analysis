/* Copyright Contributors to the Open Cluster Management project */

import { ClaudeProvider } from './claude'
import type { ClaudeProviderConfig } from './claude'
import { DeterministicOnlyProvider } from './deterministic'
import { OllamaProvider } from './ollama'
import type { OllamaProviderConfig } from './ollama'
import type { PolicyAnalysisProvider } from './provider'

export type ProviderType = 'claude' | 'ollama' | 'deterministic' | 'auto'

export interface ProviderConfig {
  provider?: ProviderType
  claude?: ClaudeProviderConfig
  ollama?: OllamaProviderConfig
}

/**
 * Create a provider by name or auto-detect the best available one.
 *
 * Auto-detection order: Claude (if API key set) → Ollama (if reachable) → Deterministic.
 */
export async function createProvider(config?: ProviderConfig): Promise<PolicyAnalysisProvider> {
  const providerType = config?.provider ?? (process.env.POLICY_ANALYSIS_PROVIDER as ProviderType) ?? 'auto'

  if (providerType === 'deterministic') {
    return new DeterministicOnlyProvider()
  }

  if (providerType === 'claude') {
    return new ClaudeProvider(config?.claude)
  }

  if (providerType === 'ollama') {
    return new OllamaProvider(config?.ollama)
  }

  // Auto-detect
  const claude = new ClaudeProvider(config?.claude)
  if (await claude.isAvailable()) return claude

  const ollama = new OllamaProvider(config?.ollama)
  if (await ollama.isAvailable()) return ollama

  return new DeterministicOnlyProvider()
}
