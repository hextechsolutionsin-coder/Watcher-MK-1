/**
 * Configuration for the Supermemory-based Memory Layer.
 * All values are read from environment variables with sensible defaults.
 */
export interface MemoryLayerConfig {
  /** Supermemory server URL. Env: SUPERMEMORY_BASE_URL */
  baseUrl: string;
  /** API key for local instance (optional). Env: SUPERMEMORY_API_KEY */
  apiKey?: string;
  /** LLM embedding provider: openai | anthropic | ollama. Env: SUPERMEMORY_LLM_PROVIDER */
  llmProvider: string;
  /** LLM provider API key. Env: SUPERMEMORY_LLM_API_KEY */
  llmApiKey: string;
  /** Model name for embeddings (optional). Env: SUPERMEMORY_LLM_MODEL */
  llmModel?: string;
  /** Max semantic search results. Env: SUPERMEMORY_SEARCH_LIMIT */
  searchLimit: number;
  /** Per-operation timeout in milliseconds. Env: SUPERMEMORY_TIMEOUT_MS */
  timeoutMs: number;
  /** Reconnection interval in milliseconds during fallback. Env: SUPERMEMORY_RECONNECT_INTERVAL_MS */
  reconnectIntervalMs: number;
  /** Minimum relevance score for search results. Env: SUPERMEMORY_SIMILARITY_THRESHOLD */
  similarityThreshold: number;
  /** Max queued writes during fallback mode. Env: SUPERMEMORY_WRITE_QUEUE_MAX */
  writeQueueMax: number;
}

/**
 * Loads Memory Layer configuration from environment variables.
 * All SUPERMEMORY_* variables are read with documented defaults.
 */
export function loadMemoryLayerConfig(): MemoryLayerConfig {
  const env = process.env;

  return {
    baseUrl: env.SUPERMEMORY_BASE_URL || 'http://localhost:6767',
    apiKey: env.SUPERMEMORY_API_KEY || undefined,
    llmProvider: env.SUPERMEMORY_LLM_PROVIDER || 'ollama',
    llmApiKey: env.SUPERMEMORY_LLM_API_KEY || '',
    llmModel: env.SUPERMEMORY_LLM_MODEL || undefined,
    searchLimit: parseIntEnv(env.SUPERMEMORY_SEARCH_LIMIT, 10),
    timeoutMs: parseIntEnv(env.SUPERMEMORY_TIMEOUT_MS, 5000),
    reconnectIntervalMs: parseIntEnv(env.SUPERMEMORY_RECONNECT_INTERVAL_MS, 30000),
    similarityThreshold: parseFloatEnv(env.SUPERMEMORY_SIMILARITY_THRESHOLD, 0.5),
    writeQueueMax: parseIntEnv(env.SUPERMEMORY_WRITE_QUEUE_MAX, 1000),
  };
}

function parseIntEnv(value: string | undefined, defaultValue: number): number {
  if (value === undefined || value === '') return defaultValue;
  const parsed = parseInt(value, 10);
  return Number.isNaN(parsed) ? defaultValue : parsed;
}

function parseFloatEnv(value: string | undefined, defaultValue: number): number {
  if (value === undefined || value === '') return defaultValue;
  const parsed = parseFloat(value);
  return Number.isNaN(parsed) ? defaultValue : parsed;
}
