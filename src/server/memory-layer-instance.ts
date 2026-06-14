/**
 * MemoryLayer Singleton
 *
 * Creates and exports a shared MemoryLayer instance for use by server routes.
 * Configured via environment variables (see memory-layer-config.ts).
 */

import { MemoryLayer } from '../memory/memory-layer.js';
import { loadMemoryLayerConfig } from '../memory/memory-layer-config.js';

const config = loadMemoryLayerConfig();
export const memoryLayer = new MemoryLayer(config);
