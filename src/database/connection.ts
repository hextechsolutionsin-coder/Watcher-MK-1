/**
 * PostgreSQL Connection Pool
 *
 * Single shared connection pool used by all database operations.
 * Reads connection config from environment variables.
 */

import pg from 'pg';

const { Pool } = pg;

export interface DbConfig {
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
  ssl: boolean;
  max: number; // max pool connections
}

function getConfig(): DbConfig {
  return {
    host: process.env['DB_HOST'] ?? 'localhost',
    port: parseInt(process.env['DB_PORT'] ?? '5432', 10),
    database: process.env['DB_NAME'] ?? 'watcher_mk1',
    user: process.env['DB_USER'] ?? 'watcher',
    password: process.env['DB_PASSWORD'] ?? 'watcher',
    ssl: process.env['DB_SSL'] === 'true',
    max: parseInt(process.env['DB_POOL_MAX'] ?? '20', 10),
  };
}

let pool: pg.Pool | null = null;

/**
 * Gets or creates the shared connection pool.
 * Call this from any module that needs database access.
 */
export function getPool(): pg.Pool {
  if (!pool) {
    const config = getConfig();
    pool = new Pool({
      host: config.host,
      port: config.port,
      database: config.database,
      user: config.user,
      password: config.password,
      ssl: config.ssl ? { rejectUnauthorized: false } : false,
      max: config.max,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 5_000,
    });

    pool.on('error', (err) => {
      console.error('[DB] Unexpected pool error:', err.message);
    });

    console.log(`[DB] Pool created: ${config.host}:${config.port}/${config.database} (max: ${config.max})`);
  }

  return pool;
}

/**
 * Runs a query against the pool.
 * Convenience wrapper for simple queries.
 */
export async function query<T extends pg.QueryResultRow = pg.QueryResultRow>(
  text: string,
  params?: unknown[]
): Promise<pg.QueryResult<T>> {
  return getPool().query<T>(text, params);
}

/**
 * Closes the pool. Call on server shutdown.
 */
export async function closePool(): Promise<void> {
  if (pool) {
    await pool.end();
    pool = null;
    console.log('[DB] Pool closed');
  }
}

/**
 * Tests the database connection.
 * Returns true if connected, false otherwise.
 */
export async function testConnection(): Promise<boolean> {
  try {
    const result = await query('SELECT NOW() as now');
    console.log(`[DB] Connected successfully at ${result.rows[0]?.now}`);
    return true;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[DB] Connection failed: ${message}`);
    return false;
  }
}
