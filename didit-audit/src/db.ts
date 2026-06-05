import pg from 'pg';

/**
 * Shared connection pool. Set DATABASE_URL in the environment.
 * Works against any Postgres, including Supabase.
 */
export const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

export type Db = pg.Pool | pg.PoolClient;
