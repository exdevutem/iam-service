import {
  Inject,
  Injectable,
  ServiceUnavailableException,
} from '@nestjs/common';
import type { OnApplicationShutdown } from '@nestjs/common';
import type { Pool, PoolClient, QueryResult, QueryResultRow } from 'pg';
import { PG_POOL } from './database.constants';

@Injectable()
export class DatabaseService implements OnApplicationShutdown {
  constructor(@Inject(PG_POOL) private readonly pool: Pool | null) {}

  private requirePool(): Pool {
    if (!this.pool)
      throw new ServiceUnavailableException('DATABASE_NOT_CONFIGURED');
    return this.pool;
  }

  query<T extends QueryResultRow>(
    sql: string,
    values: unknown[] = [],
  ): Promise<QueryResult<T>> {
    return this.requirePool().query<T>(sql, values);
  }

  async transaction<T>(work: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.requirePool().connect();
    let discard = false;
    try {
      await client.query('BEGIN');
      const result = await work(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      try {
        await client.query('ROLLBACK');
      } catch {
        discard = true;
      }
      throw error;
    } finally {
      client.release(discard);
    }
  }

  async readiness(): Promise<'up' | 'down' | 'disabled'> {
    if (!this.pool) return 'disabled';
    try {
      await this.pool.query('SELECT 1');
      return 'up';
    } catch {
      return 'down';
    }
  }

  async onApplicationShutdown(): Promise<void> {
    await this.pool?.end();
  }
}
