import { jest } from '@jest/globals';
import type { Pool, PoolClient } from 'pg';
import { DatabaseService } from './database.service';

describe('DatabaseService', () => {
  const fixture = () => {
    const query = jest
      .fn<(sql: string) => Promise<unknown>>()
      .mockResolvedValue({ rows: [] });
    const release = jest.fn();
    const client = { query, release } as unknown as PoolClient;
    const end = jest.fn<() => Promise<void>>().mockResolvedValue(undefined);
    const pool = { connect: async () => client, query, end } as unknown as Pool;
    return { service: new DatabaseService(pool), query, release, client, end };
  };
  it('commits on the same client and releases it', async () => {
    const f = fixture();
    await expect(
      f.service.transaction(async (client) => {
        expect(client).toBe(f.client);
        await client.query('SELECT 1');
        return 'done';
      }),
    ).resolves.toBe('done');
    expect(f.query.mock.calls.map(([sql]) => sql)).toEqual([
      'BEGIN',
      'SELECT 1',
      'COMMIT',
    ]);
    expect(f.release).toHaveBeenCalledWith(false);
  });
  it('rolls back and preserves the original failure', async () => {
    const f = fixture();
    const failure = new Error('failure');
    await expect(
      f.service.transaction(() => Promise.reject(failure)),
    ).rejects.toBe(failure);
    expect(f.query.mock.calls.map(([sql]) => sql)).toEqual([
      'BEGIN',
      'ROLLBACK',
    ]);
    expect(f.release).toHaveBeenCalledWith(false);
  });
  it('destroys the connection if rollback fails', async () => {
    const f = fixture();
    f.query
      .mockResolvedValueOnce({})
      .mockRejectedValueOnce(new Error('rollback failed'));
    await expect(
      f.service.transaction(() =>
        Promise.reject(new Error('operation failed')),
      ),
    ).rejects.toThrow('operation failed');
    expect(f.release).toHaveBeenCalledWith(true);
  });
  it('closes pool on shutdown', async () => {
    const f = fixture();
    await f.service.onApplicationShutdown();
    expect(f.end).toHaveBeenCalledTimes(1);
  });
  it('reports disabled and rejects database work', async () => {
    const service = new DatabaseService(null);
    await expect(service.readiness()).resolves.toBe('disabled');
    expect(() => service.query('SELECT 1')).toThrow('DATABASE_NOT_CONFIGURED');
  });
});
