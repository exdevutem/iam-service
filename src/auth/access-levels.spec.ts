import { jest } from '@jest/globals';
import { AuthRepository } from './auth.repository';
import { DatabaseService } from '../shared/connections/database.service';

describe('Roles resolved from the authoritative member level', () => {
  it.each([
    ['trainee', 'trainee_rafael'],
    ['miembro', 'miembro_rafael'],
    ['representante', 'representante_rafael'],
    [null, null],
    ['administrador_rafael', null],
  ])(
    'maps level %s to %s without assigning administrator',
    async (level, role) => {
      const query = jest.fn(async (_sql: string, _values: unknown[]) => ({
        rows: [],
      }));
      const repo = new AuthRepository({ query } as unknown as DatabaseService);
      await repo.roles('app', 'user', level);
      expect(query).toHaveBeenCalledWith(
        expect.stringContaining("r.estado='activo'"),
        ['app', 'user', role],
      );
    },
  );
  it('replaces managed role permissions on each check and preserves separately assigned admin role', async () => {
    const query = jest.fn(async (sql: string, values: unknown[]) => {
      if (sql.includes('SELECT r.codigo'))
        return {
          rows: [
            ...(values[2] ? [{ codigo: values[2] }] : []),
            { codigo: 'administrador_rafael' },
          ],
        };
      return { rows: [{ codigo: 'members.manage' }] };
    });
    const repo = new AuthRepository({ query } as unknown as DatabaseService);
    await repo.permissions('app', 'user', 'miembro');
    expect(query).toHaveBeenLastCalledWith(expect.any(String), [
      'app',
      ['miembro_rafael', 'administrador_rafael'],
    ]);
    await repo.permissions('app', 'user', 'trainee');
    expect(query).toHaveBeenLastCalledWith(expect.any(String), [
      'app',
      ['trainee_rafael', 'administrador_rafael'],
    ]);
    await repo.permissions('app', 'user', null);
    expect(query).toHaveBeenLastCalledWith(expect.any(String), [
      'app',
      ['administrador_rafael'],
    ]);
  });
  it('excludes stale manually assigned managed roles only for Rafael', async () => {
    const query = jest.fn(async (_sql: string, _values: unknown[]) => ({
      rows: [],
    }));
    await new AuthRepository({ query } as unknown as DatabaseService).roles(
      'app',
      'user',
      'trainee',
    );
    expect(query.mock.calls[0][0]).toContain(
      "p.codigo<>'rafael' OR r.codigo NOT IN",
    );
  });
});
