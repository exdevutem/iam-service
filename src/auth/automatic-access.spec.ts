import { jest } from '@jest/globals';
import { ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service';
import { AuthRepository } from './auth.repository';
import { AuthSettings } from './auth.settings';
import {
  GoogleIdentityService,
  institutionalIdentity,
} from './google-identity.service';
import { ApplicationPolicyService } from '../applications/application-policy.service';
import { DatabaseService } from '../shared/connections/database.service';
import { randomToken, seal } from './token-protection';

const key = Buffer.alloc(32, 9);
const userId = '1236638c-55ab-441b-8e06-49d185573c35';
const claims = {
  iss: 'https://accounts.google.com',
  sub: 'google-subject',
  email: 'Member@utem.cl',
  email_verified: true,
  hd: 'utem.cl',
};

function fixture() {
  const settings = new AuthSettings(
    new ConfigService({
      AUTH_ORIGIN: 'http://localhost:3002',
      AUTH_SECRET_BASE64: key.toString('base64'),
    }),
  );
  const repository = {
    consumeLogin: jest.fn(async () => ({
      id: 'tx',
      nonce: 'nonce',
      protection_key_version: 1,
      pkce_verifier_protected: seal(randomToken(), key, 'app:tx'),
    })),
    findIdentity: jest.fn(
      async (): Promise<{ user_id: string; estado: string } | undefined> =>
        undefined,
    ),
    recordIdentity: jest.fn(async () => userId),
    checkAutomaticAccess: jest.fn(async () => {}),
    enableRafaelAccess: jest.fn(async () => {}),
    issueSession: jest.fn(async () => 'session'),
  };
  const policies = {
    application: jest.fn(async () => ({ id: 'app', codigo: 'rafael' })),
    eligible: jest.fn(async () => null),
    linkRafaelMember: jest.fn(async () => ({
      id: '1',
      iam_subject: userId,
      estado: 'activo',
    })),
    activeMember: jest.fn(async () => ({
      id: '1',
      iam_subject: userId,
      estado: 'activo',
    })),
  };
  const google = {
    exchange: jest.fn(async () => institutionalIdentity(claims)),
  };
  const service = new AuthService(
    settings,
    repository as unknown as AuthRepository,
    google as unknown as GoogleIdentityService,
    policies as unknown as ApplicationPolicyService,
  );
  const login = () =>
    service.callback(
      new URLSearchParams({ state: randomToken(), code: 'code' }),
      randomToken(),
    );
  return { repository, policies, google, login };
}

describe('Rafael automatic admission', () => {
  it('links with internal UUID after Google verification and issues a session without assigning roles', async () => {
    const f = fixture();
    expect((await f.login()).pending).toBe(false);
    expect(f.policies.linkRafaelMember).toHaveBeenCalledWith(
      'member@utem.cl',
      userId,
    );
    expect(f.google.exchange.mock.invocationCallOrder[0]).toBeLessThan(
      f.policies.linkRafaelMember.mock.invocationCallOrder[0],
    );
    expect(
      f.repository.enableRafaelAccess.mock.invocationCallOrder[0],
    ).toBeLessThan(f.repository.issueSession.mock.invocationCallOrder[0]);
  });
  it('completes an identity left pending by the previous flow', async () => {
    const f = fixture();
    f.repository.findIdentity.mockResolvedValue({
      user_id: userId,
      estado: 'habilitado',
    });
    expect((await f.login()).pending).toBe(false);
    expect(f.repository.enableRafaelAccess).toHaveBeenCalledWith('app', userId);
  });
  it('can repeat and process two independent verified callbacks', async () => {
    const f = fixture();
    await f.login();
    const results = await Promise.all([f.login(), f.login()]);
    expect(results.every((r) => !r.pending)).toBe(true);
    expect(
      f.policies.linkRafaelMember.mock.calls.every(
        (args) => args[1] === userId,
      ),
    ).toBe(true);
  });
  it.each(['missing', 'inactive', 'conflicting UUID', 'ambiguous email'])(
    'never emits a session for a %s member',
    async () => {
      const f = fixture();
      f.policies.linkRafaelMember.mockRejectedValue(
        new Error('ACCESS_NOT_ENABLED'),
      );
      await expect(f.login()).rejects.toThrow('ACCESS_NOT_ENABLED');
      expect(f.repository.enableRafaelAccess).not.toHaveBeenCalled();
      expect(f.repository.issueSession).not.toHaveBeenCalled();
    },
  );
  it.each([{ email_verified: false }, { email: 'member@gmail.com' }])(
    'rejects invalid Google claims %j',
    async (change) => {
      const f = fixture();
      f.google.exchange.mockImplementation(async () =>
        institutionalIdentity({ ...claims, ...change }),
      );
      await expect(f.login()).rejects.toThrow();
      expect(f.repository.recordIdentity).not.toHaveBeenCalled();
      expect(f.policies.linkRafaelMember).not.toHaveBeenCalled();
    },
  );
  it('does not provision a suspended user', async () => {
    const f = fixture();
    f.repository.findIdentity.mockResolvedValue({
      user_id: userId,
      estado: 'suspendido',
    });
    await expect(f.login()).rejects.toThrow('ACCESS_NOT_ENABLED');
    expect(f.policies.linkRafaelMember).not.toHaveBeenCalled();
  });
  it('does not provision suspended access', async () => {
    const f = fixture();
    f.repository.checkAutomaticAccess.mockRejectedValue(
      new Error('ACCESS_NOT_ENABLED'),
    );
    await expect(f.login()).rejects.toThrow();
    expect(f.policies.linkRafaelMember).not.toHaveBeenCalled();
  });
  it('retries after committed membership link and failed IAM enablement', async () => {
    const f = fixture();
    f.repository.enableRafaelAccess.mockRejectedValueOnce(
      new Error('database unavailable'),
    );
    await expect(f.login()).rejects.toThrow('database unavailable');
    expect(f.repository.issueSession).not.toHaveBeenCalled();
    expect((await f.login()).pending).toBe(false);
    expect(f.policies.linkRafaelMember).toHaveBeenCalledTimes(2);
  });
  it('rechecks membership before returning the session cookie', async () => {
    const f = fixture();
    f.policies.activeMember
      .mockResolvedValueOnce({ id: '1', iam_subject: userId, estado: 'activo' })
      .mockRejectedValueOnce(new Error('inactive'));
    await expect(f.login()).rejects.toThrow('inactive');
  });
  it('does not automatically enable future applications', async () => {
    const f = fixture();
    f.policies.application.mockResolvedValue({ id: 'app', codigo: 'future' });
    expect(await f.login()).toEqual({ pending: true });
    expect(f.policies.linkRafaelMember).not.toHaveBeenCalled();
    expect(f.repository.enableRafaelAccess).not.toHaveBeenCalled();
  });
});

describe('Automatic access repository policy', () => {
  function repositoryWithState(estado?: string) {
    const query = jest.fn(async (sql: string) => ({
      rows: sql.includes('SELECT a.estado') && estado ? [{ estado }] : [],
      rowCount: 1,
    }));
    const transaction = async (
      work: (client: { query: typeof query }) => Promise<unknown>,
    ) => work({ query });
    const repository = new AuthRepository({
      transaction,
    } as unknown as DatabaseService);
    return { repository, query };
  }
  it.each(['suspendido', undefined])(
    'rejects %s access without writing',
    async (state) => {
      const f = repositoryWithState(state);
      await expect(
        f.repository.enableRafaelAccess('app', userId),
      ).rejects.toThrow('ACCESS_NOT_ENABLED');
      expect(f.query).toHaveBeenCalledTimes(1);
    },
  );
  it('leaves already enabled access and its grant audit untouched', async () => {
    const f = repositoryWithState('habilitado');
    await f.repository.enableRafaelAccess('app', userId);
    expect(f.query).toHaveBeenCalledTimes(1);
  });
  it('enables only pending Rafael access and audits the service, not a manual operator', async () => {
    const f = repositoryWithState('pendiente');
    await f.repository.enableRafaelAccess('app', userId);
    const sql = f.query.mock.calls.map(([query]) => query).join('\n');
    expect(sql).toContain("p.codigo='rafael'");
    expect(sql).toContain('FOR UPDATE OF a FOR SHARE OF u,p');
    expect(sql).toContain("AND estado='pendiente'");
    expect(sql).toContain('granted_by=NULL');
    expect(sql).toContain('access.auto_enabled');
    expect(sql).not.toContain('user_roles');
  });
});
