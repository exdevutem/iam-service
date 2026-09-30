import { jest } from '@jest/globals';
import { ConfigService } from '@nestjs/config';
import { AuthSettings, validateAuthEnvironment } from './auth.settings';
import {
  institutionalIdentity,
  GoogleIdentityService,
} from './google-identity.service';
import {
  csrfToken,
  hashToken,
  randomToken,
  sameToken,
  seal,
  unseal,
} from './token-protection';
import { AuthService } from './auth.service';
import { AuthRepository } from './auth.repository';
import { ApplicationPolicyService } from '../applications/application-policy.service';
import { MembershipService } from '../membership/membership.service';
import { DatabaseService } from '../shared/connections/database.service';

const valid = {
  iss: 'https://accounts.google.com',
  sub: '123456',
  email: 'member@utem.cl',
  email_verified: true,
  hd: 'utem.cl',
};
const key = Buffer.alloc(32, 7);
const settings = new AuthSettings(
  new ConfigService({
    AUTH_ENABLED: 'true',
    AUTH_ORIGIN: 'http://localhost:3002',
    AUTH_SECRET_BASE64: key.toString('base64'),
  }),
);

describe('Institutional policy', () => {
  it('accepts verified UTEM identity', () => {
    expect(institutionalIdentity(valid).email).toBe('member@utem.cl');
  });
  it.each([
    { hd: undefined },
    { hd: 'other.cl' },
    { email_verified: false },
    { email: 'member@gmail.com' },
    { email: 'member@utem.cl.evil' },
    { iss: 'https://evil.test' },
    { sub: '' },
  ])('rejects invalid institutional claims %j', (change) => {
    expect(() => institutionalIdentity({ ...valid, ...change })).toThrow();
  });
  it('does not equate verified email with linked membership', async () => {
    const membership = {
      findLinked: async () => null,
      findCandidate: async () => ({
        id: '42',
        estado: 'activo',
        iam_subject: null,
      }),
    } as unknown as MembershipService;
    const policy = new ApplicationPolicyService(
      {} as DatabaseService,
      settings,
      membership,
    );
    await expect(policy.eligible(valid.email)).resolves.toBeNull();
  });
  it.each([
    null,
    { id: '42', estado: 'inactivo', iam_subject: null },
    { id: '42', estado: 'activo', iam_subject: 'some-other-user' },
  ])('rejects absent/inactive/conflicting member', async (candidate) => {
    const membership = {
      findCandidate: async () => candidate,
    } as unknown as MembershipService;
    await expect(
      new ApplicationPolicyService(
        {} as DatabaseService,
        settings,
        membership,
      ).eligible(valid.email),
    ).rejects.toThrow();
  });
  it('keeps a proved identity when contact email changes', async () => {
    const membership = {
      findLinked: async () => ({
        id: '42',
        estado: 'activo',
        iam_subject: 'known',
      }),
    } as unknown as MembershipService;
    await expect(
      new ApplicationPolicyService(
        {} as DatabaseService,
        settings,
        membership,
      ).eligible('new@utem.cl', 'known'),
    ).resolves.toMatchObject({ id: '42' });
  });
});

describe('Transaction and CSRF protection', () => {
  it('encrypts PKCE with application and transaction binding', () => {
    const secret = randomToken();
    const blob = seal(secret, key, 'app:transaction');
    expect(blob.includes(Buffer.from(secret))).toBe(false);
    expect(unseal(blob, key, 'app:transaction')).toBe(secret);
    expect(() => unseal(blob, key, 'other:transaction')).toThrow();
    blob[blob.length - 1] ^= 1;
    expect(() => unseal(blob, key, 'app:transaction')).toThrow();
  });
  it('binds CSRF to opaque session', () => {
    const token = randomToken();
    expect(sameToken(csrfToken(token, key), csrfToken(token, key))).toBe(true);
    expect(
      sameToken(csrfToken(token, key), csrfToken(randomToken(), key)),
    ).toBe(false);
    expect(hashToken(token)).toHaveLength(32);
  });
  it('rejects replay when the atomic consume returns no rows', async () => {
    const db = {
      query: async () => ({ rows: [] }),
    } as unknown as DatabaseService;
    await expect(
      new AuthRepository(db).consumeLogin('app', randomToken(), randomToken()),
    ).rejects.toThrow('LOGIN_EXPIRED_OR_INVALID');
  });
});

describe('Login and session orchestration', () => {
  function fixture(linked: boolean) {
    const transaction = {
      id: 'tx',
      nonce: 'nonce',
      pkce_verifier_protected: seal(randomToken(), key, 'app:tx'),
      protection_key_version: 1,
    };
    const issueSession = jest
      .fn<(...args: unknown[]) => Promise<string>>()
      .mockResolvedValue('session');
    const consumeLogin = jest
      .fn<() => Promise<typeof transaction>>()
      .mockResolvedValue(transaction);
    const session = jest
      .fn<() => Promise<{ id: string; user_id: string; expires_at: Date }>>()
      .mockResolvedValue({
        id: 'session',
        user_id: 'user',
        expires_at: new Date(),
      });
    const repository = {
      consumeLogin,
      findIdentity: async () =>
        linked ? { user_id: 'user', estado: 'habilitado' } : undefined,
      recordIdentity: async () => 'user',
      issueSession,
      session,
      permissions: async () => ['members.read'],
      touch: async () => {},
    } as unknown as AuthRepository;
    const policies = {
      application: async () => ({ id: 'app', codigo: 'rafael' }),
      eligible: async () =>
        linked ? { id: '42', iam_subject: 'user', estado: 'activo' } : null,
      activeMember: async () => ({ id: '42' }),
    } as unknown as ApplicationPolicyService;
    const google = {
      exchange: async () => institutionalIdentity(valid),
    } as unknown as GoogleIdentityService;
    return {
      service: new AuthService(settings, repository, google, policies),
      issueSession,
      consumeLogin,
      session,
      policies,
    };
  }
  it('records pending identity but issues no session before verified linking', async () => {
    const f = fixture(false);
    await expect(
      f.service.callback(
        new URLSearchParams({ state: randomToken(), code: 'code' }),
        randomToken(),
      ),
    ).resolves.toEqual({ pending: true });
    expect(f.issueSession).not.toHaveBeenCalled();
  });
  it('issues opaque session only for linked active member and enabled access', async () => {
    const f = fixture(true);
    const result = await f.service.callback(
      new URLSearchParams({ state: randomToken(), code: 'code' }),
      randomToken(),
    );
    expect(result.pending).toBe(false);
    expect(f.issueSession).toHaveBeenCalledTimes(1);
  });
  it('requires browser binding before consuming transaction', async () => {
    const f = fixture(true);
    await expect(
      f.service.callback(
        new URLSearchParams({ state: randomToken() }),
        undefined,
      ),
    ).rejects.toThrow();
    expect(f.consumeLogin).not.toHaveBeenCalled();
  });
  it('checks member activity on every session lookup', async () => {
    const f = fixture(true);
    f.policies.activeMember = () => Promise.reject(new Error('inactive'));
    await expect(f.service.current(randomToken())).rejects.toThrow('inactive');
  });
  it('rejects revocation during membership lookup', async () => {
    const f = fixture(true);
    f.session
      .mockResolvedValueOnce({
        id: 'session',
        user_id: 'user',
        expires_at: new Date(),
      })
      .mockRejectedValueOnce(new Error('revoked'));
    await expect(f.service.current(randomToken())).rejects.toThrow('revoked');
  });
  it('rejects cross-origin logout', async () => {
    const f = fixture(true),
      token = randomToken();
    await expect(
      f.service.logout(token, csrfToken(token, key), 'https://evil.test', true),
    ).rejects.toThrow('CSRF_INVALID');
  });
});

describe('Auth configuration', () => {
  const env = {
    AUTH_ENABLED: 'true',
    AUTH_ORIGIN: 'http://localhost:3002',
    GOOGLE_CLIENT_ID: 'client',
    GOOGLE_CLIENT_SECRET: 'secret',
    AUTH_SECRET_BASE64: key.toString('base64'),
    DATABASE_URL: 'postgresql://user:pass@localhost/business',
  };
  it('allows first local test without public DNS', () =>
    expect(() => validateAuthEnvironment(env)).not.toThrow());
  it('requires HTTPS outside local development', () =>
    expect(() =>
      validateAuthEnvironment({ ...env, NODE_ENV: 'production' }),
    ).toThrow());
  it('rejects callback origin with an attacker path', () =>
    expect(() =>
      validateAuthEnvironment({
        ...env,
        AUTH_ORIGIN: 'http://localhost:3002/other',
      }),
    ).toThrow());
});

describe('Rafael frontend integration', () => {
  it('accepts only the configured local frontend origin', () => {
    const config = new ConfigService({
      AUTH_ORIGIN: 'http://localhost:3002',
      AUTH_FRONTEND_ORIGIN: 'http://localhost:3000',
      NODE_ENV: 'development',
    });
    expect(new AuthSettings(config).frontendOrigin).toBe(
      'http://localhost:3000',
    );
    for (const origin of [
      'https://evil.example',
      'http://127.0.0.1:3000',
      'http://localhost:3000/path',
    ])
      expect(
        () =>
          new AuthSettings(
            new ConfigService({
              AUTH_ORIGIN: 'http://localhost:3002',
              AUTH_FRONTEND_ORIGIN: origin,
              NODE_ENV: 'development',
            }),
          ).frontendOrigin,
      ).toThrow();
  });
  it('rejects cross-origin configuration in production', () => {
    expect(
      () =>
        new AuthSettings(
          new ConfigService({
            AUTH_ORIGIN: 'https://rafael.exdev.cl',
            AUTH_FRONTEND_ORIGIN: 'https://other.exdev.cl',
            NODE_ENV: 'production',
          }),
        ).frontendOrigin,
    ).toThrow();
  });
  it('validates CSRF and origin before a private mutation', async () => {
    const token = randomToken();
    const service = new AuthService(
      settings,
      {} as AuthRepository,
      {} as GoogleIdentityService,
      {} as ApplicationPolicyService,
    );
    const current = jest.spyOn(service, 'current').mockResolvedValue({
      user: { id: 'u' },
      member: { id: '1' },
      application: 'rafael',
      access: 'enabled',
      permissions: [],
      expiresAt: new Date(),
    });
    await expect(
      service.validateRequest(token, {
        csrf: csrfToken(token, key),
        origin: settings.origin,
      }),
    ).resolves.toBeDefined();
    for (const mutation of [
      { origin: settings.origin },
      { csrf: 'bad', origin: settings.origin },
      { csrf: csrfToken(token, key), origin: 'https://evil.example' },
    ])
      await expect(service.validateRequest(token, mutation)).rejects.toThrow(
        'CSRF_INVALID',
      );
    expect(current).toHaveBeenCalledTimes(1);
  });
});
