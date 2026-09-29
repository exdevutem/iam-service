import { validateEnvironment } from './environment';

describe('environment', () => {
  it('keeps the business connection separate from the IAM connection', () => {
    const result = validateEnvironment({
      DATABASE_URL: 'postgresql://user:pass@localhost/business',
      DATABASE_IAM_URL: 'postgresql://user:pass@localhost/iam',
    });
    expect(result).toMatchObject({ DATABASE_URL: 'postgresql://user:pass@localhost/business' });
    expect(result.DATABASE_IAM_URL).toBe('postgresql://user:pass@localhost/iam');
    expect(result.DATABASE_ENABLED).toBe(true);
    expect(validateEnvironment({ DATABASE_URL: 'postgresql://user:pass@localhost/business' }).DATABASE_ENABLED).toBe(false);
  });
  it('starts development without inventing database credentials', () => {
    expect(validateEnvironment({})).toMatchObject({
      PORT: 3002,
      DATABASE_ENABLED: false,
    });
  });
  it.each([
    { PORT: '0' },
    { PORT: '3002abc' },
    { DATABASE_POOL_MAX: '0' },
    { DATABASE_ENABLED: 'yes' },
    { NODE_ENV: 'production' },
  ])('rejects invalid configuration %j', (input) => {
    expect(() => validateEnvironment(input)).toThrow();
  });
  it('rejects URL TLS overrides without leaking secrets', () => {
    expect(() =>
      validateEnvironment({
        DATABASE_ENABLED: 'true',
        DATABASE_IAM_URL:
          'postgresql://user:private@localhost/iam?sslmode=no-verify',
      }),
    ).toThrow('DATABASE_IAM_URL');
    try {
      validateEnvironment({
        DATABASE_ENABLED: 'true',
        DATABASE_IAM_URL: 'private-secret',
      });
    } catch (error) {
      expect(String(error)).not.toContain('private-secret');
    }
  });
  it('accepts explicitly configured PostgreSQL', () => {
    expect(
      validateEnvironment({
        NODE_ENV: 'production',
        DATABASE_ENABLED: 'true',
        DATABASE_IAM_URL: 'postgresql://user:password@localhost/iam',
        DATABASE_IAM_SSL: 'verify-full',
      }).DATABASE_ENABLED,
    ).toBe(true);
  });
});
