import { validateAuthEnvironment } from '../auth/auth.settings';

export function validateEnvironment(input: Record<string, unknown>) {
  const text = (key: string, fallback = '') => {
    const value = input[key] ?? fallback;
    if (
      typeof value !== 'string' &&
      typeof value !== 'number' &&
      typeof value !== 'boolean'
    ) {
      throw new Error(`Configuracion invalida: ${key}`);
    }
    return String(value).trim();
  };
  const integer = (key: string, fallback: number, max: number) => {
    const raw = text(key, String(fallback));
    const value = Number(raw);
    if (
      !/^\d+$/.test(raw) ||
      !Number.isSafeInteger(value) ||
      value < 1 ||
      value > max
    ) {
      throw new Error(`Configuracion invalida: ${key}`);
    }
    return value;
  };
  const nodeEnv = text('NODE_ENV', 'development');
  if (!['development', 'test', 'production'].includes(nodeEnv)) {
    throw new Error('Configuracion invalida: NODE_ENV');
  }
  const enabledValue = text(
    'DATABASE_ENABLED',
    text('DATABASE_IAM_URL') ? 'true' : 'false',
  );
  if (!['true', 'false'].includes(enabledValue))
    throw new Error('Configuracion invalida: DATABASE_ENABLED');
  const enabled = enabledValue === 'true';
  if (nodeEnv === 'production' && !enabled)
    throw new Error('Produccion requiere DATABASE_ENABLED=true');
  const databaseUrl = text('DATABASE_IAM_URL');
  if (enabled) {
    try {
      const url = new URL(databaseUrl);
      if (
        !['postgres:', 'postgresql:'].includes(url.protocol) ||
        !url.hostname ||
        url.pathname.length < 2 ||
        url.search ||
        url.hash
      )
        throw new Error();
    } catch {
      throw new Error(
        'DATABASE_IAM_URL debe identificar PostgreSQL y una base, sin parametros; configurar TLS por separado',
      );
    }
  }
  const ssl = text('DATABASE_IAM_SSL', 'disable');
  if (!['disable', 'verify-full'].includes(ssl))
    throw new Error('Configuracion invalida: DATABASE_IAM_SSL');
  validateAuthEnvironment({ ...input, NODE_ENV: nodeEnv });
  if (input.AUTH_ENABLED === 'true' && !enabled)
    throw new Error('El login requiere base IAM habilitada');
  return {
    ...input,
    NODE_ENV: nodeEnv,
    PORT: integer('PORT', 3002, 65535),
    HOST: text('HOST', '127.0.0.1'),
    DATABASE_ENABLED: enabled,
    DATABASE_IAM_URL: databaseUrl,
    DATABASE_IAM_SSL: ssl,
    DATABASE_IAM_CA_FILE: text('DATABASE_IAM_CA_FILE'),
    DATABASE_POOL_MAX: integer('DATABASE_POOL_MAX', 10, 100),
    DATABASE_CONNECT_TIMEOUT_MS: integer(
      'DATABASE_CONNECT_TIMEOUT_MS',
      3000,
      60000,
    ),
    DATABASE_QUERY_TIMEOUT_MS: integer(
      'DATABASE_QUERY_TIMEOUT_MS',
      5000,
      120000,
    ),
    DATABASE_IDLE_TIMEOUT_MS: integer(
      'DATABASE_IDLE_TIMEOUT_MS',
      30000,
      300000,
    ),
  };
}
