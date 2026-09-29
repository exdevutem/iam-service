import { Injectable, ServiceUnavailableException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthSettings {
  constructor(private readonly config: ConfigService) {}
  get enabled() {
    return this.config.get<string>('AUTH_ENABLED', 'false') === 'true';
  }
  get code() {
    return this.config.get<string>('AUTH_APPLICATION_CODE', 'rafael');
  }
  get origin() {
    return this.config.get<string>('AUTH_ORIGIN', '');
  }
  get redirectUri() {
    return `${this.origin}/auth/callback`;
  }
  get clientId() {
    return this.config.get<string>('GOOGLE_CLIENT_ID', '');
  }
  get clientSecret() {
    return this.config.get<string>('GOOGLE_CLIENT_SECRET', '');
  }
  get secure() {
    return this.origin.startsWith('https://');
  }
  get sessionCookie() {
    return `${this.secure ? '__Host-' : ''}exdev_${this.code}_session`;
  }
  get bindingCookie() {
    return `${this.secure ? '__Host-' : ''}exdev_${this.code}_login`;
  }
  get key() {
    return Buffer.from(
      this.config.get<string>('AUTH_SECRET_BASE64', ''),
      'base64',
    );
  }
  requireEnabled() {
    if (!this.enabled)
      throw new ServiceUnavailableException('AUTH_NOT_CONFIGURED');
  }
}

export function validateAuthEnvironment(input: Record<string, unknown>) {
  const text = (key: string, fallback = '') => {
    const value = input[key] ?? fallback;
    if (typeof value !== 'string')
      throw new Error(`Configuracion invalida: ${key}`);
    return value;
  };
  if (
    input.AUTH_ENABLED !== undefined &&
    !['true', 'false'].includes(text('AUTH_ENABLED'))
  )
    throw new Error('Configuracion invalida: AUTH_ENABLED');
  if (input.AUTH_ENABLED !== 'true') return;
  const required = [
    'AUTH_ORIGIN',
    'GOOGLE_CLIENT_ID',
    'GOOGLE_CLIENT_SECRET',
    'AUTH_SECRET_BASE64',
    'DATABASE_URL',
  ];
  if (
    required.some(
      (key) => typeof input[key] !== 'string' || !String(input[key]).trim(),
    )
  )
    throw new Error('Falta configuracion de login Google o base de miembros');
  const code = text('AUTH_APPLICATION_CODE', 'rafael');
  if (!/^[a-z][a-z0-9_-]{0,63}$/.test(code))
    throw new Error('AUTH_APPLICATION_CODE invalido');
  const origin = new URL(String(input.AUTH_ORIGIN));
  if (origin.origin !== input.AUTH_ORIGIN || origin.username || origin.password)
    throw new Error('AUTH_ORIGIN debe ser origen sin ruta ni credenciales');
  const local =
    input.NODE_ENV !== 'production' &&
    origin.protocol === 'http:' &&
    ['localhost', '127.0.0.1'].includes(origin.hostname);
  if (origin.protocol !== 'https:' && !local)
    throw new Error('AUTH_ORIGIN requiere HTTPS fuera de localhost');
  const secret = String(input.AUTH_SECRET_BASE64);
  if (
    Buffer.from(secret, 'base64').length !== 32 ||
    Buffer.from(secret, 'base64').toString('base64') !== secret
  )
    throw new Error('AUTH_SECRET_BASE64 requiere 32 bytes en Base64 canonico');
  const members = new URL(String(input.DATABASE_URL));
  if (
    !['postgres:', 'postgresql:'].includes(members.protocol) ||
    !members.hostname ||
    members.pathname.length < 2 ||
    members.search ||
    members.hash
  )
    throw new Error('DATABASE_URL invalida');
  if (
    !['disable', 'verify-full'].includes(
      text('DATABASE_SSL', 'disable'),
    )
  )
    throw new Error('DATABASE_SSL invalido');
}
