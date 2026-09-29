import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';

export const randomToken = () => randomBytes(32).toString('base64url');
export const hashToken = (value: string) =>
  createHash('sha256').update(value).digest();
export const isToken = (value: unknown): value is string =>
  typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value);
export function seal(value: string, key: Buffer, context: string): Buffer {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(context));
  const encrypted = Buffer.concat([
    cipher.update(value, 'utf8'),
    cipher.final(),
  ]);
  return Buffer.concat([iv, cipher.getAuthTag(), encrypted]);
}
export function unseal(value: Buffer, key: Buffer, context: string): string {
  if (value.length < 29) throw new Error('INVALID_TRANSACTION');
  const decipher = createDecipheriv('aes-256-gcm', key, value.subarray(0, 12));
  decipher.setAAD(Buffer.from(context));
  decipher.setAuthTag(value.subarray(12, 28));
  return Buffer.concat([
    decipher.update(value.subarray(28)),
    decipher.final(),
  ]).toString('utf8');
}
export function csrfToken(sessionToken: string, key: Buffer) {
  return createHmac('sha256', key)
    .update(`csrf:${sessionToken}`)
    .digest('base64url');
}
export function sameToken(left: string, right: string) {
  return (
    isToken(left) &&
    isToken(right) &&
    timingSafeEqual(Buffer.from(left), Buffer.from(right))
  );
}
