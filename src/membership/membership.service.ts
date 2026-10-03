import { Injectable, ServiceUnavailableException } from '@nestjs/common';
import type { OnApplicationShutdown } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { readFileSync } from 'node:fs';
import { Pool } from 'pg';

export interface Member {
  id: string;
  iam_subject: string | null;
  estado: string;
  rafael_access_level?: 'trainee' | 'miembro' | 'representante' | null;
}

@Injectable()
export class MembershipService implements OnApplicationShutdown {
  private pool?: Pool;
  constructor(private readonly config: ConfigService) {}
  private connection() {
    if (this.pool) return this.pool;
    const url = this.config.get<string>('DATABASE_URL');
    if (!url) throw new ServiceUnavailableException('MEMBERSHIP_UNAVAILABLE');
    const ca = this.config.get<string>('DATABASE_CA_FILE');
    this.pool = new Pool({
      connectionString: url,
      max: 5,
      connectionTimeoutMillis: 3000,
      query_timeout: 5000,
      statement_timeout: 5000,
      application_name: 'exdev-iam-membership',
      ssl:
        this.config.get<string>('DATABASE_SSL') === 'verify-full'
          ? {
              rejectUnauthorized: true,
              ...(ca ? { ca: readFileSync(ca, 'utf8') } : {}),
            }
          : false,
    });
    this.pool.on('error', () => {});
    return this.pool;
  }
  async findCandidate(email: string): Promise<Member | null> {
    try {
      const result = await this.connection().query<Member>(
        'SELECT id::text, iam_subject, estado FROM public.miembros WHERE lower(btrim(correo_institucional))=$1',
        [email],
      );
      return result.rows.length === 1 ? result.rows[0] : null;
    } catch {
      throw new ServiceUnavailableException('MEMBERSHIP_UNAVAILABLE');
    }
  }
  async linkVerifiedRafaelMember(
    userId: string,
    email: string,
  ): Promise<Member | null> {
    try {
      const result = await this.connection().query<Member>(
        'SELECT id::text, iam_subject, estado FROM public.iam_link_verified_rafael_member($1::uuid,$2::text)',
        [userId, email.trim().toLowerCase()],
      );
      return result.rows.length === 1 ? result.rows[0] : null;
    } catch {
      throw new ServiceUnavailableException('MEMBERSHIP_UNAVAILABLE');
    }
  }
  async findLinked(userId: string): Promise<Member | null> {
    try {
      const result = await this.connection().query<Member>(
        'SELECT id::text, iam_subject, estado, rafael_access_level FROM public.miembros WHERE iam_subject=$1',
        [userId],
      );
      return result.rows.length === 1 ? result.rows[0] : null;
    } catch {
      throw new ServiceUnavailableException('MEMBERSHIP_UNAVAILABLE');
    }
  }
  async onApplicationShutdown() {
    await this.pool?.end();
  }
}
