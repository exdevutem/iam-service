import {
  Injectable,
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import type { PoolClient } from 'pg';
import { DatabaseService } from '../shared/connections/database.service';
import { hashToken } from './token-protection';
import type { VerifiedIdentity } from './google-identity.service';

export interface LoginTransaction {
  id: string;
  nonce: string;
  pkce_verifier_protected: Buffer;
  protection_key_version: number;
}
export interface IdentityRow {
  user_id: string;
  estado: string;
}
export interface SessionRow {
  id: string;
  user_id: string;
  application_id: string;
  expires_at: Date;
}

@Injectable()
export class AuthRepository {
  constructor(private readonly db: DatabaseService) {}
  async createLogin(
    appId: string,
    id: string,
    state: string,
    nonce: string,
    verifier: Buffer,
    binding: string,
  ) {
    await this.db.query(
      `INSERT INTO public.login_transactions (id,application_id,provider_key,state_hash,nonce,pkce_verifier_protected,protection_key_version,browser_binding_hash,expires_at) VALUES ($1,$2,'google',$3,$4,$5,1,$6,now()+interval '5 minutes')`,
      [id, appId, hashToken(state), nonce, verifier, hashToken(binding)],
    );
  }
  async consumeLogin(appId: string, state: string, binding: string) {
    const result = await this.db.query<LoginTransaction>(
      `UPDATE public.login_transactions SET consumed_at=clock_timestamp() WHERE application_id=$1 AND state_hash=$2 AND browser_binding_hash=$3 AND provider_key='google' AND consumed_at IS NULL AND expires_at>clock_timestamp() RETURNING id,nonce,pkce_verifier_protected,protection_key_version`,
      [appId, hashToken(state), hashToken(binding)],
    );
    if (!result.rows[0])
      throw new UnauthorizedException('LOGIN_EXPIRED_OR_INVALID');
    return result.rows[0];
  }
  async findIdentity(
    identity: VerifiedIdentity,
  ): Promise<IdentityRow | undefined> {
    const result = await this.db.query<IdentityRow>(
      `SELECT e.user_id,u.estado FROM public.external_identities e JOIN public.users u ON u.id=e.user_id WHERE e.issuer=$1 AND e.subject=$2`,
      [identity.issuer, identity.subject],
    );
    return result.rows[0];
  }
  async recordIdentity(appId: string, identity: VerifiedIdentity) {
    return this.db.transaction(async (client) => {
      await client.query(
        'SELECT pg_advisory_xact_lock(hashtextextended($1,0))',
        [`${identity.issuer}:${identity.subject}`],
      );
      const existing = await client.query<IdentityRow>(
        `SELECT e.user_id,u.estado FROM public.external_identities e JOIN public.users u ON u.id=e.user_id WHERE e.issuer=$1 AND e.subject=$2 FOR UPDATE OF u`,
        [identity.issuer, identity.subject],
      );
      let userId = existing.rows[0]?.user_id;
      if (existing.rows[0]?.estado === 'suspendido')
        throw new ForbiddenException('ACCESS_NOT_ENABLED');
      if (!userId) {
        userId = randomUUID();
        await client.query('INSERT INTO public.users(id) VALUES ($1)', [
          userId,
        ]);
        await client.query(
          'INSERT INTO public.external_identities(id,user_id,issuer,subject,correo_observado,correo_verificado) VALUES ($1,$2,$3,$4,$5,true)',
          [
            randomUUID(),
            userId,
            identity.issuer,
            identity.subject,
            identity.email,
          ],
        );
      } else {
        await client.query(
          'UPDATE public.external_identities SET correo_observado=$3,correo_verificado=true WHERE issuer=$1 AND subject=$2',
          [identity.issuer, identity.subject, identity.email],
        );
      }
      await client.query(
        `INSERT INTO public.application_access(application_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING`,
        [appId, userId],
      );
      await this.audit(client, appId, userId, 'identity.verified', userId);
      return userId;
    });
  }
  async issueSession(
    appId: string,
    userId: string,
    token: string,
    previous?: string,
  ) {
    return this.db.transaction(async (client) => {
      const access = await client.query(
        `SELECT a.user_id FROM public.application_access a JOIN public.users u ON u.id=a.user_id JOIN public.applications p ON p.id=a.application_id WHERE a.application_id=$1 AND a.user_id=$2 AND a.estado='habilitado' AND u.estado='habilitado' AND p.estado='habilitada' FOR SHARE OF a,u,p`,
        [appId, userId],
      );
      if (!access.rowCount) throw new ForbiddenException('ACCESS_NOT_ENABLED');
      if (previous)
        await client.query(
          'UPDATE public.sessions SET revoked_at=clock_timestamp() WHERE token_hash=$1 AND application_id=$2 AND revoked_at IS NULL',
          [hashToken(previous), appId],
        );
      const id = randomUUID();
      await client.query(
        `INSERT INTO public.sessions(id,token_hash,application_id,user_id,authenticated_at,expires_at) VALUES($1,$2,$3,$4,now(),now()+interval '8 hours')`,
        [id, hashToken(token), appId, userId],
      );
      await this.audit(client, appId, userId, 'session.created', id);
      return id;
    });
  }
  async session(appId: string, token: string): Promise<SessionRow> {
    const result = await this.db.query<SessionRow>(
      `SELECT s.id,s.user_id,s.application_id,s.expires_at FROM public.sessions s JOIN public.users u ON u.id=s.user_id JOIN public.applications p ON p.id=s.application_id JOIN public.application_access a ON a.application_id=s.application_id AND a.user_id=s.user_id WHERE s.token_hash=$1 AND s.application_id=$2 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND s.last_seen_at>clock_timestamp()-interval '30 minutes' AND u.estado='habilitado' AND p.estado='habilitada' AND a.estado='habilitado'`,
      [hashToken(token), appId],
    );
    if (!result.rows[0]) throw new UnauthorizedException('SESSION_INVALID');
    return result.rows[0];
  }
  async touch(id: string) {
    const result = await this.db.query(
      `UPDATE public.sessions SET last_seen_at=clock_timestamp() WHERE id=$1 AND revoked_at IS NULL AND expires_at>clock_timestamp() AND last_seen_at>clock_timestamp()-interval '30 minutes' RETURNING id`,
      [id],
    );
    if (!result.rowCount) throw new UnauthorizedException('SESSION_INVALID');
  }
  async permissions(appId: string, userId: string) {
    const result = await this.db.query<{ codigo: string }>(
      `SELECT DISTINCT p.codigo FROM public.user_roles ur JOIN public.access_roles r ON r.id=ur.role_id AND r.application_id=ur.application_id JOIN public.role_permissions rp ON rp.role_id=r.id AND rp.application_id=r.application_id JOIN public.permissions p ON p.id=rp.permission_id AND p.application_id=rp.application_id WHERE ur.application_id=$1 AND ur.user_id=$2 AND r.estado='activo' ORDER BY p.codigo`,
      [appId, userId],
    );
    return result.rows.map((row) => row.codigo);
  }
  async revoke(appId: string, token: string, all: boolean) {
    await this.db.transaction(async (client) => {
      const session = await client.query<{ id: string; user_id: string }>(
        'SELECT id,user_id FROM public.sessions WHERE token_hash=$1 AND application_id=$2 FOR UPDATE',
        [hashToken(token), appId],
      );
      const row = session.rows[0];
      if (!row) return;
      if (all)
        await client.query(
          'UPDATE public.sessions SET revoked_at=clock_timestamp() WHERE application_id=$1 AND user_id=$2 AND revoked_at IS NULL',
          [appId, row.user_id],
        );
      else
        await client.query(
          'UPDATE public.sessions SET revoked_at=clock_timestamp() WHERE id=$1 AND revoked_at IS NULL',
          [row.id],
        );
      await this.audit(
        client,
        appId,
        row.user_id,
        all ? 'session.revoked_all' : 'session.revoked',
        row.id,
      );
    });
  }
  private async audit(
    client: PoolClient,
    appId: string,
    userId: string,
    action: string,
    targetId: string,
  ) {
    await client.query(
      `INSERT INTO public.audit_events(application_id,actor_user_id,action,target_type,target_id,resultado) VALUES($1,$2,$3,'identity_session',$4,'exito')`,
      [appId, userId, action, targetId],
    );
  }
}
