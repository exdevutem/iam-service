import {
  Injectable,
  ForbiddenException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { DatabaseService } from '../shared/connections/database.service';
import { MembershipService } from '../membership/membership.service';
import { AuthSettings } from '../auth/auth.settings';

@Injectable()
export class ApplicationPolicyService {
  constructor(
    private readonly db: DatabaseService,
    private readonly settings: AuthSettings,
    private readonly membership: MembershipService,
  ) {}
  async application() {
    this.settings.requireEnabled();
    let result;
    try {
      result = await this.db.query<{
        id: string;
        codigo: string;
        estado: string;
      }>('SELECT id,codigo,estado FROM public.applications WHERE codigo=$1', [
        this.settings.code,
      ]);
    } catch {
      throw new ServiceUnavailableException('IAM_SCHEMA_UNAVAILABLE');
    }
    const app = result.rows[0];
    if (!app || app.estado !== 'habilitada')
      throw new ForbiddenException('APPLICATION_UNAVAILABLE');
    return app;
  }
  async eligible(email: string, userId?: string) {
    if (userId) {
      const member = await this.membership.findLinked(userId);
      if (member?.estado === 'activo') return member;
    }
    const candidate = await this.membership.findCandidate(email);
    if (!candidate || candidate.estado !== 'activo' || candidate.iam_subject)
      throw new ForbiddenException('ACCESS_NOT_ENABLED');
    // A verified email only establishes eligibility to request linking, never identity ownership.
    return null;
  }
  async activeMember(userId: string) {
    const member = await this.membership.findLinked(userId);
    if (!member || member.estado !== 'activo')
      throw new ForbiddenException('ACCESS_NOT_ENABLED');
    return member;
  }
}
