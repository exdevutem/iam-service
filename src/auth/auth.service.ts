import {
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { AuthSettings } from './auth.settings';
import { AuthRepository } from './auth.repository';
import { GoogleIdentityService } from './google-identity.service';
import { ApplicationPolicyService } from '../applications/application-policy.service';
import {
  csrfToken,
  isToken,
  randomToken,
  sameToken,
  seal,
  unseal,
} from './token-protection';

@Injectable()
export class AuthService {
  constructor(
    private readonly settings: AuthSettings,
    private readonly repository: AuthRepository,
    private readonly google: GoogleIdentityService,
    private readonly policies: ApplicationPolicyService,
  ) {}
  async suspend(userId: string) {
    const app = await this.policies.application();
    await this.repository.suspend(app.id, userId);
  }
  async login() {
    const app = await this.policies.application();
    const state = randomToken(),
      nonce = randomToken(),
      verifier = randomToken(),
      binding = randomToken(),
      id = randomUUID();
    const url = await this.google.authorizationUrl(state, nonce, verifier);
    await this.repository.createLogin(
      app.id,
      id,
      state,
      nonce,
      seal(verifier, this.settings.key, `${app.id}:${id}`),
      binding,
    );
    return { url, binding };
  }
  async callback(
    params: URLSearchParams,
    binding: string | undefined,
    previous?: string,
  ) {
    const state = params.get('state');
    if (
      !isToken(state) ||
      !isToken(binding) ||
      params.getAll('state').length !== 1 ||
      params.getAll('code').length > 1
    )
      throw new UnauthorizedException('LOGIN_INVALID');
    const app = await this.policies.application();
    const transaction = await this.repository.consumeLogin(
      app.id,
      state,
      binding,
    );
    if (transaction.protection_key_version !== 1)
      throw new UnauthorizedException('LOGIN_INVALID');
    let verifier: string;
    try {
      verifier = unseal(
        transaction.pkce_verifier_protected,
        this.settings.key,
        `${app.id}:${transaction.id}`,
      );
    } catch {
      throw new UnauthorizedException('LOGIN_INVALID');
    }
    const callback = new URL(this.settings.redirectUri);
    callback.search = params.toString();
    const identity = await this.google.exchange(
      callback,
      state,
      transaction.nonce,
      verifier,
    );
    const known = await this.repository.findIdentity(identity);
    if (known?.estado === 'suspendido')
      throw new ForbiddenException('ACCESS_NOT_ENABLED');
    const member =
      app.codigo === 'rafael'
        ? null
        : await this.policies.eligible(identity.email, known?.user_id);
    const userId = await this.repository.recordIdentity(app.id, identity);
    if (app.codigo === 'rafael') {
      await this.repository.checkAutomaticAccess(app.id, userId);
      await this.policies.linkRafaelMember(identity.email, userId);
      await this.repository.enableRafaelAccess(app.id, userId);
    } else if (!member || member.iam_subject !== userId)
      return { pending: true as const };
    await this.policies.activeMember(userId);
    const token = randomToken();
    await this.repository.issueSession(
      app.id,
      userId,
      token,
      isToken(previous) ? previous : undefined,
    );
    await this.policies.activeMember(userId);
    return { pending: false as const, token };
  }
  async current(token: string | undefined) {
    if (!isToken(token)) throw new UnauthorizedException('SESSION_REQUIRED');
    const app = await this.policies.application();
    const session = await this.repository.session(app.id, token);
    const member = await this.policies.activeMember(session.user_id);
    const permissions = await this.repository.permissions(
      app.id,
      session.user_id,
    );
    // Recheck revocation/access after the external membership read.
    await this.repository.session(app.id, token);
    await this.repository.touch(session.id);
    return {
      user: { id: session.user_id },
      member: { id: member.id },
      application: app.codigo,
      access: 'enabled',
      permissions,
      expiresAt: session.expires_at,
    };
  }
  async validateRequest(
    token: string,
    mutation?: { csrf?: string; origin?: string },
  ) {
    if (
      mutation &&
      (mutation.origin !== this.settings.frontendOrigin ||
        !mutation.csrf ||
        !sameToken(mutation.csrf, csrfToken(token, this.settings.key)))
    )
      throw new ForbiddenException('CSRF_INVALID');
    return this.current(token);
  }
  async csrf(token: string | undefined) {
    await this.current(token);
    return { csrfToken: csrfToken(token!, this.settings.key) };
  }
  async logout(
    token: string | undefined,
    csrf: string | undefined,
    origin: string | undefined,
    all: boolean,
  ) {
    this.settings.requireEnabled();
    if (
      origin !== this.settings.frontendOrigin ||
      !isToken(token) ||
      !csrf ||
      !sameToken(csrf, csrfToken(token, this.settings.key))
    )
      throw new ForbiddenException('CSRF_INVALID');
    // Logout also works after local suspension; it never restores access.
    const app = await this.policies.application();
    await this.repository.revoke(app.id, token, all);
  }
}
