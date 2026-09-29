import { Injectable, UnauthorizedException } from '@nestjs/common';
import * as oidc from 'openid-client';
import { AuthSettings } from './auth.settings';

export interface VerifiedIdentity {
  issuer: string;
  subject: string;
  email: string;
  domain: string;
}

export function institutionalIdentity(
  claims: Record<string, unknown>,
): VerifiedIdentity {
  if (
    claims.iss !== 'https://accounts.google.com' ||
    typeof claims.sub !== 'string' ||
    !claims.sub ||
    claims.email_verified !== true ||
    claims.hd !== 'utem.cl' ||
    typeof claims.email !== 'string' ||
    !/^[^\s@]+@utem\.cl$/i.test(claims.email)
  ) {
    throw new UnauthorizedException('INSTITUTIONAL_ACCOUNT_REQUIRED');
  }
  return {
    issuer: claims.iss,
    subject: claims.sub,
    email: claims.email.toLowerCase(),
    domain: 'utem.cl',
  };
}

@Injectable()
export class GoogleIdentityService {
  private configuration?: Promise<oidc.Configuration>;
  constructor(private readonly settings: AuthSettings) {}
  private configurationForGoogle() {
    this.settings.requireEnabled();
    this.configuration ??= oidc
      .discovery(
        new URL('https://accounts.google.com'),
        this.settings.clientId,
        this.settings.clientSecret,
        undefined,
        { timeout: 10, execute: [oidc.enableNonRepudiationChecks] },
      )
      .catch((error) => {
        this.configuration = undefined;
        throw error;
      });
    return this.configuration;
  }
  async authorizationUrl(state: string, nonce: string, verifier: string) {
    const configuration = await this.configurationForGoogle();
    return oidc.buildAuthorizationUrl(configuration, {
      redirect_uri: this.settings.redirectUri,
      scope: 'openid email',
      response_type: 'code',
      state,
      nonce,
      code_challenge: await oidc.calculatePKCECodeChallenge(verifier),
      code_challenge_method: 'S256',
      hd: 'utem.cl',
      prompt: 'select_account',
    }).href;
  }
  async exchange(
    callback: URL,
    state: string,
    nonce: string,
    verifier: string,
  ): Promise<VerifiedIdentity> {
    try {
      const configuration = await this.configurationForGoogle();
      const tokens = await oidc.authorizationCodeGrant(
        configuration,
        callback,
        {
          expectedState: state,
          expectedNonce: nonce,
          pkceCodeVerifier: verifier,
          idTokenExpected: true,
        },
      );
      const claims = tokens.claims();
      if (!claims) throw new Error('ID_TOKEN_REQUIRED');
      return institutionalIdentity(claims);
    } catch {
      throw new UnauthorizedException('GOOGLE_LOGIN_REJECTED');
    }
  }
}
