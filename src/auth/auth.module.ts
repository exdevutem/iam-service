import { Module } from '@nestjs/common';
import { SharedModule } from '../shared/shared.module';
import { AuthSettings } from './auth.settings';
import { AuthRepository } from './auth.repository';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { InternalController } from './internal.controller';
import { GoogleIdentityService } from './google-identity.service';
import { MembershipService } from '../membership/membership.service';
import { ApplicationPolicyService } from '../applications/application-policy.service';

@Module({
  imports: [SharedModule],
  controllers: [AuthController, InternalController],
  providers: [
    AuthSettings,
    AuthRepository,
    AuthService,
    GoogleIdentityService,
    MembershipService,
    ApplicationPolicyService,
  ],
})
export class AuthModule {}
