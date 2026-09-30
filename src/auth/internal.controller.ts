import {
  Body,
  Controller,
  HttpCode,
  Post,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  IsString,
  Matches,
  IsOptional,
  IsBoolean,
  MaxLength,
  IsUUID,
} from 'class-validator';
import type { Request } from 'express';
import { AuthService } from './auth.service';
import { hashToken } from './token-protection';
import { timingSafeEqual } from 'node:crypto';

export class ValidateSessionDto {
  @IsString() @Matches(/^[A-Za-z0-9_-]{43}$/) token!: string;
  @IsOptional() @IsBoolean() mutation?: boolean;
  @IsOptional() @IsString() @MaxLength(200) csrf?: string;
  @IsOptional() @IsString() @MaxLength(300) origin?: string;
}

export class SuspendAccessDto {
  @IsUUID() userId!: string;
}

@Controller('internal/sessions')
export class InternalController {
  constructor(
    private readonly auth: AuthService,
    private readonly config: ConfigService,
  ) {}
  private authorize(req: Request) {
    const secret = this.config.get<string>('IAM_SERVICE_TOKEN', '');
    if (
      secret.length < 43 ||
      !timingSafeEqual(
        hashToken(req.get('Authorization') ?? ''),
        hashToken(`Bearer ${secret}`),
      )
    )
      throw new UnauthorizedException('SERVICE_AUTH_REQUIRED');
  }
  @Post('suspend-access')
  @HttpCode(204)
  async suspend(@Req() req: Request, @Body() body: SuspendAccessDto) {
    this.authorize(req);
    await this.auth.suspend(body.userId);
  }
  @Post('validate')
  @HttpCode(200)
  validate(@Req() req: Request, @Body() body: ValidateSessionDto) {
    const secret = this.config.get<string>('IAM_SERVICE_TOKEN', '');
    const supplied = req.get('Authorization') ?? '';
    if (
      secret.length < 43 ||
      !timingSafeEqual(hashToken(supplied), hashToken(`Bearer ${secret}`))
    )
      throw new UnauthorizedException('SERVICE_AUTH_REQUIRED');
    return this.auth.validateRequest(
      body.token,
      body.mutation ? { csrf: body.csrf, origin: body.origin } : undefined,
    );
  }
}
