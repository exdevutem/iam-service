import {
  Body,
  Controller,
  HttpCode,
  Post,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { IsString, Matches } from 'class-validator';
import type { Request } from 'express';
import { AuthService } from './auth.service';
import { hashToken } from './token-protection';
import { timingSafeEqual } from 'node:crypto';

export class ValidateSessionDto {
  @IsString() @Matches(/^[A-Za-z0-9_-]{43}$/) token!: string;
}

@Controller('internal/sessions')
export class InternalController {
  constructor(
    private readonly auth: AuthService,
    private readonly config: ConfigService,
  ) {}
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
    return this.auth.current(body.token);
  }
}
