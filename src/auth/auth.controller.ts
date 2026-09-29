import { Controller, Get, Post, Req, Res, HttpCode } from '@nestjs/common';
import type { Request, Response } from 'express';
import { parseCookie } from 'cookie';
import { Throttle } from '@nestjs/throttler';
import { AuthSettings } from './auth.settings';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly service: AuthService,
    private readonly settings: AuthSettings,
  ) {}
  private token(req: Request) {
    return parseCookie(req.headers.cookie ?? '')[this.settings.sessionCookie];
  }
  private cookieOptions() {
    return {
      httpOnly: true,
      secure: this.settings.secure,
      sameSite: 'lax' as const,
      path: '/',
    };
  }
  @Get('login')
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  async login(@Res() res: Response) {
    const result = await this.service.login();
    res.cookie(this.settings.bindingCookie, result.binding, {
      ...this.cookieOptions(),
      maxAge: 300000,
    });
    res.redirect(302, result.url);
  }
  @Get('callback')
  @Throttle({ default: { limit: 20, ttl: 60000 } })
  async callback(@Req() req: Request, @Res() res: Response) {
    const params = new URL(
      req.originalUrl,
      this.settings.origin || 'http://localhost',
    ).searchParams;
    const binding = parseCookie(req.headers.cookie ?? '')[
      this.settings.bindingCookie
    ];
    res.clearCookie(this.settings.bindingCookie, this.cookieOptions());
    try {
      const result = await this.service.callback(
        params,
        binding,
        this.token(req),
      );
      if (result.pending) {
        res.clearCookie(this.settings.sessionCookie, this.cookieOptions());
        res.status(403).json({
          code: 'ACCESS_PENDING',
          message:
            'Cuenta institucional verificada. Falta vincular y habilitar el acceso.',
        });
        return;
      }
      res.cookie(this.settings.sessionCookie, result.token, {
        ...this.cookieOptions(),
        maxAge: 8 * 60 * 60 * 1000,
      });
      res.redirect(303, '/auth/me');
    } catch (error) {
      res.clearCookie(this.settings.sessionCookie, this.cookieOptions());
      throw error;
    }
  }
  @Get('me') me(@Req() req: Request) {
    return this.service.current(this.token(req));
  }
  @Get('csrf') csrf(@Req() req: Request) {
    return this.service.csrf(this.token(req));
  }
  @Post('logout')
  @HttpCode(204)
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    await this.service.logout(
      this.token(req),
      req.get('X-CSRF-Token'),
      req.get('Origin'),
      false,
    );
    res.clearCookie(this.settings.sessionCookie, this.cookieOptions());
  }
  @Post('logout-all')
  @HttpCode(204)
  async logoutAll(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    await this.service.logout(
      this.token(req),
      req.get('X-CSRF-Token'),
      req.get('Origin'),
      true,
    );
    res.clearCookie(this.settings.sessionCookie, this.cookieOptions());
  }
}
