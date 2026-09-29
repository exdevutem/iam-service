import { Controller, Get, ServiceUnavailableException } from '@nestjs/common';
import { DatabaseService } from '../shared/connections/database.service';

@Controller('health')
export class HealthController {
  constructor(private readonly database: DatabaseService) {}

  @Get('live')
  live() {
    return { status: 'ok' };
  }

  @Get('ready')
  async ready() {
    const database = await this.database.readiness();
    if (database !== 'up')
      throw new ServiceUnavailableException({ status: 'not_ready', database });
    return { status: 'ok', database };
  }
}
