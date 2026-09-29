import { Logger, Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { readFileSync } from 'node:fs';
import { Pool } from 'pg';
import { PG_POOL } from './database.constants';
import { DatabaseService } from './database.service';

export { PG_POOL } from './database.constants';

@Module({
  imports: [ConfigModule],
  providers: [
    {
      provide: PG_POOL,
      inject: [ConfigService],
      useFactory: (config: ConfigService): Pool | null => {
        if (!config.getOrThrow<boolean>('DATABASE_ENABLED')) return null;
        const caFile = config.getOrThrow<string>('DATABASE_IAM_CA_FILE');
        const pool = new Pool({
          connectionString: config.getOrThrow<string>('DATABASE_IAM_URL'),
          max: config.getOrThrow<number>('DATABASE_POOL_MAX'),
          connectionTimeoutMillis: config.getOrThrow<number>(
            'DATABASE_CONNECT_TIMEOUT_MS',
          ),
          idleTimeoutMillis: config.getOrThrow<number>(
            'DATABASE_IDLE_TIMEOUT_MS',
          ),
          statement_timeout: config.getOrThrow<number>(
            'DATABASE_QUERY_TIMEOUT_MS',
          ),
          query_timeout: config.getOrThrow<number>('DATABASE_QUERY_TIMEOUT_MS'),
          idle_in_transaction_session_timeout: 10000,
          application_name: 'exdev-iam-service',
          ssl:
            config.getOrThrow<string>('DATABASE_IAM_SSL') === 'verify-full'
              ? {
                  rejectUnauthorized: true,
                  ...(caFile ? { ca: readFileSync(caFile, 'utf8') } : {}),
                }
              : false,
        });
        const logger = new Logger('DatabasePool');
        pool.on('error', () => logger.error('DATABASE_POOL_ERROR'));
        return pool;
      },
    },
    DatabaseService,
  ],
  exports: [PG_POOL, DatabaseService],
})
export class DatabaseModule {}
