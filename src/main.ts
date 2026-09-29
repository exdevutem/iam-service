import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { configureApp } from './config/configure-app';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    abortOnError: false,
    logger: false,
  });
  app.useLogger(['log', 'warn', 'error']);
  configureApp(app);
  const config = app.get(ConfigService);
  await app.listen(
    config.getOrThrow<number>('PORT'),
    config.getOrThrow<string>('HOST'),
  );
}
void bootstrap().catch(() => {
  console.error(
    'IAM_STARTUP_FAILED: revise configuracion, puerto y archivos TLS.',
  );
  process.exitCode = 1;
});
