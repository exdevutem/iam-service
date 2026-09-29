import { Test, TestingModule } from '@nestjs/testing';
import type { NestExpressApplication } from '@nestjs/platform-express';
import request from 'supertest';
import { AppModule } from './../src/app.module';
import { PG_POOL } from '../src/shared/connections/database.constants';
import { configureApp } from '../src/config/configure-app';
import { DatabaseService } from '../src/shared/connections/database.service';

describe('AppController (e2e)', () => {
  let app: NestExpressApplication;
  let databaseState: 'up' | 'down' | 'disabled';

  beforeEach(async () => {
    databaseState = 'disabled';
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(PG_POOL)
      .useValue(null)
      .overrideProvider(DatabaseService)
      .useValue({ readiness: async () => databaseState })
      .compile();

    app = moduleFixture.createNestApplication<NestExpressApplication>();
    configureApp(app);
    await app.init();
  });

  it('liveness does not depend on PostgreSQL and has security headers', async () => {
    const response = await request(app.getHttpServer())
      .get('/health/live')
      .expect(200);
    expect(response.body).toEqual({ status: 'ok' });
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.headers['x-request-id']).toBeDefined();
    expect(response.headers['x-powered-by']).toBeUndefined();
  });

  it.each(['disabled', 'down'] as const)(
    'is not ready when database is %s',
    async (state) => {
      databaseState = state;
      const response = await request(app.getHttpServer())
        .get('/health/ready')
        .expect(503);
      expect(response.body.message).toBe('Servicio no disponible');
      expect(response.body.requestId).toBeDefined();
    },
  );

  it('is ready when PostgreSQL probe succeeds', async () => {
    databaseState = 'up';
    await request(app.getHttpServer())
      .get('/health/ready')
      .expect(200)
      .expect({ status: 'ok', database: 'up' });
  });

  it('/ (GET)', () => {
    return request(app.getHttpServer())
      .get('/')
      .expect(200)
      .expect('Hello World!');
  });

  it('does not expose identity without a valid session', async () => {
    await request(app.getHttpServer()).get('/auth/me').expect(401);
  });

  it('does not expose session validation to unauthenticated services', async () => {
    await request(app.getHttpServer())
      .post('/internal/sessions/validate')
      .send({ token: 'a'.repeat(43) })
      .expect(401);
  });

  it('rejects caller-selected application and identity fields', async () => {
    await request(app.getHttpServer())
      .post('/internal/sessions/validate')
      .send({
        token: 'a'.repeat(43),
        applicationId: 'other',
        userId: 'attacker',
      })
      .expect(400);
  });

  afterEach(async () => {
    await app.close();
  });
});
