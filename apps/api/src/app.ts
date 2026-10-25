import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import type { INestApplication } from '@nestjs/common';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { AppModule } from './app.module';
import type { AppConfig } from './config';

export async function createApp(config: AppConfig, opts: { logger?: boolean } = {}): Promise<INestApplication> {
  const app = await NestFactory.create<NestExpressApplication>(AppModule.forConfig(config), {
    // Raw body is required to verify agent request signatures byte-for-byte.
    rawBody: true,
    logger: opts.logger === false ? false : ['log', 'warn', 'error'],
  });
  app.useBodyParser('json', { limit: '64kb' });
  app.disable('x-powered-by');
  // Behind a load balancer (e.g. Render), trust exactly N proxy hops so rate
  // limits key on the real client IP, not the proxy's. 0 = trust none.
  if (config.trustProxyHops > 0) app.set('trust proxy', config.trustProxyHops);
  app.enableShutdownHooks();
  return app;
}
