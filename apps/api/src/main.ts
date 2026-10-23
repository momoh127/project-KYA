import { Logger } from '@nestjs/common';
import { createApp } from './app';
import { loadConfig } from './config';

async function main() {
  const config = loadConfig();
  const app = await createApp(config);
  await app.listen(config.port);
  const log = new Logger('AgentTrust');
  log.log(`API listening on http://localhost:${config.port}`);
  if (config.devAuth.enabled) log.warn('Development login is ENABLED (never use in production)');
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
