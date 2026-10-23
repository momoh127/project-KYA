import { Body, Controller, Get, Inject, Post } from '@nestjs/common';
import { z } from 'zod';
import { Bootstrap, Public } from '../auth/principal';
import { DevTokenService } from '../auth/human-token';
import { Errors } from '../common/errors';
import { PrismaService } from '../common/prisma.service';
import { ZodPipe, zId } from '../common/validation';

const DevTokenBody = z.object({ userId: zId('usr') }).strict();

/**
 * DEVELOPMENT ONLY: issues human access tokens without a real identity
 * provider. Requires the bootstrap token, and is disabled unless
 * AGENTTRUST_DEV_AUTH=true (which config refuses in production).
 */
@Controller('v1')
export class DevAuthController {
  constructor(
    @Inject(DevTokenService) private readonly devTokens: DevTokenService,
    private readonly prisma: PrismaService,
  ) {}

  @Post('dev/token')
  @Bootstrap()
  async token(@Body(new ZodPipe(DevTokenBody)) body: z.infer<typeof DevTokenBody>) {
    if (!this.devTokens.enabled) throw Errors.notFound('Endpoint');
    const user = await this.prisma.user.findUnique({ where: { id: body.userId } });
    if (!user || user.status !== 'active') throw Errors.notFound('User');
    return this.devTokens.issue(user.externalIdentityId);
  }

  @Get('health')
  @Public()
  health() {
    return { status: 'ok' };
  }
}
