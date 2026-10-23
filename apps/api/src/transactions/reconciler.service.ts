import { Inject, Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { APP_CONFIG, type AppConfig } from '../config';
import { TransactionsService } from './transactions.service';

/**
 * Background reconciler: periodically resolves transactions whose outcome is
 * unknown (provider timeouts, gateway crashes). Production would run this as
 * a separate worker (SQS-scheduled); here it is an in-process interval.
 */
@Injectable()
export class ReconcilerService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger('Reconciler');
  private timer: NodeJS.Timeout | null = null;
  private running = false;

  constructor(
    private readonly transactions: TransactionsService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  onModuleInit(): void {
    const every = this.config.reconcileIntervalMs;
    if (every <= 0) return;
    this.timer = setInterval(() => void this.tick(every), every);
    this.timer.unref();
  }

  onModuleDestroy(): void {
    if (this.timer) clearInterval(this.timer);
  }

  private async tick(staleAfterMs: number): Promise<void> {
    if (this.running) return;
    this.running = true;
    try {
      const n = await this.transactions.reconcileStale(staleAfterMs);
      if (n > 0) this.logger.log(`reconciled ${n} stale transaction(s)`);
    } catch (e) {
      this.logger.error(e instanceof Error ? e.message : String(e));
    } finally {
      this.running = false;
    }
  }
}
