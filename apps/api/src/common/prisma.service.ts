import { Inject, Injectable, OnModuleDestroy } from '@nestjs/common';
import { Prisma, PrismaClient } from '@prisma/client';
import { APP_CONFIG, type AppConfig } from '../config';

export type Tx = Prisma.TransactionClient;

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleDestroy {
  constructor(@Inject(APP_CONFIG) config: AppConfig) {
    super({ datasources: { db: { url: config.databaseUrl } } });
  }

  async onModuleDestroy(): Promise<void> {
    await this.$disconnect();
  }

  /**
   * Runs `fn` in a READ COMMITTED transaction. Correctness under concurrency
   * comes from explicit row locks (SELECT ... FOR UPDATE) taken inside `fn`,
   * always in this global order to avoid deadlocks:
   *   Authorization -> Agent -> PurchaseOrder -> Invoice -> AuditChainHead
   * The Agent row lock serializes all spending decisions for one agent, which
   * makes the monthly-budget check race-free.
   */
  tx<T>(fn: (tx: Tx) => Promise<T>): Promise<T> {
    return this.$transaction(fn, {
      isolationLevel: Prisma.TransactionIsolationLevel.ReadCommitted,
      maxWait: 10_000,
      timeout: 20_000,
    });
  }
}

/** Converts a BigInt money column to a JS number, refusing unsafe values. */
export function cents(value: bigint): number {
  const n = Number(value);
  if (!Number.isSafeInteger(n)) throw new Error('amount out of safe range');
  return n;
}

export async function lockRow(tx: Tx, table: string, id: string): Promise<boolean> {
  // `table` is always a hard-coded identifier from our code, never user input.
  const rows = await tx.$queryRawUnsafe<{ id: string }[]>(`SELECT id FROM "${table}" WHERE id = $1 FOR UPDATE`, id);
  return rows.length === 1;
}
