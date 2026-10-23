import { Module, type DynamicModule } from '@nestjs/common';
import { APP_FILTER, APP_GUARD } from '@nestjs/core';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { AgentsController } from './agents/agents.controller';
import { AuditController } from './audit/audit.controller';
import { AuditService } from './audit/audit.service';
import { AuthGuard } from './auth/auth.guard';
import { DevAuthController } from './auth/dev-auth.controller';
import { DevTokenService, HUMAN_TOKEN_VERIFIER, RejectAllHumanTokens } from './auth/human-token';
import { AuthorizationsController } from './authorizations/authorizations.controller';
import { AuthorizationsService } from './authorizations/authorizations.service';
import { CircuitBreakerService } from './authorizations/circuit-breaker.service';
import { FactsLoader } from './authorizations/facts.loader';
import { CryptoService } from './common/crypto.service';
import { AllExceptionsFilter } from './common/exception.filter';
import { PrismaService } from './common/prisma.service';
import { APP_CONFIG, type AppConfig } from './config';
import { DelegationsController } from './delegations/delegations.controller';
import { OrganizationsController } from './organizations/organizations.controller';
import { PoliciesController } from './policies/policies.controller';
import { ProcurementController } from './procurement/procurement.controller';
import { SuppliersController } from './suppliers/suppliers.controller';
import { PAYMENT_ADAPTER, SandboxPaymentAdapter } from './transactions/payment-adapter';
import { TransactionsController } from './transactions/transactions.controller';
import { TransactionsService } from './transactions/transactions.service';

@Module({})
export class AppModule {
  static forConfig(config: AppConfig): DynamicModule {
    return {
      module: AppModule,
      imports: [ThrottlerModule.forRoot([{ ttl: 60_000, limit: 1200 }])],
      controllers: [
        DevAuthController,
        OrganizationsController,
        AgentsController,
        DelegationsController,
        PoliciesController,
        SuppliersController,
        ProcurementController,
        AuthorizationsController,
        TransactionsController,
        AuditController,
      ],
      providers: [
        { provide: APP_CONFIG, useValue: config },
        PrismaService,
        CryptoService,
        AuditService,
        DevTokenService,
        {
          provide: HUMAN_TOKEN_VERIFIER,
          inject: [DevTokenService],
          // Production: provide an OIDC/JWKS verifier here.
          useFactory: (dev: DevTokenService) => (dev.enabled ? dev : new RejectAllHumanTokens()),
        },
        FactsLoader,
        CircuitBreakerService,
        AuthorizationsService,
        TransactionsService,
        { provide: PAYMENT_ADAPTER, useClass: SandboxPaymentAdapter },
        { provide: APP_GUARD, useClass: ThrottlerGuard },
        { provide: APP_GUARD, useClass: AuthGuard },
        { provide: APP_FILTER, useClass: AllExceptionsFilter },
      ],
    };
  }
}
