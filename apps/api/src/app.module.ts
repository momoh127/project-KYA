import { Module, type DynamicModule } from '@nestjs/common';
import { APP_FILTER, APP_GUARD } from '@nestjs/core';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { AgentsController } from './agents/agents.controller';
import { AuditController } from './audit/audit.controller';
import { AnchorService } from './audit/anchor.service';
import { AuditService } from './audit/audit.service';
import { IMMUTABLE_STORAGE, LocalWriteOnceStorage } from './audit/immutable-storage';
import { AuthGuard } from './auth/auth.guard';
import { DevAuthController } from './auth/dev-auth.controller';
import { DevTokenService, HUMAN_TOKEN_VERIFIER, RejectAllHumanTokens } from './auth/human-token';
import { SessionsController } from './auth/sessions.controller';
import { AuthorizationsController } from './authorizations/authorizations.controller';
import { AuthorizationsService } from './authorizations/authorizations.service';
import { FactsLoader } from './authorizations/facts.loader';
import { InstructionsController } from './instructions/instructions.controller';
import { InstructionsService } from './instructions/instructions.service';
import { ReceiptsController } from './instructions/receipts.controller';
import { IntegrationsController } from './integrations/integrations.controller';
import { CryptoService } from './common/crypto.service';
import { AllExceptionsFilter } from './common/exception.filter';
import { PrismaService } from './common/prisma.service';
import { APP_CONFIG, type AppConfig } from './config';
import { DelegationsController } from './delegations/delegations.controller';
import { OrganizationsController } from './organizations/organizations.controller';
import { PoliciesController } from './policies/policies.controller';
import { ProcurementController } from './procurement/procurement.controller';
import { SecurityMonitorService } from './security/security-monitor.service';
import { ACCOUNT_VERIFICATION_PROVIDER, SandboxAccountVerificationProvider } from './suppliers/account-verification';
import { SuppliersController } from './suppliers/suppliers.controller';
import { PAYMENT_ADAPTER, SandboxPaymentAdapter } from './transactions/payment-adapter';
import { ReconcilerService } from './transactions/reconciler.service';
import { PaymentEventsService } from './transactions/payment-events.service';
import { SandboxController, WebhooksController } from './transactions/sandbox.controller';
import { SandboxOnboardingController } from './sandbox/sandbox.controller';
import { DocsController } from './docs/docs.controller';
import { SandboxAccountsService } from './sandbox/sandbox-accounts.service';
import { TransactionsController } from './transactions/transactions.controller';
import { TransactionsService } from './transactions/transactions.service';

@Module({})
export class AppModule {
  static forConfig(config: AppConfig): DynamicModule {
    return {
      module: AppModule,
      imports: [ThrottlerModule.forRoot([{ ttl: 60_000, limit: 2000 }])],
      controllers: [
        DevAuthController,
        SessionsController,
        OrganizationsController,
        AgentsController,
        DelegationsController,
        PoliciesController,
        SuppliersController,
        ProcurementController,
        IntegrationsController,
        InstructionsController,
        ReceiptsController,
        AuthorizationsController,
        TransactionsController,
        SandboxController,
        SandboxOnboardingController,
        DocsController,
        WebhooksController,
        AuditController,
      ],
      providers: [
        { provide: APP_CONFIG, useValue: config },
        PrismaService,
        CryptoService,
        AuditService,
        // Production: S3 Object Lock (compliance mode) adapter in a separate account.
        { provide: IMMUTABLE_STORAGE, inject: [APP_CONFIG], useFactory: (c: AppConfig) => new LocalWriteOnceStorage(c.anchorDir) },
        AnchorService,
        SandboxAccountsService,
        DevTokenService,
        {
          provide: HUMAN_TOKEN_VERIFIER,
          inject: [DevTokenService],
          // Production: provide an OIDC/JWKS verifier here.
          useFactory: (dev: DevTokenService) => (dev.enabled ? dev : new RejectAllHumanTokens()),
        },
        SecurityMonitorService,
        FactsLoader,
        InstructionsService,
        AuthorizationsService,
        TransactionsService,
        PaymentEventsService,
        ReconcilerService,
        // Production: replace with a real provider adapter (Stripe, Modern Treasury, bank API).
        { provide: PAYMENT_ADAPTER, useClass: SandboxPaymentAdapter },
        // Production: a real account/ownership verification provider.
        { provide: ACCOUNT_VERIFICATION_PROVIDER, useClass: SandboxAccountVerificationProvider },
        { provide: APP_GUARD, useClass: ThrottlerGuard },
        { provide: APP_GUARD, useClass: AuthGuard },
        { provide: APP_FILTER, useClass: AllExceptionsFilter },
      ],
    };
  }
}
