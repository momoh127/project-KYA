-- AddForeignKey
ALTER TABLE "PurchaseInstructionLine" ADD CONSTRAINT "PurchaseInstructionLine_instructionId_fkey" FOREIGN KEY ("instructionId") REFERENCES "PurchaseInstruction"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "InvoiceLine" ADD CONSTRAINT "InvoiceLine_invoiceId_fkey" FOREIGN KEY ("invoiceId") REFERENCES "Invoice"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

