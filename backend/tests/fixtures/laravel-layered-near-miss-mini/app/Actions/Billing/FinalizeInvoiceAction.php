<?php

namespace App\Actions\Billing;

use App\Services\Billing\InvoiceService;

final class FinalizeInvoiceAction
{
    public function __construct(
        private readonly InvoiceService $invoices,
    ) {
    }

    public function execute(string $invoiceId, bool $sendReceipt, float $total): void
    {
        $this->invoices->finalize($invoiceId, $sendReceipt, $total);
    }
}
