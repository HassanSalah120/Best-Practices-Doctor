<?php

namespace App\Services\Billing;

use App\Repositories\Billing\InvoiceRepository;

final class InvoiceService
{
    public function __construct(
        private readonly InvoiceRepository $invoices,
    ) {
    }

    public function finalize(string $invoiceId, bool $sendReceipt): void
    {
        $this->invoices->markFinalized($invoiceId, $sendReceipt);
    }
}
