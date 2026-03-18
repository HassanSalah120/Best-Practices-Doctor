<?php

namespace App\Services\Billing;

use App\Repositories\Billing\InvoiceRepository;

final class InvoiceService
{
    public function __construct(
        private readonly InvoiceRepository $invoices,
    ) {
    }

    public function flagForReview(string $invoiceId, float $total): void
    {
        $this->invoices->find($invoiceId);
    }

    public function finalize(string $invoiceId, bool $sendReceipt, float $total): void
    {
        $this->invoices->find($invoiceId);
    }
}
