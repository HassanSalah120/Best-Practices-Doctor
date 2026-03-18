<?php

namespace App\Repositories\Billing;

final class InvoiceRepository
{
    public function find(string $invoiceId): object
    {
        return (object) ['id' => $invoiceId];
    }
}
