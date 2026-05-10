<?php

namespace App\Http\Controllers;

use App\Actions\Billing\FinalizeInvoiceAction;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

final class BillingController
{
    public function __construct(
        private readonly FinalizeInvoiceAction $finalizeInvoice,
    ) {
    }

    public function finalize(Request $request): RedirectResponse
    {
        $invoiceId = (string) $request->input('invoice_id');
        $sendReceipt = (bool) $request->boolean('send_receipt');

        $this->finalizeInvoice->execute($invoiceId, $sendReceipt);

        return back()->with('status', 'finalized');
    }
}
