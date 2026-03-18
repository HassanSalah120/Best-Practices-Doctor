<?php

namespace App\Http\Controllers;

use App\Actions\Billing\FinalizeInvoiceAction;
use App\Services\Billing\InvoiceService;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

final class BillingController
{
    public function __construct(
        private readonly FinalizeInvoiceAction $finalizeInvoice,
        private readonly InvoiceService $invoiceService,
    ) {
    }

    public function finalize(Request $request): RedirectResponse
    {
        $invoiceId = (string) $request->input('invoice_id');
        $sendReceipt = (bool) $request->boolean('send_receipt');
        $items = (array) $request->input('line_items', []);
        $total = $this->calculateInvoiceTotal($items);

        if ($total > 1000) {
            $this->invoiceService->flagForReview($invoiceId, $total);
        }

        $this->finalizeInvoice->execute($invoiceId, $sendReceipt, $total);

        return back()->with('status', 'finalized');
    }

    private function calculateInvoiceTotal(array $items): float
    {
        $total = 0.0;

        foreach ($items as $item) {
            $quantity = (int) ($item['qty'] ?? 1);
            $price = (float) ($item['price'] ?? 0);
            $lineTotal = $quantity * $price;

            if (($item['discount'] ?? 0) > 0) {
                $lineTotal -= $lineTotal * ((float) $item['discount'] / 100);
            }

            if (($item['taxable'] ?? false) === true) {
                $lineTotal += $lineTotal * 0.15;
            }

            $total += $lineTotal;
        }

        return $total;
    }
}
