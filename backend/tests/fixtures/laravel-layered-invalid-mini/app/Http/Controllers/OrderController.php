<?php

namespace App\Http\Controllers;

use App\Actions\ProcessOrderAction;
use App\Services\OrderService;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

final class OrderController
{
    public function __construct(
        private readonly ProcessOrderAction $processOrder,
        private readonly OrderService $orders,
    ) {
    }

    public function store(Request $request): RedirectResponse
    {
        $items = (array) $request->input('items', []);
        $orderId = (string) $request->input('order_id');
        $shouldEscalate = $request->boolean('escalate');
        $riskScore = $this->calculateRiskScore($items);

        if ($riskScore > 8) {
            $this->orders->process($orderId, $riskScore);
        }

        if ($shouldEscalate && $riskScore > 10) {
            $this->orders->process($orderId, $riskScore + 1);
        }

        $this->processOrder->execute($orderId, $riskScore);

        return back()->with('status', 'processed');
    }

    private function calculateRiskScore(array $items): int
    {
        $riskScore = 0;

        foreach ($items as $item) {
            if (($item['fragile'] ?? false) === true) {
                $riskScore += 3;
            } else {
                $riskScore += 1;
            }
        }

        return $riskScore;
    }
}
