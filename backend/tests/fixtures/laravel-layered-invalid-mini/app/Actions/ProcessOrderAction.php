<?php

namespace App\Actions;

use App\Services\OrderService;

final class ProcessOrderAction
{
    public function __construct(
        private readonly OrderService $orders,
    ) {
    }

    public function execute(string $orderId, int $riskScore): void
    {
        $this->orders->process($orderId, $riskScore);
    }
}
