<?php

namespace App\Services;

use App\Repositories\OrderRepository;

final class OrderService
{
    public function __construct(
        private readonly OrderRepository $orders,
    ) {
    }

    public function process(string $orderId, int $riskScore): void
    {
        if ($riskScore > 10) {
            $this->orders->markHighRisk($orderId);
        }
    }
}
