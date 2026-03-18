<?php

namespace App\Domains\Inventory\Actions;

use App\Domains\Inventory\Services\StockService;

final class ReserveStockAction
{
    public function __construct(
        private readonly StockService $stock,
    ) {
    }

    public function execute(string $sku, int $quantity): void
    {
        $this->stock->reserve($sku, $quantity);
    }
}
