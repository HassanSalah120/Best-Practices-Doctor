<?php

namespace App\Domains\Inventory\Http\Controllers;

use App\Domains\Inventory\Services\StockService;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

final class ReserveStockController
{
    public function __construct(
        private readonly StockService $stock,
    ) {
    }

    public function store(Request $request): RedirectResponse
    {
        $items = (array) $request->input('items', []);
        $priority = 0;

        foreach ($items as $item) {
            if (($item['fragile'] ?? false) === true) {
                $priority += 3;
            } else {
                $priority += 1;
            }
        }

        if ($priority > 5) {
            $priority += 2;
        }

        $this->stock->reserve((string) $request->input('sku'), (int) $request->input('quantity', 1), $priority);

        return back()->with('status', 'reserved');
    }
}
