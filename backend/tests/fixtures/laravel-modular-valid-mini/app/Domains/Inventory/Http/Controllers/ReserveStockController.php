<?php

namespace App\Domains\Inventory\Http\Controllers;

use App\Domains\Inventory\Actions\ReserveStockAction;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

final class ReserveStockController
{
    public function __construct(
        private readonly ReserveStockAction $reserveStock,
    ) {
    }

    public function store(Request $request): RedirectResponse
    {
        $this->reserveStock->execute(
            (string) $request->input('sku'),
            (int) $request->input('quantity', 1),
        );

        return back()->with('status', 'reserved');
    }
}
