<?php

use App\Domains\Inventory\Http\Controllers\ReserveStockController;
use Illuminate\Support\Facades\Route;

Route::post('/inventory/reserve', [ReserveStockController::class, 'store'])->name('inventory.reserve');
