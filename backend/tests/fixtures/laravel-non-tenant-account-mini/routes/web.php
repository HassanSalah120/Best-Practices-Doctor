<?php

use App\Http\Controllers\AccountController;
use Illuminate\Support\Facades\Route;

Route::middleware(['auth'])->group(function () {
    Route::get('/account/profile', [AccountController::class, 'show']);
});
