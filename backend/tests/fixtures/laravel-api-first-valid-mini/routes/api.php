<?php

use App\Http\Controllers\Api\SessionController;
use Illuminate\Support\Facades\Route;

Route::post('/sessions', [SessionController::class, 'store'])->name('api.sessions.store');
