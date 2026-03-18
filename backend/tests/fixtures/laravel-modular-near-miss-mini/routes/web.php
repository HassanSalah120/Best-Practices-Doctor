<?php

use App\Domains\Rooms\Http\Controllers\JoinRoomController;
use Illuminate\Support\Facades\Route;

Route::post('/rooms/join', [JoinRoomController::class, 'store'])->name('rooms.join');
