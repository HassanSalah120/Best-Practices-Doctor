<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\DB;

Route::get("/users", [\App\Http\Controllers\FatController::class, "index"]);

// Positive for no-closure-routes + heavy-logic-in-routes
Route::get("/health", function () {
    DB::select("select 1");
    return "ok";
});
