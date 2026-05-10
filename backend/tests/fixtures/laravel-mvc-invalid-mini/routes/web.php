<?php

use App\Http\Controllers\PostController;
use Illuminate\Support\Facades\Route;

Route::post('/posts/publish', [PostController::class, 'publish'])->name('posts.publish');
