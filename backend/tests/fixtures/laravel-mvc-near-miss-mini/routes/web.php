<?php

use App\Http\Controllers\PostController;
use Illuminate\Support\Facades\Route;

Route::post('/posts/draft', [PostController::class, 'storeDraft'])->name('posts.draft');
