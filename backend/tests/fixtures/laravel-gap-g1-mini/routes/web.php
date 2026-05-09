<?php

use App\Http\Controllers\Admin\SubmissionManagementController;
use App\Http\Controllers\Admin\TopicController;
use App\Http\Controllers\Admin\UserManagementController;
use Illuminate\Support\Facades\Route;

Route::get('/admin/submissions', [SubmissionManagementController::class, 'index']);
Route::get('/admin/users', [UserManagementController::class, 'index']);
Route::get('/admin/topics', [TopicController::class, 'index']);
