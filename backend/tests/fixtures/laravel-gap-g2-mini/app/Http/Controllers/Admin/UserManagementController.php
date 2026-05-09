<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Inertia\Inertia;
use Inertia\Response;

class UserManagementController extends Controller
{
    public function index(Request $request): Response
    {
        $status = $request->string('status')->value() ?: 'all';
        $search = $request->string('q')->trim()->value();

        return Inertia::render('Admin/Users', [
            'filters' => [
                'status' => $status,
                'q' => $search,
            ],
        ]);
    }
}
