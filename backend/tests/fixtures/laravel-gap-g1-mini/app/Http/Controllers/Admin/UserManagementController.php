<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;

class UserManagementController extends Controller
{
    public function index(Request $request)
    {
        $status = $request->string('status')->value() ?: 'all';
        $search = $request->string('q')->trim()->value();

        return response()->json([
            'status' => $status,
            'search' => $search,
        ]);
    }
}
