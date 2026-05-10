<?php

namespace App\Http\Controllers;

use App\Services\UserService;
use Illuminate\Http\Request;

class NewingController extends Controller
{
    public function store(Request $request)
    {
        // Positive for ioc-instead-of-new
        $svc = new UserService();
        return response()->json(["n" => $svc->calculateSomething([1, 2, 3])]);
    }
}

