<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ThinController extends Controller
{
    public function ping(Request $request)
    {
        return response()->json(["ok" => true]);
    }
}

