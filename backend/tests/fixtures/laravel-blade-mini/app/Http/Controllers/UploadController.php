<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

// Fixture controller with unsafe upload handling (no validation).
class UploadController extends Controller
{
    public function store(Request $request)
    {
        $request->file('avatar')->move(public_path('uploads'), 'avatar.jpg');
        return response()->json(['ok' => true]);
    }
}

