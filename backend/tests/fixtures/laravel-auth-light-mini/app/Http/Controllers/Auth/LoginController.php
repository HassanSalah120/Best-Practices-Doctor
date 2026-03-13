<?php

namespace App\Http\Controllers\Auth;

use Illuminate\Http\Request;

class LoginController
{
    public function store(Request $request)
    {
        return $request->validate([
            'email' => ['required', 'email'],
            'password' => ['required'],
        ]);
    }
}
