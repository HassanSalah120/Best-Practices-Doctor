<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Exception;

class UserController extends Controller
{
    public function store(Request $request)
    {
        // Bad Practice: Direct validation in controller
        $validated = $request->validate([
            'email' => 'required|email|unique:users',
            'name' => 'required|string|max:255',
        ]);

        // Bad Practice: Business logic in controller (User creation)
        $user = User::create($validated);

        // Bad Practice: More logic
        if ($request->has('send_welcome')) {
            try {
                // Mock mail logic
            } catch (Exception $e) {
                logger()->error($e->getMessage());
            }
        }

        return response()->json($user);
    }
}
