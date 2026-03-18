<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Resources\TokenResource;
use App\Services\TokenService;
use Illuminate\Http\Request;

class TokenController extends Controller
{
    public function __construct(
        private readonly TokenService $tokens,
    ) {
    }

    public function store(Request $request): TokenResource
    {
        $payload = $request->only('device_name');
        $payload['user_id'] = (string) $request->user()->id;
        $token = $this->tokens->issue($payload['user_id'], (string) $payload['device_name']);

        return new TokenResource($token);
    }
}
