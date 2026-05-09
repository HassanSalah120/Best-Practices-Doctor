<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Resources\SessionResource;
use App\Services\SessionService;
use Illuminate\Http\Request;

class SessionController extends Controller
{
    public function __construct(
        private readonly SessionService $sessions,
    ) {
    }

    public function store(Request $request): SessionResource
    {
        $session = $this->sessions->create($request->only('id'));

        return new SessionResource($session);
    }
}
