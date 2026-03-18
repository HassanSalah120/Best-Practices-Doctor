<?php

namespace App\Domains\Rooms\Http\Controllers;

use App\Domains\Rooms\Services\JoinRoomService;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

final class JoinRoomController
{
    public function __construct(
        private readonly JoinRoomService $joinRoom,
    ) {
    }

    public function store(Request $request): RedirectResponse
    {
        $roomCode = (string) $request->input('room_code');
        $userId = (string) $request->user()->id;

        $this->joinRoom->execute($roomCode, $userId);

        return redirect()->back()->with('status', 'joined');
    }
}
