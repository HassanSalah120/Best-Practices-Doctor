<?php

namespace App\Http\Controllers;

use App\Actions\Game\StartRoundAction;
use App\DTO\Game\StartRoundDTO;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

final class GameController
{
    public function __construct(
        private readonly StartRoundAction $startRound,
        private readonly \App\Services\Game\StateBroadcastService $broadcast,
    ) {
    }

    public function startRound(Request $request): RedirectResponse
    {
        $dto = new StartRoundDTO(
            (string) $request->input('session_id'),
            (array) $request->input('imposter_ids', []),
        );

        $this->startRound->execute($dto);
        $this->broadcast->broadcast((object) ['id' => $dto->sessionId]);

        return back()->with('success', 'started');
    }
}
