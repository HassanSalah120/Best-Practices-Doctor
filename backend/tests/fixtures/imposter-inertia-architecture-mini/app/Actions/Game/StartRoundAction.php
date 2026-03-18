<?php

namespace App\Actions\Game;

use App\DTO\Game\StartRoundDTO;
use App\Repositories\GameSessionRepository;
use App\Services\Game\StateBroadcastService;

final class StartRoundAction
{
    public function __construct(
        private readonly GameSessionRepository $sessions,
        private readonly StateBroadcastService $broadcast,
    ) {
    }

    public function execute(StartRoundDTO $dto): void
    {
        $session = $this->sessions->findActive($dto->sessionId);
        $this->broadcast->broadcast($session, ['status' => 'started']);
    }
}
