<?php

namespace App\DTO\Game;

final class StartRoundDTO
{
    public function __construct(
        public string $sessionId,
        public array $imposterIds,
    ) {
    }
}
