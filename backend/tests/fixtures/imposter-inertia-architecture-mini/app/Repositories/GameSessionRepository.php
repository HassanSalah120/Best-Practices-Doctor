<?php

namespace App\Repositories;

final class GameSessionRepository
{
    public function findActive(string $sessionId): object
    {
        return (object) ['id' => $sessionId];
    }
}
