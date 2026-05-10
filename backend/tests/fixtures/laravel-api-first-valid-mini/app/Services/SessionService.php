<?php

namespace App\Services;

final class SessionService
{
    public function create(array $payload): array
    {
        return ['id' => $payload['id'] ?? 'new'];
    }
}
