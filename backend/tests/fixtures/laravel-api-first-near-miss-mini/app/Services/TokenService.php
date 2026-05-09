<?php

namespace App\Services;

final class TokenService
{
    public function issue(string $userId, string $deviceName): array
    {
        return ['token' => $userId . ':' . $deviceName];
    }
}
