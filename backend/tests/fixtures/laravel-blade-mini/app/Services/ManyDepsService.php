<?php

namespace App\Services;

use App\Models\User;

// Fixture service intentionally has too many constructor deps.
class ManyDepsService
{
    public function __construct(
        private readonly UserService $a,
        private readonly UserService $b,
        private readonly UserService $c,
        private readonly UserService $d,
        private readonly UserService $e,
        private readonly UserService $f,
    ) {}

    public function handle(User $user): void
    {
        // no-op
    }
}

