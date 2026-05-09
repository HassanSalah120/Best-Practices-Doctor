<?php

namespace App\Services;

use App\Exceptions\UserNotFoundException;

class ThrowsGood
{
    public function run(): void
    {
        // Negative: domain exception
        throw new UserNotFoundException("boom");
    }
}

