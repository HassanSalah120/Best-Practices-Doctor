<?php

namespace App\Services;

class ThrowsBad
{
    public function run(): void
    {
        // Positive for custom-exception-suggestion
        throw new \Exception("boom");
    }
}

