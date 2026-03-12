<?php

namespace App\Services;

use Illuminate\Support\Facades\Log;

class EnvBad
{
    public function key(): string
    {
        // Positive for env-outside-config
        // Positive for no-log-debug-in-app
        Log::debug("fixture");
        return env("STRIPE_KEY", "");
    }
}
