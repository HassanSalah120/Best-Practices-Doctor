<?php

namespace App\Services;

use App\Contracts\BoundViaProviderOnlyInterface;

final class BoundViaProviderOnly implements BoundViaProviderOnlyInterface
{
    public function handle(): void
    {
        // No-op (fixture).
    }
}
