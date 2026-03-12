<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use App\Contracts\BoundViaProviderOnlyInterface;
use App\Services\BoundViaProviderOnly;

final class BindingOnlyServiceProvider extends ServiceProvider
{
    private const BINDINGS = [
        // Important fixture: references service only via `::class` and outside method bodies.
        BoundViaProviderOnlyInterface::class => BoundViaProviderOnly::class,
    ];

    public function register(): void
    {
        foreach (self::BINDINGS as $abstract => $concrete) {
            $this->app->bind($abstract, $concrete);
        }
    }
}
