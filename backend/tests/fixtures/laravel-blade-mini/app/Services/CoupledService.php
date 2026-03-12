<?php

namespace App\Services;

class CoupledService
{
    public function build(): array
    {
        // Intentionally coupled: references many App\* classes (fixture for high-coupling-class).
        new \App\Http\Controllers\FatController();
        new \App\Http\Controllers\ThinController();
        new \App\Http\Controllers\NewingController();
        new \App\Http\Controllers\ContractController();
        new \App\Http\Controllers\UploadController();

        new \App\Models\User();
        new \App\Models\Massive();

        new \App\Exceptions\UserNotFoundException();

        // Static class reference should count as a dependency.
        app(\App\Contracts\UserServiceInterface::class);

        new \App\Support\DupeA();
        new \App\Support\DupeB();

        new \App\Services\UserService();
        new \App\Services\ManyDepsService();
        new \App\Services\EnvBad();
        new \App\Services\ThrowsBad();
        new \App\Services\ThrowsGood();

        return [];
    }
}

