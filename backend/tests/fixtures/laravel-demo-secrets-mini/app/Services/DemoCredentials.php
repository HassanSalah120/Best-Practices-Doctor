<?php

namespace App\Services;

class DemoCredentials
{
    public function defaults(): array
    {
        return [
            'api_key' => 'demo-api-key',
            'password' => 'example-password',
            'secret' => 'placeholder-secret',
        ];
    }
}
