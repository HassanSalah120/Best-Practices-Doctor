<?php

namespace App\Contracts\Realtime;

interface QueueDriverInterface
{
    public function push(string $channel, array $payload): void;
}
