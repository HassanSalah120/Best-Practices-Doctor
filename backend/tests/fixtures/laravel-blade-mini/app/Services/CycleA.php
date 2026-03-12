<?php

namespace App\Services;

class CycleA
{
    public function __construct(
        private readonly \App\Services\CycleB $b,
    ) {}
}

