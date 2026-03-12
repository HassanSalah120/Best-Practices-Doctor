<?php

namespace App\Services;

class CycleB
{
    public function __construct(
        private readonly \App\Services\CycleA $a,
    ) {}
}

