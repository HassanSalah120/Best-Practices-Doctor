<?php

namespace App\Services;

final class SlugService
{
    public function make(string $title): string
    {
        return strtolower(str_replace(' ', '-', trim($title)));
    }
}
