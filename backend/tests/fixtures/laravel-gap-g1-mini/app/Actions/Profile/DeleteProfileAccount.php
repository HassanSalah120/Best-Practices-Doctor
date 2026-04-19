<?php

namespace App\Actions\Profile;

class DeleteProfileAccount
{
    public function handle(int $userId): bool
    {
        return $userId > 0;
    }
}
