<?php

namespace App\Actions\Admin;

class GrantAdminFromConsoleAction
{
    public function __invoke(string $email): bool
    {
        return !empty($email);
    }
}
