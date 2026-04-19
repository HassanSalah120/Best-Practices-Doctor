<?php

namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable
{
    public function isAdmin(): bool
    {
        return AdminGrant::query()
            ->active()
            ->where('email', $this->email)
            ->exists();
    }
}
