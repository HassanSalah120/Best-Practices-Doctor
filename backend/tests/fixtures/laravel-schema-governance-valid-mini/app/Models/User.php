<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    protected $hidden = ['password', 'remember_token', 'api_token_preview'];

    protected $appends = ['avatar_url'];

    protected $casts = [
        'password' => 'hashed',
        'remember_token' => 'encrypted',
    ];
}
